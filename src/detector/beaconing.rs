// =============================================================================
// detector/beaconing.rs - Beaconing C2 (#24)
// =============================================================================
//
// Trafic periodic catre un host C2 / staging pivot: un flow
// `(src_ip, dest_ip, dest_port)` cu intervale aproape constante intre
// conexiuni acceptate.
//
// Conditii:
//   a) Beaconing activat in config
//   b) dest_ip prezent
//   c) action == accept (callback C2 e o conexiune reusita; drop-urile
//      reflecta un firewall care taie traficul → nu mai e beacon viabil)
//   d) Portul destinatie nu e in ignore_beaconing_ports
//   e) Sursa nu e in authorized_beaconing_sources
//
// Algoritm: pe cheia (src, dst, dport) acumulam timestamp-uri. Cand avem
// >= min_events in fereastra, calculam CV (stddev / mean) pe intervalele
// dintre timestamp-uri consecutive. CV mic + mean in [min_interval,
// max_interval] => beaconing.
//
// =============================================================================

use super::alert::{Alert, ScanType};
use super::capacity::{keep_newest, make_room, prune};
use super::cooldown::Cooldowns;
use super::ParsedExceptions;
use crate::config::DetectionConfig;
use crate::parser::{Action, LogEvent};
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Cheia unui flow: (sursa, destinatie, port destinatie).
pub(super) type FlowKey = (IpAddr, IpAddr, u16);

/// Timestamp-ul unei conexiuni dintr-un flow.
///
/// Toate campurile flow-ului sunt deja codificate in cheie. Tinem doar
/// momentul cand a aparut conexiunea — diferentele consecutive dintre
/// `seen_at`-uri sunt intervalele pe care le analizam statistic.
pub(super) struct BeaconHit {
    pub(super) seen_at: Instant,
}

/// Statisticile unui flow in fereastra de analiza.
#[derive(Debug)]
pub(super) struct BeaconStats {
    pub(super) mean_interval_secs: f64,
    pub(super) cv: f64,
    pub(super) count: usize,
}

pub(super) struct Beaconing {
    /// Flow-urile diferite pe acelasi port sau intre aceleasi hosturi nu se
    /// amesteca. Valorile sunt timestamp-uri.
    pub(super) hits: DashMap<FlowKey, Vec<BeaconHit>>,
    /// Cooldown alerte per flow (src, dst, dport).
    cooldowns: Cooldowns<FlowKey>,
}

impl Beaconing {
    pub(super) fn new() -> Self {
        Self {
            hits: DashMap::new(),
            cooldowns: Cooldowns::new(),
        }
    }

    pub(super) fn record_and_check(
        &self,
        event: &LogEvent,
        now: Instant,
        cfg: &DetectionConfig,
        exceptions: &ParsedExceptions,
        cooldown: Duration,
    ) -> Option<Alert> {
        let bc_cfg = &cfg.beaconing;
        if !bc_cfg.enabled || event.action != Action::Accept {
            return None;
        }
        let dest_ip = event.dest_ip?;
        let source = event.source_ip;
        let port = event.dest_port;
        if exceptions.ignore_beaconing_ports.contains(&port)
            || exceptions.authorized_beaconing_sources.contains(&source)
        {
            return None;
        }
        let flow_key = (source, dest_ip, port);

        // --- Cap pe numarul de flow-uri urmarite (LRU pe ultimul seen_at) ---
        for evicted in make_room(&self.hits, &flow_key, cfg.max_tracked_ips, |hit| {
            hit.seen_at
        }) {
            self.cooldowns.remove(&evicted);
        }

        // Inregistram timestamp-ul. Cap memorie per flow: min_events * 4.
        let cap = bc_cfg
            .min_events
            .saturating_mul(4)
            .max(bc_cfg.min_events + 4);
        {
            let mut hits = self.hits.entry(flow_key).or_default();
            hits.push(BeaconHit { seen_at: now });
            keep_newest(&mut hits, cap);
        }

        // Calcul CV pe fereastra activa.
        let window = Duration::from_secs(bc_cfg.time_window_secs);
        let stats = self.stats(&flow_key, window, now)?;
        let mean_ok = stats.mean_interval_secs >= bc_cfg.min_interval_secs as f64
            && stats.mean_interval_secs <= bc_cfg.max_interval_secs as f64;
        let triggered = stats.count >= bc_cfg.min_events
            && mean_ok
            && stats.cv <= bc_cfg.cv_threshold
            && !self.cooldowns.is_active(&flow_key, cooldown);
        if !triggered {
            return None;
        }
        self.cooldowns.start(flow_key, now);
        let mut alert = Alert::new(ScanType::Beaconing, source, Some(dest_ip));
        alert.beacon_port = Some(port);
        alert.mean_interval_secs = Some(stats.mean_interval_secs);
        alert.cv = Some(stats.cv);
        alert.event_count = Some(stats.count);
        Some(alert)
    }

    /// Statisticile (interval mediu, CV, numar) pentru un flow.
    ///
    /// `None` daca avem < 2 intrari in fereastra (nu putem calcula intervale)
    /// sau daca media intervalelor este 0 (toate timestamp-urile identice →
    /// impartire la zero).
    pub(super) fn stats(
        &self,
        flow_key: &FlowKey,
        window: Duration,
        now: Instant,
    ) -> Option<BeaconStats> {
        // Selectam doar timestamp-urile din fereastra de timp, in ordine cronologica.
        let timestamps: Vec<Instant> = self
            .hits
            .get(flow_key)?
            .iter()
            .filter(|h| now.saturating_duration_since(h.seen_at) <= window)
            .map(|h| h.seen_at)
            .collect();

        if timestamps.len() < 2 {
            return None;
        }
        // Intervalele consecutive (in secunde, f64 pentru precizie).
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| w[1].saturating_duration_since(w[0]).as_secs_f64())
            .collect();
        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;
        if mean <= 0.0 {
            return None;
        }
        let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        Some(BeaconStats {
            mean_interval_secs: mean,
            cv: variance.sqrt() / mean,
            count: timestamps.len(),
        })
    }

    pub(super) fn evict_sources(&self, victims: &HashSet<IpAddr>) {
        self.hits
            .retain(|(source, _, _), _| !victims.contains(source));
        self.cooldowns
            .retain_keys(|(source, _, _)| !victims.contains(source));
    }

    pub(super) fn cleanup(&self, now: Instant, max_age: Duration, cooldown: Duration) {
        prune(&self.hits, |hit| {
            now.saturating_duration_since(hit.seen_at) <= max_age
        });
        self.cooldowns.prune(now, cooldown);
    }
}
