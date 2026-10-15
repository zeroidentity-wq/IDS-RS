// =============================================================================
// detector/distributed.rs - Distributed Scan (#23)
// =============================================================================
//
// N surse diferite lovesc aceeasi tinta in aceeasi fereastra de timp.
//
// Perspectiva inversata: tabela este indexata dupa dest_ip, nu dupa sursa.
// Hit-ul se inregistreaza indiferent de actiune (drop sau accept) — un atac
// coordonat poate genera ambele tipuri de trafic.
//
// Cooldown-ul este per dest_ip (tinta), nu per source_ip: daca 10 surse
// scaneaza tinta X, o singura alerta este generata pentru X.
//
// =============================================================================

use super::alert::{Alert, ScanType};
use super::capacity::{keep_newest, make_room, prune};
use super::cooldown::Cooldowns;
use super::ParsedExceptions;
use crate::config::DetectionConfig;
use crate::parser::LogEvent;
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Inregistrarea unui hit asupra unei tinte.
///
/// Indexat dupa dest_ip (cheia DashMap-ului). Tine minte CINE a lovit tinta si CAND.
pub(super) struct DistributedHit {
    pub(super) source_ip: IpAddr,
    pub(super) port: u16,
    pub(super) seen_at: Instant,
}

pub(super) struct DistributedScan {
    /// Key: IP-ul destinatie | Value: lista de (source_ip, port, timestamp)
    pub(super) hits: DashMap<IpAddr, Vec<DistributedHit>>,
    /// Cooldown alerte per IP destinatie (tinta).
    cooldowns: Cooldowns<IpAddr>,
}

impl DistributedScan {
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
        let ds_cfg = &cfg.distributed_scan;
        if !ds_cfg.enabled {
            return None;
        }
        let dest_ip = event.dest_ip?;

        // Exceptie: portul destinatie e in ignore_distributed_target_ports
        // (ex: DNS 53, NTP 123) → nu contorizam acest hit. Verificarea de mai
        // jos ruleaza oricum, pe hit-urile deja inregistrate pentru tinta.
        if !exceptions
            .ignore_distributed_target_ports
            .contains(&event.dest_port)
        {
            // --- Cap pe numarul de tinte urmarite ---
            //
            // Tabela este indexata dupa dest_ip, deci LRU-ul global pe
            // `last_seen` (pe sursa) nu o afecteaza. Pentru a preveni cresterea
            // nelimitata a numarului de chei (#bug-8), aplicam o limita
            // explicita = `max_tracked_ips`.
            for evicted in make_room(&self.hits, &dest_ip, cfg.max_tracked_ips, |hit| hit.seen_at) {
                self.cooldowns.remove(&evicted);
            }

            let mut hits = self.hits.entry(dest_ip).or_default();
            hits.push(DistributedHit {
                source_ip: event.source_ip,
                port: event.dest_port,
                seen_at: now,
            });
            // Cap memorie: refolosim max_hits_per_ip ca limita.
            keep_newest(&mut hits, cfg.max_hits_per_ip);
        }

        let window = Duration::from_secs(ds_cfg.time_window_secs);
        let (unique_sources, targeted_ports) =
            self.unique_sources_in_window(dest_ip, window, now)?;
        if unique_sources.len() < ds_cfg.unique_sources_threshold
            || self.cooldowns.is_active(&dest_ip, cooldown)
        {
            return None;
        }
        self.cooldowns.start(dest_ip, now);
        // `source_ip` = ultimul atacator; lista completa e in `unique_sources`.
        let mut alert = Alert::new(ScanType::DistributedScan, event.source_ip, Some(dest_ip));
        alert.unique_ports = targeted_ports;
        alert.unique_sources = unique_sources;
        Some(alert)
    }

    /// Sursele unice si porturile vizate (sortate) pe o tinta in fereastra `window`.
    /// `None` daca nu exista date sau lista e goala.
    fn unique_sources_in_window(
        &self,
        dest_ip: IpAddr,
        window: Duration,
        now: Instant,
    ) -> Option<(Vec<IpAddr>, Vec<u16>)> {
        let hits = self.hits.get(&dest_ip)?;
        let mut sources: HashSet<IpAddr> = HashSet::new();
        let mut ports: HashSet<u16> = HashSet::new();
        for hit in hits.iter() {
            if now.saturating_duration_since(hit.seen_at) <= window {
                sources.insert(hit.source_ip);
                ports.insert(hit.port);
            }
        }
        if sources.is_empty() {
            return None;
        }
        let mut ports: Vec<u16> = ports.into_iter().collect();
        ports.sort_unstable();
        Some((sources.into_iter().collect(), ports))
    }

    /// Sterge hit-urile surselor `victims` de pe toate tintele.
    pub(super) fn evict_sources(&self, victims: &HashSet<IpAddr>) {
        for mut entry in self.hits.iter_mut() {
            entry
                .value_mut()
                .retain(|hit| !victims.contains(&hit.source_ip));
        }
    }

    pub(super) fn cleanup(&self, now: Instant, max_age: Duration, cooldown: Duration) {
        prune(&self.hits, |hit| {
            now.saturating_duration_since(hit.seen_at) <= max_age
        });
        self.cooldowns.prune(now, cooldown);
    }
}
