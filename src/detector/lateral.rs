// =============================================================================
// detector/lateral.rs - Lateral Movement (#22)
// =============================================================================
//
// Un IP sursa contacteaza N destinatii diferite pe conexiuni acceptate.
//
// Fara filtru de port: detectia e bazata pe comportament (1 sursa → N
// destinatii unice), nu pe asumptii despre porturile atacatorului.
// Servicii legitime cu fan-out mare se pun in whitelist sau in
// `authorized_scanners` / `ignore_lateral_ports`.
//
// =============================================================================

use super::alert::{Alert, ScanType};
use super::capacity::{keep_newest, prune};
use super::cooldown::Cooldowns;
use super::snapshot::{
    restore_cooldowns, restore_table, snapshot_cooldowns, snapshot_table, Clock, TableSnapshot,
    Timestamped,
};
use super::ParsedExceptions;
use crate::config::DetectionConfig;
use crate::parser::{Action, LogEvent};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Inregistrarea unei conexiuni catre o destinatie.
///
/// Tine minte CATRE CE IP s-a conectat sursa si cand.
/// Spre deosebire de PortHit (care tine minte portul accesat),
/// DestHit tine minte destinatia accesata.
pub(super) struct DestHit {
    dest_ip: IpAddr,
    pub(super) seen_at: Instant,
}

impl Timestamped for DestHit {
    type Data = IpAddr;
    fn split(&self) -> (IpAddr, Instant) {
        (self.dest_ip, self.seen_at)
    }
    fn join(dest_ip: IpAddr, seen_at: Instant) -> Self {
        Self { dest_ip, seen_at }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct LateralSnapshot {
    hits: TableSnapshot<IpAddr, IpAddr>,
    cooldowns: Vec<(IpAddr, u64)>,
}

pub(super) struct LateralMovement {
    /// Destinatiile contactate, per IP sursa.
    /// Key: IP-ul sursa | Value: lista de (dest_ip, timestamp)
    pub(super) hits: DashMap<IpAddr, Vec<DestHit>>,
    /// Cooldown alerte per IP sursa.
    cooldowns: Cooldowns<IpAddr>,
}

impl LateralMovement {
    pub(super) fn new() -> Self {
        Self {
            hits: DashMap::new(),
            cooldowns: Cooldowns::new(),
        }
    }

    /// Conditii: detectia activata, dest_ip prezent, actiune accept, sursa
    /// nu e scanner autorizat, portul nu e ignorat.
    pub(super) fn record_and_check(
        &self,
        event: &LogEvent,
        now: Instant,
        cfg: &DetectionConfig,
        exceptions: &ParsedExceptions,
        cooldown: Duration,
    ) -> Option<Alert> {
        let lm_cfg = &cfg.lateral_movement;
        let source = event.source_ip;
        let dest_ip = event.dest_ip?;
        if !lm_cfg.enabled
            || event.action != Action::Accept
            || exceptions.authorized_scanners.contains(&source)
            || exceptions.ignore_lateral_ports.contains(&event.dest_port)
        {
            return None;
        }

        {
            let mut hits = self.hits.entry(source).or_default();
            hits.push(DestHit {
                dest_ip,
                seen_at: now,
            });
            // Cap memorie: refolosim max_hits_per_ip ca limita.
            keep_newest(&mut hits, cfg.max_hits_per_ip);
        }

        let window = Duration::from_secs(lm_cfg.time_window_secs);
        let unique_dests = self.unique_dests_in_window(source, window, now)?;
        if unique_dests.len() < lm_cfg.unique_dest_threshold
            || self.cooldowns.is_active(&source, cooldown)
        {
            return None;
        }
        self.cooldowns.start(source, now);
        let mut alert = Alert::new(ScanType::LateralMovement, source, Some(dest_ip));
        alert.unique_dests = unique_dests;
        Some(alert)
    }

    /// Destinatiile unice contactate de `source` in fereastra `window`.
    /// `None` daca nu exista date pentru sursa sau lista e goala.
    fn unique_dests_in_window(
        &self,
        source: IpAddr,
        window: Duration,
        now: Instant,
    ) -> Option<Vec<IpAddr>> {
        let hits = self.hits.get(&source)?;
        let seen: HashSet<IpAddr> = hits
            .iter()
            .filter(|hit| now.saturating_duration_since(hit.seen_at) <= window)
            .map(|hit| hit.dest_ip)
            .collect();
        if seen.is_empty() {
            None
        } else {
            Some(seen.into_iter().collect())
        }
    }

    pub(super) fn evict_sources(&self, victims: &HashSet<IpAddr>) {
        for source in victims {
            self.hits.remove(source);
            self.cooldowns.remove(source);
        }
    }

    pub(super) fn cleanup(&self, now: Instant, max_age: Duration, cooldown: Duration) {
        prune(&self.hits, |hit| {
            now.saturating_duration_since(hit.seen_at) <= max_age
        });
        self.cooldowns.prune(now, cooldown);
    }

    pub(super) fn snapshot(&self, clock: &Clock) -> LateralSnapshot {
        LateralSnapshot {
            hits: snapshot_table(&self.hits, clock),
            cooldowns: snapshot_cooldowns(&self.cooldowns, clock),
        }
    }

    pub(super) fn restore(&self, snapshot: LateralSnapshot, clock: &Clock) {
        restore_table(&self.hits, snapshot.hits, clock);
        restore_cooldowns(&self.cooldowns, snapshot.cooldowns, clock);
    }

    /// Adauga sursele care mai au hit-uri (pentru sincronizarea `last_seen`).
    pub(super) fn collect_active_sources(&self, sources: &mut HashSet<IpAddr>) {
        sources.extend(self.hits.iter().map(|entry| *entry.key()));
    }
}
