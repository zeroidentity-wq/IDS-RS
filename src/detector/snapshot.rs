// =============================================================================
// detector/snapshot.rs - Starea detectorului salvata pe disc (#32)
// =============================================================================
//
// La restart (upgrade, systemctl restart, crash) detectorul ar pierde tot
// contextul: Slow Scan (5 min) si Beaconing (1 h) ar reincepe numaratoarea,
// iar cooldown-urile ar disparea - o scanare in desfasurare ar genera din
// nou aceeasi alerta catre SIEM si email.
//
// TIMPUL: hit-urile folosesc `Instant` (monotonic, fara sens dupa repornirea
// procesului). In snapshot fiecare moment devine o VARSTA in nanosecunde
// fata de momentul salvarii (nanosecunde, ca ordinea relativa a momentelor sa
// ramana exacta - evictia LRU alege dupa ea); la restaurare varsta creste cu timpul scurs de
// la salvare si devine din nou un `Instant` in trecut. Momentele mai vechi
// decat ceasul monotonic al sistemului (ex: dupa un reboot recent) nu pot fi
// reprezentate si sunt ignorate - oricum sunt in afara ferestrelor scurte.
//
// =============================================================================

use super::cooldown::Cooldowns;
use dashmap::DashMap;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Converteste intre `Instant` si varste serializabile.
pub(super) struct Clock {
    now: Instant,
    /// Timpul scurs intre salvare si restaurare (0 la salvare).
    elapsed: Duration,
}

impl Clock {
    pub(super) fn for_snapshot(now: Instant) -> Self {
        Self {
            now,
            elapsed: Duration::ZERO,
        }
    }

    pub(super) fn for_restore(now: Instant, elapsed: Duration) -> Self {
        Self { now, elapsed }
    }

    pub(super) fn age_ns(&self, instant: Instant) -> u64 {
        let age = self.now.saturating_duration_since(instant);
        u64::try_from(age.as_nanos()).unwrap_or(u64::MAX)
    }

    pub(super) fn instant(&self, age_ns: u64) -> Option<Instant> {
        let age = Duration::from_nanos(age_ns).checked_add(self.elapsed)?;
        self.now.checked_sub(age)
    }
}

/// Un hit cu momentul lui: datele serializabile + `seen_at`.
pub(super) trait Timestamped: Sized {
    type Data: Serialize + DeserializeOwned;
    fn split(&self) -> (Self::Data, Instant);
    fn join(data: Self::Data, seen_at: Instant) -> Self;
}

/// O tabela de hit-uri: cheie → lista de (date, varsta in ns).
pub(super) type TableSnapshot<K, D> = Vec<(K, Vec<(D, u64)>)>;

pub(super) fn snapshot_table<K, H>(
    map: &DashMap<K, Vec<H>>,
    clock: &Clock,
) -> TableSnapshot<K, H::Data>
where
    K: Eq + Hash + Clone,
    H: Timestamped,
{
    map.iter()
        .map(|entry| {
            let hits = entry
                .value()
                .iter()
                .map(|hit| {
                    let (data, seen_at) = hit.split();
                    (data, clock.age_ns(seen_at))
                })
                .collect();
            (entry.key().clone(), hits)
        })
        .collect()
}

/// Reface tabela; ordinea cronologica din snapshot se pastreaza.
pub(super) fn restore_table<K, H>(
    map: &DashMap<K, Vec<H>>,
    table: TableSnapshot<K, H::Data>,
    clock: &Clock,
) where
    K: Eq + Hash,
    H: Timestamped,
{
    for (key, hits) in table {
        let hits: Vec<H> = hits
            .into_iter()
            .filter_map(|(data, age_ns)| Some(H::join(data, clock.instant(age_ns)?)))
            .collect();
        if !hits.is_empty() {
            map.insert(key, hits);
        }
    }
}

pub(super) fn snapshot_cooldowns<K>(cooldowns: &Cooldowns<K>, clock: &Clock) -> Vec<(K, u64)>
where
    K: Eq + Hash + Clone,
{
    cooldowns
        .entries()
        .into_iter()
        .map(|(key, started)| (key, clock.age_ns(started)))
        .collect()
}

pub(super) fn restore_cooldowns<K>(cooldowns: &Cooldowns<K>, entries: Vec<(K, u64)>, clock: &Clock)
where
    K: Eq + Hash,
{
    for (key, age_ns) in entries {
        if let Some(started) = clock.instant(age_ns) {
            cooldowns.start(key, started);
        }
    }
}

/// Starea completa a detectorului. Campurile sunt private: formatul este
/// un detaliu intern, versionat de fisierul de stare (persistence.rs).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DetectorSnapshot {
    pub(super) last_seen: Vec<(IpAddr, u64)>,
    pub(super) port_scan: super::port_scan::PortScanSnapshot,
    pub(super) lateral: super::lateral::LateralSnapshot,
    pub(super) distributed: super::distributed::DistributedSnapshot,
    pub(super) beaconing: super::beaconing::BeaconingSnapshot,
    pub(super) baseline: super::baseline::BaselineSnapshot,
}

impl DetectorSnapshot {
    /// Numarul de IP-uri sursa urmarite in snapshot.
    pub fn tracked_ips(&self) -> usize {
        self.last_seen.len()
    }
}
