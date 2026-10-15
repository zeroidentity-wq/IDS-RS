// =============================================================================
// detector/port_scan.rs - Fast Scan, Slow Scan si Accept Scan
// =============================================================================
//
// Toate trei numara porturile unice pe perechea (sursa, destinatie):
//   - Fast Scan:   >= X porturi BLOCATE unice in Y secunde
//   - Slow Scan:   >= Z porturi BLOCATE unice in W minute
//   - Accept Scan: >= N porturi ACCEPTATE unice in M secunde
//
// Fast si Slow citesc aceleasi hit-uri (drop) cu ferestre diferite, iar
// Accept are tabela lui (accept). Capacitatea (max_tracked_flows,
// max_flows_per_source) este comuna ambelor tabele, deci starea sta impreuna.
//
// =============================================================================

use super::alert::{Alert, ScanType};
use super::capacity::{eviction_count, keep_newest, oldest_keys, prune};
use super::cooldown::Cooldowns;
use crate::config::DetectionConfig;
use crate::parser::{Action, LogEvent};
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Inregistrarea unui port accesat de un IP la un moment dat.
///
/// NOTA RUST: `Instant` este un timestamp monotonic (nu wall-clock).
/// Nu poate fi afectat de schimbari de ora / NTP. Perfect pentru
/// masurarea duratelor si timeout-uri.
/// `Instant` NU implementeaza Serialize - nu poate fi salvat pe disc,
/// dar este eficient si sigur pentru masuratori in-process.
pub(super) struct PortHit {
    pub(super) port: u16,
    pub(super) seen_at: Instant,
}

/// Cheie de corelare pentru detectiile Fast/Slow/Accept: perechea (sursa, destinatie).
pub(super) type ScanPairKey = (IpAddr, IpAddr);

/// Pragurile efective (statice sau dinamice #35) pentru un eveniment.
pub(super) struct Thresholds {
    pub(super) fast: usize,
    pub(super) slow: usize,
    pub(super) accept: usize,
}

pub(super) struct PortScan {
    /// Evidenta porturilor BLOCATE (drop) accesate per pereche (IP sursa, IP destinatie).
    /// Alimenteaza detectia Fast Scan si Slow Scan.
    /// Key: (IP sursa, IP destinatie) | Value: lista de (port, timestamp)
    pub(super) drop_hits: DashMap<ScanPairKey, Vec<PortHit>>,

    /// Evidenta porturilor ACCEPTATE (accept) accesate per pereche (IP sursa, IP destinatie).
    /// Alimenteaza detectia Accept Scan (porturi deschise).
    ///
    /// NOTA: Separat de drop_hits intentionat — amestecarea drop-urilor cu
    /// accept-urile ar contamina detectia. Un Fast Scan poate aparea simultan
    /// cu un Accept Scan de la acelasi IP, si vrem sa le detectam independent.
    pub(super) accept_hits: DashMap<ScanPairKey, Vec<PortHit>>,

    /// Index secundar peste `drop_hits` + `accept_hits`: fluxurile fiecarei
    /// surse, ca `(is_drop, dest_ip)`. Permite numararea si evictia per sursa
    /// fara a parcurge toate fluxurile urmarite la fiecare flux nou.
    pub(super) source_flows: DashMap<IpAddr, HashSet<(bool, IpAddr)>>,

    /// Cooldown alerte per pereche (src, dst), independent pe fiecare tip.
    fast_cooldowns: Cooldowns<ScanPairKey>,
    slow_cooldowns: Cooldowns<ScanPairKey>,
    accept_cooldowns: Cooldowns<ScanPairKey>,
}

impl PortScan {
    pub(super) fn new() -> Self {
        Self {
            drop_hits: DashMap::new(),
            accept_hits: DashMap::new(),
            source_flows: DashMap::new(),
            fast_cooldowns: Cooldowns::new(),
            slow_cooldowns: Cooldowns::new(),
            accept_cooldowns: Cooldowns::new(),
        }
    }

    fn hits(&self, is_drop: bool) -> &DashMap<ScanPairKey, Vec<PortHit>> {
        if is_drop {
            &self.drop_hits
        } else {
            &self.accept_hits
        }
    }

    /// Inregistreaza evenimentul si adauga in `alerts` alertele Fast, Slow si
    /// Accept Scan declansate, in aceasta ordine.
    pub(super) fn record_and_check(
        &self,
        event: &LogEvent,
        now: Instant,
        cfg: &DetectionConfig,
        thresholds: &Thresholds,
        cooldown: Duration,
        alerts: &mut Vec<Alert>,
    ) {
        // Fara destinatie nu exista pereche (src, dst) de corelat.
        let Some(dest_ip) = event.dest_ip else {
            return;
        };
        let key = (event.source_ip, dest_ip);

        // --- Inregistram port hit-ul in tabela corespunzatoare actiunii ---
        //
        //   drop   → drop_hits   (port BLOCAT de firewall → Fast/Slow Scan)
        //   accept → accept_hits (port PERMIS de firewall → Accept Scan)
        //
        // NOTA RUST - SCOP (SCOPE) EXPLICIT cu `{}`:
        // Blocul `{}` garanteaza ca `RefMut` (write-lock-ul DashMap) este dropit
        // (eliberat) inainte de urmatoarele operatii pe DashMap.
        // Altfel: write-lock activ → urmatorul .get() pe acelasi shard → deadlock.
        //
        // NOTA #3 - LIMITARE MEMORIE PER IP: pastram doar ultimele
        // max_hits_per_ip intrari, la ambele tabele.
        let is_drop = event.action == Action::Drop;
        self.ensure_capacity(key, is_drop, cfg);
        self.index_flow(is_drop, key);
        {
            let mut hits = self.hits(is_drop).entry(key).or_default();
            hits.push(PortHit {
                port: event.dest_port,
                seen_at: now,
            });
            keep_newest(&mut hits, cfg.max_hits_per_ip);
        }

        // --- Fast Scan si Slow Scan (pe drop_hits) ---
        //
        // Aceleasi hit-uri, ferestre si cooldown-uri diferite.
        let checks = [
            (
                ScanType::Fast,
                &self.drop_hits,
                Duration::from_secs(cfg.fast_scan.time_window_secs),
                thresholds.fast,
                &self.fast_cooldowns,
            ),
            (
                ScanType::Slow,
                &self.drop_hits,
                Duration::from_secs(cfg.slow_scan.time_window_mins * 60),
                thresholds.slow,
                &self.slow_cooldowns,
            ),
            // --- Accept Scan (pe accept_hits — conexiuni permise) ---
            //
            // Separarea completa de Fast/Slow Scan inseamna ca un IP poate
            // declansa simultan o alerta Fast Scan (din drop-uri) SI o alerta
            // Accept Scan (din accept-uri) — independent.
            (
                ScanType::AcceptScan,
                &self.accept_hits,
                Duration::from_secs(cfg.accept_scan.time_window_secs),
                thresholds.accept,
                &self.accept_cooldowns,
            ),
        ];
        for (scan_type, hits, window, threshold, cooldowns) in checks {
            let Some(ports) = unique_ports_in_window(hits, key, window, now) else {
                continue;
            };
            if ports.len() >= threshold && !cooldowns.is_active(&key, cooldown) {
                cooldowns.start(key, now);
                let mut alert = Alert::new(scan_type, event.source_ip, Some(dest_ip));
                alert.unique_ports = ports;
                alerts.push(alert);
            }
        }
    }

    fn remove_flow(&self, is_drop: bool, key: ScanPairKey) {
        self.hits(is_drop).remove(&key);
        if is_drop {
            self.fast_cooldowns.remove(&key);
            self.slow_cooldowns.remove(&key);
        } else {
            self.accept_cooldowns.remove(&key);
        }
        self.unindex_flow(is_drop, key);
    }

    fn index_flow(&self, is_drop: bool, key: ScanPairKey) {
        self.source_flows
            .entry(key.0)
            .or_default()
            .insert((is_drop, key.1));
    }

    fn unindex_flow(&self, is_drop: bool, key: ScanPairKey) {
        let now_empty = match self.source_flows.get_mut(&key.0) {
            Some(mut flows) => {
                flows.remove(&(is_drop, key.1));
                flows.is_empty()
            }
            None => false,
        };
        if now_empty {
            self.source_flows
                .remove_if(&key.0, |_, flows| flows.is_empty());
        }
    }

    pub(super) fn scan_flow_count_for_source(&self, source: IpAddr) -> usize {
        self.source_flows
            .get(&source)
            .map_or(0, |flows| flows.len())
    }

    /// Elimina cele mai vechi `count` fluxuri dintre `candidates` (dupa
    /// ultimul hit).
    fn evict_oldest_flows(&self, candidates: Vec<(bool, ScanPairKey)>, count: usize) {
        let aged = candidates
            .into_iter()
            .map(|(is_drop, key)| {
                let last = self
                    .hits(is_drop)
                    .get(&key)
                    .and_then(|hits| hits.last().map(|hit| hit.seen_at));
                (last, (is_drop, key))
            })
            .collect();
        for (is_drop, key) in oldest_keys(aged, count) {
            self.remove_flow(is_drop, key);
        }
    }

    /// Face loc pentru un flux nou `(source, dest)` respectand
    /// `max_flows_per_source` si `max_tracked_flows`.
    ///
    /// Gasirea celor mai vechi fluxuri cere o parcurgere O(n). Ca un sweep
    /// orizontal (cate un flux nou la fiecare pachet) sa nu plateasca O(n)
    /// per eveniment, evictia elibereaza un lot de ~1/8 din limita: costul
    /// parcurgerii se amortizeaza la O(1) per flux nou.
    fn ensure_capacity(&self, key: ScanPairKey, is_drop: bool, cfg: &DetectionConfig) {
        if self.hits(is_drop).contains_key(&key) {
            return;
        }
        let source = key.0;

        let per_source = self.scan_flow_count_for_source(source);
        if per_source >= cfg.max_flows_per_source {
            let candidates: Vec<(bool, ScanPairKey)> = self
                .source_flows
                .get(&source)
                .map(|flows| {
                    flows
                        .iter()
                        .map(|(flow_is_drop, dest)| (*flow_is_drop, (source, *dest)))
                        .collect()
                })
                .unwrap_or_default();
            self.evict_oldest_flows(
                candidates,
                eviction_count(per_source, cfg.max_flows_per_source),
            );
        }

        let total = self.drop_hits.len() + self.accept_hits.len();
        if total >= cfg.max_tracked_flows {
            let candidates: Vec<(bool, ScanPairKey)> = self
                .drop_hits
                .iter()
                .map(|entry| (true, *entry.key()))
                .chain(self.accept_hits.iter().map(|entry| (false, *entry.key())))
                .collect();
            self.evict_oldest_flows(candidates, eviction_count(total, cfg.max_tracked_flows));
        }
    }

    /// Elimina toate fluxurile si cooldown-urile surselor `victims`.
    pub(super) fn evict_sources(&self, victims: &HashSet<IpAddr>) {
        // Fluxurile de scan sunt gasite prin indexul `source_flows`.
        for ip in victims {
            if let Some((_, flows)) = self.source_flows.remove(ip) {
                for (is_drop, dest) in flows {
                    self.remove_flow(is_drop, (*ip, dest));
                }
            }
        }
        // Cooldown-urile pot supravietui fluxului (cleanup sterge hit-urile
        // vechi, nu si cooldown-ul), deci nu sunt acoperite de index.
        for cooldowns in [
            &self.fast_cooldowns,
            &self.slow_cooldowns,
            &self.accept_cooldowns,
        ] {
            cooldowns.retain_keys(|(source, _)| !victims.contains(source));
        }
    }

    /// Maximul de porturi unice per pereche in ferestrele Fast, Slow si
    /// Accept — esantionul pentru baseline-ul pragurilor dinamice (#35).
    ///
    /// COMPROMIS — DE CE `max` SI NU PERCENTIL:
    ///
    /// Folosim `max` peste toate perechile per scan type. Implicatie: un singur
    /// IP intern foarte zgomotos (scanner autorizat, backup orchestrator,
    /// monitoring activ) ridica EWMA-ul si trage pragul dinamic in sus pentru
    /// TOATE IP-urile. La extrem, daca acel IP genereaza constant N >> static
    /// porturi, pragul dinamic se loveste de `max_threshold_ratio` si poate
    /// masca scanari reale facute de alte IP-uri.
    ///
    /// Mitigari deja prezente:
    ///   - Clamp [min_ratio * static, max_ratio * static] previne valori absurde.
    ///   - Whitelist + `authorized_scanners` exclud sursele cunoscute zgomotoase
    ///     din detectie complet, deci nu contribuie la baseline-ul lor propriu.
    ///   - `min_samples` evita activarea pragurilor dinamice in primele ~10 cicluri.
    ///
    /// Imbunatatire viitoare (out of scope MVP): inlocuieste `max` cu p95
    /// (percentil) sau filtreaza top-K outlier-i inainte de update — costul
    /// este o sortare partiala O(n log k) per ciclu de cleanup. Vezi #35 follow-up.
    pub(super) fn baseline_sample(&self, cfg: &DetectionConfig, now: Instant) -> Thresholds {
        let fast_window = Duration::from_secs(cfg.fast_scan.time_window_secs);
        let slow_window = Duration::from_secs(cfg.slow_scan.time_window_mins * 60);
        let accept_window = Duration::from_secs(cfg.accept_scan.time_window_secs);
        let mut sample = Thresholds {
            fast: 0,
            slow: 0,
            accept: 0,
        };
        for entry in self.drop_hits.iter() {
            let hits = entry.value();
            sample.fast = sample.fast.max(count_unique_ports(hits, fast_window, now));
            sample.slow = sample.slow.max(count_unique_ports(hits, slow_window, now));
        }
        for entry in self.accept_hits.iter() {
            sample.accept =
                sample
                    .accept
                    .max(count_unique_ports(entry.value(), accept_window, now));
        }
        sample
    }

    /// Sterge hit-urile mai vechi decat `drop_age` / `accept_age`, fluxurile
    /// ramase goale (si din index) si cooldown-urile expirate.
    pub(super) fn cleanup(
        &self,
        now: Instant,
        drop_age: Duration,
        accept_age: Duration,
        cooldown: Duration,
    ) {
        for (is_drop, age) in [(true, drop_age), (false, accept_age)] {
            let removed = prune(self.hits(is_drop), |hit| {
                now.saturating_duration_since(hit.seen_at) <= age
            });
            for key in removed {
                self.unindex_flow(is_drop, key);
            }
        }
        for cooldowns in [
            &self.fast_cooldowns,
            &self.slow_cooldowns,
            &self.accept_cooldowns,
        ] {
            cooldowns.prune(now, cooldown);
        }
    }

    /// Adauga sursele care mai au hit-uri (pentru sincronizarea `last_seen`).
    pub(super) fn collect_active_sources(&self, sources: &mut HashSet<IpAddr>) {
        for entry in self.drop_hits.iter().chain(self.accept_hits.iter()) {
            sources.insert(entry.key().0);
        }
    }
}

/// Porturile unice (sortate) accesate pe perechea `key` in fereastra de timp.
///
/// NOTA RUST - ITERATORS (zero-cost abstractions):
/// .iter() → lazy, .filter() → lazy, .map() → lazy, .collect() → EXECUTA.
/// Compilatorul fuzioneaza lantul intr-un singur loop optimizat, fara colectii intermediare.
///
/// NOTA RUST - `.get(&key)` returneaza Option<Ref<K, V>>:
/// `Ref` este un guard de citire al DashMap (similar cu RwLockReadGuard).
/// Tine lock-ul de citire cat timp exista — dropat automat la finalul scope-ului (RAII).
fn unique_ports_in_window(
    hits_map: &DashMap<ScanPairKey, Vec<PortHit>>,
    key: ScanPairKey,
    window: Duration,
    now: Instant,
) -> Option<Vec<u16>> {
    let entry = hits_map.get(&key)?;
    let mut unique_ports: Vec<u16> = entry
        .value()
        .iter()
        // `saturating_duration_since` nu poate panica daca seen_at > now
        // (imposibil cu Instant monotonic, dar defensiv).
        .filter(|h| now.saturating_duration_since(h.seen_at) <= window)
        .map(|h| h.port)
        .collect();

    // Deduplicam: sort + dedup elimina duplicatele consecutive.
    // Rezultat: lista de porturi unice, sortata.
    unique_ports.sort_unstable();
    unique_ports.dedup();

    if unique_ports.is_empty() {
        None
    } else {
        Some(unique_ports)
    }
}

fn count_unique_ports(hits: &[PortHit], window: Duration, now: Instant) -> usize {
    let mut ports: Vec<u16> = hits
        .iter()
        .filter(|h| now.saturating_duration_since(h.seen_at) <= window)
        .map(|h| h.port)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports.len()
}
