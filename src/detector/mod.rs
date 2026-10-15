// =============================================================================
// detector/mod.rs - Motor de Detectie Scanari de Retea
// =============================================================================
//
// Acest modul implementeaza logica centrala a IDS-ului. `Detector` primeste
// fiecare eveniment si il da, pe rand, fiecarei detectii:
//
//   port_scan.rs    Fast Scan, Slow Scan, Accept Scan (porturi unice per pereche)
//   lateral.rs      Lateral Movement (destinatii unice per sursa)
//   distributed.rs  Distributed Scan (surse unice per tinta)
//   beaconing.rs    Beaconing C2 (intervale regulate per flow)
//
// Detectorul pastreaza partile comune: whitelist-ul, pragurile dinamice
// (baseline.rs), exceptiile, limita globala de IP-uri urmarite (last_seen +
// evictie LRU in lot, capacity.rs) si curatarea periodica.
//
// CONCEPTE RUST EXPLICATE:
//
// 1. THREAD SAFETY (Send + Sync)
//    In Rust, thread safety este GARANTATA de compilator, nu de programator.
//    Tipurile care implementeaza Send pot fi transferate intre thread-uri.
//    Tipurile care implementeaza Sync pot fi accesate concurent (&T shared).
//    Compilatorul refuza sa compileze cod care nu respecta aceste reguli.
//
// 2. DashMap vs Arc<RwLock<HashMap>>
//    DashMap este un HashMap concurent bazat pe "sharding":
//    - Intern, are N sub-harti (shards), fiecare cu propriul lock
//    - Operatiile pe chei diferite NU se blocheaza reciproc
//    - Performanta superioara fata de un singur RwLock pe tot HashMap-ul
//    - API similar cu HashMap standard (.get, .insert, .entry, .remove)
//
//    Arc<RwLock<HashMap>> ar fi alternativa:
//    - Arc = Atomic Reference Count (smart pointer thread-safe)
//    - RwLock = Read-Write Lock (multi-reader, single-writer)
//    - Dezavantaj: un singur lock pe intreaga structura = bottleneck
//
// 3. INTERIOR MUTABILITY
//    DashMap permite modificarea continutului prin &self (referinta imutabila).
//    Aceasta se numeste "interior mutability" - mutabilitatea este controlata
//    la RUNTIME prin lock-uri, nu la COMPILE-TIME prin &mut.
//    Alte exemple: RefCell, Mutex, RwLock, Cell, AtomicU64.
//
// 4. MODULE PRIVATE, API PUBLIC
//    Sub-modulele sunt private (`mod port_scan;`), iar tipurile lor sunt
//    `pub(super)`: vizibile doar in `detector` si in testele lui. In afara
//    raman vizibile doar `Detector`, `Alert` si `ScanType` (`pub use`).
//
// =============================================================================

mod alert;
mod baseline;
mod beaconing;
mod capacity;
mod cooldown;
mod distributed;
mod lateral;
mod port_scan;
mod whitelist;

pub use alert::{Alert, ScanType};

use crate::config::{DetectionConfig, DetectionExceptions};
use crate::parser::LogEvent;
use arc_swap::ArcSwap;
use baseline::{effective_threshold_value, BaselineState};
use beaconing::Beaconing;
use capacity::{eviction_count, oldest_keys};
use dashmap::DashMap;
use distributed::DistributedScan;
use lateral::LateralMovement;
use port_scan::{PortScan, Thresholds};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use whitelist::{parse_whitelist, WhitelistEntry};

/// Exceptii de detectie parsate (IP-uri ca IpAddr, porturi ca HashSet pentru O(1) lookup).
/// Parsate o singura data la constructie / hot reload, nu la fiecare eveniment.
pub(super) struct ParsedExceptions {
    pub(super) authorized_scanners: HashSet<IpAddr>,
    pub(super) ignore_lateral_ports: HashSet<u16>,
    pub(super) ignore_distributed_target_ports: HashSet<u16>,
    pub(super) ignore_beaconing_ports: HashSet<u16>,
    pub(super) authorized_beaconing_sources: HashSet<IpAddr>,
}

impl ParsedExceptions {
    fn from_config(exc: &DetectionExceptions) -> Self {
        Self {
            authorized_scanners: exc
                .authorized_scanners
                .iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .collect(),
            ignore_lateral_ports: exc.ignore_lateral_ports.iter().copied().collect(),
            ignore_distributed_target_ports: exc
                .ignore_distributed_target_ports
                .iter()
                .copied()
                .collect(),
            ignore_beaconing_ports: exc.ignore_beaconing_ports.iter().copied().collect(),
            authorized_beaconing_sources: exc
                .authorized_beaconing_sources
                .iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .collect(),
        }
    }
}

// =============================================================================
// Detector - Motorul de detectie
// =============================================================================

// Motorul de detectie a scanarilor de retea.
//
// NOTA RUST - SAFETY fara overhead:
//
// `Detector` poate fi partajat intre task-uri async prin `Arc<Detector>`.
// `Arc` (Atomic Reference Counting) este un smart pointer care:
//   - Numara cate referinte exista catre aceeasi valoare
//   - Cand ultimul Arc este dropat, valoarea este dealocata
//   - Este thread-safe (numararea este atomica)
//   - Cost: un contor atomic per clone/drop (~1 instructiune CPU)
//
// DashMap ofera interior mutability: putem modifica datele prin &self.
// Aceasta combina:
//   Arc<Detector> (shared ownership) + DashMap (interior mutability)
// = acces concurent thread-safe fara a avea nevoie de &mut.
pub struct Detector {
    /// Fast / Slow / Accept Scan.
    port_scan: PortScan,
    /// Lateral Movement (#22).
    lateral: LateralMovement,
    /// Distributed Scan (#23).
    distributed: DistributedScan,
    /// Beaconing C2 (#24).
    beaconing: Beaconing,

    /// Ultimul moment cand fiecare IP sursa a fost vazut (drop SAU accept).
    /// Folosit pentru LRU eviction: cand numarul de IP-uri urmarite ajunge
    /// la max_tracked_ips, IP-urile cu cel mai vechi `last_seen` sunt eliminate
    /// din toate detectiile.
    last_seen: DashMap<IpAddr, Instant>,

    /// IP-uri si subretele excluse din detectie (parsate din config la constructie).
    /// Wrapat in ArcSwap pentru hot reload atomic la SIGHUP (#16).
    whitelist: ArcSwap<Vec<WhitelistEntry>>,

    /// Configurarea pragurilor de detectie.
    /// Wrapat in ArcSwap pentru hot reload atomic la SIGHUP (#16).
    /// `ArcSwap::load()` returneaza un `Guard` (pointer atomic, lock-free) —
    /// cost: un load atomic per acces, neglijabil la scala UDP processing.
    config: ArcSwap<DetectionConfig>,

    /// Exceptii de detectie parsate (authorized_scanners, ignore_lateral_ports, etc.).
    /// Wrapat in ArcSwap pentru hot reload atomic la SIGHUP.
    exceptions: ArcSwap<ParsedExceptions>,

    /// Starea baseline pentru praguri dinamice (#35).
    /// Protejat de Mutex — accesat doar in cleanup (~60s) pentru write
    /// si in process_event pentru read (lock < 1μs, doar copie 3 floats).
    baseline: Mutex<BaselineState>,
}

impl Detector {
    /// Creeaza un nou Detector cu configurarea specificata.
    ///
    /// NOTA RUST: `DashMap::new()` creeaza un map gol, pre-alocat cu
    /// numar optim de shard-uri (de obicei = numar de CPU cores).
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            port_scan: PortScan::new(),
            lateral: LateralMovement::new(),
            distributed: DistributedScan::new(),
            beaconing: Beaconing::new(),
            last_seen: DashMap::new(),
            whitelist: ArcSwap::from_pointee(parse_whitelist(&config.whitelist)),
            exceptions: ArcSwap::from_pointee(ParsedExceptions::from_config(&config.exceptions)),
            config: ArcSwap::from_pointee(config),
            baseline: Mutex::new(BaselineState::new()),
        }
    }

    /// Actualizeaza configurarea detectorului la runtime (hot reload SIGHUP).
    ///
    /// NOTA RUST — SAFETY:
    /// `Detector` este wrapat in `Arc` si partajat intre task-uri, deci nu
    /// putem obtine `&mut` direct. Solutia: campurile `config`, `whitelist` si
    /// `exceptions` sunt wrappate in `ArcSwap` pentru swap atomic lock-free.
    ///
    /// Starea de detectie (DashMap-urile) NU este afectata — IP-urile urmarite,
    /// port hit-urile si cooldown-urile raman intacte dupa reload.
    pub fn update_config(&self, new_config: DetectionConfig) {
        let new_whitelist = parse_whitelist(&new_config.whitelist);
        let new_exceptions = ParsedExceptions::from_config(&new_config.exceptions);

        // Swap atomic: noua configurare devine activa imediat.
        self.config.store(Arc::new(new_config));
        self.whitelist.store(Arc::new(new_whitelist));
        self.exceptions.store(Arc::new(new_exceptions));
    }

    /// Verifica daca un IP este in whitelist (exclus din detectie).
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.whitelist.load().iter().any(|entry| entry.matches(ip))
    }

    /// Proceseaza un eveniment de log si returneaza alertele detectate,
    /// in ordinea: Fast, Slow, Accept, Lateral Movement, Distributed, Beaconing.
    ///
    /// NOTA RUST - BORROWING si LIFETIME-URI implicite:
    ///
    /// `&self`         - imprumut imutabil al Detector-ului
    /// `event: &LogEvent` - imprumut imutabil al evenimentului
    ///
    /// Ambele sunt referinte (&) = NU consuma valorile. Detector-ul si
    /// evenimentul pot fi refolosite dupa apel.
    ///
    /// Returnam `Vec<Alert>` (owned) - apelantul devine proprietar.
    /// Vec gol = nicio alerta detectata.
    pub fn process_event(&self, event: &LogEvent) -> Vec<Alert> {
        let now = Instant::now();
        let ip = event.source_ip;

        // Incarcam config-ul o singura data per eveniment (load atomic, lock-free).
        // Daca un SIGHUP reload schimba config-ul in timpul procesarii, acest
        // eveniment continua cu config-ul vechi — urmatorul il va folosi pe cel nou.
        let cfg = self.config.load();

        // --- 0. Whitelist check ---
        // IP-urile din whitelist sunt excluse complet din detectie.
        // Nu consuma memorie in DashMap, nu genereaza alerte.
        if self.is_whitelisted(&ip) {
            return Vec::new();
        }

        // --- 0b. Praguri efective (statice sau dinamice #35) ---
        // Lock pe baseline < 1μs — doar citire a 3 floats per scan type.
        let thresholds = {
            let bl = self.baseline.lock().unwrap_or_else(|e| e.into_inner());
            let dt = &cfg.dynamic_threshold;
            Thresholds {
                fast: effective_threshold_value(cfg.fast_scan.port_threshold, &bl.fast_scan, dt),
                slow: effective_threshold_value(cfg.slow_scan.port_threshold, &bl.slow_scan, dt),
                accept: effective_threshold_value(
                    cfg.accept_scan.port_threshold,
                    &bl.accept_scan,
                    dt,
                ),
            }
        };

        // --- 1. Limitare globala IP-uri (anti-IP-spoofing flood) ---
        //
        // NOTA #4 - LRU EVICTION:
        //
        // Un atacator poate trimite pachete cu milioane de IP-uri sursa false (spoofed).
        // Fara limita, fiecare IP nou creeaza intrari noi → memory exhaustion.
        //
        // Solutia: cand `last_seen` ajunge la max_tracked_ips si soseste un IP NOU,
        // eliminam in lot IP-urile cele mai vechi (LRU) din toate detectiile.
        // `last_seen` este actualizat la FIECARE eveniment (drop si accept), deci
        // reflecta corect totalul IP-urilor active, indiferent de tipul actiunii.
        let is_new_ip = !self.last_seen.contains_key(&ip);
        if is_new_ip && self.last_seen.len() >= cfg.max_tracked_ips {
            let aged = self
                .last_seen
                .iter()
                .map(|entry| (*entry.value(), *entry.key()))
                .collect();
            let count = eviction_count(self.last_seen.len(), cfg.max_tracked_ips);
            let victims: HashSet<IpAddr> = oldest_keys(aged, count).into_iter().collect();
            self.evict_sources(&victims);
        }

        // Actualizam last_seen pentru IP-ul curent (nou sau existent).
        self.last_seen.insert(ip, now);

        // --- 2. Detectiile, in ordine ---
        let exceptions = self.exceptions.load();
        let cooldown = Duration::from_secs(cfg.alert_cooldown_secs);
        let mut alerts = Vec::new();
        self.port_scan
            .record_and_check(event, now, &cfg, &thresholds, cooldown, &mut alerts);
        alerts.extend(
            self.lateral
                .record_and_check(event, now, &cfg, &exceptions, cooldown),
        );
        alerts.extend(
            self.distributed
                .record_and_check(event, now, &cfg, &exceptions, cooldown),
        );
        alerts.extend(
            self.beaconing
                .record_and_check(event, now, &cfg, &exceptions, cooldown),
        );
        alerts
    }

    /// Elimina complet un set de IP-uri sursa din toate detectiile.
    fn evict_sources(&self, victims: &HashSet<IpAddr>) {
        if victims.is_empty() {
            return;
        }
        self.port_scan.evict_sources(victims);
        self.lateral.evict_sources(victims);
        self.distributed.evict_sources(victims);
        self.beaconing.evict_sources(victims);
        for ip in victims {
            self.last_seen.remove(ip);
        }
    }

    /// Curata datele vechi din memorie - previne memory leaks.
    ///
    /// NOTA RUST - ITERATIE MUTABILA pe DashMap:
    /// `.iter_mut()` returneaza un iterator care ofera acces mutabil (&mut)
    /// la fiecare valoare. Lock-urile sunt luate per-shard, deci alte
    /// shard-uri pot fi accesate concurent in acest timp.
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        let cfg = self.config.load();

        // Fiecare tabela pastreaza datele cel putin cat fereastra ei de
        // detectie. Altfel, o fereastra mai lunga decat `max_age` (ex:
        // beaconing 3600s vs cleanup 600s) nu ar putea strange niciodata
        // destule evenimente: un beacon la 2 minute ar ramane cu 5 hit-uri.
        let at_least = |secs: u64| max_age.max(Duration::from_secs(secs));
        let cooldown = Duration::from_secs(cfg.alert_cooldown_secs);

        // --- Baseline sampling (#35) — INAINTE de curatare ---
        //
        // Esantionam numarul maxim de porturi unice per pereche per fereastra.
        // Trebuie facut inainte de prune-ul datelor vechi, altfel pierdem datele
        // necesare pentru calculul baseline-ului.
        if cfg.dynamic_threshold.enabled {
            let alpha = cfg.dynamic_threshold.ewma_alpha;
            let sample = self.port_scan.baseline_sample(&cfg, now);
            let mut bl = self.baseline.lock().unwrap_or_else(|e| e.into_inner());
            bl.fast_scan.update(sample.fast as f64, alpha);
            bl.slow_scan.update(sample.slow as f64, alpha);
            bl.accept_scan.update(sample.accept as f64, alpha);
        }

        self.port_scan.cleanup(
            now,
            at_least((cfg.slow_scan.time_window_mins * 60).max(cfg.fast_scan.time_window_secs)),
            at_least(cfg.accept_scan.time_window_secs),
            cooldown,
        );
        self.lateral.cleanup(
            now,
            at_least(cfg.lateral_movement.time_window_secs),
            cooldown,
        );
        self.distributed.cleanup(
            now,
            at_least(cfg.distributed_scan.time_window_secs),
            cooldown,
        );
        self.beaconing
            .cleanup(now, at_least(cfg.beaconing.time_window_secs), cooldown);

        // --- Sincronizam last_seen ---
        //
        // Eliminam din last_seen IP-urile care nu mai au date in tabelele
        // indexate pe sursa (port scan si lateral movement).
        let mut active_sources: HashSet<IpAddr> = HashSet::new();
        self.port_scan.collect_active_sources(&mut active_sources);
        self.lateral.collect_active_sources(&mut active_sources);
        self.last_seen.retain(|ip, _| active_sources.contains(ip));
    }

    /// Returneaza numarul total de IP-uri urmarite in memorie (drop + accept).
    ///
    /// `last_seen` este sursa de adevar: contine orice IP care a generat cel
    /// putin un eveniment (drop sau accept) si nu a fost inca curatat.
    /// Util pentru monitorizarea starii interne si afisarea in CLI.
    pub fn tracked_ips(&self) -> usize {
        self.last_seen.len()
    }
}

#[cfg(test)]
mod tests;
