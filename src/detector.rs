// =============================================================================
// detector.rs - Motor de Detectie Scanari de Retea
// =============================================================================
//
// Acest modul implementeaza logica centrala a IDS-ului:
//   1. Inregistreaza fiecare eveniment "drop" (IP sursa + port destinatie)
//   2. Detecteaza Fast Scan: > X porturi unice in Y secunde
//   3. Detecteaza Slow Scan: > Z porturi unice in W minute
//   4. Gestioneaza cooldown-ul alertelor (anti-spam)
//   5. Curata periodic datele vechi din memorie
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
// =============================================================================

use crate::config::DetectionConfig;
use crate::parser::LogEvent;
use chrono::{DateTime, Local};
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

// =============================================================================
// Structuri de date
// =============================================================================

/// Tipul de scanare detectat.
///
/// NOTA RUST: `enum` in Rust este un "tagged union" (sum type).
/// Fiecare varianta poate avea date asociate (aici nu are - sunt simple labels).
/// Enum-urile Rust sunt MULT mai puternice decat cele din C/Java:
///   enum Message {
///       Quit,                       // fara date
///       Move { x: i32, y: i32 },    // cu struct inline
///       Write(String),              // cu un singur camp
///   }
#[derive(Debug, Clone)]
pub enum ScanType {
    Fast,
    Slow,
}

/// Implementarea trait-ului Display pentru ScanType.
///
/// NOTA RUST: `std::fmt::Display` este trait-ul folosit de `{}` in format!().
/// Este echivalentul lui toString() din Java. Fiecare tip care implementeaza
/// Display poate fi printat cu `println!("{}", value)`.
/// Debug ({:?}) este generat automat cu #[derive(Debug)], dar Display
/// trebuie implementat manual - Rust nu face presupuneri despre cum
/// vrei sa arate output-ul "human-readable".
impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Fast => write!(f, "Fast Scan"),
            ScanType::Slow => write!(f, "Slow Scan"),
        }
    }
}

/// Alerta generata cand se detecteaza o scanare.
///
/// NOTA RUST: Aceasta structura este OWNED - cand este creata, toate
/// datele sunt copiate/mutate in ea. Poate fi transmisa liber intre
/// functii si thread-uri fara grija ca datele originale se schimba.
#[derive(Debug, Clone)]
pub struct Alert {
    pub scan_type: ScanType,
    pub source_ip: IpAddr,
    /// IP-ul tinta al scanarii — din campul `dst` al log-ului care a
    /// declansat alerta. Option<> deoarece unele log-uri nu au dst valid.
    pub dest_ip: Option<IpAddr>,
    pub unique_ports: Vec<u16>,
    pub timestamp: DateTime<Local>,
}

/// Inregistrarea unui port accesat de un IP la un moment dat.
///
/// NOTA RUST: `Instant` este un timestamp monotonic (nu wall-clock).
/// Nu poate fi afectat de schimbari de ora / NTP. Perfect pentru
/// masurarea duratelor si timeout-uri.
/// `Instant` NU implementeaza Serialize - nu poate fi salvat pe disc,
/// dar este eficient si sigur pentru masuratori in-process.
struct PortHit {
    port: u16,
    seen_at: Instant,
}

// =============================================================================
// Detector - Motorul de detectie
// =============================================================================

/// Motorul de detectie a scanarilor de retea.
///
/// NOTA RUST - SAFETY fara overhead:
///
/// `Detector` poate fi partajat intre task-uri async prin `Arc<Detector>`.
/// `Arc` (Atomic Reference Counting) este un smart pointer care:
///   - Numara cate referinte exista catre aceeasi valoare
///   - Cand ultimul Arc este dropat, valoarea este dealocata
///   - Este thread-safe (numararea este atomica)
///   - Cost: un contor atomic per clone/drop (~1 instructiune CPU)
///
/// DashMap ofera interior mutability: putem modifica datele prin &self.
/// Aceasta combina:
///   Arc<Detector> (shared ownership) + DashMap (interior mutability)
/// = acces concurent thread-safe fara a avea nevoie de &mut.
///
/// COMPARATIE cu alte limbaje:
///   - Java: ConcurrentHashMap (similar, dar cu garbage collector)
///   - Go:   sync.Map (similar, dar fara garantii compile-time)
///   - C++:  Nu exista echivalent standard - trebuie implementat manual
///   - Rust: DashMap cu garantii COMPILE-TIME de thread safety
///
pub struct Detector {
    /// Evidenta porturilor accesate per IP sursa.
    /// Key: IP-ul sursa | Value: lista de (port, timestamp)
    port_hits: DashMap<IpAddr, Vec<PortHit>>,

    /// Cooldown alerte Fast Scan per IP.
    /// Previne re-alertarea pentru acelasi IP inainte de expirarea cooldown-ului.
    fast_cooldowns: DashMap<IpAddr, Instant>,

    /// Cooldown alerte Slow Scan per IP.
    slow_cooldowns: DashMap<IpAddr, Instant>,

    /// Configurarea pragurilor de detectie (owned, cloned din AppConfig).
    config: DetectionConfig,
}

impl Detector {
    /// Creeaza un nou Detector cu configurarea specificata.
    ///
    /// NOTA RUST: `DashMap::new()` creeaza un map gol, pre-alocat cu
    /// numar optim de shard-uri (de obicei = numar de CPU cores).
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            port_hits: DashMap::new(),
            fast_cooldowns: DashMap::new(),
            slow_cooldowns: DashMap::new(),
            config,
        }
    }

    /// Proceseaza un eveniment de log si returneaza alertele detectate.
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
    ///
    /// NOTA: Chiar daca `&self` este imutabil, DashMap permite modificari
    /// prin interior mutability (lock-uri interne). Aceasta este sigura
    /// deoarece DashMap garanteaza consistenta prin sincronizare.
    ///
    pub fn process_event(&self, event: &LogEvent) -> Vec<Alert> {
        let now = Instant::now();
        let ip = event.source_ip;

        // --- 1. Inregistram port hit-ul ---
        //
        // NOTA RUST - ENTRY API:
        // `.entry(key)` este pattern-ul standard pentru "get or insert":
        //   - Daca cheia exista: returneaza o referinta mutabila la valoare
        //   - Daca nu exista: insereaza valoarea default si returneaza ref
        //
        // `.or_default()` foloseste Default::default() care pentru Vec este Vec::new().
        //
        // NOTA RUST - DEREF si AUTO-DEREF:
        // `.push()` este apelat pe `&mut Vec<PortHit>`, nu pe entry guard.
        // Rust aplica auto-deref: entry_guard -> &mut Vec -> Vec.push().
        // Acest mecanism face codul mai ergonomic fara pierdere de control.
        self.port_hits
            .entry(ip)
            .or_default()
            .push(PortHit {
                port: event.dest_port,
                seen_at: now,
            });

        let mut alerts = Vec::new();

        // --- 2. Verificam Fast Scan ---
        let fast_window = Duration::from_secs(self.config.fast_scan.time_window_secs);
        if let Some(ports) = self.unique_ports_in_window(ip, fast_window, now) {
            if ports.len() > self.config.fast_scan.port_threshold
                && !self.in_cooldown(&self.fast_cooldowns, ip)
            {
                // Setam cooldown-ul pentru acest IP (prevenim spam).
                self.fast_cooldowns.insert(ip, now);
                alerts.push(Alert {
                    scan_type: ScanType::Fast,
                    source_ip: ip,
                    dest_ip: event.dest_ip,
                    unique_ports: ports,
                    timestamp: Local::now(),
                });
            }
        }

        // --- 3. Verificam Slow Scan ---
        let slow_window = Duration::from_secs(self.config.slow_scan.time_window_mins * 60);
        if let Some(ports) = self.unique_ports_in_window(ip, slow_window, now) {
            if ports.len() > self.config.slow_scan.port_threshold
                && !self.in_cooldown(&self.slow_cooldowns, ip)
            {
                self.slow_cooldowns.insert(ip, now);
                alerts.push(Alert {
                    scan_type: ScanType::Slow,
                    source_ip: ip,
                    dest_ip: event.dest_ip,
                    unique_ports: ports,
                    timestamp: Local::now(),
                });
            }
        }

        alerts
    }

    /// Returneaza lista porturilor unice accesate de un IP in fereastra de timp.
    ///
    /// NOTA RUST - ITERATORS (Iteratori):
    /// Rust iterators sunt "zero-cost abstractions":
    ///   .iter()        -> creeaza iterator (lazy, nu face nimic inca)
    ///   .filter(|h|..) -> creeaza un nou iterator care filtreaza
    ///   .map(|h|..)    -> creeaza un nou iterator care transforma
    ///   .collect()     -> CONSUMA iteratorul si produce rezultatul
    ///
    /// Compilatorul fuzioneaza intregul lant intr-un singur loop optimizat.
    /// Nu se creeaza colectii intermediare - totul e procesat element cu element.
    ///
    /// Aceasta este ECHIVALENT cu:
    ///   let mut result = Vec::new();
    ///   for h in hits.iter() {
    ///       if now.duration_since(h.seen_at) <= window {
    ///           result.push(h.port);
    ///       }
    ///   }
    /// Dar versiunea cu iteratori este mai concisa si la fel de performanta.
    ///
    fn unique_ports_in_window(
        &self,
        ip: IpAddr,
        window: Duration,
        now: Instant,
    ) -> Option<Vec<u16>> {
        // `.get(&ip)` returneaza Option<Ref<IpAddr, Vec<PortHit>>>
        // `Ref` este un guard de citire al DashMap (similar cu RwLockReadGuard).
        // Guard-ul tine lock-ul cat timp exista - este dropat automat la
        // finalul scope-ului (RAII).
        let entry = self.port_hits.get(&ip)?;
        let hits = entry.value();

        let mut unique_ports: Vec<u16> = hits
            .iter()
            // `now.duration_since(h.seen_at)` poate panica daca h.seen_at > now
            // (imposibil cu Instant monotonic, dar saturating_duration_since e mai safe).
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

    /// Verifica daca un IP este in perioada de cooldown pentru un tip de alerta.
    ///
    /// NOTA RUST - REFERINTE la DashMap:
    /// `cooldowns: &DashMap<...>` - imprumut imutabil al DashMap-ului.
    /// DashMap permite `.get()` prin &self (interior mutability cu read-lock).
    fn in_cooldown(&self, cooldowns: &DashMap<IpAddr, Instant>, ip: IpAddr) -> bool {
        if let Some(last_alert) = cooldowns.get(&ip) {
            // `elapsed()` = cat timp a trecut de la momentul stocat.
            last_alert.elapsed() < Duration::from_secs(self.config.alert_cooldown_secs)
        } else {
            false
        }
    }

    /// Curata datele vechi din memorie - previne memory leaks.
    ///
    /// NOTA RUST - ITERATIE MUTABILA pe DashMap:
    /// `.iter_mut()` returneaza un iterator care ofera acces mutabil (&mut)
    /// la fiecare valoare. Lock-urile sunt luate per-shard, deci alte
    /// shard-uri pot fi accesate concurent in acest timp.
    ///
    /// `.retain(|_, v| predicate)` este metoda idiomatica de a filtra
    /// in-place: pastreaza doar elementele care satisfac predicatul.
    /// Elementele care nu satisfac predicatul sunt DROP-uite (dealocate).
    ///
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        let mut empty_keys: Vec<IpAddr> = Vec::new();

        // Curatam port hits vechi din fiecare IP.
        for mut entry in self.port_hits.iter_mut() {
            // `.retain()` pastreaza doar hit-urile mai recente decat max_age.
            entry.value_mut().retain(|hit| {
                now.saturating_duration_since(hit.seen_at) <= max_age
            });

            // Marcam IP-urile fara hit-uri pentru stergere.
            if entry.value().is_empty() {
                empty_keys.push(*entry.key());
            }
        }

        // Stergem IP-urile goale (eliberam memoria complet).
        //
        // NOTA RUST: Nu putem sterge in timpul iteratiei (ar invalida
        // iteratorul). De aceea colectam cheile si le stergem separat.
        for ip in &empty_keys {
            self.port_hits.remove(ip);
        }

        // Curatam cooldown-urile expirate.
        let cooldown_dur = Duration::from_secs(self.config.alert_cooldown_secs);
        self.fast_cooldowns
            .retain(|_, instant| now.saturating_duration_since(*instant) <= cooldown_dur);
        self.slow_cooldowns
            .retain(|_, instant| now.saturating_duration_since(*instant) <= cooldown_dur);
    }

    /// Returneaza numarul de IP-uri urmarite in memorie.
    /// Util pentru monitorizarea starii interne si afisarea in CLI.
    pub fn tracked_ips(&self) -> usize {
        self.port_hits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DetectionConfig, FastScanConfig, SlowScanConfig};

    /// Creeaza o configuratie de test cu praguri mici pentru teste rapide.
    fn test_config() -> DetectionConfig {
        DetectionConfig {
            alert_cooldown_secs: 5,
            fast_scan: FastScanConfig {
                port_threshold: 3,
                time_window_secs: 10,
            },
            slow_scan: SlowScanConfig {
                port_threshold: 50,
                time_window_mins: 1,
            },
        }
    }

    fn make_event(ip: &str, port: u16) -> LogEvent {
        LogEvent {
            source_ip: ip.parse().unwrap(),
            dest_ip: Some("10.0.0.1".parse().unwrap()),
            dest_port: port,
            protocol: "tcp".to_string(),
            action: "drop".to_string(),
            raw_log: String::new(),
        }
    }

    #[test]
    fn test_no_alert_below_threshold() {
        let detector = Detector::new(test_config());

        // 3 porturi unice = exact la prag (nu PESTE prag).
        for port in 1..=3 {
            let alerts = detector.process_event(&make_event("10.0.0.1", port));
            assert!(alerts.is_empty(), "Nu ar trebui alerta la {} porturi", port);
        }
    }

    #[test]
    fn test_fast_scan_alert() {
        let detector = Detector::new(test_config());

        // 4 porturi unice = peste pragul de 3 -> trebuie alerta Fast Scan.
        for port in 1..=4 {
            let alerts = detector.process_event(&make_event("10.0.0.1", port));
            if port == 4 {
                assert_eq!(alerts.len(), 1);
                assert!(matches!(alerts[0].scan_type, ScanType::Fast));
            }
        }
    }

    #[test]
    fn test_cooldown_prevents_duplicate_alert() {
        let detector = Detector::new(test_config());

        // Trimitem 5 porturi - prima alerta la port 4.
        for port in 1..=5 {
            detector.process_event(&make_event("10.0.0.1", port));
        }

        // Al 6-lea port - NU ar trebui sa genereze alerta (cooldown activ).
        let alerts = detector.process_event(&make_event("10.0.0.1", 100));
        assert!(alerts.is_empty(), "Cooldown-ul ar fi trebuit sa previna alerta");
    }

    #[test]
    fn test_different_ips_tracked_separately() {
        let detector = Detector::new(test_config());

        // IP 1: 4 porturi -> alerta
        for port in 1..=4 {
            detector.process_event(&make_event("10.0.0.1", port));
        }

        // IP 2: 2 porturi -> nicio alerta
        for port in 1..=2 {
            let alerts = detector.process_event(&make_event("10.0.0.2", port));
            assert!(alerts.is_empty());
        }
    }

    #[test]
    fn test_cleanup_removes_old_entries() {
        let detector = Detector::new(test_config());

        detector.process_event(&make_event("10.0.0.1", 22));
        assert_eq!(detector.tracked_ips(), 1);

        // Cleanup cu max_age = 0 -> sterge totul.
        detector.cleanup(Duration::from_secs(0));
        assert_eq!(detector.tracked_ips(), 0);
    }
}
