// =============================================================================
// detector.rs - Motor de Detectie Scanari de Retea
// =============================================================================
//
// Acest modul implementeaza logica centrala a IDS-ului:
//   1. Inregistreaza evenimentele "drop" si "accept" (IP sursa + port destinatie)
//   2. Detecteaza Fast Scan:   >= X porturi BLOCATE unice in Y secunde
//   3. Detecteaza Slow Scan:   >= Z porturi BLOCATE unice in W minute
//   4. Detecteaza Accept Scan: >= N porturi ACCEPTATE unice in M secunde
//   5. Gestioneaza cooldown-ul alertelor (anti-spam)
//   6. Curata periodic datele vechi din memorie
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

use crate::config::{DetectionConfig, DynamicThresholdConfig};
use crate::parser::LogEvent;
use arc_swap::ArcSwap;
use chrono::{DateTime, Local};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// =============================================================================
// Whitelist — IP-uri si subretele excluse din detectie
// =============================================================================

/// Intrare in whitelist: IP individual sau subnet CIDR.
///
/// Parsata din string-urile din config.toml la constructia Detector-ului.
/// Matching-ul CIDR se face prin bitmask: (ip & mask) == (network & mask).
#[derive(Debug, Clone)]
enum WhitelistEntry {
    /// IP individual (ex: "10.0.1.10").
    Single(IpAddr),
    /// Subnet CIDR IPv4 (ex: "10.0.2.0/24"). Stocam adresa de retea si masca.
    CidrV4(u32, u32),
    /// Subnet CIDR IPv6 (ex: "fd00::/64"). Stocam adresa de retea si masca.
    CidrV6(u128, u128),
}

impl WhitelistEntry {
    /// Parseaza un string din config.toml intr-o intrare whitelist.
    /// Formatul validat deja in config.rs::validate().
    fn parse(entry: &str) -> Option<Self> {
        if entry.contains('/') {
            let parts: Vec<&str> = entry.splitn(2, '/').collect();
            let ip: IpAddr = parts[0].parse().ok()?;
            let prefix: u8 = parts[1].parse().ok()?;
            match ip {
                IpAddr::V4(addr) => {
                    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
                    let network = u32::from(addr) & mask;
                    Some(WhitelistEntry::CidrV4(network, mask))
                }
                IpAddr::V6(addr) => {
                    let mask = if prefix == 0 { 0u128 } else { !0u128 << (128 - prefix) };
                    let network = u128::from(addr) & mask;
                    Some(WhitelistEntry::CidrV6(network, mask))
                }
            }
        } else {
            let ip: IpAddr = entry.parse().ok()?;
            Some(WhitelistEntry::Single(ip))
        }
    }

    /// Verifica daca un IP se potriveste cu aceasta intrare.
    fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            WhitelistEntry::Single(wl_ip) => wl_ip == ip,
            WhitelistEntry::CidrV4(network, mask) => {
                if let IpAddr::V4(addr) = ip {
                    (u32::from(*addr) & mask) == *network
                } else {
                    false
                }
            }
            WhitelistEntry::CidrV6(network, mask) => {
                if let IpAddr::V6(addr) = ip {
                    (u128::from(*addr) & mask) == *network
                } else {
                    false
                }
            }
        }
    }
}

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
#[derive(Debug, Clone, serde::Serialize)]
pub enum ScanType {
    // Nota: LateralMovement adaugat ca varianta noua (#22).
    // Match-urile existente in alerter.rs si display.rs sunt exhaustive —
    // compilatorul va semnala toate locurile unde trebuie adaugat noul caz.
    Fast,
    Slow,

    /// Scanare de porturi DESCHISE (conexiuni permise de firewall).
    ///
    /// Diferenta fata de Fast si Slow Scan:
    ///   Fast / Slow  → urmaresc drop-uri: atacatorul testeaza porturi INCHISE/filtrate
    ///   AcceptScan   → urmareste accept-uri: atacatorul mapeaza porturi DESCHISE
    ///
    /// Accept Scan este mai subtil — traficul generat este "legitim" din perspectiva
    /// firewall-ului (conexiunile sunt permise de reguli). Fara aceasta detectie,
    /// un atacator care enumera serviciile active ar trece complet neobservat.
    ///
    /// Exemplu concret: un host intern acceseaza porturile 22, 80, 443, 3306, 5432
    /// pe mai multe servere in scurt timp. Firewall-ul le permite (sunt servicii
    /// legitime), dar pattern-ul sistematic denota enumerare, nu comportament normal.
    AcceptScan,

    /// Miscare laterala in retea (#22) — un IP intern contacteaza N destinatii
    /// diferite pe conexiuni acceptate (orice port).
    ///
    /// Diferenta fundamentala fata de celelalte tipuri:
    ///   Fast/Slow/Accept → 1 sursa × N porturi × 1 destinatie
    ///   LateralMovement  → 1 sursa × orice port × N destinatii
    ///
    /// Detectia e bazata pe comportament, nu pe port — servicii legitime cu
    /// fan-out mare (backup, monitoring) se pun in whitelist.
    ///
    /// SignatureID SIEM: 1004. Severitate: 8 (Critical) — miscarea laterala
    /// indica un host compromis care incearca sa se extinda in retea.
    LateralMovement,

    /// Scanare coordonata din surse multiple (#23) — N IP-uri sursa diferite
    /// scanează aceeasi destinatie in aceeasi fereastra de timp.
    ///
    /// Perspectiva inversata fata de celelalte tipuri:
    ///   Fast/Slow/Accept → 1 sursa × N porturi × 1 destinatie
    ///   LateralMovement  → 1 sursa × orice port × N destinatii
    ///   DistributedScan  → N surse × aceeasi tinta
    ///
    /// Pattern tipic de botnet sau atac coordonat: mai multi atacatori scanează
    /// simultan acelasi server. Detectia se face din perspectiva TINTEI, nu a
    /// atacatorului — DashMap-ul este indexat dupa dest_ip.
    ///
    /// SignatureID SIEM: 1005. Severitate: 7 (High) — atac coordonat.
    DistributedScan,
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
            ScanType::AcceptScan => write!(f, "Accept Scan"),
            ScanType::LateralMovement => write!(f, "Lateral Movement"),
            ScanType::DistributedScan => write!(f, "Distributed Scan"),
        }
    }
}

/// Alerta generata cand se detecteaza o scanare.
///
/// NOTA RUST: Aceasta structura este OWNED - cand este creata, toate
/// datele sunt copiate/mutate in ea. Poate fi transmisa liber intre
/// functii si thread-uri fara grija ca datele originale se schimba.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    pub scan_type: ScanType,
    pub source_ip: IpAddr,
    /// IP-ul tinta al scanarii — din campul `dst` al log-ului care a
    /// declansat alerta. Option<> deoarece unele log-uri nu au dst valid.
    pub dest_ip: Option<IpAddr>,
    /// Porturi unice detectate — populat pentru Fast/Slow/AcceptScan.
    /// Gol pentru LateralMovement (acolo relevant este unique_dests).
    pub unique_ports: Vec<u16>,
    /// Destinatii unice contactate — populat doar pentru LateralMovement.
    /// Gol pentru celelalte tipuri de scan.
    pub unique_dests: Vec<IpAddr>,
    /// Surse unice care au scanat aceeasi tinta — populat doar pentru DistributedScan.
    /// Gol pentru celelalte tipuri de scan.
    pub unique_sources: Vec<IpAddr>,
    pub timestamp: DateTime<Local>,
}

/// Inregistrarea unei conexiuni catre o destinatie (Lateral Movement #22).
///
/// Tine minte CATRE CE IP s-a conectat sursa si cand.
/// Spre deosebire de PortHit (care tine minte portul accesat),
/// DestHit tine minte destinatia accesata.
struct DestHit {
    dest_ip: IpAddr,
    seen_at: Instant,
}

/// Inregistrarea unui hit asupra unei tinte din perspectiva Distributed Scan (#23).
///
/// Indexat dupa dest_ip (cheia DashMap-ului). Tine minte CINE a lovit tinta si CAND.
/// Perspectiva inversata: celelalte structuri sunt indexate dupa sursa,
/// aceasta este indexata dupa destinatie.
struct DistributedHit {
    source_ip: IpAddr,
    port: u16,
    seen_at: Instant,
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
// =============================================================================
// EWMA Baseline — Praguri dinamice (#35)
// =============================================================================
//
// EWMA (Exponentially Weighted Moving Average) urmareste media si varianta
// numarului maxim de porturi unice per IP per fereastra de timp.
//
// La fiecare ciclu de cleanup (~60s), esantionam starea curenta:
//   - Pentru fiecare IP urmarit, numaram porturile unice in fereastra Fast/Slow/Accept.
//   - Luam maximul per scan type (cel mai "zgomotos" IP legitim din retea).
//   - Actualizam EWMA cu acest maxim.
//
// Formula EWMA:
//   mean    = mean + alpha * (value - mean)
//   variance = (1 - alpha) * (variance + alpha * delta^2)
//
// Pragul efectiv: mean + multiplier * stddev, clamped in [static*min_ratio, static*max_ratio].
// Cost memorie: 24 bytes per scan type (3 x f64).

/// Starea EWMA pentru un singur tip de scan.
struct BaselineEwma {
    mean: f64,
    variance: f64,
    samples: u64,
}

impl BaselineEwma {
    fn new() -> Self {
        Self { mean: 0.0, variance: 0.0, samples: 0 }
    }

    /// Actualizeaza EWMA cu o observatie noua.
    fn update(&mut self, value: f64, alpha: f64) {
        self.samples += 1;
        if self.samples == 1 {
            self.mean = value;
            self.variance = 0.0;
            return;
        }
        let delta = value - self.mean;
        self.mean += alpha * delta;
        self.variance = (1.0 - alpha) * (self.variance + alpha * delta * delta);
    }

    fn stddev(&self) -> f64 {
        self.variance.sqrt()
    }
}

/// Stare baseline pentru toate tipurile de scan cu praguri dinamice.
struct BaselineState {
    fast_scan: BaselineEwma,
    slow_scan: BaselineEwma,
    accept_scan: BaselineEwma,
}

impl BaselineState {
    fn new() -> Self {
        Self {
            fast_scan: BaselineEwma::new(),
            slow_scan: BaselineEwma::new(),
            accept_scan: BaselineEwma::new(),
        }
    }
}

/// Calculeaza pragul efectiv pentru un tip de scan, tinand cont de baseline dinamic.
///
/// Daca pragurile dinamice sunt dezactivate sau nu s-au colectat destule esantioane,
/// returneaza pragul static din config.
fn effective_threshold_value(
    static_threshold: usize,
    baseline: &BaselineEwma,
    dt: &DynamicThresholdConfig,
) -> usize {
    if !dt.enabled || baseline.samples < dt.min_samples {
        return static_threshold;
    }
    let dynamic = baseline.mean + dt.sensitivity_multiplier * baseline.stddev();
    let floor = (static_threshold as f64 * dt.min_threshold_ratio).ceil() as usize;
    let ceiling = (static_threshold as f64 * dt.max_threshold_ratio).floor() as usize;
    (dynamic.ceil() as usize).clamp(floor.max(1), ceiling.max(1))
}

pub struct Detector {
    /// Evidenta porturilor BLOCATE (drop) accesate per IP sursa.
    /// Alimenteaza detectia Fast Scan si Slow Scan.
    /// Key: IP-ul sursa | Value: lista de (port, timestamp)
    port_hits: DashMap<IpAddr, Vec<PortHit>>,

    /// Evidenta porturilor ACCEPTATE (accept) accesate per IP sursa.
    /// Alimenteaza detectia Accept Scan (porturi deschise).
    ///
    /// NOTA: Separat de port_hits intentionat — amestecarea drop-urilor cu
    /// accept-urile ar contamina detectia. Un Fast Scan poate aparea simultan
    /// cu un Accept Scan de la acelasi IP, si vrem sa le detectam independent.
    accept_hits: DashMap<IpAddr, Vec<PortHit>>,

    /// Cooldown alerte Fast Scan per IP.
    /// Previne re-alertarea pentru acelasi IP inainte de expirarea cooldown-ului.
    fast_cooldowns: DashMap<IpAddr, Instant>,

    /// Cooldown alerte Slow Scan per IP.
    slow_cooldowns: DashMap<IpAddr, Instant>,

    /// Cooldown alerte Accept Scan per IP.
    accept_cooldowns: DashMap<IpAddr, Instant>,

    /// Ultimul moment cand fiecare IP a fost vazut (drop SAU accept).
    /// Folosit pentru LRU eviction: cand numarul de IP-uri urmarite ajunge
    /// la max_tracked_ips, IP-ul cu cel mai vechi `last_seen` este eliminat.
    ///
    /// NOTA RUST: Mentinem aceasta structura separata (nu parcurgem port_hits
    /// sau accept_hits) pentru a gasi rapid LRU-ul fara write-lock-uri suprapuse.
    /// `last_seen` acum urmareste TOATE IP-urile, indiferent de tipul actiunii
    /// (drop sau accept), deci este sursa de adevar pentru capacitate totala.
    last_seen: DashMap<IpAddr, Instant>,

    /// Evidenta destinatiilor contactate pe porturi laterale, per IP sursa.
    /// Alimenteaza detectia Lateral Movement (#22).
    /// Key: IP-ul sursa | Value: lista de (dest_ip, timestamp)
    lateral_hits: DashMap<IpAddr, Vec<DestHit>>,

    /// Cooldown alerte Lateral Movement per IP sursa.
    lateral_cooldowns: DashMap<IpAddr, Instant>,

    /// Evidenta hit-urilor per destinatie (Distributed Scan #23).
    /// Perspectiva inversata: cheia este dest_ip, nu source_ip.
    /// Key: IP-ul destinatie | Value: lista de (source_ip, port, timestamp)
    distributed_hits: DashMap<IpAddr, Vec<DistributedHit>>,

    /// Cooldown alerte Distributed Scan per IP destinatie (tinta).
    /// Indexat dupa dest_ip — cooldown-ul este al tintei, nu al atacatorului.
    distributed_cooldowns: DashMap<IpAddr, Instant>,

    /// IP-uri si subretele excluse din detectie (parsate din config la constructie).
    /// Wrapat in ArcSwap pentru hot reload atomic la SIGHUP (#16).
    whitelist: ArcSwap<Vec<WhitelistEntry>>,

    /// Configurarea pragurilor de detectie.
    /// Wrapat in ArcSwap pentru hot reload atomic la SIGHUP (#16).
    /// `ArcSwap::load()` returneaza un `Guard` (pointer atomic, lock-free) —
    /// cost: un load atomic per acces, neglijabil la scala UDP processing.
    config: ArcSwap<DetectionConfig>,

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
        // Parsam whitelist-ul din config la constructie (o singura data).
        let whitelist: Vec<WhitelistEntry> = config
            .whitelist
            .iter()
            .filter_map(|entry| WhitelistEntry::parse(entry))
            .collect();

        Self {
            port_hits: DashMap::new(),
            accept_hits: DashMap::new(),
            fast_cooldowns: DashMap::new(),
            slow_cooldowns: DashMap::new(),
            accept_cooldowns: DashMap::new(),
            lateral_hits: DashMap::new(),
            lateral_cooldowns: DashMap::new(),
            distributed_hits: DashMap::new(),
            distributed_cooldowns: DashMap::new(),
            last_seen: DashMap::new(),
            whitelist: ArcSwap::from_pointee(whitelist),
            config: ArcSwap::from_pointee(config),
            baseline: Mutex::new(BaselineState::new()),
        }
    }

    /// Actualizeaza configurarea detectorului la runtime (hot reload SIGHUP).
    ///
    /// NOTA RUST — SAFETY:
    /// Aceasta metoda necesita `&mut self`, ceea ce inseamna acces EXCLUSIV.
    /// In practica, `Detector` este wrapat in `Arc` si partajat intre task-uri,
    /// deci nu putem obtine `&mut` direct. Solutia: campurile `config` si
    /// `whitelist` sunt wrappate in `ArcSwap` pentru swap atomic lock-free.
    ///
    /// Starea de detectie (DashMap-urile) NU este afectata — IP-urile urmarite,
    /// port hit-urile si cooldown-urile raman intacte dupa reload.
    pub fn update_config(&self, new_config: DetectionConfig) {
        // Re-parsam whitelist-ul din noua configurare.
        let new_whitelist: Vec<WhitelistEntry> = new_config
            .whitelist
            .iter()
            .filter_map(|entry| WhitelistEntry::parse(entry))
            .collect();

        // Swap atomic: noua configurare devine activa imediat.
        self.config.store(Arc::new(new_config));
        self.whitelist.store(Arc::new(new_whitelist));
    }

    /// Verifica daca un IP este in whitelist (exclus din detectie).
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.whitelist.load().iter().any(|entry| entry.matches(ip))
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

        // Incarcam config-ul o singura data per eveniment (load atomic, lock-free).
        // `Guard` din ArcSwap tine o referinta la snapshot-ul curent al config-ului.
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
        let (fast_threshold, slow_threshold, accept_threshold) = {
            let bl = self.baseline.lock()
                .unwrap_or_else(|e| e.into_inner());
            let dt = &cfg.dynamic_threshold;
            (
                effective_threshold_value(cfg.fast_scan.port_threshold, &bl.fast_scan, dt),
                effective_threshold_value(cfg.slow_scan.port_threshold, &bl.slow_scan, dt),
                effective_threshold_value(cfg.accept_scan.port_threshold, &bl.accept_scan, dt),
            )
        };

        // --- 1. Limitare globala IP-uri (anti-IP-spoofing flood) ---
        //
        // NOTA #4 - LRU EVICTION:
        //
        // Un atacator poate trimite pachete cu milioane de IP-uri sursa false (spoofed).
        // Fara limita, fiecare IP nou creeaza o intrare noua in DashMap → memory exhaustion.
        //
        // Solutia: cand DashMap-ul ajunge la max_tracked_ips si soseste un IP NOU,
        // eliminam IP-ul cel mai vechi (LRU = Least Recently Used) inainte de a insera.
        //
        // Algoritmul:
        //   1. Verificam daca IP-ul este nou (nu exista in port_hits)
        //   2. Daca da si am atins limita → parcurgem last_seen si gasim minimul
        //   3. Eliminam acel IP din toate structurile
        //
        // NOTA RUST - `.iter().min_by_key()`:
        // Parcurge intregul DashMap si returneaza elementul cu valoarea minima.
        // Returneaza Option<Ref<K,V>> — None daca map-ul e gol, Some altfel.
        // `.map(|e| *e.key())` extrage cheia (IpAddr e Copy → * dereferentiaza si copiaza).
        // Ref-ul este dropit inainte de `.remove()` → fara deadlock.
        //
        // Complexitate: O(n) per evictie. Evictia apare rar (doar la IP-uri noi dupa
        // atingerea limitei). In practica, un flood de IP-uri spoofed este cel mai
        // rau caz — dar atunci O(n) eviction este acceptabil vs. OOM.
        //
        // NOTA #4 — LRU EVICTION (actualizat pentru Accept Scan):
        //
        // Folosim `last_seen` ca sursa de adevar pentru "cate IP-uri urmarim".
        // `last_seen` este actualizat la FIECARE eveniment (drop si accept),
        // deci reflecta corect totalul IP-urilor active, indiferent de tipul actiunii.
        //
        // Inainte de #10 verificam `port_hits.contains_key` si `port_hits.len()`.
        // Problema: un IP care trimite doar "accept"-uri (fara "drop") nu aparea in
        // port_hits → nu era considerat "urmarit" → evictia nu se activa corect.
        // Acum: `last_seen` urmareste orice IP, indiferent de actiune.
        let is_new_ip = !self.last_seen.contains_key(&ip);
        if is_new_ip && self.last_seen.len() >= cfg.max_tracked_ips {
            // Gasim IP-ul cu cel mai vechi last_seen (Least Recently Used).
            let lru_ip: Option<IpAddr> = self
                .last_seen
                .iter()
                .min_by_key(|e| *e.value())
                .map(|e| *e.key());

            if let Some(old_ip) = lru_ip {
                // Eliminam IP-ul LRU din TOATE structurile.
                self.port_hits.remove(&old_ip);
                self.accept_hits.remove(&old_ip);
                self.lateral_hits.remove(&old_ip);
                self.last_seen.remove(&old_ip);
                self.fast_cooldowns.remove(&old_ip);
                self.slow_cooldowns.remove(&old_ip);
                self.accept_cooldowns.remove(&old_ip);
                self.lateral_cooldowns.remove(&old_ip);
            }
        }

        // Actualizam last_seen pentru IP-ul curent (nou sau existent).
        self.last_seen.insert(ip, now);

        // --- 2. Inregistram port hit-ul in map-ul corespunzator actiunii ---
        //
        // NOTA RUST - REFERINTE IMUTABILE la campuri diferite ale structurii:
        //
        // Selectam map-ul tinta pe baza actiunii evenimentului:
        //   "drop"   → port_hits   (port BLOCAT de firewall → Fast/Slow Scan)
        //   "accept" → accept_hits (port PERMIS de firewall → Accept Scan)
        //
        // `let hits_map: &DashMap<...>` stocheaza o referinta imutabila la unul
        // din cele doua campuri. Chiar daca referinta este imutabila (&), DashMap
        // permite modificari prin INTERIOR MUTABILITY (lock-uri interne per shard).
        //
        // Borrow checker-ul Rust stie ca `if-else` produce O SINGURA referinta,
        // deci nu exista "doua borrows simultane". Compilatorul accepta acest cod
        // si garanteaza la compile-time ca nu exista aliasing periculos.
        //
        // NOTA RUST - SCOP (SCOPE) EXPLICIT cu `{}`:
        // Blocul `{}` garanteaza ca `RefMut` (write-lock-ul DashMap) este dropit
        // (eliberat) inainte de urmatoarele operatii pe DashMap.
        // Altfel: write-lock activ → urmatorul .get() pe acelasi shard → deadlock.
        //
        // NOTA #3 - LIMITARE MEMORIE PER IP:
        // `.drain(..N)` sterge primele N elemente (cele mai vechi, oldest-first).
        // Aplica aceeasi limita (max_hits_per_ip) la ambele map-uri.
        //
        let hits_map: &DashMap<IpAddr, Vec<PortHit>> = if event.action == "drop" {
            &self.port_hits
        } else {
            // "accept" si orice alta actiune filtrata de parser → accept_hits.
            &self.accept_hits
        };
        {
            let mut hits = hits_map.entry(ip).or_default();
            hits.push(PortHit {
                port: event.dest_port,
                seen_at: now,
            });

            // Cap la max_hits_per_ip: pastram doar cele mai recente intrari.
            let max_hits = cfg.max_hits_per_ip;
            if hits.len() > max_hits {
                let overflow = hits.len() - max_hits;
                hits.drain(..overflow);
            }
        }

        let mut alerts = Vec::new();

        // --- 3. Verificam Fast Scan (pe port_hits — drop-uri) ---
        //
        // `unique_ports_in_window` acum primeste map-ul ca parametru explicit.
        // Aceasta este o REFACTORIZARE necesara: inainte functia accesa `self.port_hits`
        // direct (hardcodat). Acum poate lucra cu orice DashMap de tip corect,
        // ceea ce ne permite sa o refolosim pentru Accept Scan (pasul 5) cu `accept_hits`.
        let fast_window = Duration::from_secs(cfg.fast_scan.time_window_secs);
        if let Some(ports) = self.unique_ports_in_window(&self.port_hits, ip, fast_window, now) {
            if ports.len() >= fast_threshold
                && !self.in_cooldown(&self.fast_cooldowns, ip)
            {
                self.fast_cooldowns.insert(ip, now);
                alerts.push(Alert {
                    scan_type: ScanType::Fast,
                    source_ip: ip,
                    dest_ip: event.dest_ip,
                    unique_ports: ports,
                    unique_dests: Vec::new(),
                    unique_sources: Vec::new(),
                    timestamp: Local::now(),
                });
            }
        }

        // --- 4. Verificam Slow Scan (pe port_hits — drop-uri) ---
        let slow_window = Duration::from_secs(cfg.slow_scan.time_window_mins * 60);
        if let Some(ports) = self.unique_ports_in_window(&self.port_hits, ip, slow_window, now) {
            if ports.len() >= slow_threshold
                && !self.in_cooldown(&self.slow_cooldowns, ip)
            {
                self.slow_cooldowns.insert(ip, now);
                alerts.push(Alert {
                    scan_type: ScanType::Slow,
                    source_ip: ip,
                    dest_ip: event.dest_ip,
                    unique_ports: ports,
                    unique_dests: Vec::new(),
                    unique_sources: Vec::new(),
                    timestamp: Local::now(),
                });
            }
        }

        // --- 5. Verificam Accept Scan (pe accept_hits — conexiuni permise) ---
        //
        // Logica este identica cu Fast Scan, dar:
        //   - Sursa de date: accept_hits (nu port_hits)
        //   - Praguri: din config.accept_scan (pot fi diferite de Fast Scan)
        //   - Cooldown propriu: accept_cooldowns (independent de fast/slow)
        //   - ScanType: AcceptScan → SignatureID 1003 in SIEM
        //
        // Separarea completa de Fast/Slow Scan inseamna ca un IP poate declansa
        // simultan o alerta Fast Scan (din drop-uri) SI o alerta Accept Scan (din
        // accept-uri) — si amandoua vor fi trimise la SIEM si email, independent.
        let accept_window = Duration::from_secs(cfg.accept_scan.time_window_secs);
        if let Some(ports) = self.unique_ports_in_window(&self.accept_hits, ip, accept_window, now) {
            if ports.len() >= accept_threshold
                && !self.in_cooldown(&self.accept_cooldowns, ip)
            {
                self.accept_cooldowns.insert(ip, now);
                alerts.push(Alert {
                    scan_type: ScanType::AcceptScan,
                    source_ip: ip,
                    dest_ip: event.dest_ip,
                    unique_ports: ports,
                    unique_dests: Vec::new(),
                    unique_sources: Vec::new(),
                    timestamp: Local::now(),
                });
            }
        }

        // --- 6. Verificam Lateral Movement (#22) ---
        //
        // Conditii necesare:
        //   a) Lateral Movement este activat in config
        //   b) dest_ip este prezent in eveniment (fara destinatie, nu putem detecta)
        //   c) Actiunea este "accept" (conexiune reusita pe orice port)
        //
        // Fara filtru de port: detectia e bazata pe comportament (1 sursa → N
        // destinatii unice), nu pe asumptii despre porturile atacatorului.
        // Servicii legitime cu fan-out mare se pun in whitelist.
        //
        // Logica: inregistram fiecare destinatie unica contactata. Daca numarul
        // de destinatii unice in fereastra de timp depaseste pragul, generam alerta.
        let lm_cfg = &cfg.lateral_movement;
        if lm_cfg.enabled {
            if let Some(dest_ip) = event.dest_ip {
                if event.action == "accept" {
                    // Inregistram destinatia in lateral_hits pentru IP-ul sursa.
                    {
                        let mut hits = self.lateral_hits.entry(ip).or_default();
                        hits.push(DestHit { dest_ip, seen_at: now });
                        // Cap memorie: refolosim max_hits_per_ip ca limita.
                        let max_hits = cfg.max_hits_per_ip;
                        if hits.len() > max_hits {
                            let overflow = hits.len() - max_hits;
                            hits.drain(..overflow);
                        }
                    }

                    // Colectam destinatiile unice in fereastra de timp.
                    let lm_window = Duration::from_secs(lm_cfg.time_window_secs);
                    if let Some(unique_dests) = self.unique_dests_in_window(ip, lm_window, now) {
                        if unique_dests.len() >= lm_cfg.unique_dest_threshold
                            && !self.in_cooldown(&self.lateral_cooldowns, ip)
                        {
                            self.lateral_cooldowns.insert(ip, now);
                            alerts.push(Alert {
                                scan_type: ScanType::LateralMovement,
                                source_ip: ip,
                                dest_ip: Some(dest_ip),
                                unique_ports: Vec::new(),
                                unique_dests,
                                unique_sources: Vec::new(),
                                timestamp: Local::now(),
                            });
                        }
                    }
                }
            }
        }

        // --- 7. Verificam Distributed Scan (#23) ---
        //
        // Perspectiva inversata: indexam dupa dest_ip, numaram surse unice.
        // Conditii:
        //   a) Distributed Scan este activat in config
        //   b) dest_ip este prezent in eveniment
        //
        // Inregistram hit-ul indiferent de actiune (drop sau accept) —
        // un atac coordonat poate genera ambele tipuri de trafic.
        //
        // Cooldown-ul este per dest_ip (tinta), nu per source_ip:
        // daca 10 surse scanează tinta X, o singura alerta este generata
        // pentru X, nu 10 alerte separate.
        let ds_cfg = &cfg.distributed_scan;
        if ds_cfg.enabled {
            if let Some(dest_ip) = event.dest_ip {
                // Inregistram hit-ul in distributed_hits pentru IP-ul destinatie.
                {
                    let mut hits = self.distributed_hits.entry(dest_ip).or_default();
                    hits.push(DistributedHit { source_ip: ip, port: event.dest_port, seen_at: now });
                    // Cap memorie: refolosim max_hits_per_ip ca limita.
                    let max_hits = cfg.max_hits_per_ip;
                    if hits.len() > max_hits {
                        let overflow = hits.len() - max_hits;
                        hits.drain(..overflow);
                    }
                }

                // Colectam sursele unice si porturile in fereastra de timp.
                let ds_window = Duration::from_secs(ds_cfg.time_window_secs);
                if let Some((unique_srcs, targeted_ports)) = self.unique_sources_in_window(dest_ip, ds_window, now) {
                    if unique_srcs.len() >= ds_cfg.unique_sources_threshold
                        && !self.in_cooldown(&self.distributed_cooldowns, dest_ip)
                    {
                        self.distributed_cooldowns.insert(dest_ip, now);
                        alerts.push(Alert {
                            scan_type: ScanType::DistributedScan,
                            source_ip: ip,
                            dest_ip: Some(dest_ip),
                            unique_ports: targeted_ports,
                            unique_dests: Vec::new(),
                            unique_sources: unique_srcs,
                            timestamp: Local::now(),
                        });
                    }
                }
            }
        }

        alerts
    }

    /// Returneaza lista porturilor unice accesate de un IP in fereastra de timp.
    ///
    /// NOTA RUST - REFACTORIZARE (#10): Aceasta functie primeste `hits_map` ca parametru.
    ///
    /// Inainte de #10, functia accesa `self.port_hits` direct (hardcodat).
    /// Problema: nu o puteam refolosi pentru Accept Scan (care foloseste `accept_hits`).
    ///
    /// Solutia: injectam map-ul ca referinta `&DashMap<IpAddr, Vec<PortHit>>`.
    /// Aceasta este "dependency injection" la nivel de functie — un principiu
    /// fundamental in design-ul de software testabil si extensibil.
    ///
    /// Apeluri:
    ///   self.unique_ports_in_window(&self.port_hits, ip, window, now)   → Fast/Slow Scan
    ///   self.unique_ports_in_window(&self.accept_hits, ip, window, now) → Accept Scan
    ///
    /// NOTA RUST - ITERATORS (zero-cost abstractions):
    /// .iter() → lazy, .filter() → lazy, .map() → lazy, .collect() → EXECUTA.
    /// Compilatorul fuzioneaza lantul intr-un singur loop optimizat, fara colectii intermediare.
    ///
    /// NOTA RUST - `.get(&ip)` returneaza Option<Ref<K, V>>:
    /// `Ref` este un guard de citire al DashMap (similar cu RwLockReadGuard).
    /// Tine lock-ul de citire cat timp exista — dropat automat la finalul scope-ului (RAII).
    fn unique_ports_in_window(
        &self,
        hits_map: &DashMap<IpAddr, Vec<PortHit>>,
        ip: IpAddr,
        window: Duration,
        now: Instant,
    ) -> Option<Vec<u16>> {
        let entry = hits_map.get(&ip)?;
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

    /// Returneaza destinatiile unice contactate de `ip` in fereastra `window`.
    ///
    /// Analog cu `unique_ports_in_window`, dar opereaza pe `lateral_hits`
    /// si colecteaza IP-uri destinatie unice in loc de porturi unice.
    ///
    /// Returneaza `None` daca nu exista date pentru IP sau lista e goala.
    /// Returneaza `Some(Vec<IpAddr>)` cu destinatiile unice din fereastra.
    fn unique_dests_in_window(
        &self,
        ip: IpAddr,
        window: Duration,
        now: Instant,
    ) -> Option<Vec<IpAddr>> {
        let hits = self.lateral_hits.get(&ip)?;
        let mut seen: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();
        for hit in hits.iter() {
            if now.duration_since(hit.seen_at) <= window {
                seen.insert(hit.dest_ip);
            }
        }
        if seen.is_empty() {
            None
        } else {
            Some(seen.into_iter().collect())
        }
    }

    /// Returneaza sursele unice si porturile vizate pe o tinta in fereastra `window`.
    ///
    /// Analog cu `unique_dests_in_window`, dar opereaza pe `distributed_hits`
    /// (indexat dupa dest_ip) si colecteaza IP-uri sursa unice + porturi vizate.
    ///
    /// Returneaza `None` daca nu exista date sau lista e goala.
    /// Returneaza `Some((Vec<IpAddr>, Vec<u16>))` cu sursele unice si porturile.
    fn unique_sources_in_window(
        &self,
        dest_ip: IpAddr,
        window: Duration,
        now: Instant,
    ) -> Option<(Vec<IpAddr>, Vec<u16>)> {
        let hits = self.distributed_hits.get(&dest_ip)?;
        let mut sources: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();
        let mut ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
        for hit in hits.iter() {
            if now.saturating_duration_since(hit.seen_at) <= window {
                sources.insert(hit.source_ip);
                ports.insert(hit.port);
            }
        }
        if sources.is_empty() {
            None
        } else {
            let src_vec: Vec<IpAddr> = sources.into_iter().collect();
            let mut port_vec: Vec<u16> = ports.into_iter().collect();
            port_vec.sort_unstable();
            Some((src_vec, port_vec))
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
            last_alert.elapsed() < Duration::from_secs(self.config.load().alert_cooldown_secs)
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

        // --- Baseline sampling (#35) — INAINTE de curatare ---
        //
        // Esantionam numarul maxim de porturi unice per IP per fereastra de timp.
        // Acest "maxim" reprezinta cel mai zgomotos IP legitim din retea.
        // Trebuie facut inainte de prune-ul datelor vechi, altfel pierdem datele
        // necesare pentru calculul baseline-ului.
        {
            let cfg = self.config.load();
            if cfg.dynamic_threshold.enabled {
                let alpha = cfg.dynamic_threshold.ewma_alpha;
                let fast_w = Duration::from_secs(cfg.fast_scan.time_window_secs);
                let slow_w = Duration::from_secs(cfg.slow_scan.time_window_mins * 60);
                let accept_w = Duration::from_secs(cfg.accept_scan.time_window_secs);

                let mut fast_max: usize = 0;
                let mut slow_max: usize = 0;
                let mut accept_max: usize = 0;

                // Iteram port_hits: esantionam fast_max si slow_max.
                for entry in self.port_hits.iter() {
                    let ip = *entry.key();
                    if let Some(ports) = self.unique_ports_in_window(&self.port_hits, ip, fast_w, now) {
                        fast_max = fast_max.max(ports.len());
                    }
                    if let Some(ports) = self.unique_ports_in_window(&self.port_hits, ip, slow_w, now) {
                        slow_max = slow_max.max(ports.len());
                    }
                }

                // Iteram accept_hits: esantionam accept_max.
                for entry in self.accept_hits.iter() {
                    let ip = *entry.key();
                    if let Some(ports) = self.unique_ports_in_window(&self.accept_hits, ip, accept_w, now) {
                        accept_max = accept_max.max(ports.len());
                    }
                }

                let mut bl = self.baseline.lock()
                    .unwrap_or_else(|e| e.into_inner());
                bl.fast_scan.update(fast_max as f64, alpha);
                bl.slow_scan.update(slow_max as f64, alpha);
                bl.accept_scan.update(accept_max as f64, alpha);
            }
        }

        // --- Curatam port_hits (drop-uri) ---
        //
        // NOTA RUST: Nu putem sterge din DashMap in timpul iteratiei (ar invalida
        // iteratorul). De aceea colectam cheile goale si le stergem separat.
        let mut drop_empty: Vec<IpAddr> = Vec::new();
        for mut entry in self.port_hits.iter_mut() {
            entry.value_mut().retain(|hit| {
                now.saturating_duration_since(hit.seen_at) <= max_age
            });
            if entry.value().is_empty() {
                drop_empty.push(*entry.key());
            }
        }
        for ip in &drop_empty {
            self.port_hits.remove(ip);
        }

        // --- Curatam accept_hits (accept-uri) ---
        //
        // Aceeasi logica ca pentru port_hits, dar pe map-ul separat al Accept Scan.
        // Datele vechi de accept sunt la fel de costisitoare in memorie ca cele de drop.
        let mut accept_empty: Vec<IpAddr> = Vec::new();
        for mut entry in self.accept_hits.iter_mut() {
            entry.value_mut().retain(|hit| {
                now.saturating_duration_since(hit.seen_at) <= max_age
            });
            if entry.value().is_empty() {
                accept_empty.push(*entry.key());
            }
        }
        for ip in &accept_empty {
            self.accept_hits.remove(ip);
        }

        // --- Curatam lateral_hits (Lateral Movement #22) ---
        let mut lateral_empty: Vec<IpAddr> = Vec::new();
        for mut entry in self.lateral_hits.iter_mut() {
            entry.value_mut().retain(|hit| {
                now.saturating_duration_since(hit.seen_at) <= max_age
            });
            if entry.value().is_empty() {
                lateral_empty.push(*entry.key());
            }
        }
        for ip in &lateral_empty {
            self.lateral_hits.remove(ip);
        }

        // --- Curatam distributed_hits (Distributed Scan #23) ---
        // Indexat dupa dest_ip, nu source_ip — cleanup separat de celelalte.
        let mut dist_empty: Vec<IpAddr> = Vec::new();
        for mut entry in self.distributed_hits.iter_mut() {
            entry.value_mut().retain(|hit| {
                now.saturating_duration_since(hit.seen_at) <= max_age
            });
            if entry.value().is_empty() {
                dist_empty.push(*entry.key());
            }
        }
        for ip in &dist_empty {
            self.distributed_hits.remove(ip);
        }

        // --- Sincronizam last_seen ---
        //
        // Eliminam din last_seen IP-urile care nu mai au date in NICIUN map.
        // Un IP urmarit exclusiv pentru Accept Scan sau Lateral Movement trebuie
        // sters din last_seen cand map-ul respectiv il curata.
        //
        // NOTA RUST: `.retain()` pe DashMap cu closure care acceseaza ALTE DashMap-uri.
        // Aceasta este sigura deoarece:
        //   - last_seen, port_hits, accept_hits, lateral_hits sunt DashMap-uri SEPARATE
        //   - Fiecare are propriile sale shard-uri si lock-uri
        //   - Nu exista overlapping borrows sau deadlock potential
        //   - Garantat de Rust la compile-time prin tipurile Send + Sync ale DashMap
        self.last_seen.retain(|ip, _| {
            self.port_hits.contains_key(ip)
                || self.accept_hits.contains_key(ip)
                || self.lateral_hits.contains_key(ip)
        });

        // --- Curatam cooldown-urile expirate (toate patru tipuri) ---
        let cooldown_dur = Duration::from_secs(self.config.load().alert_cooldown_secs);
        self.fast_cooldowns
            .retain(|_, instant| now.saturating_duration_since(*instant) <= cooldown_dur);
        self.slow_cooldowns
            .retain(|_, instant| now.saturating_duration_since(*instant) <= cooldown_dur);
        self.accept_cooldowns
            .retain(|_, instant| now.saturating_duration_since(*instant) <= cooldown_dur);
        self.lateral_cooldowns
            .retain(|_, instant| now.saturating_duration_since(*instant) <= cooldown_dur);
        self.distributed_cooldowns
            .retain(|_, instant| now.saturating_duration_since(*instant) <= cooldown_dur);
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
mod tests {
    use super::*;
    use crate::config::{
        AcceptScanConfig, DetectionConfig, DistributedScanConfig, DynamicThresholdConfig,
        FastScanConfig, LateralMovementConfig, SlowScanConfig,
    };

    /// Creeaza o configuratie de test cu praguri mici pentru teste rapide.
    fn test_config() -> DetectionConfig {
        DetectionConfig {
            alert_cooldown_secs: 5,
            max_hits_per_ip: 1_000,
            max_tracked_ips: 10_000,
            whitelist: Vec::new(),
            fast_scan: FastScanConfig {
                port_threshold: 3,
                time_window_secs: 10,
            },
            slow_scan: SlowScanConfig {
                port_threshold: 50,
                time_window_mins: 1,
            },
            // Accept Scan cu acelasi prag ca Fast Scan pentru teste simetrice.
            accept_scan: AcceptScanConfig {
                port_threshold: 3,
                time_window_secs: 10,
            },
            // Lateral Movement dezactivat implicit in test_config.
            // Testele specifice folosesc lateral_config().
            lateral_movement: LateralMovementConfig {
                enabled: false,
                unique_dest_threshold: 3,
                time_window_secs: 10,
            },
            // Distributed Scan dezactivat implicit in test_config.
            // Testele specifice folosesc distributed_config().
            distributed_scan: DistributedScanConfig {
                enabled: false,
                unique_sources_threshold: 3,
                time_window_secs: 10,
            },
            dynamic_threshold: DynamicThresholdConfig {
                enabled: false,
                ewma_alpha: 0.1,
                sensitivity_multiplier: 3.0,
                min_samples: 10,
                min_threshold_ratio: 0.5,
                max_threshold_ratio: 3.0,
            },
        }
    }

    /// Creeaza o configuratie cu Lateral Movement activat (prag 3 destinatii in 10s).
    fn lateral_config() -> DetectionConfig {
        DetectionConfig {
            alert_cooldown_secs: 5,
            max_hits_per_ip: 1_000,
            max_tracked_ips: 10_000,
            whitelist: Vec::new(),
            fast_scan: FastScanConfig {
                port_threshold: 100,
                time_window_secs: 10,
            },
            slow_scan: SlowScanConfig {
                port_threshold: 200,
                time_window_mins: 1,
            },
            accept_scan: AcceptScanConfig {
                port_threshold: 100,
                time_window_secs: 10,
            },
            lateral_movement: LateralMovementConfig {
                enabled: true,
                unique_dest_threshold: 3,
                time_window_secs: 10,
            },
            distributed_scan: DistributedScanConfig {
                enabled: false,
                unique_sources_threshold: 3,
                time_window_secs: 10,
            },
            dynamic_threshold: DynamicThresholdConfig {
                enabled: false,
                ewma_alpha: 0.1,
                sensitivity_multiplier: 3.0,
                min_samples: 10,
                min_threshold_ratio: 0.5,
                max_threshold_ratio: 3.0,
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

    /// Creeaza un eveniment accept cu IP destinatie explicit (pentru Lateral Movement).
    fn make_lateral_event(src_ip: &str, dest_ip: &str, port: u16) -> LogEvent {
        LogEvent {
            source_ip: src_ip.parse().unwrap(),
            dest_ip: Some(dest_ip.parse().unwrap()),
            dest_port: port,
            protocol: "tcp".to_string(),
            action: "accept".to_string(),
            raw_log: String::new(),
        }
    }

    #[test]
    fn test_no_alert_below_threshold() {
        let detector = Detector::new(test_config());

        // 2 porturi unice = sub pragul de 3 (>=3 declanseaza alerta).
        for port in 1..=2 {
            let alerts = detector.process_event(&make_event("10.0.0.1", port));
            assert!(alerts.is_empty(), "Nu ar trebui alerta la {} porturi", port);
        }
    }

    #[test]
    fn test_fast_scan_alert() {
        let detector = Detector::new(test_config());

        // 3 porturi unice = egal cu pragul de 3 (>=) -> alerta Fast Scan la al 3-lea.
        for port in 1..=3 {
            let alerts = detector.process_event(&make_event("10.0.0.1", port));
            if port == 3 {
                assert_eq!(alerts.len(), 1);
                assert!(matches!(alerts[0].scan_type, ScanType::Fast));
            }
        }
    }

    #[test]
    fn test_cooldown_prevents_duplicate_alert() {
        let detector = Detector::new(test_config());

        // Trimitem 5 porturi - prima alerta la port 3 (prag >= 3).
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

    // =========================================================================
    // Teste pentru #3 — MAX_HITS_PER_IP si #4 — MAX_TRACKED_IPS
    // =========================================================================

    #[test]
    fn test_max_hits_per_ip_cap() {
        // Configuram o limita mica (5 hits) pentru a testa usor.
        let mut config = test_config();
        config.max_hits_per_ip = 5;
        let detector = Detector::new(config);

        // Trimitem 10 evenimente pe acelasi IP (porturi 1..=10).
        for port in 1..=10u16 {
            detector.process_event(&make_event("10.0.0.1", port));
        }

        // Vec-ul nu trebuie sa depaseasca limita de 5.
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let entry = detector.port_hits.get(&ip).unwrap();
        assert!(
            entry.len() <= 5,
            "Vec-ul a depasit max_hits_per_ip: are {} intrari",
            entry.len()
        );

        // Trebuie sa contina porturile CELE MAI RECENTE (6..=10), nu pe cele vechi (1..5).
        let ports: Vec<u16> = entry.iter().map(|h| h.port).collect();
        assert!(ports.contains(&10), "Portul cel mai recent (10) trebuie sa fie prezent");
        assert!(!ports.contains(&1), "Portul cel mai vechi (1) trebuia eliminat");
    }

    // =========================================================================
    // Teste pentru #10 — Accept Scan Detection
    // =========================================================================

    /// Construieste un eveniment de tip "accept" (port deschis, permis de firewall).
    fn make_accept_event(ip: &str, port: u16) -> LogEvent {
        LogEvent {
            source_ip: ip.parse().unwrap(),
            dest_ip: Some("10.0.0.1".parse().unwrap()),
            dest_port: port,
            protocol: "tcp".to_string(),
            // Diferenta fata de make_event: actiunea este "accept" nu "drop".
            action: "accept".to_string(),
            raw_log: String::new(),
        }
    }

    #[test]
    fn test_accept_scan_alert() {
        // 3 porturi ACCEPTATE unice cu prag = 3 (>=) → alerta la al 3-lea port.
        let detector = Detector::new(test_config());

        for port in 1..=3 {
            let alerts = detector.process_event(&make_accept_event("10.1.0.1", port));
            if port == 3 {
                assert_eq!(alerts.len(), 1, "Trebuia o alerta Accept Scan la {} porturi", port);
                assert!(
                    matches!(alerts[0].scan_type, ScanType::AcceptScan),
                    "Tipul alertei trebuie sa fie AcceptScan"
                );
            } else {
                assert!(alerts.is_empty(), "Fara alerta la {} porturi (sub prag)", port);
            }
        }
    }

    #[test]
    fn test_drop_events_do_not_trigger_accept_scan() {
        // Evenimentele "drop" NU trebuie sa declanseze Accept Scan.
        // Sunt inregistrate in port_hits, nu in accept_hits.
        let detector = Detector::new(test_config());

        for port in 1..=10 {
            let alerts = detector.process_event(&make_event("10.2.0.1", port));
            for alert in &alerts {
                assert!(
                    !matches!(alert.scan_type, ScanType::AcceptScan),
                    "Drop events NU trebuie sa declanseze Accept Scan (port {})", port
                );
            }
        }
    }

    #[test]
    fn test_accept_events_do_not_trigger_fast_scan() {
        // Evenimentele "accept" NU trebuie sa declanseze Fast/Slow Scan.
        // Sunt inregistrate in accept_hits, nu in port_hits.
        let detector = Detector::new(test_config());

        for port in 1..=10 {
            let alerts = detector.process_event(&make_accept_event("10.3.0.1", port));
            for alert in &alerts {
                assert!(
                    !matches!(alert.scan_type, ScanType::Fast),
                    "Accept events NU trebuie sa declanseze Fast Scan (port {})", port
                );
                assert!(
                    !matches!(alert.scan_type, ScanType::Slow),
                    "Accept events NU trebuie sa declanseze Slow Scan (port {})", port
                );
            }
        }
    }

    #[test]
    fn test_accept_scan_cooldown() {
        // Cooldown-ul Accept Scan este independent de cel Fast Scan.
        let detector = Detector::new(test_config());

        // Generam alerta initiala (4 porturi accept).
        for port in 1..=4 {
            detector.process_event(&make_accept_event("10.4.0.1", port));
        }

        // Al 5-lea port accept → cooldown activ → fara alerta noua.
        let alerts = detector.process_event(&make_accept_event("10.4.0.1", 5));
        assert!(
            alerts.is_empty(),
            "Cooldown-ul Accept Scan trebuia sa previna alerta duplicata"
        );
    }

    #[test]
    fn test_max_tracked_ips_eviction() {
        // Configuram limita mica (2 IP-uri) pentru a testa usor.
        let mut config = test_config();
        config.max_tracked_ips = 2;
        let detector = Detector::new(config);

        // Adaugam 3 IP-uri diferite. Al treilea trebuie sa provoace evictia primului.
        detector.process_event(&make_event("10.0.0.1", 80));
        detector.process_event(&make_event("10.0.0.2", 80));
        detector.process_event(&make_event("10.0.0.3", 80)); // depaseste limita → evictie LRU

        // Trebuie sa avem maxim max_tracked_ips IP-uri urmarite.
        assert!(
            detector.tracked_ips() <= 2,
            "DashMap a depasit max_tracked_ips: urmareste {} IP-uri",
            detector.tracked_ips()
        );

        // IP-ul 10.0.0.1 a fost cel mai vechi → trebuie evictat.
        let ip1: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        assert!(
            !detector.port_hits.contains_key(&ip1),
            "IP-ul cel mai vechi (10.0.0.1) trebuia evictat"
        );

        // IP-ul 10.0.0.3 (cel mai recent) trebuie sa fie prezent.
        let ip3: std::net::IpAddr = "10.0.0.3".parse().unwrap();
        assert!(
            detector.port_hits.contains_key(&ip3),
            "IP-ul cel mai recent (10.0.0.3) trebuie sa fie prezent"
        );
    }

    // =========================================================================
    // Teste pentru Slow Scan (#18)
    // =========================================================================
    //
    // test_config() are slow_scan.port_threshold = 50 — prea mare pentru teste.
    // slow_test_config() seteaza prag mic (3) si Fast Scan dezactivat practic
    // (prag 1000) pentru a testa Slow Scan izolat.

    /// Configuratie dedicata testelor Slow Scan.
    ///
    /// Fast Scan are prag ridicat (1000) astfel incat nu se declanseaza in
    /// testele curente (max ~10 porturi). Slow Scan are prag mic (3) pentru
    /// teste rapide. Fereastra de 1 minut inseamna ca toate evenimentele
    /// din test (milisecunde) sunt in cadrul ferestrei.
    fn slow_test_config() -> DetectionConfig {
        DetectionConfig {
            alert_cooldown_secs: 5,
            max_hits_per_ip: 1_000,
            max_tracked_ips: 10_000,
            whitelist: Vec::new(),
            fast_scan: FastScanConfig {
                port_threshold: 1_000, // prag mare — nu se declanseaza in teste slow
                time_window_secs: 10,
            },
            slow_scan: SlowScanConfig {
                port_threshold: 3, // prag mic pentru teste rapide
                time_window_mins: 1,
            },
            accept_scan: AcceptScanConfig {
                port_threshold: 1_000,
                time_window_secs: 60,
            },
            lateral_movement: LateralMovementConfig {
                enabled: false,
                unique_dest_threshold: 3,
                time_window_secs: 10,
            },
            distributed_scan: DistributedScanConfig {
                enabled: false,
                unique_sources_threshold: 3,
                time_window_secs: 10,
            },
            dynamic_threshold: DynamicThresholdConfig {
                enabled: false,
                ewma_alpha: 0.1,
                sensitivity_multiplier: 3.0,
                min_samples: 10,
                min_threshold_ratio: 0.5,
                max_threshold_ratio: 3.0,
            },
        }
    }

    #[test]
    fn test_slow_scan_alert() {
        // 3 porturi unice (drop) cu prag slow = 3 (>=) → alerta Slow Scan la al 3-lea port.
        let detector = Detector::new(slow_test_config());

        for port in 1..=3u16 {
            let alerts = detector.process_event(&make_event("192.168.1.1", port));
            if port == 3 {
                assert_eq!(alerts.len(), 1, "Trebuia o alerta Slow Scan la {} porturi", port);
                assert!(
                    matches!(alerts[0].scan_type, ScanType::Slow),
                    "Tipul alertei trebuie sa fie Slow, nu {:?}",
                    alerts[0].scan_type
                );
                assert_eq!(alerts[0].unique_ports.len(), 3);
            } else {
                assert!(alerts.is_empty(), "Fara alerta sub prag (port {})", port);
            }
        }
    }

    #[test]
    fn test_slow_scan_cooldown() {
        // Dupa o alerta Slow Scan, porturi suplimentare nu genereaza alerta noua
        // cat timp cooldown-ul este activ.
        let detector = Detector::new(slow_test_config());

        // Generam alerta initiala (3 porturi drop → prag 3 atins cu >=).
        for port in 1..=4u16 {
            detector.process_event(&make_event("192.168.2.1", port));
        }

        // Al 5-lea port → cooldown activ → fara alerta noua.
        let alerts = detector.process_event(&make_event("192.168.2.1", 5));
        assert!(
            alerts.is_empty(),
            "Cooldown-ul Slow Scan trebuia sa previna alerta duplicata"
        );
    }

    #[test]
    fn test_slow_scan_independent_from_fast() {
        // Slow Scan si Fast Scan sunt urmarite independent.
        // Cu slow_test_config: Fast threshold = 1000, Slow threshold = 3.
        // 3+ porturi drop → doar Slow Scan se declanseaza (Fast prag=1000, neatins).
        let detector = Detector::new(slow_test_config());

        let mut got_slow = false;
        let mut got_fast = false;

        for port in 1..=4u16 {
            let alerts = detector.process_event(&make_event("192.168.3.1", port));
            for alert in &alerts {
                match alert.scan_type {
                    ScanType::Slow => got_slow = true,
                    ScanType::Fast => got_fast = true,
                    _ => {}
                }
            }
        }

        assert!(got_slow, "Trebuia o alerta Slow Scan");
        assert!(!got_fast, "Fast Scan NU trebuia sa se declanseze cu prag 1000");
    }

    // =========================================================================
    // Teste Whitelist (#12)
    // =========================================================================

    #[test]
    fn test_whitelist_single_ip_blocks_alert() {
        // IP-ul 10.0.0.1 este in whitelist → nu trebuie sa genereze alerta.
        let mut config = test_config();
        config.whitelist = vec!["10.0.0.1".to_string()];
        let detector = Detector::new(config);

        // Trimitem 5 porturi (peste prag 3) — fara alerta.
        for port in 1..=5 {
            let alerts = detector.process_event(&make_event("10.0.0.1", port));
            assert!(alerts.is_empty(), "IP in whitelist nu trebuie sa genereze alerta");
        }
    }

    #[test]
    fn test_whitelist_cidr_blocks_alert() {
        // Subnet-ul 10.0.0.0/24 este in whitelist → 10.0.0.50 nu genereaza alerta.
        let mut config = test_config();
        config.whitelist = vec!["10.0.0.0/24".to_string()];
        let detector = Detector::new(config);

        for port in 1..=5 {
            let alerts = detector.process_event(&make_event("10.0.0.50", port));
            assert!(alerts.is_empty(), "IP din subnet whitelist nu trebuie sa genereze alerta");
        }
    }

    #[test]
    fn test_whitelist_does_not_block_other_ips() {
        // 10.0.0.1 in whitelist, dar 10.0.0.2 NU — trebuie sa genereze alerta.
        let mut config = test_config();
        config.whitelist = vec!["10.0.0.1".to_string()];
        let detector = Detector::new(config);

        for port in 1..=3 {
            let alerts = detector.process_event(&make_event("10.0.0.2", port));
            if port == 3 {
                assert_eq!(alerts.len(), 1, "IP-ul care NU e in whitelist trebuie sa genereze alerta");
            }
        }
    }

    #[test]
    fn test_whitelist_cidr_boundary() {
        // 10.0.1.0/24 in whitelist → 10.0.2.1 NU e acoperit.
        let mut config = test_config();
        config.whitelist = vec!["10.0.1.0/24".to_string()];
        let detector = Detector::new(config);

        for port in 1..=3 {
            let alerts = detector.process_event(&make_event("10.0.2.1", port));
            if port == 3 {
                assert_eq!(alerts.len(), 1, "IP din alt subnet nu e acoperit de whitelist");
            }
        }
    }

    #[test]
    fn test_whitelist_accept_scan_blocked() {
        // Whitelist blocheaza si Accept Scan, nu doar Fast/Slow.
        let mut config = test_config();
        config.whitelist = vec!["10.1.0.1".to_string()];
        let detector = Detector::new(config);

        for port in 1..=5 {
            let alerts = detector.process_event(&make_accept_event("10.1.0.1", port));
            assert!(alerts.is_empty(), "Accept Scan trebuie blocat de whitelist");
        }
    }

    // =========================================================================
    // Teste Lateral Movement (#22)
    // =========================================================================

    #[test]
    fn test_lateral_movement_alert() {
        // 3 destinatii diferite pe port 445 (SMB) = egal cu pragul -> alerta.
        let detector = Detector::new(lateral_config());

        let dests = ["10.0.0.10", "10.0.0.11", "10.0.0.12"];
        let mut last_alerts = vec![];
        for dest in &dests {
            last_alerts = detector.process_event(&make_lateral_event("10.0.1.5", dest, 445));
        }

        assert_eq!(last_alerts.len(), 1);
        assert!(
            matches!(last_alerts[0].scan_type, ScanType::LateralMovement),
            "Tipul alertei trebuie sa fie LateralMovement"
        );
        assert_eq!(
            last_alerts[0].unique_dests.len(),
            3,
            "Trebuie sa contina exact 3 destinatii unice"
        );
        assert!(
            last_alerts[0].unique_ports.is_empty(),
            "unique_ports trebuie sa fie gol pentru LateralMovement"
        );
    }

    #[test]
    fn test_lateral_movement_below_threshold_no_alert() {
        // 2 destinatii < prag 3 -> fara alerta.
        let detector = Detector::new(lateral_config());

        for dest in &["10.0.0.10", "10.0.0.11"] {
            let alerts = detector.process_event(&make_lateral_event("10.0.1.5", dest, 445));
            assert!(
                alerts.is_empty(),
                "Nu trebuie alerta sub prag ({} destinatii)", dest
            );
        }
    }

    #[test]
    fn test_lateral_movement_any_port_triggers() {
        // Orice port accept declanseaza Lateral Movement — fara filtru de port.
        let detector = Detector::new(lateral_config());

        let dests = ["10.0.0.10", "10.0.0.11", "10.0.0.12"];
        let mut last_alerts = vec![];
        for dest in &dests {
            // Port 80 (HTTP) — nu e "lateral movement tipic", dar detectia e bazata
            // pe comportament (N destinatii), nu pe port.
            last_alerts = detector.process_event(&make_lateral_event("10.0.1.5", dest, 80));
        }

        assert_eq!(last_alerts.len(), 1);
        assert!(
            matches!(last_alerts[0].scan_type, ScanType::LateralMovement),
            "Lateral Movement trebuie detectat pe orice port, nu doar pe porturi predefinite"
        );
    }

    #[test]
    fn test_lateral_movement_cooldown() {
        // Dupa prima alerta, cooldown previne alerta repetata.
        let detector = Detector::new(lateral_config());

        // Prima alerta la a 3-a destinatie.
        let dests = ["10.0.0.10", "10.0.0.11", "10.0.0.12"];
        for dest in &dests {
            detector.process_event(&make_lateral_event("10.0.1.5", dest, 445));
        }

        // A 4-a destinatie — cooldown activ, nu trebuie alerta.
        let alerts = detector.process_event(&make_lateral_event("10.0.1.5", "10.0.0.13", 445));
        let lateral: Vec<_> = alerts
            .iter()
            .filter(|a| matches!(a.scan_type, ScanType::LateralMovement))
            .collect();
        assert!(
            lateral.is_empty(),
            "Cooldown trebuie sa previna alerta repetata Lateral Movement"
        );
    }

    #[test]
    fn test_lateral_movement_disabled_no_alert() {
        // Cand lateral_movement.enabled = false, nicio alerta nu trebuie generata.
        let detector = Detector::new(test_config()); // enabled: false

        for dest in &["10.0.0.10", "10.0.0.11", "10.0.0.12"] {
            let alerts = detector.process_event(&make_lateral_event("10.0.1.5", dest, 445));
            let lateral: Vec<_> = alerts
                .iter()
                .filter(|a| matches!(a.scan_type, ScanType::LateralMovement))
                .collect();
            assert!(
                lateral.is_empty(),
                "Lateral Movement dezactivat nu trebuie sa genereze alerte"
            );
        }
    }

    // =========================================================================
    // Teste Distributed Scan (#23)
    // =========================================================================

    /// Creeaza o configuratie cu Distributed Scan activat (prag 3 surse in 10s).
    /// Fast/Slow/Accept au praguri ridicate pentru a nu se declansa in teste.
    fn distributed_config() -> DetectionConfig {
        DetectionConfig {
            alert_cooldown_secs: 5,
            max_hits_per_ip: 1_000,
            max_tracked_ips: 10_000,
            whitelist: Vec::new(),
            fast_scan: FastScanConfig {
                port_threshold: 100,
                time_window_secs: 10,
            },
            slow_scan: SlowScanConfig {
                port_threshold: 200,
                time_window_mins: 1,
            },
            accept_scan: AcceptScanConfig {
                port_threshold: 100,
                time_window_secs: 10,
            },
            lateral_movement: LateralMovementConfig {
                enabled: false,
                unique_dest_threshold: 100,
                time_window_secs: 10,
            },
            distributed_scan: DistributedScanConfig {
                enabled: true,
                unique_sources_threshold: 3,
                time_window_secs: 10,
            },
            dynamic_threshold: DynamicThresholdConfig {
                enabled: false,
                ewma_alpha: 0.1,
                sensitivity_multiplier: 3.0,
                min_samples: 10,
                min_threshold_ratio: 0.5,
                max_threshold_ratio: 3.0,
            },
        }
    }

    /// Creeaza un eveniment drop cu sursa si destinatie explicite (pentru Distributed Scan).
    fn make_distributed_event(src_ip: &str, dest_ip: &str, port: u16) -> LogEvent {
        LogEvent {
            source_ip: src_ip.parse().unwrap(),
            dest_ip: Some(dest_ip.parse().unwrap()),
            dest_port: port,
            protocol: "tcp".to_string(),
            action: "drop".to_string(),
            raw_log: String::new(),
        }
    }

    #[test]
    fn test_distributed_scan_alert() {
        // 3 surse diferite → aceeasi tinta (10.0.0.100) = egal cu pragul -> alerta.
        let detector = Detector::new(distributed_config());

        let sources = ["10.0.1.1", "10.0.1.2", "10.0.1.3"];
        let target = "10.0.0.100";
        let mut last_alerts = vec![];
        for src in &sources {
            last_alerts = detector.process_event(&make_distributed_event(src, target, 80));
        }

        assert_eq!(last_alerts.len(), 1);
        assert!(
            matches!(last_alerts[0].scan_type, ScanType::DistributedScan),
            "Tipul alertei trebuie sa fie DistributedScan"
        );
        assert_eq!(
            last_alerts[0].unique_sources.len(),
            3,
            "Trebuie sa contina exact 3 surse unice"
        );
        assert_eq!(
            last_alerts[0].dest_ip,
            Some(target.parse().unwrap()),
            "dest_ip trebuie sa fie tinta scanarii"
        );
    }

    #[test]
    fn test_distributed_scan_below_threshold_no_alert() {
        // 2 surse < prag 3 -> fara alerta.
        let detector = Detector::new(distributed_config());

        for src in &["10.0.1.1", "10.0.1.2"] {
            let alerts = detector.process_event(&make_distributed_event(src, "10.0.0.100", 80));
            assert!(
                alerts.iter().all(|a| !matches!(a.scan_type, ScanType::DistributedScan)),
                "Nu trebuie alerta sub prag ({} surse)", src
            );
        }
    }

    #[test]
    fn test_distributed_scan_different_targets_independent() {
        // Surse diferite catre tinte DIFERITE nu se cumuleaza.
        let detector = Detector::new(distributed_config());

        // 2 surse → tinta A
        detector.process_event(&make_distributed_event("10.0.1.1", "10.0.0.100", 80));
        detector.process_event(&make_distributed_event("10.0.1.2", "10.0.0.100", 80));

        // 1 sursa → tinta B (diferita)
        let alerts = detector.process_event(&make_distributed_event("10.0.1.3", "10.0.0.200", 80));
        // Tinta A are 2 surse (sub prag), tinta B are 1 sursa (sub prag).
        let dist: Vec<_> = alerts.iter()
            .filter(|a| matches!(a.scan_type, ScanType::DistributedScan))
            .collect();
        assert!(
            dist.is_empty(),
            "Tinte diferite nu se cumuleaza — fara alerta"
        );
    }

    #[test]
    fn test_distributed_scan_cooldown() {
        // Dupa prima alerta, cooldown previne alerta repetata.
        let detector = Detector::new(distributed_config());

        // Prima alerta la a 3-a sursa.
        for src in &["10.0.1.1", "10.0.1.2", "10.0.1.3"] {
            detector.process_event(&make_distributed_event(src, "10.0.0.100", 80));
        }

        // A 4-a sursa — cooldown activ, nu trebuie alerta.
        let alerts = detector.process_event(&make_distributed_event("10.0.1.4", "10.0.0.100", 80));
        let dist: Vec<_> = alerts.iter()
            .filter(|a| matches!(a.scan_type, ScanType::DistributedScan))
            .collect();
        assert!(
            dist.is_empty(),
            "Cooldown trebuie sa previna alerta repetata Distributed Scan"
        );
    }

    #[test]
    fn test_distributed_scan_disabled_no_alert() {
        // Cand distributed_scan.enabled = false, nicio alerta nu trebuie generata.
        let detector = Detector::new(test_config()); // enabled: false

        for src in &["10.0.1.1", "10.0.1.2", "10.0.1.3"] {
            let alerts = detector.process_event(&make_distributed_event(src, "10.0.0.100", 80));
            let dist: Vec<_> = alerts.iter()
                .filter(|a| matches!(a.scan_type, ScanType::DistributedScan))
                .collect();
            assert!(
                dist.is_empty(),
                "Distributed Scan dezactivat nu trebuie sa genereze alerte"
            );
        }
    }

    #[test]
    fn test_distributed_scan_both_actions() {
        // Distributed Scan detecteaza atat drop cat si accept.
        let detector = Detector::new(distributed_config());

        // Sursa 1: drop
        detector.process_event(&make_distributed_event("10.0.1.1", "10.0.0.100", 80));
        // Sursa 2: accept
        detector.process_event(&LogEvent {
            source_ip: "10.0.1.2".parse().unwrap(),
            dest_ip: Some("10.0.0.100".parse().unwrap()),
            dest_port: 80,
            protocol: "tcp".to_string(),
            action: "accept".to_string(),
            raw_log: String::new(),
        });
        // Sursa 3: drop → ar trebui sa declanseze alerta
        let alerts = detector.process_event(&make_distributed_event("10.0.1.3", "10.0.0.100", 80));

        let dist: Vec<_> = alerts.iter()
            .filter(|a| matches!(a.scan_type, ScanType::DistributedScan))
            .collect();
        assert_eq!(
            dist.len(), 1,
            "Distributed Scan trebuie sa detecteze mix de drop si accept"
        );
    }

    #[test]
    fn test_distributed_scan_ports_collected() {
        // Verificam ca porturile vizate sunt colectate corect in alerta.
        let detector = Detector::new(distributed_config());

        detector.process_event(&make_distributed_event("10.0.1.1", "10.0.0.100", 22));
        detector.process_event(&make_distributed_event("10.0.1.2", "10.0.0.100", 80));
        let alerts = detector.process_event(&make_distributed_event("10.0.1.3", "10.0.0.100", 443));

        let dist: Vec<_> = alerts.iter()
            .filter(|a| matches!(a.scan_type, ScanType::DistributedScan))
            .collect();
        assert_eq!(dist.len(), 1);
        // Porturile vizate: 22, 80, 443.
        assert_eq!(dist[0].unique_ports.len(), 3);
        assert!(dist[0].unique_ports.contains(&22));
        assert!(dist[0].unique_ports.contains(&80));
        assert!(dist[0].unique_ports.contains(&443));
    }

    #[test]
    fn test_lateral_movement_drop_events_ignored() {
        // Evenimentele "drop" nu declanseaza Lateral Movement (doar "accept").
        let detector = Detector::new(lateral_config());

        for dest in &["10.0.0.10", "10.0.0.11", "10.0.0.12"] {
            // drop in loc de accept
            let alerts = detector.process_event(&LogEvent {
                source_ip: "10.0.1.5".parse().unwrap(),
                dest_ip: Some(dest.parse().unwrap()),
                dest_port: 445,
                protocol: "tcp".to_string(),
                action: "drop".to_string(),
                raw_log: String::new(),
            });
            let lateral: Vec<_> = alerts
                .iter()
                .filter(|a| matches!(a.scan_type, ScanType::LateralMovement))
                .collect();
            assert!(
                lateral.is_empty(),
                "Evenimentele drop nu trebuie sa declanseze Lateral Movement"
            );
        }
    }
}
