// =============================================================================
// detector.rs - Motor de Detectie Scanari de Retea
// =============================================================================
//
// Acest modul implementeaza logica centrala a IDS-ului:
//   1. Inregistreaza evenimentele "drop" si "accept" (IP sursa + port destinatie)
//   2. Detecteaza Fast Scan:   > X porturi BLOCATE unice in Y secunde
//   3. Detecteaza Slow Scan:   > Z porturi BLOCATE unice in W minute
//   4. Detecteaza Accept Scan: > N porturi ACCEPTATE unice in M secunde
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
            accept_hits: DashMap::new(),
            fast_cooldowns: DashMap::new(),
            slow_cooldowns: DashMap::new(),
            accept_cooldowns: DashMap::new(),
            last_seen: DashMap::new(),
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
        if is_new_ip && self.last_seen.len() >= self.config.max_tracked_ips {
            // Gasim IP-ul cu cel mai vechi last_seen (Least Recently Used).
            let lru_ip: Option<IpAddr> = self
                .last_seen
                .iter()
                .min_by_key(|e| *e.value())
                .map(|e| *e.key());

            if let Some(old_ip) = lru_ip {
                // Eliminam IP-ul LRU din TOATE structurile (drop, accept, cooldowns).
                self.port_hits.remove(&old_ip);
                self.accept_hits.remove(&old_ip);
                self.last_seen.remove(&old_ip);
                self.fast_cooldowns.remove(&old_ip);
                self.slow_cooldowns.remove(&old_ip);
                self.accept_cooldowns.remove(&old_ip);
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
            let max_hits = self.config.max_hits_per_ip;
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
        let fast_window = Duration::from_secs(self.config.fast_scan.time_window_secs);
        if let Some(ports) = self.unique_ports_in_window(&self.port_hits, ip, fast_window, now) {
            if ports.len() > self.config.fast_scan.port_threshold
                && !self.in_cooldown(&self.fast_cooldowns, ip)
            {
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

        // --- 4. Verificam Slow Scan (pe port_hits — drop-uri) ---
        let slow_window = Duration::from_secs(self.config.slow_scan.time_window_mins * 60);
        if let Some(ports) = self.unique_ports_in_window(&self.port_hits, ip, slow_window, now) {
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
        let accept_window = Duration::from_secs(self.config.accept_scan.time_window_secs);
        if let Some(ports) = self.unique_ports_in_window(&self.accept_hits, ip, accept_window, now) {
            if ports.len() > self.config.accept_scan.port_threshold
                && !self.in_cooldown(&self.accept_cooldowns, ip)
            {
                self.accept_cooldowns.insert(ip, now);
                alerts.push(Alert {
                    scan_type: ScanType::AcceptScan,
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

        // --- Sincronizam last_seen ---
        //
        // Eliminam din last_seen IP-urile care nu mai au date in NICIUN map.
        // Un IP urmarit exclusiv pentru Accept Scan (fara drop-uri) trebuie
        // sters din last_seen cand accept_hits il curata (si invers).
        //
        // NOTA RUST: `.retain()` pe DashMap cu closure care acceseaza ALTE DashMap-uri.
        // Aceasta este sigura deoarece:
        //   - last_seen, port_hits, accept_hits sunt DashMap-uri SEPARATE
        //   - Fiecare are propriile sale shard-uri si lock-uri
        //   - Nu exista overlapping borrows sau deadlock potential
        //   - Garantat de Rust la compile-time prin tipurile Send + Sync ale DashMap
        self.last_seen.retain(|ip, _| {
            self.port_hits.contains_key(ip) || self.accept_hits.contains_key(ip)
        });

        // --- Curatam cooldown-urile expirate (toate trei tipuri) ---
        let cooldown_dur = Duration::from_secs(self.config.alert_cooldown_secs);
        self.fast_cooldowns
            .retain(|_, instant| now.saturating_duration_since(*instant) <= cooldown_dur);
        self.slow_cooldowns
            .retain(|_, instant| now.saturating_duration_since(*instant) <= cooldown_dur);
        self.accept_cooldowns
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
    use crate::config::{AcceptScanConfig, DetectionConfig, FastScanConfig, SlowScanConfig};

    /// Creeaza o configuratie de test cu praguri mici pentru teste rapide.
    fn test_config() -> DetectionConfig {
        DetectionConfig {
            alert_cooldown_secs: 5,
            max_hits_per_ip: 1_000,
            max_tracked_ips: 10_000,
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
        // 4 porturi ACCEPTATE unice cu prag = 3 → alerta la al 4-lea port.
        let detector = Detector::new(test_config());

        for port in 1..=4 {
            let alerts = detector.process_event(&make_accept_event("10.1.0.1", port));
            if port == 4 {
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
        }
    }

    #[test]
    fn test_slow_scan_alert() {
        // 4 porturi unice (drop) cu prag slow = 3 → alerta Slow Scan la al 4-lea port.
        let detector = Detector::new(slow_test_config());

        for port in 1..=4u16 {
            let alerts = detector.process_event(&make_event("192.168.1.1", port));
            if port == 4 {
                assert_eq!(alerts.len(), 1, "Trebuia o alerta Slow Scan la {} porturi", port);
                assert!(
                    matches!(alerts[0].scan_type, ScanType::Slow),
                    "Tipul alertei trebuie sa fie Slow, nu {:?}",
                    alerts[0].scan_type
                );
                assert_eq!(alerts[0].unique_ports.len(), 4);
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

        // Generam alerta initiala (4 porturi drop → prag 3 depasit).
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
        // 4 porturi drop → doar Slow Scan se declanseaza (Fast nu are prag depasit).
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
}
