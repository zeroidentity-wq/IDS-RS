// =============================================================================
// detector/alert.rs - Tipurile publice ale alertelor
// =============================================================================
//
// `Alert` este serializat in spool-ul de pe disc, in API-ul web
// (/api/alerts) si folosit de alerter (CEF, email): forma lui nu se schimba
// fara a migra spool-ul si dashboard-ul.
//
// =============================================================================

use chrono::{DateTime, Local};
use std::net::IpAddr;

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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

    /// Beaconing C2 (#24) — trafic periodic catre un host C2 / staging pivot.
    ///
    /// Detecteaza un flow `(src_ip, dest_ip, dest_port)` cu intervale aproape
    /// constante intre conexiuni acceptate, indicator clasic de malware
    /// (Cobalt Strike, Meterpreter, custom beacons) care face callback periodic
    /// la un controller. Intr-o retea interna izolata, "controller-ul" e tot
    /// un host intern (pivot) — beaconing aici = compromis lateral confirmat.
    ///
    /// Algoritm: Coefficient of Variation (CV) pe intervalele inter-arrival;
    /// `cv = stddev(intervals) / mean(intervals)`. CV <= prag → beacon.
    ///
    /// SignatureID SIEM: 1006. Severitate: 9 (Critical).
    Beaconing,
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
            ScanType::Beaconing => write!(f, "Beaconing C2"),
        }
    }
}

/// Alerta generata cand se detecteaza o scanare.
///
/// NOTA RUST: Aceasta structura este OWNED - cand este creata, toate
/// datele sunt copiate/mutate in ea. Poate fi transmisa liber intre
/// functii si thread-uri fara grija ca datele originale se schimba.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Alert {
    pub scan_type: ScanType,
    /// IP-ul sursa al alertei.
    ///
    /// SEMANTICA DIFERA PE TIP DE SCAN:
    ///   - Fast / Slow / Accept / LateralMovement: atacatorul real (1 sursa → N).
    ///   - DistributedScan: doar ULTIMUL atacator care a declansat alerta — nu
    ///     toata lista. Atacatorii reali, semantic relevanti, se gasesc in
    ///     `unique_sources` (care include si acest `source_ip`).
    ///     Consumatorii (SIEM, web dashboard) trebuie sa folosesca
    ///     `unique_sources` pentru DistributedScan, nu doar `source_ip`.
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

    /// Pentru Beaconing C2: portul tinta al flow-ului. None pentru celelalte tipuri.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beacon_port: Option<u16>,
    /// Pentru Beaconing C2: intervalul mediu (secunde) intre conexiuni. None pentru celelalte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_interval_secs: Option<f64>,
    /// Pentru Beaconing C2: coeficientul de variatie (stddev / mean). None pentru celelalte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cv: Option<f64>,
    /// Pentru Beaconing C2: numarul de evenimente in fereastra. None pentru celelalte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_count: Option<usize>,
}

impl Alert {
    /// Alerta de baza pentru `scan_type`: listele goale si campurile
    /// Beaconing pe None. Fiecare detectie completeaza ce o priveste.
    pub(super) fn new(scan_type: ScanType, source_ip: IpAddr, dest_ip: Option<IpAddr>) -> Self {
        Self {
            scan_type,
            source_ip,
            dest_ip,
            unique_ports: Vec::new(),
            unique_dests: Vec::new(),
            unique_sources: Vec::new(),
            timestamp: Local::now(),
            beacon_port: None,
            mean_interval_secs: None,
            cv: None,
            event_count: None,
        }
    }
}
