// =============================================================================
// config.rs - Modul de Configurare
// =============================================================================
//
// CONCEPTE RUST EXPLICATE:
//
// 1. DERIVE MACROS (#[derive(...)])
//    Rust nu genereaza automat implementari pentru trait-uri comune.
//    #[derive(Debug, Clone, Deserialize)] instruieste compilatorul sa genereze
//    automat implementari la compile-time:
//      - Debug:       permite printarea structurii cu {:?} (util la debugging)
//      - Clone:       permite duplicarea valorii cu .clone()
//      - Deserialize: permite serde sa populeze structura din TOML/JSON/etc.
//
// 2. OWNERSHIP (Proprietate)
//    Fiecare valoare in Rust are un singur "owner" (proprietar).
//    Cand owner-ul iese din scope, valoarea este dealocata automat (RAII).
//    De aceea folosim String (owned) in loc de &str (borrowed) in structuri:
//    structura trebuie sa detina datele, nu sa le imprumute temporar.
//
// 3. Vec<T> (Vector)
//    Vector este un array dinamic (heap-allocated). Vec<String> = lista de
//    String-uri care poate creste/scadea. Este owned - cand structura este
//    dropata, toate String-urile din Vec sunt la randul lor dealocate.
//
// =============================================================================

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Structura principala de configurare a aplicatiei.
///
/// Fiecare camp corespunde unei sectiuni din `config.toml`.
/// `Deserialize` permite parsarea automata din TOML in aceasta structura.
///
/// NOTA RUST: #[derive(Clone)] este necesar deoarece vom transmite
/// sub-structuri (ex: DetectionConfig) catre alte componente prin `.clone()`.
/// In Rust, copierea explicita (Clone) este preferata fata de copierea
/// implicita, pentru a face costul vizibil in cod.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub network: NetworkConfig,
    pub detection: DetectionConfig,
    pub alerting: AlertingConfig,
    pub cleanup: CleanupConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub parser: String,
    #[serde(default)]
    pub debug: bool,
}

/// Configurare detectie - contine sub-structuri pentru fiecare tip de scan.
///
/// NOTA RUST: Structurile imbricate (nested) se mapeaza pe sectiuni TOML
/// imbricate. `[detection.fast_scan]` in TOML -> campul `fast_scan` aici.
/// serde + toml fac aceasta mapare automat datorita derive(Deserialize).
#[derive(Debug, Clone, Deserialize)]
pub struct DetectionConfig {
    pub alert_cooldown_secs: u64,
    pub fast_scan: FastScanConfig,
    pub slow_scan: SlowScanConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FastScanConfig {
    /// Numar de porturi unice peste care se declanseaza alerta.
    pub port_threshold: usize,
    /// Fereastra de timp in secunde.
    pub time_window_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SlowScanConfig {
    pub port_threshold: usize,
    /// Fereastra de timp in minute (convertita in secunde la utilizare).
    pub time_window_mins: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertingConfig {
    pub siem: SiemConfig,
    pub email: EmailConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SiemConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
}

/// Configurare email.
///
/// NOTA RUST: `Vec<String>` permite lista dinamica de destinatari.
/// Fiecare String este owned (detinut) de Vec, care la randul lui
/// este owned de EmailConfig. Cand EmailConfig este dropat, tot
/// lantul de ownership este dealocat automat - zero memory leaks.
#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_tls: bool,
    pub from: String,
    pub to: Vec<String>,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CleanupConfig {
    pub interval_secs: u64,
    pub max_entry_age_secs: u64,
}

impl AppConfig {
    /// Incarca si parseaza fisierul de configurare TOML.
    ///
    /// CONCEPTE RUST:
    ///
    /// 1. GENERICS + TRAIT BOUNDS: `P: AsRef<Path>`
    ///    Aceasta functie accepta orice tip care poate fi convertit la un &Path:
    ///    String, &str, PathBuf, &Path - toate implementeaza AsRef<Path>.
    ///    Compilatorul genereaza (monomorphize) o versiune specializata pentru
    ///    fiecare tip concret folosit. Zero overhead la runtime.
    ///
    /// 2. OPERATORUL ? (Question Mark / Try)
    ///    `something()?` este echivalent cu:
    ///      match something() {
    ///          Ok(val) => val,
    ///          Err(e)  => return Err(e.into()),
    ///      }
    ///    Propaga erorile automat in sus pe call stack. Functioneaza doar
    ///    in functii care returneaza Result sau Option.
    ///
    /// 3. .with_context() / .context()
    ///    Metode din anyhow care adauga un mesaj descriptiv la eroare.
    ///    Utile pentru debugging - stii exact UNDE si DE CE a esuat operatia.
    ///
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        // `read_to_string` citeste intregul fisier intr-un String (owned).
        // Returneaza Result<String, io::Error>.
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Nu pot citi fisierul: {:?}", path.as_ref()))?;

        // `toml::from_str` deserializeaza continutul TOML in structura noastra.
        // Aceasta functioneaza datorita #[derive(Deserialize)] de pe AppConfig.
        // serde mapeaza automat cheile TOML pe campurile structurii.
        let config: AppConfig = toml::from_str(&content)
            .context("Eroare la parsarea fisierului TOML")?;

        Ok(config)
    }
}
