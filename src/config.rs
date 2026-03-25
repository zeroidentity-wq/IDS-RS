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
// 4. VALIDARE POST-DESERIALIZARE
//    serde/toml verifica doar tipurile (u64, String, bool) si campurile
//    obligatorii. Nu stie nimic despre semantica valorilor. De aceea avem
//    AppConfig::validate() care verifica constrangerile logice dupa parsare:
//    valori zero invalide, consistenta intre ferestre de timp, campuri
//    obligatorii conditionale (email enabled -> smtp_server nenul etc.).
//    Toate erorile sunt colectate intr-un Vec<String> si raportate simultan,
//    pentru a nu forta utilizatorul sa reporneasca aplicatia de N ori.
//
// =============================================================================

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
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

    /// Rate limit UDP: pachete acceptate per secunda. 0 = dezactivat.
    /// Retrocompatibil: daca lipseste din config.toml, serde pune 0 (dezactivat).
    #[serde(default)]
    pub udp_rate_limit: u64,

    /// Capacitate burst token bucket. Permite varfuri scurte peste rata medie.
    /// Implicit: 10.000 pachete.
    #[serde(default = "default_udp_burst_size")]
    pub udp_burst_size: u64,

    /// Mapping static IP → hostname (ex: "10.0.1.10" = "srv-dc01").
    /// Folosit pentru afisare in alerte CLI, email si SIEM (shost=/dhost= in CEF).
    /// Reteaua fiind izolata, nu avem DNS extern — hostname-urile sunt configurate manual.
    #[serde(default)]
    pub hostnames: HashMap<String, String>,
}

fn default_udp_burst_size() -> u64 {
    10_000
}

/// Configurare detectie - contine sub-structuri pentru fiecare tip de scan.
///
/// NOTA RUST: Structurile imbricate (nested) se mapeaza pe sectiuni TOML
/// imbricate. `[detection.fast_scan]` in TOML -> campul `fast_scan` aici.
/// serde + toml fac aceasta mapare automat datorita derive(Deserialize).
///
/// NOTA RUST - SERDE DEFAULT VALUES:
/// `#[serde(default = "fn_name")]` permite campuri optionale in TOML:
///   - Daca lipseste din fisier, serde apeleaza functia specificata pentru valoare default
///   - Retrocompatibil: configuratii vechi fara campul nou continua sa functioneze
///   - Functiile de default trebuie sa returneze acelasi tip ca si campul
#[derive(Debug, Clone, Deserialize)]
pub struct DetectionConfig {
    pub alert_cooldown_secs: u64,

    /// Numarul maxim de PortHit-uri tinute in memorie per IP sursa.
    /// Previne cresterea nelimitata a Vec<PortHit> intre cleanup cycle-uri.
    /// Implicit: 10.000 intrari (~240 KB per IP in cel mai rau caz).
    #[serde(default = "default_max_hits_per_ip")]
    pub max_hits_per_ip: usize,

    /// Numarul maxim de IP-uri urmarite simultan in DashMap.
    /// Previne flood-ul de IP-uri spoofed care umplea memoria nelimitat.
    /// Cand limita este atinsa, IP-ul cel mai vechi (LRU) este eliminat.
    /// Implicit: 100.000 IP-uri.
    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,

    /// Lista de IP-uri si subrețele excluse din detecție.
    /// Accepta IP-uri individuale ("10.0.1.10") si CIDR ("10.0.2.0/24").
    /// IP-urile din whitelist nu genereaza alerte (trafic legitim cunoscut).
    #[serde(default)]
    pub whitelist: Vec<String>,

    pub fast_scan: FastScanConfig,
    pub slow_scan: SlowScanConfig,

    /// Configurare pentru detectia Accept Scan (scanare porturi deschise).
    /// Retrocompatibil: daca lipseste din config.toml, se aplica valorile implicite
    /// (port_threshold = 5, time_window_secs = 30).
    #[serde(default = "default_accept_scan")]
    pub accept_scan: AcceptScanConfig,

    /// Configurare pentru detectia Lateral Movement (#22).
    /// Retrocompatibil: daca lipseste din config.toml, se aplica valorile implicite.
    #[serde(default = "default_lateral_movement")]
    pub lateral_movement: LateralMovementConfig,
}

fn default_max_hits_per_ip() -> usize {
    10_000
}

fn default_max_tracked_ips() -> usize {
    100_000
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

/// Configurare detectie Accept Scan (scanare porturi DESCHISE).
///
/// Accept Scan = un host acceseaza sistematic porturi permise de firewall.
/// Diferenta fata de Fast/Slow Scan (care urmaresc "drop"-uri):
///   - Fast/Slow → atacatorul loveste porturi INCHISE/filtrate (conexiuni blocate)
///   - AcceptScan → atacatorul loveste porturi DESCHISE (conexiuni permise)
///
/// Accept Scan este mai subtil: traficul generat arata "legitim" — conexiunile
/// sunt permise de regulile de firewall. Fara detectia acestui pattern, un
/// atacator care mapeaza sistematic serviciile active ar trece neobservat.
///
/// Pragurile implicite sunt mai conservative decat Fast Scan deoarece
/// traficul accepted este mai "normal" si am vrea sa evitam false positives.
#[derive(Debug, Clone, Deserialize)]
pub struct AcceptScanConfig {
    /// Numarul de porturi ACCEPTATE unice care declanseaza alerta.
    pub port_threshold: usize,
    /// Fereastra de timp in secunde in care se numara porturile unice.
    pub time_window_secs: u64,
}

fn default_accept_scan() -> AcceptScanConfig {
    AcceptScanConfig {
        port_threshold: 5,
        time_window_secs: 30,
    }
}

/// Configurare detectie Lateral Movement — miscare laterala in retea.
///
/// Lateral Movement = un IP intern contacteaza N destinatii diferite pe
/// conexiuni acceptate (orice port). Pattern tipic de propagare in retea
/// compromisa — un host compromis incearca sa se conecteze la cat mai
/// multe masini din retea.
///
/// Diferenta fata de Fast/Slow/Accept Scan:
///   - Scan-urile numara PORTURI UNICE catre aceeasi tinta
///   - Lateral Movement numara DESTINATII UNICE (orice port)
///
/// Fara filtru de port: detectia e bazata pe comportament, nu pe
/// asumptii despre ce porturi foloseste atacatorul. Daca exista servicii
/// legitime cu fan-out mare (backup, monitoring), adauga-le in whitelist.
///
/// Valori implicite: 5 destinatii in 60 secunde, dezactivat implicit
/// pentru retrocompatibilitate (config-uri vechi nu au sectiunea).
#[derive(Debug, Clone, Deserialize)]
pub struct LateralMovementConfig {
    /// Activare/dezactivare detectie. Implicit: false (retrocompatibil).
    #[serde(default)]
    pub enabled: bool,

    /// Numarul de destinatii unice care declanseaza alerta.
    #[serde(default = "default_lateral_dest_threshold")]
    pub unique_dest_threshold: usize,

    /// Fereastra de timp in secunde in care se numara destinatiile.
    #[serde(default = "default_lateral_time_window")]
    pub time_window_secs: u64,
}

fn default_lateral_dest_threshold() -> usize { 5 }
fn default_lateral_time_window() -> u64 { 60 }

fn default_lateral_movement() -> LateralMovementConfig {
    LateralMovementConfig {
        enabled: false,
        unique_dest_threshold: default_lateral_dest_threshold(),
        time_window_secs: default_lateral_time_window(),
    }
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

    /// Footer personalizabil pentru email-urile de alerta.
    /// Poate contine banner ASCII al echipei, disclaimer, etc.
    /// Afisat intre separatoarele ========== din footer-ul email-ului.
    #[serde(default = "default_email_footer")]
    pub email_footer: String,
}

fn default_email_footer() -> String {
    "\
   ____  ____  ____  ____       _       ____\n\
  / ___|| ___|| __ )|___ \\     / \\     |  _ \\\n\
  \\___ \\|___ \\|  _ \\  __) |   / _ \\    | | | |\n\
   ___) |___) | |_) |/ __/   / ___ \\ _ | |_| |\n\
  |____/|____/|____/|_____| /_/   \\_(_)|____/\n\
\n\
  Generat automat de S5B2 A.D. | Nu raspundeti la acest email"
        .to_string()
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

        // Validare semantica post-deserializare.
        // serde verifica doar tipurile; validate() verifica logica si valorile.
        config.validate()?;

        Ok(config)
    }

    /// Valideaza constrangerile semantice ale configuratiei.
    ///
    /// NOTA RUST: Colectam TOATE erorile intr-un Vec<String> inainte de a esua,
    /// astfel utilizatorul vede dintr-o singura rulare tot ce trebuie corectat,
    /// fara sa reporneasca aplicatia de N ori pentru fiecare eroare in parte.
    ///
    /// `anyhow::bail!` este echivalent cu `return Err(anyhow::anyhow!(...))`.
    /// Macro-ul bail! accepta acelasi format ca println!, cu {} interpolation.
    fn validate(&self) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        // --- Network ---

        if self.network.listen_port == 0 {
            errors.push(
                "network.listen_port = 0: portul 0 lasa OS-ul sa aleaga aleatoriu la fiecare pornire"
                    .to_string(),
            );
        }
        if self.network.listen_address.is_empty() {
            errors.push("network.listen_address nu poate fi gol".to_string());
        }
        if !matches!(self.network.parser.as_str(), "gaia" | "cef" | "gaia_cef") {
            errors.push(format!(
                "network.parser = {:?} este invalid. Valori acceptate: \"gaia\", \"cef\", \"gaia_cef\"",
                self.network.parser
            ));
        }
        // Validare hostnames: cheile trebuie sa fie IP-uri valide.
        for (ip_str, _hostname) in &self.network.hostnames {
            if ip_str.parse::<std::net::IpAddr>().is_err() {
                errors.push(format!(
                    "network.hostnames: cheia \"{}\" nu este un IP valid", ip_str
                ));
            }
        }

        if self.network.udp_rate_limit > 0 && self.network.udp_burst_size == 0 {
            errors.push(
                "network.udp_burst_size = 0 cand udp_rate_limit > 0: burst_size trebuie sa fie cel putin 1"
                    .to_string(),
            );
        }
        if self.network.udp_rate_limit > 0
            && self.network.udp_burst_size > 0
            && self.network.udp_burst_size < self.network.udp_rate_limit
        {
            errors.push(format!(
                "network.udp_burst_size ({}) < udp_rate_limit ({}): burst mai mic decat rata \
                 medie — se pierd pachete la orice varf scurt de trafic",
                self.network.udp_burst_size, self.network.udp_rate_limit
            ));
        }

        // --- Detection ---

        // Validare whitelist: fiecare intrare trebuie sa fie IP valid sau CIDR valid.
        for entry in &self.detection.whitelist {
            if entry.contains('/') {
                // CIDR: verificam IP-ul si prefixul
                let parts: Vec<&str> = entry.splitn(2, '/').collect();
                if parts.len() != 2 {
                    errors.push(format!(
                        "detection.whitelist: intrare CIDR invalida: \"{}\"", entry
                    ));
                    continue;
                }
                let ip_valid = parts[0].parse::<std::net::IpAddr>().is_ok();
                let prefix_valid = parts[1].parse::<u8>().map(|p| {
                    if parts[0].contains(':') { p <= 128 } else { p <= 32 }
                }).unwrap_or(false);
                if !ip_valid || !prefix_valid {
                    errors.push(format!(
                        "detection.whitelist: intrare CIDR invalida: \"{}\"", entry
                    ));
                }
            } else {
                // IP individual
                if entry.parse::<std::net::IpAddr>().is_err() {
                    errors.push(format!(
                        "detection.whitelist: IP invalid: \"{}\"", entry
                    ));
                }
            }
        }

        if self.detection.alert_cooldown_secs == 0 {
            errors.push(
                "detection.alert_cooldown_secs = 0: fara cooldown, acelasi IP va genera alerte la fiecare eveniment"
                    .to_string(),
            );
        }
        if self.detection.max_hits_per_ip == 0 {
            errors.push(
                "detection.max_hits_per_ip = 0: nicio inregistrare nu poate fi stocata per IP, detectia devine imposibila"
                    .to_string(),
            );
        }
        if self.detection.max_tracked_ips == 0 {
            errors.push(
                "detection.max_tracked_ips = 0: niciun IP nu poate fi urmarit, detectia devine imposibila"
                    .to_string(),
            );
        }
        if self.detection.fast_scan.port_threshold == 0 {
            errors.push(
                "detection.fast_scan.port_threshold = 0: orice pachet va declansa alerta Fast Scan"
                    .to_string(),
            );
        }
        if self.detection.fast_scan.time_window_secs == 0 {
            errors.push(
                "detection.fast_scan.time_window_secs = 0: fereastra de timp zero face detectia imposibila"
                    .to_string(),
            );
        }
        if self.detection.slow_scan.port_threshold == 0 {
            errors.push(
                "detection.slow_scan.port_threshold = 0: orice pachet va declansa alerta Slow Scan"
                    .to_string(),
            );
        }
        if self.detection.slow_scan.time_window_mins == 0 {
            errors.push(
                "detection.slow_scan.time_window_mins = 0: fereastra de timp zero face detectia imposibila"
                    .to_string(),
            );
        }
        if self.detection.accept_scan.port_threshold == 0 {
            errors.push(
                "detection.accept_scan.port_threshold = 0: orice pachet accept va declansa alerta Accept Scan"
                    .to_string(),
            );
        }
        if self.detection.accept_scan.time_window_secs == 0 {
            errors.push(
                "detection.accept_scan.time_window_secs = 0: fereastra de timp zero face detectia Accept Scan imposibila"
                    .to_string(),
            );
        }

        // Validare Lateral Movement (doar daca e activat).
        if self.detection.lateral_movement.enabled {
            if self.detection.lateral_movement.unique_dest_threshold == 0 {
                errors.push(
                    "detection.lateral_movement.unique_dest_threshold = 0: orice conexiune va declansa alerta"
                        .to_string(),
                );
            }
            if self.detection.lateral_movement.time_window_secs == 0 {
                errors.push(
                    "detection.lateral_movement.time_window_secs = 0: fereastra de timp zero face detectia imposibila"
                        .to_string(),
                );
            }
        }

        // Consistenta logica: fereastra Slow Scan trebuie sa fie mai mare decat Fast Scan.
        // Altfel cele doua detectii se suprapun si Slow Scan nu are sens.
        let fast_secs = self.detection.fast_scan.time_window_secs;
        let slow_secs = self.detection.slow_scan.time_window_mins * 60;
        if fast_secs > 0 && slow_secs > 0 && slow_secs <= fast_secs {
            errors.push(format!(
                "detection.slow_scan.time_window_mins ({} min = {}s) trebuie sa fie \
                 mai mare decat detection.fast_scan.time_window_secs ({}s)",
                self.detection.slow_scan.time_window_mins, slow_secs, fast_secs
            ));
        }

        // --- Cleanup ---

        if self.cleanup.interval_secs == 0 {
            errors.push(
                "cleanup.interval_secs = 0: cleanup continuu va bloca procesarea evenimentelor"
                    .to_string(),
            );
        }
        if self.cleanup.max_entry_age_secs == 0 {
            errors.push(
                "cleanup.max_entry_age_secs = 0: toate datele sunt sterse la fiecare cleanup, \
                 detectia devine imposibila"
                    .to_string(),
            );
        }

        // max_entry_age trebuie sa acopere cel putin fereastra Slow Scan,
        // altfel datele necesare detectiei sunt sterse inainte de a fi evaluate.
        if self.cleanup.max_entry_age_secs > 0
            && slow_secs > 0
            && self.cleanup.max_entry_age_secs < slow_secs
        {
            errors.push(format!(
                "cleanup.max_entry_age_secs ({}) este mai mic decat fereastra Slow Scan \
                 ({} min = {}s): datele necesare detectiei Slow Scan vor fi sterse prematur",
                self.cleanup.max_entry_age_secs,
                self.detection.slow_scan.time_window_mins,
                slow_secs
            ));
        }

        // --- Alerting: SIEM ---

        if self.alerting.siem.enabled {
            if self.alerting.siem.port == 0 {
                errors.push("alerting.siem.port = 0 este invalid".to_string());
            }
            if self.alerting.siem.host.is_empty() {
                errors.push("alerting.siem.host nu poate fi gol cand SIEM este activat".to_string());
            }
        }

        // --- Alerting: Email ---

        if self.alerting.email.enabled {
            if self.alerting.email.smtp_port == 0 {
                errors.push("alerting.email.smtp_port = 0 este invalid".to_string());
            }
            if self.alerting.email.smtp_server.is_empty() {
                errors.push(
                    "alerting.email.smtp_server nu poate fi gol cand email este activat"
                        .to_string(),
                );
            }
            if self.alerting.email.from.is_empty() {
                errors.push(
                    "alerting.email.from nu poate fi gol cand email este activat".to_string(),
                );
            }
            if self.alerting.email.to.is_empty() {
                errors.push(
                    "alerting.email.to nu poate fi goala: adauga cel putin un destinatar"
                        .to_string(),
                );
            }
        }

        // Raportam toate erorile dintr-o singura data.
        if errors.is_empty() {
            Ok(())
        } else {
            let listing = errors
                .iter()
                .enumerate()
                .map(|(i, e)| format!("  {}. {}", i + 1, e))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!(
                "config.toml contine {} erori de configurare:\n{}",
                errors.len(),
                listing
            );
        }
    }
}
