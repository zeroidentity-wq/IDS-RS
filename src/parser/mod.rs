// =============================================================================
// parser/mod.rs - Modul de Parsing: Trait-uri si Factory
// =============================================================================
//
// CONCEPTE RUST EXPLICATE:
//
// 1. TRAITS (Trasaturi)
//    Un trait defineste un CONTRACT - un set de metode pe care un tip trebuie
//    sa le implementeze. Este similar cu interfaces din Java/C# sau abstract
//    classes din C++, dar mai puternic (pot avea default implementations,
//    associated types, const generics).
//
//    trait LogParser {
//        fn parse(&self, line: &str) -> Option<LogEvent>;
//    }
//
//    Orice struct care face `impl LogParser for MyStruct` TREBUIE sa
//    implementeze TOATE metodele fara default din trait.
//
// 2. TRAIT OBJECTS si DYNAMIC DISPATCH (Box<dyn Trait>)
//    `Box<dyn LogParser>` este un "trait object" - un pointer catre o
//    valoare alocata pe heap care implementeaza LogParser.
//    "dyn" = dynamic dispatch: metoda concreta este rezolvata la RUNTIME
//    printr-o vtable (tabel de pointeri la functii), nu la compile-time.
//
//    Alternativa: generics cu trait bounds (static dispatch) - mai rapid
//    dar nu permite selectia tipului la runtime din config.
//    Noi avem nevoie de selectie la runtime (config.parser = "gaia"/"cef"),
//    deci dynamic dispatch este solutia corecta.
//
// 3. SEND + SYNC (Thread Safety Markers)
//    - Send: tipul poate fi TRANSFERAT intre thread-uri (ownership transfer)
//    - Sync: tipul poate fi ACCESAT CONCURENT din mai multe thread-uri (&T)
//
//    `trait LogParser: Send + Sync` cere ca orice implementare sa fie
//    thread-safe. Aceasta este necesar deoarece parser-ul va fi folosit
//    din runtime-ul async tokio, care poate muta task-uri intre thread-uri.
//
// 4. MODULES (Moduli)
//    `pub mod gaia;` declara un sub-modul si ii spune compilatorului sa
//    caute codul in `parser/gaia.rs`. `pub` il face vizibil din exterior.
//
// =============================================================================

pub mod cef;
pub mod custom;
pub mod gaia;
pub mod gaia_cef;

use crate::config::AppConfig;
use std::net::IpAddr;

/// Split the eight CEF fields while respecting escaped header delimiters
/// (`\|`). `str::splitn('|')` corrupts valid CEF headers containing a pipe.
pub(crate) fn split_cef_fields(input: &str) -> Option<Vec<&str>> {
    let fields = split_cef_fields_lenient(input);
    (fields.len() == 8).then_some(fields)
}

/// Like [`split_cef_fields`], but returns however many fields (up to eight)
/// the line has. Used where truncated CEF records still carry useful data,
/// e.g. a Gaia LEA blob in the Name field with severity/extensions missing.
pub(crate) fn split_cef_fields_lenient(input: &str) -> Vec<&str> {
    let mut fields = Vec::with_capacity(8);
    let mut start = 0;
    let mut escaped = false;
    for (index, character) in input.char_indices() {
        if character == '|' && !escaped && fields.len() < 7 {
            fields.push(&input[start..index]);
            start = index + character.len_utf8();
        }
        if character == '\\' {
            escaped = !escaped;
        } else {
            escaped = false;
        }
    }
    fields.push(&input[start..]);
    fields
}

/// Actiunea firewall-ului, singurele doua valori pe care detectorul le foloseste.
///
/// NOTA RUST: un enum in loc de String face imposibila o valoare neasteptata
/// (ex: "deny", "Drop ") dupa parser - compilatorul obliga fiecare `match`
/// sa trateze exact aceste doua cazuri. Normalizarea se face o singura data,
/// la granita parser-ului.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Conexiune BLOCATA de firewall → Fast/Slow Scan.
    Drop,
    /// Conexiune PERMISA de firewall → Accept Scan, Lateral, Distributed, Beaconing.
    Accept,
}

impl Action {
    /// Normalizeaza actiunea Check Point / CEF ("Drop", "ACCEPT", ...).
    /// Orice alta actiune ("reject", "log", ...) este ignorata → None.
    pub fn from_firewall(raw: &str) -> Option<Self> {
        if raw.eq_ignore_ascii_case("drop") {
            Some(Action::Drop)
        } else if raw.eq_ignore_ascii_case("accept") {
            Some(Action::Accept)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Drop => "drop",
            Action::Accept => "accept",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `pad` respecta latimea si alinierea ceruta (ex: `{:<6}` in rapoarte).
        f.pad(self.as_str())
    }
}

/// Eveniment de log parsabil - structura comuna pentru toate formatele.
///
/// NOTA RUST: #[derive(Debug, Clone)]
/// - Debug permite `println!("{:?}", event)` pentru inspectie rapida
/// - Clone permite duplicarea evenimentului cand este nevoie (ex: logging)
///
/// Toate campurile sunt OWNED (String, nu &str) deoarece LogEvent trebuie
/// sa traiasca independent de buffer-ul din care a fost parsat. Daca am
/// folosi &str, ar trebui lifetime annotations si event-ul ar fi legat
/// de buffer - complicat si restrictiv.
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// Adresa IP sursa a atacatorului / scannerului.
    /// IpAddr este un enum: poate fi V4(Ipv4Addr) sau V6(Ipv6Addr).
    pub source_ip: IpAddr,

    /// Adresa IP destinatie (tinta atacului). Option<> deoarece
    /// unele log-uri (ex: broadcast, ICMP malformat) nu au dst valid.
    pub dest_ip: Option<IpAddr>,

    /// Portul destinatie care a fost scanat / accesat.
    pub dest_port: u16,

    /// Protocolul (tcp, udp, icmp, etc.).
    pub protocol: String,

    /// Actiunea firewall-ului, normalizata de parser.
    pub action: Action,

    /// Log-ul original brut - pastrat pentru audit/debugging.
    pub raw_log: String,
}

/// Trait-ul central de parsing - contractul pe care orice parser trebuie
/// sa il respecte.
///
/// NOTA RUST: `&self` = borrowed reference (imprumut imutabil).
/// Parser-ul nu este consumat sau modificat cand parseaza - doar citeste
/// propriile date (ex: regex-ul compilat). Acesta este principiul
/// "borrowing" din Rust: poti avea NELIMITATE referinte imutabile (&T)
/// SAU exact UNA mutabila (&mut T), niciodata ambele simultan.
///
/// `Option<LogEvent>` = tipul returnat. Option este un enum:
///   - Some(event) = parsare reusita
///   - None        = linia nu a putut fi parsata sau nu ne intereseaza
///     Rust nu are null - Option este mecanismul safe de a reprezenta
///     absenta unei valori.
pub trait LogParser: Send + Sync {
    /// Parseaza o linie de log si returneaza un LogEvent daca este relevanta.
    fn parse(&self, line: &str) -> Option<LogEvent>;

    /// Returneaza numele uman al parser-ului (pentru afisare).
    fn name(&self) -> &str;

    /// Returneaza un exemplu de format valid (pentru debug/diagnostic).
    fn expected_format(&self) -> &str;

    /// Evenimente ignorate de la ultimul apel deoarece actiunea nu a putut fi
    /// mapata pe drop/accept, plus un exemplu de valoare. Raportate periodic
    /// ca o mapare incompleta sa nu piarda evenimente fara urma.
    fn take_unmapped_actions(&self) -> Option<(u64, String)> {
        None
    }
}

/// Mapeaza numere de protocol IANA la nume standard (6 → tcp, 17 → udp,
/// 1 → icmp); orice alt nume este doar convertit la lowercase.
pub(crate) fn normalize_protocol(proto: &str) -> String {
    match proto {
        "6" => "tcp".to_string(),
        "17" => "udp".to_string(),
        "1" => "icmp".to_string(),
        other => other.to_lowercase(),
    }
}

/// Factory function - creeaza parser-ul potrivit pe baza configurarii.
///
/// NOTA RUST: Returneaza `Result<Box<dyn LogParser>>`:
/// - Result: operatia poate esua (parser necunoscut)
/// - Box: aloca parser-ul pe heap (necesar pentru trait objects deoarece
///   compilatorul nu stie la compile-time dimensiunea tipului concret)
/// - dyn LogParser: oricare implementare a trait-ului LogParser
///
/// Aceasta functie exemplifica POLIMORFISMUL in Rust:
/// La compile-time nu stim ce tip concret vom returna (GaiaParser sau
/// CefParser). Box<dyn LogParser> rezolva metoda corecta la runtime.
pub fn create_parser(config: &AppConfig) -> anyhow::Result<Box<dyn LogParser>> {
    let parser_type = config.network.parser.as_str();
    // `match` este EXHAUSTIV in Rust - compilatorul verifica ca toate
    // cazurile posibile sunt acoperite. Wildcard `_` prinde tot restul.
    match parser_type {
        "gaia" => Ok(Box::new(gaia::GaiaParser::new()?)),
        "cef" => Ok(Box::new(cef::CefParser::new())),
        "gaia_cef" => Ok(Box::new(gaia_cef::GaiaCefParser::new())),
        "custom" => {
            let custom = config.custom_parser.as_ref().ok_or_else(|| {
                anyhow::anyhow!("parser = \"custom\" cere sectiunea [custom_parser]")
            })?;
            Ok(Box::new(custom::CustomParser::new(custom)))
        }
        _ => anyhow::bail!(
            "Parser necunoscut: '{}'. Optiuni valide: gaia, cef, gaia_cef, custom",
            parser_type
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::Action;

    #[test]
    fn firewall_actions_are_normalized_case_insensitively() {
        assert_eq!(Action::from_firewall("Drop"), Some(Action::Drop));
        assert_eq!(Action::from_firewall("ACCEPT"), Some(Action::Accept));
        assert_eq!(Action::from_firewall("reject"), None);
        assert_eq!(Action::from_firewall("Log"), None);
        assert_eq!(Action::from_firewall(""), None);
    }

    #[test]
    fn display_respects_width() {
        assert_eq!(format!("[{:<6}]", Action::Drop), "[drop  ]");
    }
}
