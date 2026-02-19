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
pub mod gaia;

use std::net::IpAddr;

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

    /// Actiunea firewall-ului (drop, reject, accept, etc.).
    pub action: String,

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
/// Rust nu are null - Option este mecanismul safe de a reprezenta
/// absenta unei valori.
pub trait LogParser: Send + Sync {
    /// Parseaza o linie de log si returneaza un LogEvent daca este relevanta.
    fn parse(&self, line: &str) -> Option<LogEvent>;

    /// Returneaza numele uman al parser-ului (pentru afisare).
    fn name(&self) -> &str;

    /// Returneaza un exemplu de format valid (pentru debug/diagnostic).
    fn expected_format(&self) -> &str;
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
pub fn create_parser(parser_type: &str) -> anyhow::Result<Box<dyn LogParser>> {
    // `match` este EXHAUSTIV in Rust - compilatorul verifica ca toate
    // cazurile posibile sunt acoperite. Wildcard `_` prinde tot restul.
    match parser_type {
        "gaia" => Ok(Box::new(gaia::GaiaParser::new()?)),
        "cef" => Ok(Box::new(cef::CefParser::new())),
        _ => anyhow::bail!("Parser necunoscut: '{}'. Optiuni valide: gaia, cef", parser_type),
    }
}
