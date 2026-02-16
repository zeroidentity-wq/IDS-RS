// =============================================================================
// parser/gaia.rs - Parser pentru Checkpoint Gaia (Format Raw / Brut)
// =============================================================================
//
// FORMAT LOG GAIA (exemplu real):
//   Sep 3 15:12:20 192.168.99.1 Checkpoint: drop 192.168.11.7 \
//     proto: tcp; service: 22; s_port: 1352
//
// Campuri extrase:
//   - Actiune: "drop" (doar drop-urile ne intereseaza)
//   - IP sursa: 192.168.11.7 (cel care scaneaza)
//   - Port destinatie: 22 (portul scanat / serviciul tinta)
//   - Protocol: tcp
//
// CONCEPTE RUST EXPLICATE:
//
// 1. `impl Trait for Struct` (Implementare Trait)
//    Aceasta este sintaxa prin care un struct concret "semneaza contractul"
//    definit de un trait. Compilatorul verifica ca TOATE metodele sunt
//    implementate cu semnaturile corecte.
//
// 2. REGEX (Compilare Lazy)
//    Regex-ul este compilat O SINGURA DATA la constructie (GaiaParser::new).
//    Regex compilat = automat finit deterministic (DFA) stocat in memorie.
//    Reutilizarea regex-ului compilat este esentiala pentru performanta -
//    compilarea este costisitoare, dar match-ul ulterior este rapid.
//
// =============================================================================

use super::{LogEvent, LogParser};
use regex::Regex;
use std::net::IpAddr;

/// Parser pentru log-uri Checkpoint Gaia in format brut (raw syslog).
///
/// NOTA RUST: Struct-ul detine (owns) regex-ul compilat.
/// Cand GaiaParser este dropat, regex-ul este dealocat automat.
/// Nu exista niciun risc de memory leak - RAII in actiune.
pub struct GaiaParser {
    /// Regex pre-compilat pentru extragerea campurilor din log Gaia.
    /// `Regex` este Send + Sync, deci GaiaParser mosteneste aceste
    /// proprietati automat - poate fi partajat intre thread-uri.
    pattern: Regex,
}

impl GaiaParser {
    /// Construieste un nou GaiaParser cu regex-ul pre-compilat.
    ///
    /// NOTA RUST: Returneaza `anyhow::Result<Self>` deoarece
    /// compilarea regex-ului poate teoretic esua (desi regex-ul
    /// nostru este valid - este o buna practica sa propagam eroarea).
    /// `Self` este un alias pentru tipul curent (GaiaParser).
    pub fn new() -> anyhow::Result<Self> {
        // Regex-ul captureaza:
        //   Grup 1: actiunea (drop/accept/reject)
        //   Grup 2: IP-ul sursa al scannerului
        //   Grup 3: protocolul (tcp/udp)
        //   Grup 4: portul destinatie (serviciul scanat)
        //
        // (?i) = case-insensitive flag
        // \s+  = unul sau mai multe spatii/tab-uri
        // \d{1,3} = 1-3 cifre (octet IP)
        // \w+  = caractere alfanumerice (word characters)
        let pattern = Regex::new(
            r"(?i)Checkpoint:\s+(\w+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+proto:\s*(\w+);\s*service:\s*(\d+)"
        )?;

        Ok(Self { pattern })
    }
}

/// Implementarea trait-ului LogParser pentru GaiaParser.
///
/// NOTA RUST: `impl Trait for Struct` - aceasta este "legatura" dintre
/// contractul abstract (LogParser) si implementarea concreta (GaiaParser).
/// Dupa aceasta implementare, GaiaParser poate fi folosit oriunde se
/// asteapta un `dyn LogParser` (polimorfism).
impl LogParser for GaiaParser {
    /// Parseaza o linie de log Gaia si extrage campurile relevante.
    ///
    /// NOTA RUST - OWNERSHIP si BORROWING in aceasta functie:
    ///
    /// `&self`     - imprumut imutabil al parser-ului (citim regex-ul)
    /// `line: &str`- imprumut imutabil al string-ului de parsat (slice)
    ///
    /// Nici parser-ul, nici linia nu sunt consumate. Pot fi refolosite
    /// dupa apel. Acesta este avantajul borrowing-ului: acces fara transfer
    /// de ownership.
    ///
    /// Returnam `Option<LogEvent>`:
    ///   - `Some(event)` daca linia este un log Gaia valid cu actiune "drop"
    ///   - `None` daca linia nu poate fi parsata sau actiunea nu este "drop"
    ///
    fn parse(&self, line: &str) -> Option<LogEvent> {
        // `.captures(line)` returneaza Option<Captures>
        // `?` pe Option propaga None-ul: daca nu e match, returnam None direct.
        //
        // NOTA RUST: Operatorul `?` functioneaza si pe Option, nu doar pe
        // Result. Pe Option: None -> return None. Pe Result: Err -> return Err.
        let caps = self.pattern.captures(line)?;

        // `.get(n)` returneaza Option<Match> - grupul capturat la indexul n.
        // `.as_str()` obtine &str din Match.
        // `.to_lowercase()` creeaza un String owned (alocare pe heap).
        let action = caps.get(1)?.as_str().to_lowercase();

        // Filtram: ne intereseaza DOAR actiunile "drop".
        // Drop = firewall-ul a blocat conexiunea = potential scan.
        if action != "drop" {
            return None;
        }

        // `.parse()` este o metoda generica: `str::parse::<T>()`.
        // Tipul tinta (IpAddr) este inferat din annotarea variabilei.
        // Returneaza Result - `.ok()` converteste Result in Option,
        // iar `?` propaga None-ul.
        let source_ip: IpAddr = caps.get(2)?.as_str().parse().ok()?;
        let protocol = caps.get(3)?.as_str().to_lowercase();
        let dest_port: u16 = caps.get(4)?.as_str().parse().ok()?;

        // Construim LogEvent-ul. `line.to_string()` creaza un String owned
        // din &str (copiaza datele pe heap). Necesar deoarece LogEvent
        // trebuie sa fie independent de buffer-ul original.
        Some(LogEvent {
            source_ip,
            dest_port,
            protocol,
            action,
            raw_log: line.to_string(),
        })
    }

    fn name(&self) -> &str {
        "Checkpoint Gaia (Raw)"
    }
}

// =============================================================================
// UNIT TESTS
// =============================================================================
// NOTA RUST: #[cfg(test)] compileaza acest modul DOAR cand rulam `cargo test`.
// Nu este inclus in build-ul final (release). Aceasta este o conventie Rust
// standard: testele unitare stau langa codul pe care il testeaza.
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_drop() {
        let parser = GaiaParser::new().unwrap();
        let log = "Sep 3 15:12:20 192.168.99.1 Checkpoint: drop 192.168.11.7 proto: tcp; service: 22; s_port: 1352";

        let event = parser.parse(log);
        // `.unwrap()` extrage valoarea din Some sau panics pe None.
        // In teste, panic = test esuat = comportament dorit.
        let event = event.unwrap();

        assert_eq!(event.source_ip.to_string(), "192.168.11.7");
        assert_eq!(event.dest_port, 22);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, "drop");
    }

    #[test]
    fn test_ignore_accept_action() {
        let parser = GaiaParser::new().unwrap();
        let log = "Sep 3 15:12:20 192.168.99.1 Checkpoint: accept 192.168.11.7 proto: tcp; service: 80; s_port: 5000";

        // Actiunea "accept" nu ne intereseaza - trebuie sa returneze None.
        assert!(parser.parse(log).is_none());
    }

    #[test]
    fn test_invalid_log_format() {
        let parser = GaiaParser::new().unwrap();
        let log = "some random text that is not a firewall log";

        assert!(parser.parse(log).is_none());
    }
}
