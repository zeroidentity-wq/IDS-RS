// =============================================================================
// parser/cef.rs - Parser pentru Common Event Format (CEF / ArcSight)
// =============================================================================
//
// FORMAT CEF (exemplu):
//   CEF:0|CheckPoint|VPN-1 & FireWall-1|R81|drop|Drop|5|src=192.168.11.7 \
//     dst=10.0.0.1 dpt=443 proto=TCP act=Drop
//
// Structura CEF:
//   CEF:Versiune|Vendor|Produs|Versiune Produs|Signature ID|Nume|Severity|Extensii
//
// Extensiile sunt perechi cheie=valoare separate prin spatiu:
//   src  = IP sursa
//   dst  = IP destinatie
//   dpt  = port destinatie
//   proto= protocol
//   act  = actiune
//
// NOTA: Acesta este un SCHELET functional. Parseaza formatul CEF de baza,
// dar va trebui adaptat cand integrarea ArcSight reala va fi disponibila.
// Campurile specifice pot varia in functie de configurarea ArcSight.
//
// =============================================================================

use super::{LogEvent, LogParser};
use std::net::IpAddr;

/// Parser pentru log-uri in format CEF (Common Event Format).
///
/// NOTA RUST - UNIT STRUCTS:
/// `CefParser` nu are campuri (similar cu un "marker type").
/// In Rust, un struct fara campuri ocupa 0 bytes in memorie (ZST = Zero
/// Sized Type). Compilatorul il optimizeaza complet - exista doar la
/// nivel de tip, nu la runtime.
pub struct CefParser;

impl CefParser {
    pub fn new() -> Self {
        // Constructorul pentru un unit struct este trivial.
        Self
    }
}

impl LogParser for CefParser {
    /// Parseaza o linie CEF si extrage campurile relevante.
    ///
    /// NOTA RUST - ITERATORS si COLECTARE:
    /// Aceasta functie demonstreaza pattern-ul iterator in Rust:
    ///   string.splitn(n, delim)  -> creeaza un iterator lazy
    ///   .collect::<Vec<&str>>()  -> consuma iteratorul si aduna in Vec
    ///
    /// Iteratorii in Rust sunt "zero-cost abstractions": compilatorul
    /// ii optimizeaza la acelasi cod masina ca un loop manual.
    /// Sunt lazy - nu fac nimic pana nu sunt consumati (collect, for, etc).
    ///
    fn parse(&self, line: &str) -> Option<LogEvent> {
        // Gasim offset-ul "CEF:" in linie. Log-urile reale vin adesea cu un
        // prefix syslog (ex: "Feb 17 11:32:44 gw-hostname CEF:0|..."),
        // deci nu putem folosi starts_with.
        let cef_start = line.find("CEF:")?;

        // Separam headerul CEF in maxim 8 parti (7 delimitatori '|').
        // `splitn(8, '|')` produce maxim 8 segmente.
        //
        // NOTA RUST: `collect::<Vec<&str>>()` - turbofish syntax `::<T>`
        // specifica explicit tipul in care colectam. Necesar cand compilatorul
        // nu poate infera tipul (collect este generic si poate produce
        // Vec, String, HashMap, etc).
        let parts: Vec<&str> = line[cef_start..].splitn(8, '|').collect();

        // Validam ca avem toate cele 8 campuri CEF.
        if parts.len() < 8 {
            return None;
        }

        // Extensiile sunt in ultimul camp (index 7), ca perechi cheie=valoare.
        let extension = parts[7];

        // Declaram variabilele ca Option<T> - le vom popula din extensii.
        //
        // NOTA RUST: `let mut` declara o variabila MUTABILA.
        // In Rust, variabilele sunt IMUTABILE by default. Trebuie sa
        // specifici explicit `mut` daca vrei sa le modifici.
        // Aceasta este o decizie de design: previne modificari accidentale
        // si face codul mai usor de rationat (mai putine stari posibile).
        let mut source_ip: Option<IpAddr> = None;
        let mut dest_ip: Option<IpAddr> = None;
        let mut dest_port: Option<u16> = None;
        let mut protocol = String::from("tcp");
        let mut action = String::new();

        // Parcurgem perechile cheie=valoare din extensii.
        //
        // NOTA RUST - PATTERN MATCHING cu `match`:
        // `match` in Rust este EXHAUSTIV - compilatorul verifica ca
        // toate cazurile posibile sunt tratate. `_` este wildcard-ul
        // care prinde tot ce nu a fost tratat explicit.
        //
        // Match pe &str compara string-uri la nivel de continut (nu pointeri).
        for token in extension.split_whitespace() {
            // `splitn(2, '=')` imparte in maxim 2 parti la primul '='.
            let kv: Vec<&str> = token.splitn(2, '=').collect();
            if kv.len() == 2 {
                match kv[0] {
                    "src" => source_ip = kv[1].parse().ok(),
                    "dst" => dest_ip = kv[1].parse().ok(),
                    "dpt" => dest_port = kv[1].parse().ok(),
                    "proto" => protocol = kv[1].to_lowercase(),
                    "act" => action = kv[1].to_lowercase(),
                    // Ignoram cheile necunoscute (extensibil pe viitor).
                    _ => {}
                }
            }
        }

        // Extragem valorile din Option-uri cu `?`.
        // Daca oricare este None, intreaga functie returneaza None.
        let source_ip = source_ip?;
        let dest_port = dest_port?;

        // Filtram doar actiunile "drop" (similar cu parser-ul Gaia).
        if action != "drop" {
            return None;
        }

        Some(LogEvent {
            source_ip,
            dest_ip,
            dest_port,
            protocol,
            action,
            raw_log: line.to_string(),
        })
    }

    fn name(&self) -> &str {
        "CEF (ArcSight)"
    }

    fn expected_format(&self) -> &str {
        "<PRI>Mon DD HH:MM:SS hostname CEF:0|Vendor|Product|Version|ID|Name|Severity|src=IP dst=IP dpt=PORT proto=PROTO act=ACTION"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_cef_drop() {
        let parser = CefParser::new();
        let log = "CEF:0|CheckPoint|VPN-1|R81|100|Drop|5|src=192.168.11.7 dst=10.0.0.1 dpt=443 proto=TCP act=drop";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "192.168.11.7");
        assert_eq!(event.dest_port, 443);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, "drop");
    }

    #[test]
    fn test_ignore_cef_accept() {
        let parser = CefParser::new();
        let log = "CEF:0|CheckPoint|VPN-1|R81|100|Accept|3|src=10.0.0.5 dst=10.0.0.1 dpt=80 proto=TCP act=accept";

        assert!(parser.parse(log).is_none());
    }

    #[test]
    fn test_parse_cef_with_syslog_header() {
        let parser = CefParser::new();
        let log = "Feb 17 11:32:44 gw-hostname CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|Drop|5|src=11.11.11.11 dst=22.22.22.22 spt=444 dpt=444 proto=udp act=Drop";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "11.11.11.11");
        assert_eq!(event.dest_port, 444);
        assert_eq!(event.protocol, "udp");
        assert_eq!(event.action, "drop");
    }

    #[test]
    fn test_parse_cef_with_syslog_priority_header() {
        let parser = CefParser::new();
        let log = "<134>Feb 17 11:32:44 gw-hostname CEF:0|CheckPoint|VPN-1 & FireWall-1|R81.20|100|Drop|5|src=10.0.0.5 dst=10.0.0.1 dpt=8080 proto=TCP act=Drop";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "10.0.0.5");
        assert_eq!(event.dest_port, 8080);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, "drop");
    }

    #[test]
    fn test_reject_non_cef() {
        let parser = CefParser::new();
        assert!(parser.parse("not a CEF log").is_none());
    }

    #[test]
    fn test_incomplete_cef_fields() {
        let parser = CefParser::new();
        // Lipsesc campuri obligatorii.
        let log = "CEF:0|CheckPoint|VPN-1|R81|100|Drop|5|src=192.168.11.7";
        assert!(parser.parse(log).is_none());
    }
}
