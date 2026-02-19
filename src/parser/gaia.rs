// =============================================================================
// parser/gaia.rs - Parser pentru Checkpoint Gaia (Format Raw / Brut)
// =============================================================================
//
// FORMAT LOG GAIA REAL (exemplu):
//   Sep 3 15:12:20 192.168.99.1 Checkpoint: 3Sep2007 15:12:08 drop \
//     192.168.11.7 >eth8 rule: 113; rule_uid: {AAAA-...}; service_id: http; \
//     src: 192.168.11.34; dst: 4.23.34.126; proto: tcp; \
//     product: VPN-1 & FireWall-1; service: 80; s_port: 2854;
//
// Parsarea se face in doua etape (similar cu pattern-ul din cef.rs):
//   1. Regex pe header - extrage actiunea (drop/accept/reject) din zona
//      dupa "Checkpoint:" (sare peste checkpoint date+time).
//   2. Key-value extraction - parseaza campurile "; "-separate:
//      src: <IP>, proto: <proto>, service: <port>
//
// Campuri extrase:
//   - Actiune: "drop" (doar drop-urile ne intereseaza)
//   - IP sursa: din "src: <IP>" (cel care scaneaza)
//   - Port destinatie: din "service: <port>" (portul scanat)
//   - Protocol: din "proto: <proto>"
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
    /// Regex pre-compilat pentru extragerea actiunii din header-ul Gaia.
    /// Captureaza doar actiunea (drop/accept/reject) dupa checkpoint date+time.
    /// `Regex` este Send + Sync, deci GaiaParser mosteneste aceste
    /// proprietati automat - poate fi partajat intre thread-uri.
    header_re: Regex,
}

impl GaiaParser {
    /// Construieste un nou GaiaParser cu regex-ul pre-compilat.
    ///
    /// NOTA RUST: Returneaza `anyhow::Result<Self>` deoarece
    /// compilarea regex-ului poate teoretic esua (desi regex-ul
    /// nostru este valid - este o buna practica sa propagam eroarea).
    /// `Self` este un alias pentru tipul curent (GaiaParser).
    pub fn new() -> anyhow::Result<Self> {
        // Regex pe header-ul Gaia:
        //   (?i)           = case-insensitive
        //   Checkpoint:\s+ = literalul "Checkpoint:" urmat de spatii
        //   \S+\s+\S+\s+  = checkpoint date + time (ex: "3Sep2007 15:10:28")
        //   (accept|drop|reject) = actiunea (grup 1 capturat)
        let header_re = Regex::new(
            r"(?i)Checkpoint:\s+\S+\s+\S+\s+(accept|drop|reject)\s+"
        )?;

        Ok(Self { header_re })
    }

    /// Extrage valoarea unui camp key-value din zona de extensii.
    ///
    /// Campurile sunt separate prin "; " sau ";" si au formatul "key: value".
    /// Aceasta functie cauta un camp specific (ex: "src", "proto", "service")
    /// si returneaza valoarea asociata.
    fn extract_field<'a>(extensions: &'a str, key: &str) -> Option<&'a str> {
        // Construim prefixul cautat: "key: " (cu spatiu dupa colon)
        let prefix = format!("{}: ", key);

        for part in extensions.split(';') {
            let trimmed = part.trim();
            if let Some(value) = trimmed.strip_prefix(&prefix) {
                // Returnam valoarea pana la urmatorul separator (spatiu sau ;).
                // Valoarea nu contine spatii in cazurile noastre (IP, port, protocol).
                return Some(value.split(';').next().unwrap_or(value).trim());
            }
        }
        None
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
    /// Parsarea se face in doua etape:
    /// 1. Regex pe header - extrage actiunea (doar "drop" ne intereseaza)
    /// 2. Key-value extraction - extrage src, proto, service din campurile
    ///    separate prin ";"
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
        // Etapa 1: Regex pe header - extragem actiunea.
        // `.captures(line)` returneaza Option<Captures>
        // `?` pe Option propaga None-ul: daca nu e match, returnam None direct.
        let caps = self.header_re.captures(line)?;

        // `.get(1)` returneaza Option<Match> - grupul capturat la indexul 1.
        // `.as_str()` obtine &str din Match.
        // `.to_lowercase()` creeaza un String owned (alocare pe heap).
        let action = caps.get(1)?.as_str().to_lowercase();

        // Filtram: ne intereseaza DOAR actiunile "drop".
        // Drop = firewall-ul a blocat conexiunea = potential scan.
        if action != "drop" {
            return None;
        }

        // Etapa 2: Key-value extraction din zona de extensii.
        // Zona de extensii este tot ce urmeaza dupa match-ul header-ului.
        let header_end = caps.get(0)?.end();
        let extensions = &line[header_end..];

        // Extragem source_ip din "src: <IP>".
        // Log-urile broadcast (fara "src:") sunt ignorate - return None.
        let src_str = Self::extract_field(extensions, "src")?;
        let source_ip: IpAddr = src_str.parse().ok()?;

        // Extragem dest_ip din "dst: <IP>" (tinta atacului).
        // Option<> - unele log-uri pot lipsi campul dst.
        let dest_ip: Option<IpAddr> = Self::extract_field(extensions, "dst")
            .and_then(|s| s.parse().ok());

        // Extragem protocolul din "proto: <proto>".
        let protocol = Self::extract_field(extensions, "proto")
            .unwrap_or("tcp")
            .to_lowercase();

        // Extragem portul destinatie din "service: <port>".
        // Log-urile ICMP (fara "service:") sunt ignorate - return None.
        let service_str = Self::extract_field(extensions, "service")?;
        let dest_port: u16 = service_str.parse().ok()?;

        // Construim LogEvent-ul. `line.to_string()` creaza un String owned
        // din &str (copiaza datele pe heap). Necesar deoarece LogEvent
        // trebuie sa fie independent de buffer-ul original.
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
        "Checkpoint Gaia (Raw)"
    }

    fn expected_format(&self) -> &str {
        "Mon  D HH:MM:SS host Checkpoint: DDMmmYYYY HH:MM:SS action src >iface rule: N; src: IP; dst: IP; proto: PROTO; service: PORT;"
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
    fn test_parse_valid_drop_real_format() {
        // Log real Checkpoint GAIA cu header complet (date+time, gateway, interfata).
        let parser = GaiaParser::new().unwrap();
        let log = "Sep 3 15:12:20 192.168.99.1 Checkpoint: 3Sep2007 15:12:08 drop \
            192.168.11.7 >eth8 rule: 113; rule_uid: {AAAAAAAA-9999-8888-FFCF33A92D27}; \
            service_id: http; src: 192.168.11.34; dst: 4.23.34.126; proto: tcp; \
            product: VPN-1 & FireWall-1; service: 80; s_port: 2854;";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "192.168.11.34");
        assert_eq!(event.dest_port, 80);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, "drop");
    }

    #[test]
    fn test_ignore_accept_real_format() {
        // Log real cu accept - trebuie ignorat.
        let parser = GaiaParser::new().unwrap();
        let log = "Sep 3 15:10:54 192.168.99.1 Checkpoint: 3Sep2007 15:10:28 accept \
            192.168.99.1 >eth2 rule: 9; rule_uid: {11111111-2222-3333-8A67-F54CED606693}; \
            service_id: domain-udp; src: 200.14.120.9; dst: 192.168.99.184; proto: udp; \
            product: VPN-1 & FireWall-1; service: 53; s_port: 32769;";

        assert!(parser.parse(log).is_none());
    }

    #[test]
    fn test_broadcast_drop_no_src() {
        // Drop broadcast fara "src:" - trebuie ignorat (return None).
        let parser = GaiaParser::new().unwrap();
        let log = "Sep 3 15:10:54 192.168.99.1 Checkpoint: 3Sep2007 15:10:52 drop \
            192.168.99.1 >eth8 rule: 134; rule_uid: {11111111-2222-3333-BD17-711F536C7C33}; \
            dst: 255.255.255.255; proto: udp; product: VPN-1 & FireWall-1; service: 67; \
            s_port: 68;";

        assert!(parser.parse(log).is_none());
    }

    #[test]
    fn test_icmp_drop_no_service() {
        // Drop ICMP fara "service:" - trebuie ignorat (return None).
        let parser = GaiaParser::new().unwrap();
        let log = "Sep 3 15:12:56 192.168.99.1 Checkpoint: 3Sep2007 15:13:53 drop \
            192.168.11.7 >eth2 rule: 134; rule_uid: {11111111-2222-3333-BD17-711F536C7C33}; \
            ICMP: Echo Request; src: 203.193.149.227; dst: 64.129.8.245; proto: icmp; \
            ICMP Type: 8; ICMP Code: 0; product: VPN-1 & FireWall-1;";

        assert!(parser.parse(log).is_none());
    }

    #[test]
    fn test_drop_with_service_port() {
        // Drop cu src si service (port numeric) - trebuie parsat.
        let parser = GaiaParser::new().unwrap();
        let log = "Sep 3 15:11:40 192.168.99.1 Checkpoint: 3Sep2007 15:10:54 drop \
            192.168.99.1 >eth8 rule: 134; rule_uid: {11111111-2222-3333-BD17-711F536C7C33}; \
            src: 192.168.99.185; dst: 192.149.252.44; proto: tcp; \
            product: VPN-1 & FireWall-1; service: 43; s_port: 57172;";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "192.168.99.185");
        assert_eq!(event.dest_port, 43);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, "drop");
    }

    #[test]
    fn test_invalid_log_format() {
        let parser = GaiaParser::new().unwrap();
        let log = "some random text that is not a firewall log";

        assert!(parser.parse(log).is_none());
    }
}
