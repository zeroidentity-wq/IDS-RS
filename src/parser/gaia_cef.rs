// =============================================================================
// parser/gaia_cef.rs - Parser pentru Checkpoint Gaia LEA blob in CEF Name
// =============================================================================
//
// FORMAT (exemplu real):
//   <134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action="Drop"
//     src="1.2.3.4" dst="5.6.7.8" service="443" proto="6"|5|
//
// Context:
//   Firewall-urile Checkpoint Gaia (versiune veche, LEA v5) trimit log-uri
//   prin ArcSight. ArcSight le impacheteaza in CEF, dar pune TOT blob-ul LEA
//   in campul Name (index 5), nu in extensii (index 7).
//
//   Blob-ul LEA contine perechi key="value" separate prin spatiu.
//   Campuri relevante:
//     action = "Drop" / "Accept"
//     src    = IP sursa
//     dst    = IP destinatie
//     service= port destinatie
//     proto  = numar protocol IANA (6=tcp, 17=udp, 1=icmp)
//
// =============================================================================

use super::{LogEvent, LogParser};
use std::net::IpAddr;

/// Parser pentru log-uri Checkpoint Gaia LEA impachetate in CEF Name field.
///
/// Cazul specific: ArcSight primeste log-uri LEA v5 de la Checkpoint Gaia
/// si le pune in campul Name al CEF-ului (index 5), nu in extensii (index 7).
/// Parser-ul CEF standard ignora campul Name, deci aceste log-uri nu sunt parsate.
pub struct GaiaCefParser;

impl GaiaCefParser {
    pub fn new() -> Self {
        Self
    }

    /// Extrage valoarea unui camp key="value" din blob-ul LEA.
    ///
    /// Cauta `key="value"` cu verificare boundary: characterul dinaintea cheii
    /// trebuie sa fie spatiu sau inceputul string-ului (nu sub-string match).
    /// Valorile sunt intre ghilimele duble.
    fn extract_lea_field<'a>(blob: &'a str, key: &str) -> Option<&'a str> {
        // Construim pattern-ul cautat: key="
        let pattern = format!("{}=\"", key);

        let mut search_from = 0;
        while search_from < blob.len() {
            // Cautam pattern-ul in restul string-ului.
            let remaining = &blob[search_from..];
            let pos = remaining.find(&pattern)?;
            let abs_pos = search_from + pos;

            // Verificam boundary: trebuie sa fie la inceputul blob-ului
            // sau precedat de spatiu (nu sub-string match, ex: "dst" in "xdst").
            let at_boundary = abs_pos == 0
                || blob.as_bytes()[abs_pos - 1] == b' '
                || blob.as_bytes()[abs_pos - 1] == b'|';

            if at_boundary {
                // Extragem valoarea de dupa ghilimeaua de deschidere.
                let value_start = abs_pos + pattern.len();
                // Cautam ghilimeaua de inchidere.
                let value_end = blob[value_start..].find('"')?;
                return Some(&blob[value_start..value_start + value_end]);
            }

            // Nu era la boundary, continuam cautarea dupa aceasta aparitie.
            search_from = abs_pos + pattern.len();
        }

        None
    }

    /// Mapeaza numere de protocol IANA la nume standard.
    ///
    /// Log-urile LEA folosesc numere IANA (6, 17, 1) in loc de nume
    /// (tcp, udp, icmp). Convertim la format lowercase standard.
    fn map_protocol(proto_str: &str) -> String {
        match proto_str {
            "6" => "tcp".to_string(),
            "17" => "udp".to_string(),
            "1" => "icmp".to_string(),
            other => other.to_lowercase(),
        }
    }
}

impl LogParser for GaiaCefParser {
    /// Parseaza o linie CEF cu blob LEA in campul Name.
    ///
    /// Etape:
    /// 1. Gaseste "CEF:" in linie (sare peste syslog header)
    /// 2. Split pe '|' — extrage Name (index 5)
    /// 3. Parseaza perechi key="value" din Name
    /// 4. Filtreaza: doar action="Drop" si action="Accept"
    /// 5. Construieste LogEvent
    fn parse(&self, line: &str) -> Option<LogEvent> {
        // Gasim offset-ul "CEF:" in linie (sare peste syslog header).
        let cef_start = line.find("CEF:")?;

        // Separam headerul CEF in maxim 8 parti.
        let parts: Vec<&str> = line[cef_start..].splitn(8, '|').collect();

        // Avem nevoie de cel putin 6 parti (0..5) pentru a accesa Name (index 5).
        if parts.len() < 6 {
            return None;
        }

        // Blob-ul LEA este in campul Name (index 5).
        let lea_blob = parts[5];

        // Extragem actiunea. Daca lipseste, nu putem procesa.
        let action_raw = Self::extract_lea_field(lea_blob, "action")?;
        let action = action_raw.to_lowercase();

        // Filtram: doar "drop" si "accept" (case-insensitive deja).
        if action != "drop" && action != "accept" {
            return None;
        }

        // Extragem IP sursa (obligatoriu).
        let src_str = Self::extract_lea_field(lea_blob, "src")?;
        let source_ip: IpAddr = src_str.parse().ok()?;

        // Extragem IP destinatie (optional).
        let dest_ip: Option<IpAddr> = Self::extract_lea_field(lea_blob, "dst")
            .and_then(|s| s.parse().ok());

        // Extragem portul destinatie din "service" (obligatoriu).
        let service_str = Self::extract_lea_field(lea_blob, "service")?;
        let dest_port: u16 = service_str.parse().ok()?;

        // Extragem protocolul (optional, default tcp).
        let protocol = Self::extract_lea_field(lea_blob, "proto")
            .map(Self::map_protocol)
            .unwrap_or_else(|| "tcp".to_string());

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
        "Checkpoint Gaia LEA in CEF (ArcSight)"
    }

    fn expected_format(&self) -> &str {
        "<PRI>Mon DD HH:MM:SS hostname CEF:0|Vendor|Product|Version|ID|action=\"Drop\" src=\"IP\" dst=\"IP\" service=\"PORT\" proto=\"6\"|Severity|"
    }
}

// =============================================================================
// UNIT TESTS
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_drop() {
        // Drop complet cu toate campurile — cazul standard.
        let parser = GaiaCefParser::new();
        let log = "<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action=\"Drop\" src=\"192.168.11.7\" dst=\"10.0.0.1\" service=\"443\" proto=\"6\"|5|";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "192.168.11.7");
        assert_eq!(event.dest_ip.unwrap().to_string(), "10.0.0.1");
        assert_eq!(event.dest_port, 443);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, "drop");
    }

    #[test]
    fn test_parse_valid_accept() {
        // Accept complet — pentru detectia Accept Scan.
        let parser = GaiaCefParser::new();
        let log = "<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action=\"Accept\" src=\"10.0.0.5\" dst=\"10.0.0.1\" service=\"80\" proto=\"6\"|3|";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "10.0.0.5");
        assert_eq!(event.dest_port, 80);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, "accept");
    }

    #[test]
    fn test_parse_missing_src() {
        // Fara src — trebuie ignorat (return None).
        let parser = GaiaCefParser::new();
        let log = "<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action=\"Drop\" dst=\"10.0.0.1\" service=\"443\" proto=\"6\"|5|";

        assert!(parser.parse(log).is_none());
    }

    #[test]
    fn test_parse_missing_service() {
        // Fara service (port) — trebuie ignorat (return None).
        let parser = GaiaCefParser::new();
        let log = "<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action=\"Drop\" src=\"192.168.11.7\" dst=\"10.0.0.1\" proto=\"6\"|5|";

        assert!(parser.parse(log).is_none());
    }

    #[test]
    fn test_protocol_mapping_udp() {
        // proto="17" trebuie mapat la "udp".
        let parser = GaiaCefParser::new();
        let log = "<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action=\"Drop\" src=\"192.168.11.7\" dst=\"10.0.0.1\" service=\"53\" proto=\"17\"|5|";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.protocol, "udp");
        assert_eq!(event.dest_port, 53);
    }

    #[test]
    fn test_protocol_mapping_icmp() {
        // proto="1" trebuie mapat la "icmp".
        // ICMP cu service valid (rar, dar posibil in log-urile LEA).
        let parser = GaiaCefParser::new();
        let log = "<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action=\"Drop\" src=\"192.168.11.7\" dst=\"10.0.0.1\" service=\"0\" proto=\"1\"|5|";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.protocol, "icmp");
        assert_eq!(event.dest_port, 0);
    }

    #[test]
    fn test_case_insensitive_action() {
        // action="DROP" (uppercase) — trebuie normalizat la "drop".
        let parser = GaiaCefParser::new();
        let log = "<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action=\"DROP\" src=\"1.2.3.4\" dst=\"5.6.7.8\" service=\"22\" proto=\"6\"|5|";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.action, "drop");
    }

    #[test]
    fn test_reject_non_cef() {
        // Input invalid (nu contine CEF:) — return None.
        let parser = GaiaCefParser::new();
        assert!(parser.parse("some random text that is not a CEF log").is_none());
    }

    #[test]
    fn test_reject_irrelevant_action() {
        // action="Log" — nu ne intereseaza, return None.
        let parser = GaiaCefParser::new();
        let log = "<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action=\"Log\" src=\"1.2.3.4\" dst=\"5.6.7.8\" service=\"443\" proto=\"6\"|5|";

        assert!(parser.parse(log).is_none());
    }

    #[test]
    fn test_dest_ip_optional() {
        // Fara dst — trebuie parsat cu dest_ip=None.
        let parser = GaiaCefParser::new();
        let log = "<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action=\"Drop\" src=\"192.168.11.7\" service=\"8080\" proto=\"6\"|5|";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "192.168.11.7");
        assert!(event.dest_ip.is_none());
        assert_eq!(event.dest_port, 8080);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, "drop");
    }
}
