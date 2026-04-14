// =============================================================================
// parser/gaia_cef.rs - Parser pentru Checkpoint Gaia LEA blob
// =============================================================================
//
// Parseaza blob-uri LEA (Log Export API) de la Checkpoint Gaia.
// Blob-ul LEA contine perechi key="value" separate prin spatiu.
//
// FORMATE ACCEPTATE (3 scenarii):
//
//   1. Blob LEA raw (fara wrapper CEF) — vine direct pe UDP, sau ca rawEvent:
//      time="177..." action="Drop" src="1.2.3.4" dst="5.6.7.8" service="443" proto="6"
//
//   2. Blob LEA impachetat in CEF Name field (index 5):
//      <134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action="Drop" src="1.2.3.4"...|5|
//
//   3. Blob LEA intr-o extensie CEF (rawEvent= sau cs6=):
//      CEF:0|...|...|5|rawEvent=time\="177..." action\="Drop" src\="1.2.3.4" ...
//      (cu escape \= in loc de =, decodat inainte de parsare)
//
// EXEMPLU REAL DE RAWEVENT (din ArcSight):
//   time="1777777777777" action="Drop" ifdir="inbound" ifname="bound.2"
//   logid="0" loguid="{gex}" origin="xxx.xxx.xxx" originsicname="X"
//   sequencenum="45" version="5" dst="xxx.xxx.xx.xxx" inzone="External"
//   layer_name="Network" layer_uuid="gex" match_id="133" parent_rule="0"
//   rule_action="Drop" rule_name="Cleanup rule" rule_uid="gec"
//   outzone="Extern" product="VPN" proto="6" s_port="66664"
//   service="23" service_id="telnet" src="190.x.x.x"
//
// CAMPURI RELEVANTE:
//   action  = "Drop" / "Accept"
//   src     = IP sursa (atacatorul)
//   dst     = IP destinatie (tinta)
//   service = port destinatie (numeric)
//   proto   = numar protocol IANA (6=tcp, 17=udp, 1=icmp)
//
// CAPCANE (rezolvate prin boundary check):
//   rule_action="Drop"   ← NU e action="Drop"  (precedat de '_', nu spatiu)
//   service_id="telnet"  ← NU e service="23"    (pattern diferit: service_id= vs service=)
//   s_port="66664"       ← NU cautam "port"     (nicio ambiguitate)
//
// =============================================================================

use super::{LogEvent, LogParser};
use std::net::IpAddr;

/// Parser pentru blob-uri LEA de la Checkpoint Gaia (via ArcSight).
///
/// Accepta trei formate de input:
/// 1. Blob LEA raw — perechi key="value" fara wrapper CEF
/// 2. Blob LEA in CEF Name field (index 5)
/// 3. Blob LEA intr-o extensie CEF (rawEvent= sau cs6=, cu escaped \=)
///
/// Ordinea de parsare: CEF Name → CEF extensie (rawEvent/cs6) → raw LEA direct.
/// Prima metoda care gaseste action="Drop"/"Accept" castiga.
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

impl GaiaCefParser {
    /// Incearca sa extraga blob-ul LEA din input.
    ///
    /// Strategia (in ordinea prioritatii):
    /// 1. Daca contine "CEF:" → extrage din Name field (index 5)
    /// 2. Daca contine "CEF:" dar Name nu are action → cauta rawEvent=/cs6= in extensii
    /// 3. Daca NU contine "CEF:" → trateaza toata linia ca blob LEA raw
    fn find_lea_blob<'a>(line: &'a str) -> Option<LeaSource<'a>> {
        if let Some(cef_start) = line.find("CEF:") {
            let parts: Vec<&str> = line[cef_start..].splitn(8, '|').collect();

            // Strategia 1: blob LEA in Name field (index 5)
            if parts.len() >= 6 {
                let name = parts[5];
                if Self::extract_lea_field(name, "action").is_some() {
                    return Some(LeaSource::Borrowed(name));
                }
            }

            // Strategia 2: blob LEA in extensii CEF (rawEvent= sau cs6=)
            if parts.len() >= 8 {
                let extensions = parts[7];
                if let Some(unescaped) = Self::extract_raw_event_from_extensions(extensions) {
                    return Some(LeaSource::Owned(unescaped));
                }
            }

            None
        } else {
            // Strategia 3: toata linia este blob LEA raw (fara wrapper CEF).
            // Verificam ca contine action=" — semn ca e un blob LEA valid.
            if Self::extract_lea_field(line, "action").is_some() {
                Some(LeaSource::Borrowed(line))
            } else {
                None
            }
        }
    }

    /// Extrage blob-ul raw din extensiile CEF (campul rawEvent= sau cs6=).
    ///
    /// In extensiile CEF, valorile sunt escaped: \= in loc de =, \\ in loc de \.
    /// Aceasta functie gaseste campul, extrage valoarea si decodeaza escape-urile.
    fn extract_raw_event_from_extensions(extensions: &str) -> Option<String> {
        // Cautam rawEvent= sau cs6= (cele mai comune campuri pentru raw event)
        for prefix in &["rawEvent=", "cs6="] {
            if let Some(start) = extensions.find(prefix) {
                let value_start = start + prefix.len();
                // Valoarea se termina la urmatorul camp CEF (spatiu urmat de key=)
                // sau la sfarsitul string-ului.
                let value = Self::extract_cef_extension_value(&extensions[value_start..]);
                if !value.is_empty() {
                    // Decodam escape-urile CEF: \= → =, \\ → \, \n → newline
                    let unescaped = value
                        .replace("\\=", "=")
                        .replace("\\\\", "\\")
                        .replace("\\n", " ");
                    return Some(unescaped);
                }
            }
        }
        None
    }

    /// Extrage valoarea unui camp din extensiile CEF.
    ///
    /// Valorile CEF se termina la urmatorul camp (pattern: " key=")
    /// sau la sfarsitul string-ului. Problema: valorile pot contine
    /// spatii, deci nu putem split pe spatiu simplu.
    fn extract_cef_extension_value(from: &str) -> &str {
        // Cautam pattern-ul " cheie=" care marcheaza inceputul urmatorului camp.
        // Un camp CEF valid: spatiu + litere/cifre + "="
        let bytes = from.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b' ' {
                // Verificam daca urmeaza un key= (litere/cifre urmate de =)
                let rest = &from[i + 1..];
                if let Some(eq_pos) = rest.find('=') {
                    let potential_key = &rest[..eq_pos];
                    // Un key CEF valid contine doar litere, cifre si underscore
                    if !potential_key.is_empty()
                        && potential_key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        // Nu e un escaped \= din valoare
                        && !from[..i + 1 + eq_pos].ends_with('\\')
                    {
                        return from[..i].trim();
                    }
                }
            }
            i += 1;
        }
        from.trim()
    }

    /// Parseaza un blob LEA si construieste un LogEvent.
    fn parse_lea_blob(&self, blob: &str, raw_log: &str) -> Option<LogEvent> {
        // Extragem actiunea. Daca lipseste, nu putem procesa.
        let action_raw = Self::extract_lea_field(blob, "action")?;
        let action = action_raw.to_lowercase();

        // Filtram: doar "drop" si "accept" (case-insensitive deja).
        if action != "drop" && action != "accept" {
            return None;
        }

        // Extragem IP sursa (obligatoriu).
        let src_str = Self::extract_lea_field(blob, "src")?;
        let source_ip: IpAddr = src_str.parse().ok()?;

        // Extragem IP destinatie (optional).
        let dest_ip: Option<IpAddr> =
            Self::extract_lea_field(blob, "dst").and_then(|s| s.parse().ok());

        // Extragem portul destinatie din "service" (obligatoriu).
        let service_str = Self::extract_lea_field(blob, "service")?;
        let dest_port: u16 = service_str.parse().ok()?;

        // Extragem protocolul (optional, default tcp).
        let protocol = Self::extract_lea_field(blob, "proto")
            .map(Self::map_protocol)
            .unwrap_or_else(|| "tcp".to_string());

        Some(LogEvent {
            source_ip,
            dest_ip,
            dest_port,
            protocol,
            action,
            raw_log: raw_log.to_string(),
        })
    }
}

/// Sursa blob-ului LEA: referinta directa (&str) sau string owned (dupa unescape).
enum LeaSource<'a> {
    Borrowed(&'a str),
    Owned(String),
}

impl LogParser for GaiaCefParser {
    /// Parseaza o linie care contine un blob LEA Checkpoint.
    ///
    /// Accepta trei scenarii (vezi documentatia struct-ului).
    /// Ordinea: CEF Name → CEF extensie rawEvent → blob LEA raw direct.
    fn parse(&self, line: &str) -> Option<LogEvent> {
        let source = Self::find_lea_blob(line)?;
        let blob = match &source {
            LeaSource::Borrowed(s) => s,
            LeaSource::Owned(s) => s.as_str(),
        };
        self.parse_lea_blob(blob, line)
    }

    fn name(&self) -> &str {
        "Checkpoint Gaia LEA (ArcSight)"
    }

    fn expected_format(&self) -> &str {
        "action=\"Drop\" src=\"IP\" dst=\"IP\" service=\"PORT\" proto=\"6\" (raw LEA, CEF Name, sau CEF rawEvent=)"
    }
}

// =============================================================================
// UNIT TESTS
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Scenariul 1: Blob LEA in CEF Name field (index 5)
    // =========================================================================

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
        // Input invalid (nu contine CEF: si nici action=) — return None.
        let parser = GaiaCefParser::new();
        assert!(parser
            .parse("some random text that is not a LEA log")
            .is_none());
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

    // =========================================================================
    // Scenariul 2: Blob LEA raw (fara wrapper CEF) — rawEvent direct
    // =========================================================================

    #[test]
    fn test_raw_lea_real_event() {
        // Eveniment REAL din ArcSight rawEvent — blob LEA complet cu
        // TOATE campurile, inclusiv cele care pot cauza ambiguitati:
        //   rule_action="Drop"  (NU e action="Drop")
        //   service_id="telnet" (NU e service="23")
        //   s_port="66664"      (NU e port)
        let parser = GaiaCefParser::new();
        let log = "time=\"1777777777777\" action=\"Drop\" ifdir=\"inbound\" ifname=\"bound.2\" \
            logid=\"0\" loguid=\"{gex}\" origin=\"10.20.30.40\" originsicname=\"X\" \
            sequencenum=\"45\" time=\"17171717171\" version=\"5\" dst=\"172.16.0.100\" \
            inzone=\"External\" layer_name=\"Network\" layer_uuid=\"gex\" match_id=\"133\" \
            parent_rule=\"0\" rule_action=\"Drop\" rule_name=\"Cleanup rule\" rule_uid=\"gec\" \
            outzone=\"Extern\" product=\"VPN\" proto=\"6\" s_port=\"66664\" \
            service=\"23\" service_id=\"telnet\" src=\"190.1.2.3\"";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "190.1.2.3");
        assert_eq!(event.dest_ip.unwrap().to_string(), "172.16.0.100");
        assert_eq!(event.dest_port, 23);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, "drop");
    }

    #[test]
    fn test_raw_lea_accept() {
        // Blob LEA raw cu action="Accept" — pentru Accept Scan.
        let parser = GaiaCefParser::new();
        let log = "time=\"1777777777777\" action=\"Accept\" dst=\"10.0.0.1\" \
            proto=\"6\" service=\"80\" src=\"192.168.1.50\"";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "192.168.1.50");
        assert_eq!(event.dest_port, 80);
        assert_eq!(event.action, "accept");
    }

    #[test]
    fn test_raw_lea_reject_log_action() {
        // Blob LEA raw cu action="Log" — nu ne intereseaza.
        let parser = GaiaCefParser::new();
        let log = "time=\"1777\" action=\"Log\" dst=\"10.0.0.1\" proto=\"6\" \
            service=\"443\" src=\"1.2.3.4\"";

        assert!(parser.parse(log).is_none());
    }

    #[test]
    fn test_raw_lea_boundary_rule_action() {
        // Verifica ca rule_action="Drop" NU este confundat cu action="Drop".
        // Daca action lipseste DAR rule_action exista → None (nu Drop).
        let parser = GaiaCefParser::new();
        let log = "time=\"1777\" rule_action=\"Drop\" dst=\"10.0.0.1\" proto=\"6\" \
            service=\"443\" src=\"1.2.3.4\"";

        // Nu are action= (doar rule_action=), deci trebuie ignorat.
        assert!(parser.parse(log).is_none());
    }

    // =========================================================================
    // Scenariul 3: Blob LEA in extensie CEF (rawEvent= cu escaped \=)
    // =========================================================================

    #[test]
    fn test_cef_raw_event_extension() {
        // Blob LEA in extensia rawEvent= cu escaped \= in loc de =
        let parser = GaiaCefParser::new();
        let log = "<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|Drop|5|\
            rawEvent=action\\=\"Drop\" src\\=\"10.1.1.1\" dst\\=\"10.2.2.2\" service\\=\"22\" proto\\=\"6\"";

        let event = parser.parse(log).unwrap();
        assert_eq!(event.source_ip.to_string(), "10.1.1.1");
        assert_eq!(event.dest_ip.unwrap().to_string(), "10.2.2.2");
        assert_eq!(event.dest_port, 22);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, "drop");
    }
}
