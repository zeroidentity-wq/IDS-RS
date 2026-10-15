// =============================================================================
// parser/custom.rs - Parser declarativ, configurat din [custom_parser]
// =============================================================================
//
// Pentru firewall-uri fara parser dedicat (FortiGate, iptables, Palo Alto...).
// Formatul nu este ghicit la runtime: config.toml descrie unde se afla fiecare
// camp si ce valori inseamna drop/accept. O linie interpretata gresit nu da
// nicio eroare, doar rateaza atacuri - de aceea maparea este explicita.
//
// FORMATE:
//
//   kv  - perechi cheie=valoare separate prin spatii, valori optional intre
//         ghilimele (cu \" si \\ escapate in interior):
//           date=2026-10-15 srcip=10.0.0.5 dstip=10.0.0.1 dstport=22 action="deny"
//           kernel: FW-DROP: IN=eth0 SRC=10.0.0.5 DST=10.0.0.1 PROTO=TCP DPT=22
//
//   csv - coloane separate de `delimiter`, cu ghilimele duble optionale
//         ("" = ghilimea literala). Coloanele se numara de la 0:
//           <14>Oct 15 10:00:00 pa 1,2026/10/15,0123,TRAFFIC,end,...,10.0.0.5,...
//
// ACTIUNEA vine din exact una dintre surse (validat in config):
//   - fields.action + drop_values/accept_values (case-insensitive)
//   - action_from_text: text cautat in linie (ex: prefixul iptables)
//
// O linie cu sursa si port valide dar cu actiune nemapata este numarata si
// raportata periodic (vezi LogParser::take_unmapped_actions).
//
// =============================================================================

use super::{normalize_protocol, Action, LogEvent, LogParser};
use crate::config::{CustomFieldMap, CustomFormat, CustomParserConfig, FieldRef};
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Lungimea maxima a exemplului de actiune nemapata pastrat pentru raportare.
const UNMAPPED_SAMPLE_CHARS: usize = 64;

pub struct CustomParser {
    format: CustomFormat,
    delimiter: char,
    require_text: Option<String>,
    fields: CustomFieldMap,
    drop_values: Vec<String>,
    accept_values: Vec<String>,
    /// Ordonate descrescator dupa lungime: cand mai multe texte apar in
    /// aceeasi linie, castiga cel mai specific (ex: "FW-DROP-SSH" > "FW-DROP").
    action_patterns: Vec<(String, Action)>,
    unmapped_count: AtomicU64,
    unmapped_sample: Mutex<String>,
}

impl CustomParser {
    pub fn new(config: &CustomParserConfig) -> Self {
        let mut action_patterns: Vec<(String, Action)> = config
            .action_from_text
            .iter()
            .map(|(text, action)| (text.clone(), *action))
            .collect();
        action_patterns.sort_by(|left, right| right.0.len().cmp(&left.0.len()));

        Self {
            format: config.format,
            delimiter: config.delimiter(),
            require_text: config.require_text.clone(),
            fields: config.fields.clone(),
            drop_values: config.drop_values.clone(),
            accept_values: config.accept_values.clone(),
            action_patterns,
            unmapped_count: AtomicU64::new(0),
            unmapped_sample: Mutex::new(String::new()),
        }
    }

    /// Rezolva actiunea; Err contine valoarea nemapata (pentru raportare).
    fn resolve_action(&self, record: &Record<'_>, line: &str) -> Result<Action, String> {
        let Some(field) = &self.fields.action else {
            return self
                .action_patterns
                .iter()
                .find(|(text, _)| line.contains(text.as_str()))
                .map(|(_, action)| *action)
                .ok_or_else(|| "(niciun text din action_from_text)".to_string());
        };
        let Some(value) = record.get(field) else {
            return Err(format!("(camp {field} lipsa)"));
        };
        let value = value.trim();
        if self
            .drop_values
            .iter()
            .any(|drop| drop.eq_ignore_ascii_case(value))
        {
            Ok(Action::Drop)
        } else if self
            .accept_values
            .iter()
            .any(|accept| accept.eq_ignore_ascii_case(value))
        {
            Ok(Action::Accept)
        } else {
            Err(value.to_string())
        }
    }

    fn record_unmapped(&self, value: String) {
        self.unmapped_count.fetch_add(1, Ordering::Relaxed);
        let mut sample = self
            .unmapped_sample
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *sample = value.chars().take(UNMAPPED_SAMPLE_CHARS).collect();
    }
}

impl LogParser for CustomParser {
    fn parse(&self, line: &str) -> Option<LogEvent> {
        if let Some(required) = &self.require_text {
            if !line.contains(required.as_str()) {
                return None;
            }
        }

        let record = match self.format {
            CustomFormat::Kv => Record::Kv(kv_pairs(line)),
            CustomFormat::Csv => Record::Csv(csv_columns(line, self.delimiter)),
        };

        let source_ip: IpAddr = record.get(&self.fields.src_ip)?.trim().parse().ok()?;
        let dest_port: u16 = record.get(&self.fields.dst_port)?.trim().parse().ok()?;
        let dest_ip: Option<IpAddr> = record
            .get(&self.fields.dst_ip)
            .and_then(|value| value.trim().parse().ok());
        let protocol = self
            .fields
            .protocol
            .as_ref()
            .and_then(|field| record.get(field))
            .map(|value| normalize_protocol(value.trim()))
            .unwrap_or_else(|| "tcp".to_string());

        let action = match self.resolve_action(&record, line) {
            Ok(action) => action,
            Err(value) => {
                self.record_unmapped(value);
                return None;
            }
        };

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
        match self.format {
            CustomFormat::Kv => "Custom (cheie=valoare)",
            CustomFormat::Csv => "Custom (CSV)",
        }
    }

    fn expected_format(&self) -> &str {
        match self.format {
            CustomFormat::Kv => {
                "cheie=valoare cheie=\"valoare cu spatii\" ... (vezi [custom_parser].fields)"
            }
            CustomFormat::Csv => {
                "coloana0,coloana1,... (vezi [custom_parser].fields, index de la 0)"
            }
        }
    }

    fn take_unmapped_actions(&self) -> Option<(u64, String)> {
        let count = self.unmapped_count.swap(0, Ordering::Relaxed);
        if count == 0 {
            return None;
        }
        let sample = self
            .unmapped_sample
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        Some((count, sample))
    }
}

/// O linie descompusa, gata pentru cautarea campurilor dupa FieldRef.
enum Record<'a> {
    Kv(Vec<(&'a str, Cow<'a, str>)>),
    Csv(Vec<Cow<'a, str>>),
}

impl Record<'_> {
    fn get(&self, field: &FieldRef) -> Option<&str> {
        match (self, field) {
            (Record::Kv(pairs), FieldRef::Key(key)) => pairs
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_ref()),
            (Record::Csv(columns), FieldRef::Column(index)) => {
                columns.get(*index).map(|value| value.as_ref())
            }
            // Combinatiile nepotrivite sunt respinse de validarea config-ului.
            _ => None,
        }
    }
}

/// Descompune o linie in perechi `cheie=valoare`. Token-urile fara `=`
/// (header syslog, prefixe) sunt ignorate; prima aparitie a unei chei castiga.
///
/// NOTA RUST: valorile sunt `Cow<str>` - imprumutate direct din linie in
/// cazul obisnuit si alocate doar cand contin escape-uri de decodat.
pub(crate) fn kv_pairs(line: &str) -> Vec<(&str, Cow<'_, str>)> {
    let bytes = line.as_bytes();
    let mut pairs = Vec::new();
    let mut position = 0;

    while position < bytes.len() {
        while position < bytes.len() && bytes[position].is_ascii_whitespace() {
            position += 1;
        }
        let key_start = position;
        while position < bytes.len()
            && bytes[position] != b'='
            && !bytes[position].is_ascii_whitespace()
        {
            position += 1;
        }
        if position >= bytes.len() || bytes[position] != b'=' || position == key_start {
            // Token fara `=`: il sarim complet.
            while position < bytes.len() && !bytes[position].is_ascii_whitespace() {
                position += 1;
            }
            continue;
        }
        let key = &line[key_start..position];
        position += 1;

        let value = if bytes.get(position) == Some(&b'"') {
            position += 1;
            let value_start = position;
            let mut escaped = false;
            while position < bytes.len() {
                match bytes[position] {
                    b'\\' if !escaped => escaped = true,
                    b'"' if !escaped => break,
                    _ => escaped = false,
                }
                position += 1;
            }
            let raw = &line[value_start..position];
            position += 1; // ghilimeaua de inchidere (sau sfarsitul liniei)
            if raw.contains('\\') {
                Cow::Owned(unescape(raw))
            } else {
                Cow::Borrowed(raw)
            }
        } else {
            let value_start = position;
            while position < bytes.len() && !bytes[position].is_ascii_whitespace() {
                position += 1;
            }
            Cow::Borrowed(&line[value_start..position])
        };
        pairs.push((key, value));
    }
    pairs
}

fn unescape(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            if let Some(next) = characters.next() {
                output.push(next);
            }
        } else {
            output.push(character);
        }
    }
    output
}

/// Imparte o linie CSV in coloane. Un camp care incepe cu `"` se termina la
/// urmatoarea ghilimea neurmata de alta ghilimea; `""` inseamna `"`.
pub(crate) fn csv_columns(line: &str, delimiter: char) -> Vec<Cow<'_, str>> {
    let mut columns = Vec::new();
    let mut rest = line;
    loop {
        if let Some(quoted) = rest.strip_prefix('"') {
            let mut value = String::new();
            let mut characters = quoted.char_indices().peekable();
            let mut consumed = quoted.len();
            while let Some((index, character)) = characters.next() {
                if character == '"' {
                    if matches!(characters.peek(), Some((_, '"'))) {
                        characters.next();
                        value.push('"');
                        continue;
                    }
                    consumed = index + 1;
                    break;
                }
                value.push(character);
            }
            columns.push(Cow::Owned(value));
            rest = &quoted[consumed..];
            // Ignoram orice text dintre ghilimeaua de inchidere si delimitator.
            match rest.find(delimiter) {
                Some(index) => rest = &rest[index + delimiter.len_utf8()..],
                None => return columns,
            }
        } else {
            match rest.find(delimiter) {
                Some(index) => {
                    columns.push(Cow::Borrowed(&rest[..index]));
                    rest = &rest[index + delimiter.len_utf8()..];
                }
                None => {
                    columns.push(Cow::Borrowed(rest));
                    return columns;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn key(name: &str) -> FieldRef {
        FieldRef::Key(name.to_string())
    }

    fn fortigate() -> CustomParser {
        CustomParser::new(&CustomParserConfig {
            format: CustomFormat::Kv,
            delimiter: None,
            require_text: Some("type=\"traffic\"".to_string()),
            fields: CustomFieldMap {
                src_ip: key("srcip"),
                dst_ip: key("dstip"),
                dst_port: key("dstport"),
                protocol: Some(key("proto")),
                action: Some(key("action")),
            },
            drop_values: vec!["deny".to_string()],
            accept_values: vec!["accept".to_string(), "close".to_string()],
            action_from_text: BTreeMap::new(),
        })
    }

    fn iptables() -> CustomParser {
        CustomParser::new(&CustomParserConfig {
            format: CustomFormat::Kv,
            delimiter: None,
            require_text: None,
            fields: CustomFieldMap {
                src_ip: key("SRC"),
                dst_ip: key("DST"),
                dst_port: key("DPT"),
                protocol: Some(key("PROTO")),
                action: None,
            },
            drop_values: Vec::new(),
            accept_values: Vec::new(),
            action_from_text: BTreeMap::from([
                ("FW-DROP".to_string(), Action::Drop),
                ("FW-DROP-ALLOWLISTED".to_string(), Action::Accept),
                ("FW-ACCEPT".to_string(), Action::Accept),
            ]),
        })
    }

    fn palo_alto() -> CustomParser {
        CustomParser::new(&CustomParserConfig {
            format: CustomFormat::Csv,
            delimiter: None,
            require_text: Some(",TRAFFIC,".to_string()),
            fields: CustomFieldMap {
                src_ip: FieldRef::Column(7),
                dst_ip: FieldRef::Column(8),
                dst_port: FieldRef::Column(25),
                protocol: Some(FieldRef::Column(29)),
                action: Some(FieldRef::Column(30)),
            },
            drop_values: vec!["deny".to_string(), "drop".to_string()],
            accept_values: vec!["allow".to_string()],
            action_from_text: BTreeMap::new(),
        })
    }

    const FORTIGATE_DENY: &str = "<189>date=2026-10-15 time=10:00:01 devname=\"FG100F\" \
        type=\"traffic\" subtype=\"forward\" srcip=192.168.1.50 srcport=51234 \
        dstip=10.0.0.1 dstport=22 proto=6 action=\"deny\" msg=\"policy \\\"x\\\" a=b\"";

    #[test]
    fn fortigate_deny_is_parsed_as_drop() {
        let event = fortigate().parse(FORTIGATE_DENY).unwrap();
        assert_eq!(event.source_ip.to_string(), "192.168.1.50");
        assert_eq!(event.dest_ip.unwrap().to_string(), "10.0.0.1");
        assert_eq!(event.dest_port, 22);
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.action, Action::Drop);
        assert_eq!(event.raw_log, FORTIGATE_DENY);
    }

    #[test]
    fn action_values_are_case_insensitive() {
        let line = FORTIGATE_DENY.replace("\"deny\"", "\"CLOSE\"");
        assert_eq!(fortigate().parse(&line).unwrap().action, Action::Accept);
    }

    #[test]
    fn lines_without_required_text_are_ignored() {
        let parser = fortigate();
        let line = FORTIGATE_DENY.replace("type=\"traffic\"", "type=\"event\"");
        assert!(parser.parse(&line).is_none());
        assert!(parser.take_unmapped_actions().is_none());
    }

    #[test]
    fn unmapped_action_is_counted_and_reported_once() {
        let parser = fortigate();
        let line = FORTIGATE_DENY.replace("\"deny\"", "\"server-rst\"");
        assert!(parser.parse(&line).is_none());
        assert!(parser.parse(&line).is_none());
        assert_eq!(
            parser.take_unmapped_actions(),
            Some((2, "server-rst".to_string()))
        );
        assert!(parser.take_unmapped_actions().is_none());
    }

    #[test]
    fn lines_without_source_or_port_are_not_counted_as_unmapped() {
        let parser = fortigate();
        let line = FORTIGATE_DENY.replace("dstport=22 ", "");
        assert!(parser.parse(&line).is_none());
        assert!(parser.take_unmapped_actions().is_none());
    }

    #[test]
    fn iptables_action_comes_from_log_prefix() {
        let parser = iptables();
        let drop = "Oct 15 10:00:00 host kernel: [12345.678] FW-DROP: IN=eth0 OUT= \
            MAC=00:11 SRC=192.168.1.50 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=51234 DPT=3389 SYN";
        let event = parser.parse(drop).unwrap();
        assert_eq!(event.action, Action::Drop);
        assert_eq!(event.dest_port, 3389);
        assert_eq!(event.protocol, "tcp");

        let accept = drop.replace("FW-DROP:", "FW-ACCEPT:");
        assert_eq!(parser.parse(&accept).unwrap().action, Action::Accept);
    }

    #[test]
    fn longest_matching_action_text_wins() {
        let line = "kernel: FW-DROP-ALLOWLISTED: SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP DPT=22";
        assert_eq!(iptables().parse(line).unwrap().action, Action::Accept);
    }

    #[test]
    fn iptables_line_without_known_prefix_is_reported() {
        let parser = iptables();
        let line = "kernel: OTHER: SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP DPT=22";
        assert!(parser.parse(line).is_none());
        assert_eq!(parser.take_unmapped_actions().unwrap().0, 1);
    }

    #[test]
    fn iptables_icmp_without_port_is_ignored() {
        let line = "kernel: FW-DROP: SRC=192.168.1.50 DST=10.0.0.1 PROTO=ICMP TYPE=8 CODE=0";
        assert!(iptables().parse(line).is_none());
    }

    #[test]
    fn palo_alto_traffic_csv_is_parsed() {
        let line = "<14>Oct 15 10:00:00 PA-VM 1,2026/10/15 10:00:00,012801000001,TRAFFIC,drop,\
            2561,2026/10/15 10:00:00,192.168.1.50,10.0.0.1,0.0.0.0,0.0.0.0,deny-all,,,\
            not-applicable,vsys1,trust,untrust,ethernet1/2,,Forward,2026/10/15 10:00:00,\
            12345,1,51234,445,0,0,0x0,tcp,deny,74,74,0";
        let event = palo_alto().parse(line).unwrap();
        assert_eq!(event.source_ip.to_string(), "192.168.1.50");
        assert_eq!(event.dest_ip.unwrap().to_string(), "10.0.0.1");
        assert_eq!(event.dest_port, 445);
        assert_eq!(event.action, Action::Drop);
    }

    #[test]
    fn kv_pairs_handle_quotes_escapes_and_bare_tokens() {
        let pairs = kv_pairs("<134>Oct 15 a=1 b=\"two words\" c=\"q\\\"x\" d= e=\"open");
        let found: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(key, value)| (*key, value.as_ref()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("a", "1"),
                ("b", "two words"),
                ("c", "q\"x"),
                ("d", ""),
                ("e", "open")
            ]
        );
    }

    #[test]
    fn csv_columns_handle_quotes_and_empty_fields() {
        let columns = csv_columns("a,\"b,c\",,\"d\"\"e\",f", ',');
        let found: Vec<&str> = columns.iter().map(|value| value.as_ref()).collect();
        assert_eq!(found, vec!["a", "b,c", "", "d\"e", "f"]);
        assert_eq!(csv_columns("x\ty", '\t').len(), 2);
    }

    #[test]
    fn multibyte_text_does_not_break_tokenizers() {
        assert_eq!(kv_pairs("ă=ș src=1.2.3.4 ț")[1].1, "1.2.3.4");
        assert_eq!(csv_columns("ă;ș", ';')[1], "ș");
    }
}
