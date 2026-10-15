// =============================================================================
// parser_tools.rs - Subcomenzile `learn` si `test-parser`
// =============================================================================
//
// Ajuta un departament sa-si configureze parser-ul pornind de la un sample:
//
//   ids-rs learn sample.log
//       Detecteaza formatul (kv sau csv), listeaza campurile cu tipul si
//       exemple de valori si propune o sectiune [custom_parser]. Propunerea
//       este doar un punct de plecare - un om o verifica inainte de folosire.
//
//   ids-rs test-parser config.toml sample.log
//       Ruleaza parser-ul configurat (oricare, nu doar custom) pe sample si
//       arata cate linii sunt parsate, cu ce actiune, si exemple de linii
//       ignorate sau cu actiune nemapata.
//
// Sample-urile vin din alte sisteme: orice text afisat este escapat
// (display::printable) ca secventele de control sa nu ajunga in terminal.
//
// =============================================================================

use crate::config::{AppConfig, CustomFieldMap, CustomFormat, CustomParserConfig, FieldRef};
use crate::display::{printable, truncate_for_display};
use crate::parser::custom::{csv_columns, kv_pairs, CustomParser};
use crate::parser::{create_parser, Action, LogEvent, LogParser};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;

/// `learn` analizeaza doar inceputul fisierului - suficient pentru a vedea
/// structura, fara cost mare pe log-uri de mai multi GB.
const LEARN_MAX_LINES: usize = 10_000;
/// Limita de valori distincte retinute per camp (ex: porturi sursa).
const MAX_DISTINCT_VALUES: usize = 1_000;
const MAX_LISTED_FIELDS: usize = 40;
const EXAMPLES_PER_CATEGORY: usize = 5;
const LINE_DISPLAY_CHARS: usize = 160;
const VALUE_DISPLAY_CHARS: usize = 24;

const CSV_DELIMITERS: [char; 4] = [',', ';', '\t', '|'];

const SRC_NAMES: &[&str] = &[
    "src",
    "srcip",
    "src_ip",
    "source",
    "sourceip",
    "source_ip",
    "srcaddr",
    "src_addr",
    "saddr",
];
const DST_NAMES: &[&str] = &[
    "dst",
    "dstip",
    "dst_ip",
    "destination",
    "destinationip",
    "dest_ip",
    "dstaddr",
    "dst_addr",
    "daddr",
];
const PORT_NAMES: &[&str] = &[
    "dpt",
    "dstport",
    "dst_port",
    "dport",
    "destport",
    "dest_port",
    "destination_port",
    "service",
];
const PROTO_NAMES: &[&str] = &["proto", "protocol"];
const ACTION_NAMES: &[&str] = &["action", "act", "disposition", "fw_action"];

const DROP_WORDS: &[&str] = &[
    "drop",
    "dropped",
    "deny",
    "denied",
    "block",
    "blocked",
    "reject",
    "rejected",
    "discard",
    "reset-both",
    "reset-client",
    "reset-server",
];
/// "close"/"timeout" = sesiuni permise care s-au incheiat (FortiGate).
const ACCEPT_WORDS: &[&str] = &[
    "accept",
    "accepted",
    "allow",
    "allowed",
    "permit",
    "permitted",
    "pass",
    "close",
    "timeout",
];
const PROTOCOL_WORDS: &[&str] = &["tcp", "udp", "icmp", "icmp6", "ipv6-icmp", "sctp", "gre"];

/// Palo Alto TRAFFIC (PAN-OS syslog CSV): coloane stabile intre versiuni,
/// campurile noi se adauga doar la final.
const PALO_ALTO_TYPE_COLUMN: usize = 3;
const PALO_ALTO_COLUMNS: [usize; 5] = [7, 8, 25, 29, 30];

fn read_sample(path: &str, max_lines: usize) -> Result<Vec<String>> {
    let bytes = std::fs::read(Path::new(path))
        .with_context(|| format!("Nu pot citi sample-ul {path:?}"))?;
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(max_lines)
        .map(String::from)
        .collect())
}

fn shown(text: &str, max_chars: usize) -> String {
    printable(&truncate_for_display(text, max_chars)).into_owned()
}

// -----------------------------------------------------------------------------
// test-parser
// -----------------------------------------------------------------------------

/// Rezultatul rularii unui parser pe un sample.
#[derive(Debug, Default)]
pub struct ParseReport {
    pub total: usize,
    pub drop: usize,
    pub accept: usize,
    pub ignored: usize,
    /// Valoare de actiune nemapata → numar de linii.
    pub unmapped: BTreeMap<String, usize>,
    parsed_examples: Vec<(usize, LogEvent)>,
    unmapped_examples: Vec<(usize, String)>,
    ignored_examples: Vec<usize>,
}

impl ParseReport {
    pub fn parsed(&self) -> usize {
        self.drop + self.accept
    }

    pub fn unmapped_total(&self) -> usize {
        self.unmapped.values().sum()
    }
}

/// Ruleaza parser-ul pe fiecare linie. Parser-ul trebuie sa fie proaspat
/// creat, ca numaratoarea actiunilor nemapate sa inceapa de la zero.
pub fn evaluate(parser: &dyn LogParser, lines: &[String]) -> ParseReport {
    let mut report = ParseReport {
        total: lines.len(),
        ..ParseReport::default()
    };
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        match parser.parse(line) {
            Some(event) => {
                match event.action {
                    Action::Drop => report.drop += 1,
                    Action::Accept => report.accept += 1,
                }
                if report.parsed_examples.len() < EXAMPLES_PER_CATEGORY {
                    report.parsed_examples.push((number, event));
                }
            }
            None => match parser.take_unmapped_actions() {
                Some((_, value)) => {
                    if report.unmapped_examples.len() < EXAMPLES_PER_CATEGORY {
                        report.unmapped_examples.push((number, value.clone()));
                    }
                    *report.unmapped.entry(value).or_default() += 1;
                }
                None => {
                    report.ignored += 1;
                    if report.ignored_examples.len() < EXAMPLES_PER_CATEGORY {
                        report.ignored_examples.push(number);
                    }
                }
            },
        }
    }
    report
}

pub fn test_parser(config_path: &str, sample_path: &str) -> Result<()> {
    let config = AppConfig::load(config_path)?;
    let parser = create_parser(&config)?;
    let lines = read_sample(sample_path, usize::MAX)?;
    let report = evaluate(parser.as_ref(), &lines);

    println!(
        "Sample: {} — {} linii nevide, parser: {}\n",
        shown(sample_path, LINE_DISPLAY_CHARS),
        report.total,
        parser.name()
    );
    print!("{}", render_report(&report, &lines));

    if report.parsed() == 0 {
        anyhow::bail!("nicio linie nu a fost parsata — verifica network.parser si [custom_parser]");
    }
    Ok(())
}

fn render_report(report: &ParseReport, lines: &[String]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "  Parsate:          {:>7}  (drop {}, accept {})",
        report.parsed(),
        report.drop,
        report.accept
    );
    let _ = writeln!(out, "  Actiune nemapata: {:>7}", report.unmapped_total());
    let mut unmapped: Vec<(&String, &usize)> = report.unmapped.iter().collect();
    unmapped.sort_by(|left, right| right.1.cmp(left.1).then(left.0.cmp(right.0)));
    for (value, count) in unmapped.iter().take(10) {
        let _ = writeln!(
            out,
            "      {:?} ×{}",
            shown(value, VALUE_DISPLAY_CHARS),
            count
        );
    }
    let _ = writeln!(
        out,
        "  Ignorate:         {:>7}  (alt format, require_text lipsa, IP/port lipsa sau invalid)",
        report.ignored
    );

    if !report.parsed_examples.is_empty() {
        let _ = writeln!(out, "\nExemple parsate:");
        for (number, event) in &report.parsed_examples {
            let destination = event
                .dest_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "-".to_string());
            let _ = writeln!(
                out,
                "  linia {:<6} {:<6} {} → {}:{}/{}",
                number,
                event.action,
                event.source_ip,
                destination,
                event.dest_port,
                printable(&event.protocol)
            );
        }
    }
    if !report.unmapped_examples.is_empty() {
        let _ = writeln!(out, "\nExemple cu actiune nemapata:");
        for (number, value) in &report.unmapped_examples {
            let _ = writeln!(
                out,
                "  linia {:<6} {:?}",
                number,
                shown(value, VALUE_DISPLAY_CHARS)
            );
        }
    }
    if !report.ignored_examples.is_empty() {
        let _ = writeln!(out, "\nExemple ignorate:");
        for number in &report.ignored_examples {
            let _ = writeln!(
                out,
                "  linia {:<6} {}",
                number,
                shown(&lines[number - 1], LINE_DISPLAY_CHARS)
            );
        }
    }
    out
}

// -----------------------------------------------------------------------------
// learn
// -----------------------------------------------------------------------------

/// Statistici pentru un camp (cheie kv sau coloana csv) din sample.
#[derive(Debug)]
struct FieldStats {
    field: FieldRef,
    present: usize,
    ip: usize,
    port: usize,
    values: HashMap<String, usize>,
}

impl FieldStats {
    fn new(field: FieldRef) -> Self {
        Self {
            field,
            present: 0,
            ip: 0,
            port: 0,
            values: HashMap::new(),
        }
    }

    fn record(&mut self, value: &str) {
        let value = value.trim();
        self.present += 1;
        if value.parse::<IpAddr>().is_ok() {
            self.ip += 1;
        }
        if value.parse::<u16>().is_ok() {
            self.port += 1;
        }
        if let Some(count) = self.values.get_mut(value) {
            *count += 1;
        } else if self.values.len() < MAX_DISTINCT_VALUES {
            self.values.insert(value.to_string(), 1);
        }
    }

    /// Cel putin 90% din valori respecta tipul.
    fn mostly(&self, count: usize) -> bool {
        self.present > 0 && count * 10 >= self.present * 9
    }

    fn is_ip(&self) -> bool {
        self.mostly(self.ip)
    }

    fn is_port(&self) -> bool {
        self.mostly(self.port)
    }

    /// Ponderea liniilor a caror valoare (lowercase) este in `words`.
    fn share_of(&self, words: &[&str]) -> f64 {
        if self.present == 0 {
            return 0.0;
        }
        let hits: usize = self
            .values
            .iter()
            .filter(|(value, _)| words.contains(&value.to_ascii_lowercase().as_str()))
            .map(|(_, count)| count)
            .sum();
        hits as f64 / self.present as f64
    }

    fn action_share(&self) -> f64 {
        self.share_of(DROP_WORDS) + self.share_of(ACCEPT_WORDS)
    }

    /// Valorile distincte, cele mai frecvente primele.
    fn top_values(&self) -> Vec<(&str, usize)> {
        let mut values: Vec<(&str, usize)> = self
            .values
            .iter()
            .map(|(value, count)| (value.as_str(), *count))
            .collect();
        values.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(right.0)));
        values
    }

    fn kind(&self) -> &'static str {
        if self.is_ip() {
            "IP"
        } else if self.action_share() >= 0.5 {
            "actiune"
        } else if self.share_of(PROTOCOL_WORDS) >= 0.9 {
            "protocol"
        } else if self.is_port() {
            "numar/port"
        } else {
            "text"
        }
    }
}

/// Propunerea de configurare dedusa din sample.
#[derive(Debug, Default)]
pub struct Proposal {
    pub format: Option<CustomFormat>,
    pub delimiter: Option<char>,
    pub require_text: Option<String>,
    pub src_ip: Option<FieldRef>,
    pub dst_ip: Option<FieldRef>,
    pub dst_port: Option<FieldRef>,
    pub protocol: Option<FieldRef>,
    pub action: Option<FieldRef>,
    pub drop_values: Vec<String>,
    pub accept_values: Vec<String>,
    /// Valori ale campului de actiune pe care nu le-am putut clasifica.
    pub unknown_action_values: Vec<String>,
    pub action_from_text: BTreeMap<String, Action>,
    /// Lucruri ghicite care trebuie verificate de un om.
    pub notes: Vec<String>,
    pub lines_analyzed: usize,
    fields: Vec<FieldStats>,
}

impl Proposal {
    /// Configuratia completa, daca toate campurile obligatorii au fost gasite.
    pub fn to_config(&self) -> Option<CustomParserConfig> {
        Some(CustomParserConfig {
            format: self.format?,
            delimiter: self.delimiter,
            require_text: self.require_text.clone(),
            fields: CustomFieldMap {
                src_ip: self.src_ip.clone()?,
                dst_ip: self.dst_ip.clone()?,
                dst_port: self.dst_port.clone()?,
                protocol: self.protocol.clone(),
                action: self.action.clone(),
            },
            drop_values: self.drop_values.clone(),
            accept_values: self.accept_values.clone(),
            action_from_text: self.action_from_text.clone(),
        })
    }
}

/// Detecteaza formatul: kv daca majoritatea liniilor au >= 3 perechi
/// cheie=valoare, altfel csv cu delimitatorul care da cel mai consistent
/// numar de coloane (>= 5).
fn detect_format(lines: &[String]) -> Option<(CustomFormat, Option<char>)> {
    let kv_lines = lines
        .iter()
        .filter(|line| kv_pairs(line).len() >= 3)
        .count();
    if kv_lines * 10 >= lines.len() * 8 {
        return Some((CustomFormat::Kv, None));
    }

    let mut best: Option<(char, usize)> = None;
    for delimiter in CSV_DELIMITERS {
        let mut column_counts: HashMap<usize, usize> = HashMap::new();
        for line in lines {
            *column_counts
                .entry(csv_columns(line, delimiter).len())
                .or_default() += 1;
        }
        let Some((&columns, &lines_with_count)) = column_counts
            .iter()
            .max_by_key(|(columns, count)| (**count, **columns))
        else {
            continue;
        };
        if columns >= 5
            && lines_with_count * 2 >= lines.len()
            && best.is_none_or(|(_, best_columns)| columns > best_columns)
        {
            best = Some((delimiter, columns));
        }
    }
    best.map(|(delimiter, _)| {
        let delimiter = (delimiter != ',').then_some(delimiter);
        (CustomFormat::Csv, delimiter)
    })
}

fn collect_fields(lines: &[String], format: CustomFormat, delimiter: char) -> Vec<FieldStats> {
    let mut fields: Vec<FieldStats> = Vec::new();
    let mut positions: HashMap<FieldRef, usize> = HashMap::new();
    let mut record = |field: FieldRef, value: &str| {
        let index = *positions.entry(field.clone()).or_insert_with(|| {
            fields.push(FieldStats::new(field));
            fields.len() - 1
        });
        fields[index].record(value);
    };
    for line in lines {
        match format {
            CustomFormat::Kv => {
                let mut seen = Vec::new();
                for (key, value) in kv_pairs(line) {
                    // Prima aparitie a unei chei, ca in CustomParser.
                    if !seen.contains(&key) {
                        seen.push(key);
                        record(FieldRef::Key(key.to_string()), &value);
                    }
                }
            }
            CustomFormat::Csv => {
                for (index, value) in csv_columns(line, delimiter).iter().enumerate() {
                    record(FieldRef::Column(index), value);
                }
            }
        }
    }
    if format == CustomFormat::Csv {
        fields.sort_by_key(|stats| match stats.field {
            FieldRef::Column(index) => index,
            FieldRef::Key(_) => usize::MAX,
        });
    }
    fields
}

/// Analizeaza liniile si construieste propunerea. Err daca formatul nu
/// poate fi recunoscut deloc.
pub fn propose(lines: &[String]) -> Result<Proposal> {
    if lines.is_empty() {
        anyhow::bail!("sample-ul nu contine nicio linie");
    }
    let (format, delimiter) = detect_format(lines).context(
        "format nerecunoscut: liniile nu sunt nici cheie=valoare, nici CSV consistent — \
         scrie sectiunea [custom_parser] manual",
    )?;
    let fields = collect_fields(lines, format, delimiter.unwrap_or(','));
    let mut proposal = Proposal {
        format: Some(format),
        delimiter,
        lines_analyzed: lines.len(),
        ..Proposal::default()
    };

    if lines.iter().filter(|line| line.contains("CEF:")).count() * 2 >= lines.len() {
        proposal.notes.push(
            "liniile par CEF: incearca intai parser = \"cef\" sau \"gaia_cef\" cu test-parser"
                .to_string(),
        );
    }

    match format {
        CustomFormat::Kv => propose_kv(&mut proposal, &fields, lines),
        CustomFormat::Csv => propose_csv(&mut proposal, &fields),
    }

    if let Some(action) = &proposal.action {
        let stats = fields
            .iter()
            .find(|stats| &stats.field == action)
            .expect("campul de actiune provine din lista de campuri");
        for (value, _) in stats.top_values() {
            let lower = value.to_ascii_lowercase();
            if DROP_WORDS.contains(&lower.as_str()) {
                proposal.drop_values.push(value.to_string());
            } else if ACCEPT_WORDS.contains(&lower.as_str()) {
                proposal.accept_values.push(value.to_string());
            } else {
                proposal.unknown_action_values.push(value.to_string());
            }
        }
        proposal.drop_values.sort();
        proposal.accept_values.sort();
    }

    for (name, field) in [
        ("src_ip", &proposal.src_ip),
        ("dst_ip", &proposal.dst_ip),
        ("dst_port", &proposal.dst_port),
    ] {
        if field.is_none() {
            proposal.notes.push(format!(
                "TODO: nu am gasit {name} — completeaza manual in fields"
            ));
        }
    }
    if proposal.action.is_none() && proposal.action_from_text.is_empty() {
        proposal.notes.push(
            "TODO: nu am gasit actiunea — seteaza fields.action sau action_from_text".to_string(),
        );
    }

    proposal.fields = fields;
    Ok(proposal)
}

fn by_name<'a>(fields: &'a [FieldStats], names: &[&str]) -> Option<&'a FieldStats> {
    // Ordinea din lista de nume = prioritate (ex: "dpt" inaintea lui "service").
    names.iter().find_map(|name| {
        fields.iter().find(
            |stats| matches!(&stats.field, FieldRef::Key(key) if key.eq_ignore_ascii_case(name)),
        )
    })
}

fn propose_kv(proposal: &mut Proposal, fields: &[FieldStats], lines: &[String]) {
    let ip_fields: Vec<&FieldStats> = fields.iter().filter(|stats| stats.is_ip()).collect();

    proposal.src_ip = by_name(fields, SRC_NAMES)
        .filter(|stats| stats.is_ip())
        .map(|stats| stats.field.clone());
    proposal.dst_ip = by_name(fields, DST_NAMES)
        .filter(|stats| stats.is_ip())
        .map(|stats| stats.field.clone());
    if proposal.src_ip.is_none() || proposal.dst_ip.is_none() {
        // Fara nume cunoscute: primul si al doilea camp IP, in ordinea din linie.
        let taken = [proposal.src_ip.clone(), proposal.dst_ip.clone()];
        let mut unused = ip_fields
            .iter()
            .filter(|stats| !taken.contains(&Some(stats.field.clone())));
        if proposal.src_ip.is_none() {
            proposal.src_ip = unused.next().map(|stats| stats.field.clone());
            if let Some(field) = &proposal.src_ip {
                proposal.notes.push(format!(
                    "VERIFICA: src_ip = {field} ghicit dupa ordine (primul camp cu IP-uri)"
                ));
            }
        }
        if proposal.dst_ip.is_none() {
            proposal.dst_ip = unused.next().map(|stats| stats.field.clone());
            if let Some(field) = &proposal.dst_ip {
                proposal.notes.push(format!(
                    "VERIFICA: dst_ip = {field} ghicit dupa ordine (urmatorul camp cu IP-uri)"
                ));
            }
        }
    }

    proposal.dst_port = PORT_NAMES.iter().find_map(|name| {
        by_name(fields, &[name])
            .filter(|stats| stats.is_port())
            .map(|stats| stats.field.clone())
    });
    proposal.protocol = by_name(fields, PROTO_NAMES).map(|stats| stats.field.clone());

    let named_action = by_name(fields, ACTION_NAMES).filter(|stats| stats.action_share() > 0.0);
    proposal.action = named_action
        .or_else(|| best_action_field(fields))
        .map(|stats| stats.field.clone());
    if let (Some(field), None) = (&proposal.action, named_action) {
        proposal.notes.push(format!(
            "VERIFICA: action = {field} ales dupa valori (drop/accept), nu dupa nume"
        ));
    }
    if proposal.action.is_none() {
        proposal.action_from_text = action_text_markers(lines);
        if !proposal.action_from_text.is_empty() {
            proposal.notes.push(
                "VERIFICA: actiunea e dedusa din text fara '=' (ex: --log-prefix la iptables)"
                    .to_string(),
            );
        }
    }

    // Ex. FortiGate: type="traffic" separa log-urile de trafic de cele de sistem.
    if let Some(type_field) = by_name(fields, &["type"]) {
        if let (FieldRef::Key(key), Some((value, _))) = (
            &type_field.field,
            type_field
                .top_values()
                .into_iter()
                .find(|(value, _)| value.eq_ignore_ascii_case("traffic")),
        ) {
            proposal.require_text = [format!("{key}=\"{value}\""), format!("{key}={value}")]
                .into_iter()
                .find(|text| lines.iter().any(|line| line.contains(text.as_str())));
        }
    }
}

fn propose_csv(proposal: &mut Proposal, fields: &[FieldStats]) {
    let column = |index: usize| {
        fields
            .iter()
            .find(|stats| stats.field == FieldRef::Column(index))
    };

    let palo_alto = column(PALO_ALTO_TYPE_COLUMN).is_some_and(|stats| {
        stats.values.contains_key("TRAFFIC")
            && column(PALO_ALTO_COLUMNS[0]).is_some_and(FieldStats::is_ip)
            && column(PALO_ALTO_COLUMNS[2]).is_some_and(FieldStats::is_port)
    });
    if palo_alto {
        let [src, dst, port, protocol, action] = PALO_ALTO_COLUMNS.map(FieldRef::Column);
        proposal.src_ip = Some(src);
        proposal.dst_ip = Some(dst);
        proposal.dst_port = Some(port);
        proposal.protocol = Some(protocol);
        proposal.action = Some(action);
        let delimiter = proposal.delimiter.unwrap_or(',');
        proposal.require_text = Some(format!("{delimiter}TRAFFIC{delimiter}"));
        proposal
            .notes
            .push("recunoscut: Palo Alto TRAFFIC (pozitii standard PAN-OS)".to_string());
        return;
    }

    let ip_columns: Vec<&FieldStats> = fields.iter().filter(|stats| stats.is_ip()).collect();
    proposal.src_ip = ip_columns.first().map(|stats| stats.field.clone());
    proposal.dst_ip = ip_columns.get(1).map(|stats| stats.field.clone());

    // Portul destinatie: coloana numerica cu cele mai multe porturi de
    // servicii (<= 1024); porturile sursa sunt de obicei efemere (> 1024).
    proposal.dst_port = fields
        .iter()
        .filter(|stats| stats.is_port())
        .map(|stats| {
            let service: usize = stats
                .values
                .iter()
                .filter(|(value, _)| value.parse::<u16>().is_ok_and(|port| port <= 1024))
                .map(|(_, count)| count)
                .sum();
            (stats, service)
        })
        .filter(|(_, service)| *service > 0)
        .max_by_key(|(_, service)| *service)
        .map(|(stats, _)| stats.field.clone());

    proposal.protocol = fields
        .iter()
        .find(|stats| stats.share_of(PROTOCOL_WORDS) >= 0.9)
        .map(|stats| stats.field.clone());
    proposal.action = best_action_field(fields).map(|stats| stats.field.clone());

    proposal.notes.push(
        "VERIFICA: la CSV coloanele sunt ghicite dupa continut — compara cu tabelul de mai sus"
            .to_string(),
    );
}

/// Campul ale carui valori sunt in cea mai mare parte cuvinte drop/accept.
/// La egalitate castiga ultimul (actiunea finala e de obicei dupa subtipuri).
fn best_action_field(fields: &[FieldStats]) -> Option<&FieldStats> {
    fields
        .iter()
        .filter(|stats| stats.action_share() >= 0.5 && stats.values.len() <= 50)
        .max_by(|left, right| left.action_share().total_cmp(&right.action_share()))
}

/// Pentru log-uri fara camp de actiune: token-uri fara `=` (ex: prefixul
/// iptables "FW-DROP:") care contin un cuvant de tip drop/accept.
fn action_text_markers(lines: &[String]) -> BTreeMap<String, Action> {
    let mut markers = BTreeMap::new();
    for line in lines {
        for token in line.split_whitespace().filter(|token| !token.contains('=')) {
            let token = token.trim_end_matches(':');
            let lower = token.to_ascii_lowercase();
            let action = if ["drop", "deny", "block", "reject"]
                .iter()
                .any(|word| lower.contains(word))
            {
                Action::Drop
            } else if ["accept", "allow", "permit"]
                .iter()
                .any(|word| lower.contains(word))
            {
                Action::Accept
            } else {
                continue;
            };
            markers.insert(token.to_string(), action);
        }
    }
    markers
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

fn toml_key(key: &str) -> String {
    let bare = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if bare {
        key.to_string()
    } else {
        toml_string(key)
    }
}

fn toml_field(field: &FieldRef) -> String {
    match field {
        FieldRef::Key(key) => toml_string(key),
        FieldRef::Column(index) => index.to_string(),
    }
}

fn toml_list(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| toml_string(value)).collect();
    format!("[{}]", items.join(", "))
}

/// Sectiunea [custom_parser] propusa, ca text TOML (cu notele ca comentarii).
pub fn render_proposal(proposal: &Proposal, sample_path: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Propunere generata de `ids-rs learn` din {} ({} linii analizate).",
        shown(sample_path, LINE_DISPLAY_CHARS),
        proposal.lines_analyzed
    );
    let _ = writeln!(
        out,
        "# Verifica fiecare camp, apoi ruleaza: ids-rs test-parser config.toml <sample>"
    );
    for note in &proposal.notes {
        let _ = writeln!(out, "# {}", printable(note));
    }
    let _ = writeln!(out, "[custom_parser]");
    let format = match proposal.format {
        Some(CustomFormat::Kv) => "kv",
        Some(CustomFormat::Csv) | None => "csv",
    };
    let _ = writeln!(out, "format = \"{format}\"");
    if let Some(delimiter) = proposal.delimiter {
        let _ = writeln!(out, "delimiter = {}", toml_string(&delimiter.to_string()));
    }
    if let Some(text) = &proposal.require_text {
        let _ = writeln!(out, "require_text = {}", toml_string(text));
    }

    let mut fields = Vec::new();
    for (name, field) in [
        ("src_ip", &proposal.src_ip),
        ("dst_ip", &proposal.dst_ip),
        ("dst_port", &proposal.dst_port),
        ("protocol", &proposal.protocol),
        ("action", &proposal.action),
    ] {
        if let Some(field) = field {
            fields.push(format!("{name} = {}", toml_field(field)));
        }
    }
    let _ = writeln!(out, "fields = {{ {} }}", fields.join(", "));

    if proposal.action.is_some() {
        let _ = writeln!(out, "drop_values = {}", toml_list(&proposal.drop_values));
        let _ = writeln!(
            out,
            "accept_values = {}",
            toml_list(&proposal.accept_values)
        );
        if !proposal.unknown_action_values.is_empty() {
            let _ = writeln!(
                out,
                "# Valori de actiune neclasificate (ignorate daca nu le muti mai sus): {}",
                printable(&toml_list(&proposal.unknown_action_values))
            );
        }
    }
    if !proposal.action_from_text.is_empty() {
        let markers: Vec<String> = proposal
            .action_from_text
            .iter()
            .map(|(text, action)| format!("{} = \"{}\"", toml_key(text), action))
            .collect();
        let _ = writeln!(out, "action_from_text = {{ {} }}", markers.join(", "));
    }
    out
}

fn render_fields(proposal: &Proposal) -> String {
    let mut out = String::new();
    let mut fields: Vec<&FieldStats> = proposal.fields.iter().collect();
    if proposal.format == Some(CustomFormat::Kv) {
        // Cele mai frecvente chei primele; la egalitate, ordinea din linie.
        fields.sort_by(|left, right| right.present.cmp(&left.present));
    }
    let _ = writeln!(
        out,
        "  {:<24} {:>8}  {:<11} exemple",
        "camp", "prezent", "tip"
    );
    for stats in fields.iter().take(MAX_LISTED_FIELDS) {
        let examples: Vec<String> = stats
            .top_values()
            .into_iter()
            .take(3)
            .map(|(value, _)| format!("{:?}", shown(value, VALUE_DISPLAY_CHARS)))
            .collect();
        let percent = stats.present * 100 / proposal.lines_analyzed.max(1);
        let _ = writeln!(
            out,
            "  {:<24} {:>7}%  {:<11} {}",
            shown(&stats.field.to_string(), 24),
            percent,
            stats.kind(),
            examples.join(", ")
        );
    }
    if fields.len() > MAX_LISTED_FIELDS {
        let _ = writeln!(
            out,
            "  ... si inca {} campuri",
            fields.len() - MAX_LISTED_FIELDS
        );
    }
    out
}

pub fn learn(sample_path: &str) -> Result<()> {
    let lines = read_sample(sample_path, LEARN_MAX_LINES)?;
    let proposal = propose(&lines)?;

    let format = match (proposal.format, proposal.delimiter) {
        (Some(CustomFormat::Kv), _) => "cheie=valoare (kv)".to_string(),
        (_, Some(delimiter)) => format!("CSV, delimitator {delimiter:?}"),
        _ => "CSV, delimitator ','".to_string(),
    };
    println!(
        "Analizat {} linii din {} — format: {}\n",
        lines.len(),
        shown(sample_path, LINE_DISPLAY_CHARS),
        format
    );
    println!("Campuri gasite (coloanele CSV numarate de la 0):");
    println!("{}", render_fields(&proposal));
    println!("{}", render_proposal(&proposal, sample_path));

    match proposal.to_config() {
        Some(config) => {
            let mut errors = Vec::new();
            config.validate(&mut errors);
            if errors.is_empty() {
                let report = evaluate(&CustomParser::new(&config), &lines);
                println!(
                    "Cu aceasta propunere: {}/{} linii parsate (drop {}, accept {}), \
                     {} cu actiune nemapata, {} ignorate.",
                    report.parsed(),
                    report.total,
                    report.drop,
                    report.accept,
                    report.unmapped_total(),
                    report.ignored
                );
            } else {
                println!("Propunerea nu este inca valida:");
                for error in errors {
                    println!("  - {error}");
                }
            }
        }
        None => println!("Propunerea este incompleta — vezi notele TODO de mai sus."),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(String::from)
            .collect()
    }

    /// Propunerea randata trebuie sa fie TOML valid care se deserializeaza
    /// exact in configuratia propusa.
    fn assert_round_trip(proposal: &Proposal) -> CustomParserConfig {
        let expected = proposal.to_config().expect("propunere completa");
        let rendered = render_proposal(proposal, "sample.log");
        #[derive(serde::Deserialize)]
        struct Wrapper {
            custom_parser: CustomParserConfig,
        }
        let parsed: Wrapper =
            toml::from_str(&rendered).unwrap_or_else(|error| panic!("{error}\n{rendered}"));
        assert_eq!(parsed.custom_parser, expected);
        let mut errors = Vec::new();
        expected.validate(&mut errors);
        assert!(errors.is_empty(), "{errors:?}\n{rendered}");
        expected
    }

    const FORTIGATE: &str = r#"
        <189>date=2026-10-15 time=10:00:01 devname="FG100F" type="traffic" subtype="forward" srcip=192.168.1.50 srcport=51234 dstip=10.0.0.1 dstport=22 proto=6 action="deny" service="SSH"
        <189>date=2026-10-15 time=10:00:02 devname="FG100F" type="traffic" subtype="forward" srcip=192.168.1.51 srcport=51235 dstip=10.0.0.2 dstport=443 proto=6 action="accept" service="HTTPS"
        <189>date=2026-10-15 time=10:00:03 devname="FG100F" type="traffic" subtype="forward" srcip=192.168.1.52 srcport=51236 dstip=10.0.0.3 dstport=80 proto=6 action="close" service="HTTP"
        <189>date=2026-10-15 time=10:00:04 devname="FG100F" type="traffic" subtype="forward" srcip=192.168.1.53 srcport=51237 dstip=10.0.0.4 dstport=53 proto=17 action="server-rst" service="DNS"
        <189>date=2026-10-15 time=10:00:05 devname="FG100F" type="event" subtype="system" logdesc="Admin login" user="admin"
    "#;

    #[test]
    fn learns_fortigate_mapping_by_field_names() {
        let sample = lines(FORTIGATE);
        let proposal = propose(&sample).unwrap();
        let key = |name: &str| Some(FieldRef::Key(name.to_string()));
        assert_eq!(proposal.format, Some(CustomFormat::Kv));
        assert_eq!(proposal.src_ip, key("srcip"));
        assert_eq!(proposal.dst_ip, key("dstip"));
        // "dstport" are prioritate fata de "service" (care aici e text).
        assert_eq!(proposal.dst_port, key("dstport"));
        assert_eq!(proposal.protocol, key("proto"));
        assert_eq!(proposal.action, key("action"));
        assert_eq!(proposal.drop_values, vec!["deny"]);
        assert_eq!(proposal.accept_values, vec!["accept", "close"]);
        assert_eq!(proposal.unknown_action_values, vec!["server-rst"]);
        assert_eq!(proposal.require_text.as_deref(), Some("type=\"traffic\""));

        let config = assert_round_trip(&proposal);
        let report = evaluate(&CustomParser::new(&config), &sample);
        assert_eq!((report.drop, report.accept), (1, 2));
        assert_eq!(report.unmapped.get("server-rst"), Some(&1));
        assert_eq!(report.ignored, 1);
    }

    #[test]
    fn learns_iptables_action_from_log_prefix() {
        let sample = lines(
            "Oct 15 10:00:00 gw kernel: [100.1] FW-DROP: IN=eth0 OUT= SRC=192.168.1.50 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=51234 DPT=22
             Oct 15 10:00:01 gw kernel: [100.2] FW-ACCEPT: IN=eth0 OUT= SRC=192.168.1.51 DST=10.0.0.2 LEN=60 PROTO=TCP SPT=51235 DPT=443
             Oct 15 10:00:02 gw kernel: [100.3] FW-DROP: IN=eth0 OUT= SRC=192.168.1.52 DST=10.0.0.3 LEN=60 PROTO=UDP SPT=51236 DPT=53",
        );
        let proposal = propose(&sample).unwrap();
        assert_eq!(proposal.src_ip, Some(FieldRef::Key("SRC".to_string())));
        assert_eq!(proposal.dst_port, Some(FieldRef::Key("DPT".to_string())));
        assert_eq!(proposal.action, None);
        assert_eq!(
            proposal.action_from_text,
            BTreeMap::from([
                ("FW-ACCEPT".to_string(), Action::Accept),
                ("FW-DROP".to_string(), Action::Drop),
            ])
        );
        let config = assert_round_trip(&proposal);
        assert_eq!(evaluate(&CustomParser::new(&config), &sample).parsed(), 3);
    }

    #[test]
    fn recognizes_palo_alto_traffic_csv() {
        let row = |subtype: &str, src: &str, port: u16, action: &str| {
            format!(
                "<14>Oct 15 10:00:00 PA-VM 1,2026/10/15 10:00:00,012801000001,TRAFFIC,{subtype},\
                 2561,2026/10/15 10:00:00,{src},10.0.0.1,0.0.0.0,0.0.0.0,rule1,,,\
                 ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Forward,2026/10/15 10:00:00,\
                 12345,1,51234,{port},0,0,0x0,tcp,{action},74,74,0"
            )
        };
        let sample = vec![
            row("drop", "192.168.1.50", 445, "deny"),
            row("end", "192.168.1.51", 443, "allow"),
            row("drop", "192.168.1.52", 22, "drop"),
        ];
        let proposal = propose(&sample).unwrap();
        assert_eq!(proposal.format, Some(CustomFormat::Csv));
        assert_eq!(proposal.src_ip, Some(FieldRef::Column(7)));
        assert_eq!(proposal.dst_port, Some(FieldRef::Column(25)));
        assert_eq!(proposal.action, Some(FieldRef::Column(30)));
        assert_eq!(proposal.require_text.as_deref(), Some(",TRAFFIC,"));
        let config = assert_round_trip(&proposal);
        assert_eq!(evaluate(&CustomParser::new(&config), &sample).parsed(), 3);
    }

    #[test]
    fn guesses_generic_csv_columns_by_content() {
        let sample = lines(
            "2026-10-15T10:00:00;fw1;192.168.1.50;51234;10.0.0.1;22;TCP;BLOCK
             2026-10-15T10:00:01;fw1;192.168.1.51;51235;10.0.0.2;443;TCP;ALLOW
             2026-10-15T10:00:02;fw1;192.168.1.52;51236;10.0.0.3;3389;TCP;BLOCK",
        );
        let proposal = propose(&sample).unwrap();
        assert_eq!(proposal.delimiter, Some(';'));
        assert_eq!(proposal.src_ip, Some(FieldRef::Column(2)));
        assert_eq!(proposal.dst_ip, Some(FieldRef::Column(4)));
        assert_eq!(proposal.dst_port, Some(FieldRef::Column(5)));
        assert_eq!(proposal.protocol, Some(FieldRef::Column(6)));
        assert_eq!(proposal.action, Some(FieldRef::Column(7)));
        assert!(proposal
            .notes
            .iter()
            .any(|note| note.starts_with("VERIFICA")));
        let config = assert_round_trip(&proposal);
        assert_eq!(evaluate(&CustomParser::new(&config), &sample).parsed(), 3);
    }

    #[test]
    fn missing_fields_are_reported_as_todo() {
        let sample = lines(
            "host=a user=x result=ok
             host=b user=y result=ok",
        );
        let proposal = propose(&sample).unwrap();
        assert!(proposal.to_config().is_none());
        assert!(proposal
            .notes
            .iter()
            .any(|note| note.contains("TODO: nu am gasit src_ip")));
    }

    #[test]
    fn unrecognized_format_is_an_error() {
        let sample = lines("just some text\nanother free text line");
        assert!(propose(&sample).is_err());
        assert!(propose(&[]).is_err());
    }

    #[test]
    fn rendered_proposal_escapes_untrusted_text() {
        let proposal = Proposal {
            format: Some(CustomFormat::Kv),
            src_ip: Some(FieldRef::Key("s\"rc".to_string())),
            dst_ip: Some(FieldRef::Key("dst".to_string())),
            dst_port: Some(FieldRef::Key("dpt".to_string())),
            action_from_text: BTreeMap::from([("FW DROP\"x".to_string(), Action::Drop)]),
            notes: vec!["linie\u{1b}[2J".to_string()],
            ..Proposal::default()
        };
        let rendered = render_proposal(&proposal, "sample.log");
        assert!(!rendered.contains('\u{1b}'));
        assert_round_trip(&proposal);
    }

    #[test]
    fn report_counts_parsed_unmapped_and_ignored_lines() {
        let config = CustomParserConfig {
            format: CustomFormat::Kv,
            delimiter: None,
            require_text: None,
            fields: CustomFieldMap {
                src_ip: FieldRef::Key("src".to_string()),
                dst_ip: FieldRef::Key("dst".to_string()),
                dst_port: FieldRef::Key("dpt".to_string()),
                protocol: None,
                action: Some(FieldRef::Key("act".to_string())),
            },
            drop_values: vec!["deny".to_string()],
            accept_values: vec!["allow".to_string()],
            action_from_text: BTreeMap::new(),
        };
        let sample = lines(
            "src=1.1.1.1 dst=2.2.2.2 dpt=22 act=deny
             src=1.1.1.1 dst=2.2.2.2 dpt=80 act=allow
             src=1.1.1.1 dst=2.2.2.2 dpt=81 act=reset
             src=1.1.1.1 dst=2.2.2.2 dpt=82 act=reset
             garbage line",
        );
        let report = evaluate(&CustomParser::new(&config), &sample);
        assert_eq!((report.drop, report.accept, report.ignored), (1, 1, 1));
        assert_eq!(report.unmapped.get("reset"), Some(&2));
        let rendered = render_report(&report, &sample);
        assert!(rendered.contains("\"reset\" ×2"));
        assert!(rendered.contains("linia 5"));
    }
}
