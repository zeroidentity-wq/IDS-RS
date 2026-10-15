// =============================================================================
// stats.rs - Statistici de parsare
// =============================================================================
//
// Fiecare linie data parser-ului ajunge in exact una dintre categorii:
//   - parsata:          a devenit LogEvent si a mers la detector;
//   - actiune nemapata: linia era valida, dar actiunea nu e drop/accept in
//                       configuratie (vezi LogParser::take_unmapped_actions);
//   - ignorata:         alt format, alt tip de log, IP/port lipsa sau invalid.
//
// Fara aceste cifre, o schimbare de format la firewall (ex: update de
// firmware) ar opri detectia fara niciun semn: liniile ar fi ignorate in
// tacere. Contorii sunt cumulati de la pornire (expusi in /api/stats), iar
// bucla principala raporteaza diferenta la fiecare 30 de secunde.
//
// =============================================================================

use crate::display::truncate_for_display;
use crate::parser::{LogEvent, LogParser};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Lungimea exemplului de linie ignorata pastrat pentru raportare.
const SAMPLE_CHARS: usize = 160;

/// Contori cumulati, partajati intre bucla UDP si dashboard.
///
/// NOTA RUST: `AtomicU64` permite incrementarea din bucla principala si
/// citirea din handler-ele web fara Mutex. `Ordering::Relaxed` ajunge:
/// fiecare contor este independent, nu sincronizeaza alte date.
#[derive(Debug, Default)]
pub struct ParseStats {
    parsed: AtomicU64,
    unmapped: AtomicU64,
    ignored: AtomicU64,
}

/// Valorile contorilor la un moment dat (sau diferenta dintre doua momente).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ParseCounts {
    pub lines: u64,
    pub parsed: u64,
    pub unmapped: u64,
    pub ignored: u64,
}

impl ParseStats {
    pub fn snapshot(&self) -> ParseCounts {
        let parsed = self.parsed.load(Ordering::Relaxed);
        let unmapped = self.unmapped.load(Ordering::Relaxed);
        let ignored = self.ignored.load(Ordering::Relaxed);
        ParseCounts {
            lines: parsed + unmapped + ignored,
            parsed,
            unmapped,
            ignored,
        }
    }
}

impl ParseCounts {
    /// Ce s-a adunat de la `earlier` pana la `self`.
    pub fn since(self, earlier: ParseCounts) -> ParseCounts {
        ParseCounts {
            lines: self.lines.saturating_sub(earlier.lines),
            parsed: self.parsed.saturating_sub(earlier.parsed),
            unmapped: self.unmapped.saturating_sub(earlier.unmapped),
            ignored: self.ignored.saturating_sub(earlier.ignored),
        }
    }
}

/// Exemple din fereastra curenta de raportare, golite dupa fiecare raport.
#[derive(Debug, Default)]
pub struct ParseSamples {
    /// Prima linie ignorata din fereastra (trunchiata).
    pub ignored_line: Option<String>,
    /// Ultima valoare de actiune nemapata din fereastra.
    pub unmapped_action: Option<String>,
}

/// Parseaza o linie si o numara in categoria potrivita.
pub fn parse_line(
    parser: &dyn LogParser,
    line: &str,
    stats: &ParseStats,
    samples: &mut ParseSamples,
) -> Option<LogEvent> {
    if let Some(event) = parser.parse(line) {
        stats.parsed.fetch_add(1, Ordering::Relaxed);
        return Some(event);
    }
    match parser.take_unmapped_actions() {
        Some((count, value)) => {
            stats.unmapped.fetch_add(count, Ordering::Relaxed);
            samples.unmapped_action = Some(value);
        }
        None => {
            stats.ignored.fetch_add(1, Ordering::Relaxed);
            if samples.ignored_line.is_none() {
                samples.ignored_line = Some(truncate_for_display(line, SAMPLE_CHARS));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CustomFieldMap, CustomFormat, CustomParserConfig, FieldRef};
    use crate::parser::custom::CustomParser;
    use std::collections::BTreeMap;

    fn parser() -> CustomParser {
        let key = |name: &str| FieldRef::Key(name.to_string());
        CustomParser::new(&CustomParserConfig {
            format: CustomFormat::Kv,
            delimiter: None,
            require_text: None,
            fields: CustomFieldMap {
                src_ip: key("src"),
                dst_ip: key("dst"),
                dst_port: key("dpt"),
                protocol: None,
                action: Some(key("act")),
            },
            drop_values: vec!["deny".to_string()],
            accept_values: vec!["allow".to_string()],
            action_from_text: BTreeMap::new(),
        })
    }

    #[test]
    fn every_line_lands_in_exactly_one_category() {
        let parser = parser();
        let stats = ParseStats::default();
        let mut samples = ParseSamples::default();
        let lines = [
            "src=1.1.1.1 dst=2.2.2.2 dpt=22 act=deny",
            "src=1.1.1.1 dst=2.2.2.2 dpt=80 act=allow",
            "src=1.1.1.1 dst=2.2.2.2 dpt=81 act=reset",
            "first garbage line",
            "second garbage line",
        ];
        let events = lines
            .iter()
            .filter_map(|line| parse_line(&parser, line, &stats, &mut samples))
            .count();

        assert_eq!(events, 2);
        assert_eq!(
            stats.snapshot(),
            ParseCounts {
                lines: 5,
                parsed: 2,
                unmapped: 1,
                ignored: 2
            }
        );
        assert_eq!(samples.unmapped_action.as_deref(), Some("reset"));
        assert_eq!(samples.ignored_line.as_deref(), Some("first garbage line"));
    }

    #[test]
    fn window_counts_are_differences_between_snapshots() {
        let parser = parser();
        let stats = ParseStats::default();
        let mut samples = ParseSamples::default();
        parse_line(&parser, "garbage", &stats, &mut samples);
        let before = stats.snapshot();
        parse_line(
            &parser,
            "src=1.1.1.1 dst=2.2.2.2 dpt=22 act=deny",
            &stats,
            &mut samples,
        );
        assert_eq!(
            stats.snapshot().since(before),
            ParseCounts {
                lines: 1,
                parsed: 1,
                unmapped: 0,
                ignored: 0
            }
        );
    }

    #[test]
    fn ignored_sample_is_truncated() {
        let parser = parser();
        let stats = ParseStats::default();
        let mut samples = ParseSamples::default();
        parse_line(&parser, &"x".repeat(1_000), &stats, &mut samples);
        assert!(samples.ignored_line.unwrap().chars().count() <= SAMPLE_CHARS + 3);
    }
}
