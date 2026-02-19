// =============================================================================
// display.rs - Interfata CLI Moderna cu Culori ANSI
// =============================================================================
//
// Acest modul gestioneaza TOATA iesirea vizuala catre terminal:
//   - Banner-ul de start (cu informatii de configurare)
//   - Log-uri de stare formatate cu culori si badge-uri
//   - Alerte de securitate vizual distincte (Fast/Slow Scan)
//   - Statistici periodice si evenimente de drop
//
// DESIGN: Separarea logicii de afisare de logica de business.
// Modulul display.rs nu stie NIMIC despre parsare sau detectie -
// primeste date formatate si le afiseaza frumos. Aceasta separare
// face codul mai testabil si mai usor de modificat.
//
// NOTA RUST - CRATE-ul `colored`:
// Extinde &str si String cu metode de colorare:
//   "text".red()              -> ColoredString (rosu)
//   "text".bold()             -> ColoredString (bold)
//   " INFO ".on_green()       -> fundal verde (badge vizual)
//   "text".red().bold()       -> combinatie (rosu + bold)
//   "text".dimmed()           -> gri/atenuat
//
// ColoredString implementeaza Display, deci poate fi folosit direct
// in println!() si format!(). La runtime, adauga secvente escape
// ANSI (\x1b[31m etc.) in jurul textului.
//
// Detectia automata TTY: colored dezactiveaza culorile cand output-ul
// este redirectat (pipe/fisier), evitand caractere ANSI in loguri.
//
// =============================================================================

use crate::config::AppConfig;
use crate::detector::{Alert, ScanType};
use crate::parser::LogEvent;
use chrono::Local;
use colored::*;

/// Latimea separatorului orizontal (in caractere).
const SEPARATOR_WIDTH: usize = 120;

// ---------------------------------------------------------------------------
// Banner-ul de pornire al aplicatiei
//
// `r#"..."#` = raw string literal: nu necesita escape pentru backslash/ghilimele
// Caracterele box-drawing (╔, ═, etc.) sunt Unicode standard
// ---------------------------------------------------------------------------

/// Afiseaza banner-ul de start al aplicatiei.
///
/// Designul foloseste caractere box-drawing Unicode (╔═╗║╚╝) pentru un
/// aspect profesional in terminal. Informatiile de configurare sunt afisate
/// intr-un cadru vizual pentru a confirma setarile active la start.
pub fn print_banner(config: &AppConfig) {
    let inner_width = SEPARATOR_WIDTH - 2;
    let border = "═".repeat(inner_width);

    println!();
    println!("{}", format!("╔{}╗", border).bold().cyan());
    println!(
        "{}",
        format!(
            "║{:^width$}║",
            "IDS-RS  ::  INTRUSION DETECTION SYSTEM  v0.1.0",
            width = inner_width
        )
        .bold()
        .cyan()
    );
    println!(
        "{}",
        format!(
            "║{:^width$}║",
            "Network Port Scan Detector",
            width = inner_width
        )
        .cyan()
    );
    println!("{}", format!("╠{}╣", border).bold().cyan());

    // Informatii de configurare - aliniate cu padding fix.
    let parser_line = format!(
        "  Parser: {:<14} Listen: UDP/{}",
        config.network.parser.to_uppercase(),
        config.network.listen_port
    );
    println!(
        "{}",
        format!("║{:<width$}║", parser_line, width = inner_width).cyan()
    );

    // Status SIEM si Email cu indicatoare colorate.
    let siem_label = if config.alerting.siem.enabled {
        format!("{}:{}", config.alerting.siem.host, config.alerting.siem.port)
    } else {
        "OFF".to_string()
    };
    let email_label = if config.alerting.email.enabled {
        "ON".to_string()
    } else {
        "OFF".to_string()
    };

    let siem_line = format!(
        "  SIEM:   {:<14} Email:  {}",
        siem_label, email_label
    );
    println!(
        "{}",
        format!("║{:<width$}║", siem_line, width = inner_width).cyan()
    );

    // Praguri de detectie.
    let thresh_line = format!(
        "  Fast:   >{} ports/{}s       Slow:  >{} ports/{}min",
        config.detection.fast_scan.port_threshold,
        config.detection.fast_scan.time_window_secs,
        config.detection.slow_scan.port_threshold,
        config.detection.slow_scan.time_window_mins
    );
    println!(
        "{}",
        format!("║{:<width$}║", thresh_line, width = inner_width).cyan()
    );

    println!("{}", format!("╚{}╝", border).bold().cyan());
    println!();
}

/// Linie separatoare orizontala pentru lizibilitate vizuala.
pub fn print_separator() {
    println!("{}", "─".repeat(SEPARATOR_WIDTH).dimmed());
}

// ---------------------------------------------------------------------------
// Functii de logging cu nivel si culori semantice
//
// Badge-urile colorate (ex: " INFO ".on_green()) ofera recunoastere
// vizuala instantanee a nivelului de log, mai evidenta decat simplu text.
//
// Toate functiile primesc `&str` (string slice, referinta),
// nu `String` (owned). Aceasta este practica idiomatica Rust:
//   - `&str` = "imprumutam" stringul, nu il preluam in proprietate
//   - mai eficient (nu copiezi date) si mai flexibil (accepta &String, &str literal)
// ---------------------------------------------------------------------------

/// Mesaj informational - badge verde, pentru operatii normale.
pub fn log_info(message: &str) {
    let ts = timestamp();
    println!(
        "{} {} {}",
        ts.bold().white(),
        " INFO ".on_green().black().bold(),
        message.white()
    );
}

/// Avertisment - badge galben, pentru situatii care merita atentie.
pub fn log_warning(message: &str) {
    let ts = timestamp();
    println!(
        "{} {} {}",
        ts.bold().white(),
        " WARN ".on_yellow().black().bold(),
        message.yellow()
    );
}

/// Eroare - badge rosu, pentru esecuri non-fatale.
pub fn log_error(message: &str) {
    let ts = timestamp();
    eprintln!(
        "{} {} {}",
        ts.bold().white(),
        " ERR  ".on_red().white().bold(),
        message.red()
    );
}

// ---------------------------------------------------------------------------
// Functiile de alerta - cel mai inalt nivel de vizibilitate
//
// Alertele sunt cele mai importante mesaje - trebuie sa fie
// imediat vizibile in stream-ul de log. Folosim:
//   - ROSU cu fundal pentru Fast Scan (urgenta ridicata)
//   - GALBEN cu fundal pentru Slow Scan (urgenta medie)
//   - Separatoare colorate si simboluri ▶▶▶ pentru vizibilitate maxima
//   - Lista de porturi (trunchiate la 25 pentru lizibilitate)
//
// NOTA RUST - PATTERN MATCHING cu `match`:
// Match pe enum este exhaustiv - daca adaugi o noua varianta
// la ScanType, compilatorul te obliga sa o tratezi AICI.
// Nu poti "uita" un caz - eroare la compilare, nu la runtime.
// ---------------------------------------------------------------------------

/// Afiseaza o alerta de securitate cu formatare vizual distincta.
pub fn log_alert(alert: &Alert) {
    let ts = alert
        .timestamp
        .format("[%Y-%m-%d %H:%M:%S]")
        .to_string();

    // Formatam lista de porturi cu trunchiere.
    // `.take(25)` limiteaza la primele 25 porturi (iteratorul e lazy).
    let max_display = 25;
    let port_list: String = alert
        .unique_ports
        .iter()
        .take(max_display)
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let suffix = if alert.unique_ports.len() > max_display {
        format!(" ... (+{} more)", alert.unique_ports.len() - max_display)
    } else {
        String::new()
    };

    let arrows = "▶▶▶";

    match alert.scan_type {
        ScanType::Fast => {
            println!();
            println!("{}", "─".repeat(SEPARATOR_WIDTH).red());
            println!(
                "{} {} {} [FAST SCAN] {} | {} porturi unice detectate!",
                ts.bold().white(),
                arrows.red().bold(),
                " ALERT ".on_red().white().bold(),
                format!("[IP: {}]", alert.source_ip).red().bold(),
                alert.unique_ports.len().to_string().red().bold()
            );
            println!("  Porturi: {}{}", port_list, suffix);
            println!("{}", "─".repeat(SEPARATOR_WIDTH).red());
            println!();
        }
        ScanType::Slow => {
            println!();
            println!("{}", "─".repeat(SEPARATOR_WIDTH).yellow());
            println!(
                "{} {} {} [SLOW SCAN] {} | {} porturi unice detectate!",
                ts.bold().white(),
                arrows.yellow().bold(),
                " ALERT ".on_yellow().black().bold(),
                format!("[IP: {}]", alert.source_ip).yellow().bold(),
                alert.unique_ports.len().to_string().yellow().bold()
            );
            println!("  Porturi: {}{}", port_list, suffix);
            println!("{}", "─".repeat(SEPARATOR_WIDTH).yellow());
            println!();
        }
    }
}

/// Confirma ca o alerta a fost transmisa cu succes (verde subtil).
pub fn log_alert_sent(destination: &str, alert_type: &str) {
    let ts = timestamp();
    println!(
        "{} {} Alert '{}' transmis -> {}",
        ts.dimmed(),
        " SENT ".on_green().black().bold(),
        alert_type.green(),
        destination.green().underline()
    );
}

/// Logarea unui eveniment de pachet primit (drop firewall) - albastru subtil.
///
/// Afiseaza IP sursa, portul destinatie, protocolul si actiunea firewall-ului.
/// Aceasta consuma campurile `protocol` si `action` din `LogEvent`,
/// oferind vizibilitate completa asupra evenimentelor procesate.
pub fn log_drop_event(ip: &std::net::IpAddr, port: u16, protocol: &str, action: &str) {
    let ts = timestamp();
    println!(
        "{} {} Src={} DstPort={} Proto={} Action={}",
        ts.dimmed(),
        " DROP ".on_blue().white().bold(),
        format!("{}", ip).bright_blue(),
        format!("{}", port).bright_blue(),
        protocol.bright_blue(),
        action.bright_blue()
    );
}

/// Afiseaza statistici periodice (apelat din cleanup task).
///
/// Format: [timestamp] [STAT] 42 IP-uri urmarite | Cleanup: 5 sterse
pub fn log_stats(tracked_ips: usize, cleaned_ips: usize) {
    let ts = timestamp();
    println!(
        "{} {} {} IP-uri urmarite | Cleanup: {} sterse",
        ts.dimmed(),
        " STAT ".on_cyan().black().bold(),
        tracked_ips.to_string().white().bold(),
        cleaned_ips.to_string().white().bold()
    );
}

// ---------------------------------------------------------------------------
// Functii de debug/diagnostic - afiseaza detalii despre parsare
// ---------------------------------------------------------------------------

/// Afiseaza linia raw primita pe port (mod debug).
pub fn log_debug_raw(line: &str) {
    let ts = timestamp();
    println!(
        "{} {} {}",
        ts.bold().white(),
        " RAW  ".on_magenta().white().bold(),
        line.dimmed()
    );
}

/// Afiseaza confirmarea parsarii reusite cu campurile extrase (mod debug).
pub fn log_debug_parse_ok(event: &LogEvent) {
    let ts = timestamp();
    println!(
        "{} {}  src={} dpt={} proto={} action={}",
        ts.bold().white(),
        "  OK  ".on_green().black().bold(),
        event.source_ip.to_string().green(),
        event.dest_port.to_string().green(),
        event.protocol.green(),
        event.action.green()
    );
}

/// Afiseaza detalii despre esecul parsarii (mod debug).
pub fn log_debug_parse_fail(line: &str, parser_name: &str, expected: &str) {
    let ts = timestamp();
    println!(
        "{} {} Parsare esuata! (parser: {})",
        ts.bold().white(),
        " FAIL ".on_red().white().bold(),
        parser_name.red().bold()
    );
    println!(
        "                              Primit:   \"{}\"",
        if line.len() > 120 {
            format!("{}...", &line[..120])
        } else {
            line.to_string()
        }
        .yellow()
    );
    println!(
        "                              Asteptat: \"{}\"",
        expected.dimmed()
    );
}

// ---------------------------------------------------------------------------
// Functie helper privata: returneaza timestamp-ul curent formatat
//
// `-> String` inseamna ca functia returneaza un String owned (alocat pe heap)
// `Local::now()` returneaza data/ora locala, `.format(...)` o formateaza
// ---------------------------------------------------------------------------
fn timestamp() -> String {
    Local::now().format("[%Y-%m-%d %H:%M:%S]").to_string()
}
