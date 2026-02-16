// =============================================================================
// display.rs - Interfata CLI Moderna cu Culori ANSI
// =============================================================================
//
// Acest modul gestioneaza TOATA iesirea vizuala catre terminal:
//   - Banner-ul de start (cu informatii de configurare)
//   - Log-uri de stare formatate cu culori
//   - Alerte de securitate vizual distincte
//   - Statistici periodice
//
// DESIGN: Separarea logicii de afisare de logica de business.
// Modulul display.rs nu stie NIMIC despre parsare sau detectie -
// primeste date formatate si le afiseaza frumos. Aceasta separare
// face codul mai testabil si mai usor de modificat.
//
// NOTA RUST - CRATE-ul `colored`:
// Extinde &str si String cu metode de colorare:
//   "text".red()           -> ColoredString (rosu)
//   "text".bold()          -> ColoredString (bold)
//   "text".red().bold()    -> combinatie (rosu + bold)
//   "text".dimmed()        -> gri/atenuat
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
use chrono::Local;
use colored::*;

/// Afiseaza banner-ul de start al aplicatiei.
///
/// Designul foloseste caractere box-drawing Unicode pentru un aspect
/// profesional in terminal. Informatiile de configurare sunt afisate
/// pentru a confirma setarile active la start.
pub fn print_banner(config: &AppConfig) {
    let line = "=".repeat(62);

    println!();
    println!("{}", line.cyan().bold());
    println!(
        "{}",
        "  IDS-RS  ::  Intrusion Detection System"
            .white()
            .bold()
    );
    println!("{}", "  Network Scan Detector v0.1.0".dimmed());
    println!("{}", line.cyan().bold());

    // Informatii de configurare - aliniate cu padding fix.
    println!(
        "  Parser:  {:<14} Listen:  {}",
        config
            .network
            .parser
            .to_uppercase()
            .yellow()
            .bold()
            .to_string(),
        format!("UDP/{}", config.network.listen_port)
            .yellow()
            .bold()
    );

    // Status SIEM si Email cu indicatoare colorate.
    let siem_status = if config.alerting.siem.enabled {
        format!(
            "{}:{}",
            config.alerting.siem.host, config.alerting.siem.port
        )
        .green()
        .bold()
    } else {
        "OFF".red().bold()
    };
    let email_status = if config.alerting.email.enabled {
        "ON".green().bold()
    } else {
        "OFF".red().bold()
    };

    println!("  SIEM:    {:<14} Email:   {}", siem_status, email_status);

    // Praguri de detectie.
    println!(
        "  Fast:    {}       Slow:    {}",
        format!(
            ">{} ports/{}s",
            config.detection.fast_scan.port_threshold,
            config.detection.fast_scan.time_window_secs
        )
        .white()
        .bold(),
        format!(
            ">{} ports/{}min",
            config.detection.slow_scan.port_threshold,
            config.detection.slow_scan.time_window_mins
        )
        .white()
        .bold()
    );

    println!("{}", line.cyan().bold());
    println!();
}

/// Afiseaza un mesaj informativ cu timestamp.
///
/// Format: [2024-11-20 15:30:00] [INFO] Mesajul aici
///
/// NOTA RUST: `&str` parametrul este un "string slice" - o referinta
/// la un segment de memorie care contine text UTF-8 valid.
/// Nu copiem textul - doar referentiem locatia din memorie.
/// Acesta este zero-copy si eficient.
pub fn log_info(message: &str) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!(
        "{} {} {}",
        format!("[{}]", ts).dimmed(),
        "[INFO]".blue().bold(),
        message
    );
}

/// Afiseaza un avertisment cu timestamp.
///
/// Format: [2024-11-20 15:30:00] [WARN] Mesajul aici
pub fn log_warning(message: &str) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!(
        "{} {} {}",
        format!("[{}]", ts).dimmed(),
        "[WARN]".yellow().bold(),
        message
    );
}

/// Afiseaza o eroare cu timestamp.
///
/// Format: [2024-11-20 15:30:00] [ERROR] Mesajul aici
pub fn log_error(message: &str) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!(
        "{} {} {}",
        format!("[{}]", ts).dimmed(),
        "[ERROR]".red().bold(),
        message.red().to_string()
    );
}

/// Afiseaza o alerta de securitate cu formatare vizual distincta.
///
/// Alertele sunt cele mai importante mesaje - trebuie sa fie
/// imediat vizibile in stream-ul de log. Folosim:
///   - ROSU pentru Fast Scan (urgenta ridicata)
///   - GALBEN pentru Slow Scan (urgenta medie)
///   - Lista de porturi (trunchiate la 25 pentru lizibilitate)
///
/// NOTA RUST - PATTERN MATCHING cu `match`:
/// Match pe enum este exhaustiv - daca adaugi o noua varianta
/// la ScanType, compilatorul te obliga sa o tratezi AICI.
/// Nu poti "uita" un caz - eroare la compilare, nu la runtime.
///
pub fn log_alert(alert: &Alert) {
    let ts = alert
        .timestamp
        .format("%Y-%m-%d %H:%M:%S")
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

    // Separator vizual pentru alerte.
    let separator = "-".repeat(62);

    match alert.scan_type {
        ScanType::Fast => {
            println!("{}", separator.red().bold());
            println!(
                "{} {} {} {} detectat!",
                format!("[{}]", ts).dimmed(),
                "[ALERT]".red().bold(),
                format!("[IP: {}]", alert.source_ip).white().bold(),
                "Fast Scan".red().bold()
            );
            println!(
                "  {} porturi unice in fereastra de timp",
                alert.unique_ports.len().to_string().red().bold()
            );
            println!("  Porturi: {}{}", port_list, suffix);
            println!("{}", separator.red().bold());
        }
        ScanType::Slow => {
            println!("{}", separator.yellow().bold());
            println!(
                "{} {} {} {} detectat!",
                format!("[{}]", ts).dimmed(),
                "[ALERT]".yellow().bold(),
                format!("[IP: {}]", alert.source_ip).white().bold(),
                "Slow Scan".yellow().bold()
            );
            println!(
                "  {} porturi unice in fereastra de timp",
                alert.unique_ports.len().to_string().yellow().bold()
            );
            println!("  Porturi: {}{}", port_list, suffix);
            println!("{}", separator.yellow().bold());
        }
    }
}

/// Afiseaza statistici periodice (apelat din cleanup task).
///
/// Format: [timestamp] [STAT] 42 IP-uri urmarite | Cleanup: 5 sterse
pub fn log_stats(tracked_ips: usize, cleaned_ips: usize) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!(
        "{} {} {} IP-uri urmarite | Cleanup: {} sterse",
        format!("[{}]", ts).dimmed(),
        "[STAT]".cyan().bold(),
        tracked_ips.to_string().white().bold(),
        cleaned_ips.to_string().white().bold()
    );
}
