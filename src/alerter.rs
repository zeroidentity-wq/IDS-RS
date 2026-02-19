// =============================================================================
// alerter.rs - Modul de Alerte (SIEM UDP + Email SMTP)
// =============================================================================
//
// Responsabilitati:
//   1. Trimite alerte catre SIEM (ArcSight) prin UDP syslog
//   2. Trimite notificari email catre echipa IT/Security
// CONCEPTE RUST EXPLICATE:
//
// 1. ASYNC/AWAIT (Asincronicitate)
//    Rust foloseste un model de asincronicitate bazat pe "futures":
//
//    `async fn` -> functia returneaza un Future (nu se executa imediat!)
//    `.await`   -> suspenda executia pana cand Future-ul se completeaza
//
//    Diferenta fata de thread-uri:
//    - Thread: OS aloca un stack separat (~8MB), context switch costisitor
//    - Async task: ~few KB, context switch in user-space (rapid)
//
//    Tokio este runtime-ul care EXECUTA futures. Fara runtime, async nu
//    face nimic - futures sunt lazy by default.
//
//    Un Future in Rust este un state machine generat de compilator:
//    fiecare `.await` este un punct de suspendare. Compilatorul transforma
//    functia async intr-un enum cu stari, fara alocari pe heap.
//
// 2. ERROR HANDLING cu ANYHOW
//    `anyhow::Result<T>` = `Result<T, anyhow::Error>`
//    `anyhow::Error` poate contine ORICE tip de eroare (type-erased).
//    Util la application-level unde nu ne intereseaza tipul exact al erorii,
//    ci doar mesajul si stack-ul de context.
//
//    Pentru library code, se prefera `thiserror` cu enum-uri de erori custom.
//
// =============================================================================

use crate::config::{AlertingConfig, DetectionConfig};
use crate::detector::{Alert, ScanType};
use crate::display;
use anyhow::{Context, Result};
use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
use tokio::net::UdpSocket;

/// Componenta de alertare - trimite notificari catre SIEM si email.
///
/// NOTA RUST: Acest struct DETINE (owns) configurarea. Clonarea s-a facut
/// in main.rs cand am creat Alerter-ul. Acesta este pattern-ul "clone and own":
/// clonam datele de configurare la initializare, apoi le folosim fara
/// a mai avea nevoie de referinta la config-ul original.
pub struct Alerter {
    config: AlertingConfig,
    detection: DetectionConfig,
}

impl Alerter {
    pub fn new(config: AlertingConfig, detection: DetectionConfig) -> Self {
        Self { config, detection }
    }

    /// Trimite alerta catre toate destinatiile configurate.
    ///
    /// NOTA RUST - ASYNC si ERROR HANDLING:
    ///
    /// `async fn` + `.await` = functie asincrona care suspenda executia
    /// la fiecare operatie I/O fara a bloca thread-ul.
    ///
    /// Erorile individuale (SIEM/email) sunt LOGATE, nu propagate.
    /// Daca SIEM-ul e down, inca vrem sa trimitem email (si invers).
    /// Pattern: "log and continue" vs "fail fast".
    ///
    pub async fn send_alert(&self, alert: &Alert) {
        if self.config.siem.enabled {
            if let Err(e) = self.send_siem_alert(alert).await {
                display::log_error(&format!("Eroare trimitere alerta SIEM: {:#}", e));
            }
        }

        if self.config.email.enabled {
            if let Err(e) = self.send_email_alert(alert).await {
                display::log_error(&format!("Eroare trimitere email: {:#}", e));
            }
        }
    }

    /// Trimite o alerta catre SIEM prin UDP syslog.
    ///
    /// NOTA RUST - ASYNC I/O cu tokio:
    ///
    /// `UdpSocket::bind("0.0.0.0:0")` = creeaza socket pe un port efemer.
    /// `.await` = asteapta (non-blocking) pana cand OS-ul aloca socket-ul.
    ///
    /// `socket.send_to(data, addr)` = trimite datagramul UDP.
    /// `.await` = asteapta pana cand datele sunt trimise.
    ///
    /// In realitate, UDP send este aproape instant (nu asteapta confirmare),
    /// dar Rust/tokio ne forteaza sa tratam ca async - consistenta API.
    ///
    async fn send_siem_alert(&self, alert: &Alert) -> Result<()> {
        // Formatam mesajul in format CEF peste Syslog RFC 3164 pentru ArcSight.
        //
        // Structura completa:
        //   <PRIORITY>TIMESTAMP HOSTNAME CEF:0|Vendor|Product|Ver|SigID|Name|Sev|Extensions
        //
        // Prioritate syslog: facility=4 (security) × 8 + severity=6 (info) = 38
        // Campuri CEF Extensions: rt, src, cnt, act, msg, cs1Label, cs1

        let (sig_id, event_name, scan_label) = match alert.scan_type {
            ScanType::Fast => (
                "1001",
                "Fast Port Scan Detected",
                format!(
                    "Fast Scan detectat: {} porturi unice in {} secunde",
                    alert.unique_ports.len(),
                    self.detection.fast_scan.time_window_secs,
                ),
            ),
            ScanType::Slow => (
                "1002",
                "Slow Port Scan Detected",
                format!(
                    "Slow Scan detectat: {} porturi unice in {} minute",
                    alert.unique_ports.len(),
                    self.detection.slow_scan.time_window_mins,
                ),
            ),
        };

        // Lista completa de porturi pentru campul cs1 (ArcSight suporta pana la 4000 chars).
        let port_list_full: String = alert
            .unique_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        // Lista de porturi pentru campul msg — trunchiem la 512 caractere pentru
        // compatibilitate cu syslog RFC 3164 si vizibilitate in Active Channel ArcSight.
        // Daca lista completa incape, o folosim integral; altfel adaugam "...".
        let port_list_msg = if port_list_full.len() <= 512 {
            port_list_full.clone()
        } else {
            // Construim lista pana la limita, taind la ultimul ',' complet.
            let truncated = &port_list_full[..512];
            let cut = truncated.rfind(',').unwrap_or(512);
            format!("{}...", &port_list_full[..cut])
        };

        // Mesajul campului msg: descriere + lista porturi (vizibila direct in ArcSight Event List).
        let msg_text = format!("{} | ports: {}", scan_label, port_list_msg);

        // Campul dst (Target Address in ArcSight) — IP-ul tinta al scanarii.
        // Prezent doar daca log-ul sursa l-a furnizat.
        let dst_field = match alert.dest_ip {
            Some(ip) => format!(" dst={}", ip),
            None => String::new(),
        };

        let syslog_ts = alert.timestamp.format("%b %e %H:%M:%S");
        let rt_ms = alert.timestamp.timestamp_millis();

        let message = format!(
            "<38>{syslog_ts} ids-rs CEF:0|IDS-RS|Network Scanner Detector|1.0\
             |{sig_id}|{event_name}|7\
             |rt={rt_ms} src={src}{dst} cnt={cnt} act=alert \
             msg={msg} cs1Label=ScannedPorts cs1={ports}",
            syslog_ts = syslog_ts,
            sig_id = sig_id,
            event_name = event_name,
            rt_ms = rt_ms,
            src = alert.source_ip,
            dst = dst_field,
            cnt = alert.unique_ports.len(),
            msg = msg_text,
            ports = port_list_full,
        );

        // Cream un socket UDP efemer (port 0 = OS alege automat).
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Nu pot crea socket UDP pentru SIEM")?;

        let dest = format!("{}:{}", self.config.siem.host, self.config.siem.port);
        socket
            .send_to(message.as_bytes(), &dest)
            .await
            .with_context(|| format!("Nu pot trimite catre SIEM {}", dest))?;

        display::log_alert_sent(&dest, &format!("{}", alert.scan_type));
        Ok(())
    }

    /// Trimite o notificare email catre toti destinatarii configurati.
    ///
    /// NOTA RUST - CLOSURES si OWNERSHIP:
    ///
    /// In aceasta functie, `body` si `subject` sunt String-uri owned.
    /// Cand construim email-ul, `.body(body.clone())` cloneaza continutul
    /// deoarece il refolosim in loop (un email per destinatar).
    ///
    /// NOTA RUST - TRAIT BOUNDS in lettre:
    /// `AsyncSmtpTransport::<Tokio1Executor>` este un tip generic
    /// parametrizat cu executorul async. `Tokio1Executor` leaga lettre
    /// de runtime-ul tokio 1.x. Acesta este un exemplu de "zero-cost
    /// abstraction" - lettre suporta multiple runtime-uri fara overhead.
    ///
    async fn send_email_alert(&self, alert: &Alert) -> Result<()> {
        let cfg = &self.config.email;

        let subject = format!(
            "[IDS-RS] {} detectat de la {}",
            alert.scan_type, alert.source_ip
        );

        let port_list: String = alert
            .unique_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let body = format!(
            "ALERTA DE SECURITATE - IDS-RS\n\
             \n\
             Tip scanare:           {scan_type}\n\
             IP sursa:              {ip}\n\
             Porturi unice scanate: {count}\n\
             Lista porturi:         {ports}\n\
             Timestamp:             {ts}\n\
             \n\
             Aceasta alerta a fost generata automat de IDS-RS.\n\
             Verificati activitatea IP-ului sursa in firewall si SIEM.",
            scan_type = alert.scan_type,
            ip = alert.source_ip,
            count = alert.unique_ports.len(),
            ports = port_list,
            ts = alert.timestamp.format("%Y-%m-%d %H:%M:%S"),
        );

        // Configuram credentialele SMTP.
        // `.clone()` deoarece Credentials::new() preia ownership.
        let creds = Credentials::new(cfg.username.clone(), cfg.password.clone());

        // Construim transportul SMTP async.
        //
        // NOTA RUST - MATCH pe bool:
        // In loc de if/else, putem folosi match. Dar aici if este mai clar.
        //
        // `.relay()` = conectare cu TLS implicit (port 465 default)
        // `.builder_dangerous()` = fara TLS (doar pentru retele interne!)
        // `.port()` seteaza portul SMTP din configurare (ex: 465, 587, 25).
        // Fara `.port()`, lettre foloseste default-ul protocolului.
        let mailer = if cfg.smtp_tls {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_server)
                .context("Nu pot configura SMTP relay")?
                .port(cfg.smtp_port)
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_server)
                .port(cfg.smtp_port)
                .credentials(creds)
                .build()
        };

        // Trimitem un email catre fiecare destinatar.
        //
        // NOTA RUST - ITERATIE cu `for`:
        // `for recipient in &cfg.to` itereaza prin referinte (&String).
        // Nu consumam Vec-ul - il imprumutam doar pentru citire.
        for recipient in &cfg.to {
            let email = Message::builder()
                .from(
                    cfg.from
                        .parse()
                        .with_context(|| format!("Adresa 'from' invalida: {}", cfg.from))?,
                )
                .to(recipient
                    .parse()
                    .with_context(|| format!("Adresa destinatar invalida: {}", recipient))?)
                .subject(&subject)
                .body(body.clone())
                .context("Nu pot construi mesajul email")?;

            mailer
                .send(email)
                .await
                .with_context(|| format!("Nu pot trimite email catre {}", recipient))?;
        }

        display::log_alert_sent("Email", &format!("{}", alert.scan_type));
        Ok(())
    }
}
