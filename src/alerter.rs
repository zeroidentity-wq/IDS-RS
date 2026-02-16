// =============================================================================
// alerter.rs - Modul de Alerte (SIEM UDP + Email SMTP)
// =============================================================================
//
// Responsabilitati:
//   1. Trimite alerte catre SIEM (ArcSight) prin UDP syslog
//   2. Trimite notificari email catre echipa IT/Security
//
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

use crate::config::AlertingConfig;
use crate::detector::Alert;
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
}

impl Alerter {
    pub fn new(config: AlertingConfig) -> Self {
        Self { config }
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
                // `tracing::error!` logheaza la nivel ERROR.
                // Diferenta fata de eprintln!: tracing este structurat,
                // poate fi filtrat, redirectionat, si include metadata.
                tracing::error!("Eroare trimitere alerta SIEM: {:#}", e);
            }
        }

        if self.config.email.enabled {
            if let Err(e) = self.send_email_alert(alert).await {
                tracing::error!("Eroare trimitere email: {:#}", e);
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
        // Formatam mesajul in stil syslog/SIEM.
        // Folosim campuri cheie=valoare pentru parsare usoara in SIEM.
        let port_list: String = alert
            .unique_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let message = format!(
            "[IDS-RS ALERT] type={} src={} unique_ports={} time={} ports={}",
            alert.scan_type,
            alert.source_ip,
            alert.unique_ports.len(),
            alert.timestamp.format("%Y-%m-%dT%H:%M:%S"),
            port_list,
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

        tracing::debug!("Alerta SIEM trimisa catre {}", dest);
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
        let mailer = if cfg.smtp_tls {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_server)
                .context("Nu pot configura SMTP relay")?
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_server)
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

        tracing::debug!("Email trimis catre {:?}", cfg.to);
        Ok(())
    }
}
