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
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use std::time::Duration;
use tokio::net::UdpSocket;

// =============================================================================
// SECURITATE — Sanitizare campuri CEF (anti-injection)
// =============================================================================
//
// Un mesaj CEF are doua zone cu caractere speciale diferite:
//
//   Header:  CEF:0|Vendor|Product|Ver|SigID|Name|Sev|
//            Separatorul este '|'. Un '|' neescape intr-un camp header
//            injecteaza un camp nou fals in SIEM.
//
//   Extensii: key1=val1 key2=val2 ...
//             Separatorul intre perechi este spatiul. Un '=' neescape
//             intr-o valoare poate falsifica o noua pereche key=value.
//             Un '\n' sau '\r' poate injecta o linie syslog complet noua.
//
// Vector de atac concret:
//   Daca un log de firewall contine un hostname sau camp text controlat
//   de atacator, acesta poate include caractere speciale. Exemplu:
//
//     hostname: "evil\nFeb 18 00:00:00 ids-rs CEF:0|FAKE|..."
//
//   Fara sanitizare, '\n' sparge mesajul in doua linii syslog distincte,
//   a doua fiind un mesaj CEF complet fals trimis catre SIEM.
//
// Escape-uri aplicate (ordinea conteaza — backslash PRIMUL):
//   '\'  →  '\\'   backslash propriu (trebuie escapeat primul, altfel
//                  s-ar dubla escape-urile aplicate ulterior)
//   '|'  →  '\|'   separator header CEF
//   '\n' →  '\\n'  line injection in syslog / CEF
//   '\r' →  '\\r'  carriage return injection
//
/// Sanitizeaza un camp CEF impotriva injectiei de mesaje false in SIEM.
///
/// Aplica escape conform standardului CEF (ArcSight) pentru a preveni
/// injectia de caractere speciale din campuri controlate extern.
fn sanitize_cef(input: &str) -> String {
    // NOTA: ordinea replace-urilor este critica.
    // Backslash-ul trebuie escapeat primul; altfel secventele '\\n' deja
    // escapate anterior ar fi dublu-escapate incorect.
    input
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Construieste body-ul HTML al email-ului de alerta.
///
/// Folosim template cu placeholder-e `__VAR__` in loc de `format!` pentru a evita
/// escaping-ul acoladelor CSS (`{` → `{{`). Textul din `email_footer` este HTML-escapeat
/// pentru a preveni injectia de tag-uri din valori controlate extern.
fn build_html_body(
    scan_type: &str,
    severity: &str,
    src_ip: &str,
    dst_ip: &str,
    port_count: usize,
    timestamp: &str,
    ports: &str,
    footer: &str,
) -> String {
    // HTML-escape pentru campuri care pot contine caractere speciale (footer ASCII art).
    let footer_safe = footer
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    let template = r#"<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, Helvetica, sans-serif; background: #f0f2f5; padding: 20px; }
  .wrap { max-width: 620px; margin: 0 auto; background: #fff; border-radius: 6px;
          overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.12); }
  /* HEADER */
  .hdr { background: linear-gradient(135deg, #c0392b 0%, #96281b 100%);
         color: #fff; padding: 24px 28px; }
  .hdr-label { font-size: 10px; text-transform: uppercase; letter-spacing: 2px;
               opacity: 0.7; margin-bottom: 10px; }
  .hdr h1 { font-size: 21px; font-weight: 700; margin-bottom: 12px; }
  .badge { display: inline-block; background: rgba(255,255,255,0.18);
           color: #fff; padding: 3px 11px; border-radius: 12px;
           font-size: 11px; font-weight: bold; margin-right: 6px; }
  /* SECTIUNI */
  .sec { padding: 18px 28px; border-bottom: 1px solid #ecf0f1; }
  .sec-title { font-size: 10px; text-transform: uppercase; letter-spacing: 1.5px;
               color: #95a5a6; font-weight: bold; margin-bottom: 12px; }
  /* TABEL DETALII */
  .tbl { width: 100%; border-collapse: collapse; }
  .tbl td { padding: 7px 0; border-bottom: 1px solid #f4f6f8;
            font-size: 13px; vertical-align: top; }
  .tbl td:first-child { color: #7f8c8d; width: 155px; }
  .tbl td:last-child { color: #2c3e50; font-weight: 600; }
  .tbl tr:last-child td { border-bottom: none; }
  /* PORTURI */
  .ports-box { background: #fdf3f3; border-left: 4px solid #c0392b;
               padding: 11px 14px; font-family: 'Courier New', monospace;
               font-size: 12px; color: #2c3e50; line-height: 1.7;
               word-break: break-all; border-radius: 0 4px 4px 0; }
  /* COMENZI */
  .cmd-box { background: #1a2332; border-radius: 5px; padding: 16px 18px; }
  .cmd-comment { color: #5d7a99; font-family: 'Courier New', monospace;
                 font-size: 11.5px; display: block; margin-top: 12px; }
  .cmd-comment:first-child { margin-top: 0; }
  .cmd-line { color: #a8d4a8; font-family: 'Courier New', monospace;
              font-size: 12.5px; display: block; margin-top: 4px; word-break: break-all; }
  /* FOOTER */
  .footer { background: #1e2a38; padding: 22px 28px; text-align: center; }
  .footer pre { color: #5d8aa8; font-size: 10px; font-family: 'Courier New', monospace;
                line-height: 1.5; margin-bottom: 14px; display: inline-block;
                text-align: left; }
  .footer p { color: #5d6d7e; font-size: 11px; }
</style>
</head>
<body>
<div class="wrap">

  <div class="hdr">
    <div class="hdr-label">IDS-RS &mdash; Intrusion Detection System</div>
    <h1>&#x1F534; ALERTA SCANARE RETEA</h1>
    <span class="badge">__SCAN_TYPE__</span>
    <span class="badge">Severitate: __SEVERITY__</span>
  </div>

  <div class="sec">
    <div class="sec-title">Detalii eveniment</div>
    <table class="tbl">
      <tr><td>IP Sursa</td><td>__SRC_IP__</td></tr>
      <tr><td>IP Destinatie</td><td>__DST_IP__</td></tr>
      <tr><td>Porturi scanate</td><td>__PORT_COUNT__</td></tr>
      <tr><td>Timestamp</td><td>__TIMESTAMP__</td></tr>
    </table>
  </div>

  <div class="sec">
    <div class="sec-title">Porturi detectate</div>
    <div class="ports-box">__PORTS__</div>
  </div>

  <div class="footer">
    <pre>__FOOTER__</pre>
    <p>Generat automat de IDS-RS &nbsp;|&nbsp; Nu raspundeti la acest email</p>
  </div>

  <div class="sec" style="border-bottom: none;">
    <div class="sec-title">Comenzi rapide &mdash; RHEL 9.6</div>
    <div class="cmd-box">
      <span class="cmd-comment"># Conexiuni active de la/catre acest IP:</span>
      <span class="cmd-line">ss -tnp | grep __SRC_IP__</span>
      <span class="cmd-comment"># Cautare in log-urile de securitate si sistem:</span>
      <span class="cmd-line">grep __SRC_IP__ /var/log/secure /var/log/messages 2>/dev/null</span>
      <span class="cmd-comment"># Cautare in journal (ultimele 200 linii):</span>
      <span class="cmd-line">journalctl -n 200 --no-pager | grep __SRC_IP__</span>
      <span class="cmd-comment"># Captura live trafic de la acest IP (primele 30 pachete):</span>
      <span class="cmd-line">tcpdump -i any host __SRC_IP__ -n -c 30</span>
      <span class="cmd-comment"># Blocare imediata cu firewalld (persistenta):</span>
      <span class="cmd-line">firewall-cmd --add-rich-rule='rule family="ipv4" source address="__SRC_IP__" drop' --permanent &amp;&amp; firewall-cmd --reload</span>
      <span class="cmd-comment"># Verificare daca IP-ul este activ in retea (ARP):</span>
      <span class="cmd-line">ip neigh show | grep __SRC_IP__</span>
    </div>
  </div>

</div>
</body>
</html>"#;

    template
        .replace("__SCAN_TYPE__", scan_type)
        .replace("__SEVERITY__", severity)
        .replace("__SRC_IP__", src_ip)
        .replace("__DST_IP__", dst_ip)
        .replace("__PORT_COUNT__", &port_count.to_string())
        .replace("__TIMESTAMP__", timestamp)
        .replace("__PORTS__", ports)
        .replace("__FOOTER__", &footer_safe)
}

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
        // Sanitizare anti-injection: sanitizam scan_label (date interne, dar cu text dinamic),
        // NU intregul format — separatorul " | " este al nostru si nu trebuie escapeat.
        // port_list_msg contine doar cifre si virgule (u16), nu necesita sanitizare.
        let msg_text = format!("{} | ports: {}", sanitize_cef(&scan_label), port_list_msg);

        // Sanitizare anti-injection pentru event_name (camp header CEF, separator '|').
        let event_name_safe = sanitize_cef(event_name);

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
            event_name = event_name_safe,
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

        let port_count = alert.unique_ports.len();

        let subject = format!(
            "\u{1F534} [{}][SCANARE RETEA] IDS-RS {} {} porturi",
            alert.scan_type, alert.source_ip, port_count
        );

        // Lista porturi pentru body — maxim 30, restul sumarizate.
        let port_list_display = if port_count <= 30 {
            alert
                .unique_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            let first_30: String = alert.unique_ports[..30]
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} + {} more", first_30, port_count - 30)
        };

        let severity = "RIDICATA";

        let dest_ip_display = match alert.dest_ip {
            Some(ip) => ip.to_string(),
            None => "N/A".to_string(),
        };

        let timestamp = alert.timestamp.format("%Y-%m-%d %H:%M:%S");

        let html_body = build_html_body(
            &alert.scan_type.to_string(),
            severity,
            &alert.source_ip.to_string(),
            &dest_ip_display,
            port_count,
            &timestamp.to_string(),
            &port_list_display,
            &cfg.email_footer,
        );

        // Construim transportul SMTP async.
        //
        // NOTA RUST - MATCH pe bool:
        // In loc de if/else, putem folosi match. Dar aici if este mai clar.
        //
        // `.relay()` = conectare cu STARTTLS (recomandat pentru port 587)
        // `.builder_dangerous()` = fara TLS (pentru retele interne, port 25)
        // `.port()` seteaza portul SMTP din configurare.
        // `.timeout()` = timeout explicit pentru a evita asteptare infinita.
        //
        // Credentialele sunt optionale: pe servere interne (port 25 relay),
        // autentificarea nu este de obicei necesara. Daca username este gol,
        // nu trimitem AUTH — serverul va relaya pe baza IP-ului sursa.
        let smtp_timeout = Some(Duration::from_secs(30));

        let mailer = if cfg.smtp_tls {
            let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_server)
                .context("Nu pot configura SMTP relay")?
                .port(cfg.smtp_port)
                .timeout(smtp_timeout);
            if !cfg.username.is_empty() {
                let creds = Credentials::new(cfg.username.clone(), cfg.password.clone());
                builder = builder.credentials(creds);
            }
            builder.build()
        } else {
            let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_server)
                .port(cfg.smtp_port)
                .timeout(smtp_timeout);
            if !cfg.username.is_empty() {
                let creds = Credentials::new(cfg.username.clone(), cfg.password.clone());
                builder = builder.credentials(creds);
            }
            builder.build()
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
                .header(ContentType::TEXT_HTML)
                .body(html_body.clone())
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

// =============================================================================
// Teste unitare — sanitize_cef()
// =============================================================================

#[cfg(test)]
mod tests {
    use super::sanitize_cef;

    #[test]
    fn test_sanitize_newline() {
        assert_eq!(sanitize_cef("text\nfals"), "text\\nfals");
    }

    #[test]
    fn test_sanitize_carriage_return() {
        assert_eq!(sanitize_cef("text\rfals"), "text\\rfals");
    }

    #[test]
    fn test_sanitize_pipe() {
        assert_eq!(sanitize_cef("camp|fals"), "camp\\|fals");
    }

    #[test]
    fn test_sanitize_backslash() {
        assert_eq!(sanitize_cef("c:\\path"), "c:\\\\path");
    }

    #[test]
    fn test_sanitize_combinat() {
        // Atac complet: injectie linie syslog noua cu camp CEF fals
        let input = "evil\nFeb 18 00:00:00 ids-rs CEF:0|FAKE|Product|1.0|999|Fake|10|";
        let output = sanitize_cef(input);
        // Nu trebuie sa contina newline neescape
        assert!(!output.contains('\n'));
        // Nu trebuie sa contina pipe neescape (in afara de cele din escape)
        assert!(!output.contains("CEF:0|FAKE"));
        // Trebuie sa contina versiunea escapata
        assert!(output.contains("\\n"));
        assert!(output.contains("\\|"));
    }

    #[test]
    fn test_sanitize_string_curat() {
        // Textul normal nu trebuie modificat
        assert_eq!(sanitize_cef("Fast Scan detectat: 20 porturi"), "Fast Scan detectat: 20 porturi");
    }

    #[test]
    fn test_sanitize_backslash_inainte_de_pipe() {
        // Backslash urmat de pipe: trebuie escapeat corect, nu dublu-escapeat
        // Input: "a\|b" => Output: "a\\\\\\|b"  (backslash si pipe ambele escapate)
        let input = "a\\|b";
        let output = sanitize_cef(input);
        assert_eq!(output, "a\\\\\\|b");
    }
}
