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

use crate::config::{AlertingConfig, DetectionConfig, EmailConfig, SubnetEntry};
use crate::detector::{Alert, ScanType};
use crate::display;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
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
fn sanitize_cef_header(input: &str) -> String {
    // NOTA: ordinea replace-urilor este critica.
    // Backslash-ul trebuie escapeat primul; altfel secventele '\\n' deja
    // escapate anterior ar fi dublu-escapate incorect.
    input
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Escape dedicat pentru valorile din CEF extensions (`key=value`).
///
/// Standardul CEF cere escape in extensii doar pentru `\`, `=` si newline.
/// Spatiile sunt permise in valori: parserul recunoaste inceputul perechii
/// urmatoare dupa ` cheie=`, iar `=` din valoare este deja escapat, deci un
/// spatiu nu poate introduce o pereche falsa. `\ ` nu este o secventa CEF
/// definita si ar aparea literal in SIEM (`Fast\ Scan\ detectat`).
fn sanitize_cef_extension(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn sorted_ip_list(ips: &[IpAddr]) -> String {
    ips.iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn sorted_ip_list_with_primary(ips: &[IpAddr], primary: IpAddr) -> String {
    let mut unique = ips.iter().copied().collect::<BTreeSet<_>>();
    unique.insert(primary);
    unique
        .into_iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Esantion sortat de cel mult `limit` IP-uri unice. `primary` (IP-ul
/// principal al alertei) este inclus intotdeauna, indiferent unde ar cadea
/// in ordinea sortata — altfel inregistrarea SIEM ar putea omite chiar sursa.
fn sorted_ip_sample(ips: &[IpAddr], primary: Option<IpAddr>, limit: usize) -> String {
    let mut unique = ips.iter().copied().collect::<BTreeSet<_>>();
    if let Some(ip) = primary {
        unique.remove(&ip);
    }
    let others = limit.saturating_sub(usize::from(primary.is_some()));
    let mut sample: BTreeSet<IpAddr> = unique.into_iter().take(others).collect();
    if let Some(ip) = primary.filter(|_| limit > 0) {
        sample.insert(ip);
    }
    sample
        .into_iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn port_sample(ports: &[u16], limit: usize) -> String {
    ports
        .iter()
        .take(limit)
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn comma_to_display_list(value: &str) -> String {
    value.replace(',', ", ")
}

struct HtmlAlertBody<'a> {
    scan_type: &'a str,
    severity: &'a str,
    src_ip: &'a str,
    src_hostname: &'a str,
    src_location: &'a str,
    dst_ip: &'a str,
    dst_hostname: &'a str,
    dst_location: &'a str,
    item_count: usize,
    timestamp: &'a str,
    items: &'a str,
    footer: &'a str,
    count_label: &'a str,
    list_label: &'a str,
    cmd_src_ip: &'a str,
    cmd_dst_ip: &'a str,
}

/// Construieste body-ul HTML al email-ului de alerta.
///
/// Folosim template cu placeholder-e `__VAR__` in loc de `format!` pentru a evita
/// escaping-ul acoladelor CSS (`{` → `{{`). Textul din `email_footer` este HTML-escapeat
/// pentru a preveni injectia de tag-uri din valori controlate extern.
///
/// MODELUL DE INCREDERE — VALORI NE-ESCAPATE:
///
/// `scan_type`, `severity`, `count_label`, `list_label` provin din enum-uri /
/// literal-uri hardcodate => safe by construction.
///
/// `src_ip`, `dst_ip`, `item_count`, `timestamp` provin din `IpAddr`, `usize`,
/// `DateTime` formatate => safe (nu contin `<`, `>`, `&`).
///
/// `src_hostname`, `dst_hostname`, `src_location`, `dst_location`, `items` vin
/// din configuratie (admin-controlled): `[network.hostnames]`, `[network.subnets]`
/// si liste de IP-uri/porturi. Nu sunt escape-ate pentru ca:
///   1. Sursa lor este admin-ul (incredere implicita la nivel de deploy)
///   2. Pana acum, hostname-urile sunt scrise manual in config.toml
///
/// DACA ACEST MODEL SE SCHIMBA (de exemplu, hostname-uri populate din DNS reverse,
/// LDAP, log-uri parsate de la firewall sau orice sursa netrustata) →
/// TREBUIE adaugat HTML escape pe TOATE valorile `data.*` inainte de `.replace()`,
/// la fel cum se face deja pentru `data.footer`. Altfel: XSS in clientii de email
/// care randeaza HTML (Thunderbird, Outlook web, etc.).
///
/// `email_footer` este HTML-escapeat pentru ca poate contine ASCII art cu `<>&`.
fn build_html_body(data: &HtmlAlertBody<'_>) -> String {
    // HTML-escape pentru campuri care pot contine caractere speciale (footer ASCII art).
    let footer_safe = data
        .footer
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
      <tr><td>IP Sursa</td><td>__SRC_IP__ __SRC_HOST__ __SRC_LOC__</td></tr>
      <tr><td>IP Destinatie</td><td>__DST_IP__ __DST_HOST__ __DST_LOC__</td></tr>
      <tr><td>__COUNT_LABEL__</td><td>__PORT_COUNT__</td></tr>
      <tr><td>Timestamp</td><td>__TIMESTAMP__</td></tr>
    </table>
  </div>

  <div class="sec">
    <div class="sec-title">__LIST_LABEL__</div>
    <div class="ports-box">__PORTS__</div>
  </div>

  <div class="footer">
    <pre>__FOOTER__</pre>
    <p>Generat automat de IDS-RS &nbsp;|&nbsp; Nu raspundeti la acest email</p>
  </div>

  <div class="sec" style="border-bottom: none;">
    <div class="sec-title">Comenzi rapide &mdash;</div>
    <div class="cmd-box">
      <span class="cmd-comment"># Conexiuni active de la/catre acest IP:</span>
      <span class="cmd-line">ss -tnp | grep __CMD_SRC_IP__</span>
      <span class="cmd-comment"># Cautare in log-urile de securitate si sistem:</span>
      <span class="cmd-line">grep __CMD_SRC_IP__ /var/log/secure /var/log/messages 2>/dev/null</span>
      <span class="cmd-comment"># Cautare in journal (ultimele 200 linii):</span>
      <span class="cmd-line">journalctl -n 200 --no-pager | grep -E '__CMD_SRC_IP__|__CMD_DST_IP__'</span>
      <span class="cmd-comment"># Captura live trafic de la acest IP (primele 30 pachete):</span>
      <span class="cmd-line">tcpdump -i any host __CMD_SRC_IP__ -n -c 30</span>
      <span class="cmd-comment"># Blocare imediata cu firewalld (persistenta):</span>
      <span class="cmd-line">firewall-cmd --add-rich-rule='rule family="ipv4" source address="__CMD_SRC_IP__" drop' --permanent &amp;&amp; firewall-cmd --reload</span>
      <span class="cmd-comment"># Verificare daca IP-ul este activ in retea (ARP):</span>
      <span class="cmd-line">ip neigh show | grep __CMD_SRC_IP__</span>
    </div>
  </div>

</div>
</body>
</html>"#;

    // Formatam hostname-urile: "(hostname)" daca exista, altfel string gol.
    let src_host_display = if data.src_hostname.is_empty() {
        String::new()
    } else {
        format!("({})", data.src_hostname)
    };
    let dst_host_display = if data.dst_hostname.is_empty() {
        String::new()
    } else {
        format!("({})", data.dst_hostname)
    };
    // Formatam locatiile subnet: "[Etaj 1]" daca exista, altfel string gol.
    let src_loc_display = if data.src_location.is_empty() {
        String::new()
    } else {
        format!("[{}]", data.src_location)
    };
    let dst_loc_display = if data.dst_location.is_empty() {
        String::new()
    } else {
        format!("[{}]", data.dst_location)
    };

    template
        .replace("__SCAN_TYPE__", data.scan_type)
        .replace("__SEVERITY__", data.severity)
        .replace("__SRC_IP__", data.src_ip)
        .replace("__SRC_HOST__", &src_host_display)
        .replace("__SRC_LOC__", &src_loc_display)
        .replace("__DST_IP__", data.dst_ip)
        .replace("__DST_HOST__", &dst_host_display)
        .replace("__DST_LOC__", &dst_loc_display)
        .replace("__PORT_COUNT__", &data.item_count.to_string())
        .replace("__TIMESTAMP__", data.timestamp)
        .replace("__PORTS__", data.items)
        .replace("__COUNT_LABEL__", data.count_label)
        .replace("__LIST_LABEL__", data.list_label)
        .replace("__CMD_SRC_IP__", data.cmd_src_ip)
        .replace("__CMD_DST_IP__", data.cmd_dst_ip)
        .replace("__FOOTER__", &footer_safe)
}

/// Construieste transportul SMTP async din configurarea email.
///
/// Functie privata separata — transportul este construit O SINGURA DATA
/// la initializarea Alerter-ului si reutilizat la fiecare alerta,
/// evitand reconectarea TLS/STARTTLS la fiecare email trimis.
fn build_mailer(cfg: &EmailConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
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

    Ok(mailer)
}

/// Canalul de livrare nu poate trimite acum (dezactivat sau mailer
/// neinitializat). Alerta NU a fost livrata si trebuie pastrata in spool.
#[derive(Debug)]
pub struct SinkUnavailable(pub &'static str);

impl std::fmt::Display for SinkUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SinkUnavailable {}

/// Alerta nu va putea fi livrata niciodata in forma actuala (ex: mesaj CEF
/// prea mare, adresa respinsa definitiv de serverul SMTP). Reincercarea ar
/// bloca la nesfarsit coada, deci alerta este mutata in dead-letter.
#[derive(Debug)]
pub struct PermanentFailure(pub String);

impl std::fmt::Display for PermanentFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PermanentFailure {}

/// Email-ul nu a ajuns la toti destinatarii. Destinatarii care l-au primit
/// nu apar aici, ca un retry sa nu le trimita aceeasi alerta din nou.
#[derive(Debug)]
pub struct EmailFailure {
    /// Esec tranzitoriu (conexiune, 4xx): se reincearca doar pentru acestia.
    pub pending: Vec<String>,
    /// Esec permanent (5xx, mesaj invalid): merg in dead-letter.
    pub rejected: Vec<String>,
    details: Vec<String>,
}

impl std::fmt::Display for EmailFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "livrare email esuata ({} de reincercat, {} respinsi definitiv): {}",
            self.pending.len(),
            self.rejected.len(),
            self.details.join("; ")
        )
    }
}

impl std::error::Error for EmailFailure {}

/// Componenta de alertare - trimite notificari catre SIEM si email.
///
/// NOTA RUST: Acest struct DETINE (owns) configurarea. Clonarea s-a facut
/// in main.rs cand am creat Alerter-ul. Acesta este pattern-ul "clone and own":
/// clonam datele de configurare la initializare, apoi le folosim fara
/// a mai avea nevoie de referinta la config-ul original.
pub struct Alerter {
    /// Configurare alerting (SIEM + email). Wrapat in ArcSwap pentru hot reload (#16).
    config: ArcSwap<AlertingConfig>,
    /// Configurare detectie (praguri, ferestre de timp) — citita pentru mesaje alerta.
    detection: ArcSwap<DetectionConfig>,
    /// Transport SMTP pre-construit (None daca email dezactivat).
    /// ArcSwap permite rebuild-ul la reload (schimbare SMTP server/port/credentials).
    mailer: ArcSwap<Option<AsyncSmtpTransport<Tokio1Executor>>>,
    /// Mapping IP → hostname pentru afisare in alerte SIEM (shost=/dhost=) si email.
    hostnames: ArcSwap<HashMap<IpAddr, String>>,
    /// Mapping subnet CIDR → locatie (etaj, zona) pentru context fizic in alerte.
    subnets: ArcSwap<Vec<SubnetEntry>>,
}

impl Alerter {
    /// Initializeaza Alerter-ul si construieste transportul SMTP (daca email e activat).
    ///
    /// Returneaza `Result<Self>` deoarece construirea transportului SMTP poate esua
    /// (hostname invalid, port gresit, etc.). Erorile de configurare sunt detectate
    /// la startup, nu la prima alerta.
    pub fn new(
        config: AlertingConfig,
        detection: DetectionConfig,
        hostnames: HashMap<IpAddr, String>,
        subnets: Vec<SubnetEntry>,
    ) -> Result<Self> {
        // Construim mailer-ul O SINGURA DATA la startup, nu la fiecare alerta.
        let mailer = if config.email.enabled {
            Some(build_mailer(&config.email)?)
        } else {
            None
        };
        Ok(Self {
            config: ArcSwap::from_pointee(config),
            detection: ArcSwap::from_pointee(detection),
            mailer: ArcSwap::from_pointee(mailer),
            hostnames: ArcSwap::from_pointee(hostnames),
            subnets: ArcSwap::from_pointee(subnets),
        })
    }

    /// Actualizeaza configurarea alerter-ului la runtime (hot reload SIGHUP #16).
    ///
    /// Rebuild-ul mailer-ului este necesar daca se schimba SMTP server/port/TLS/credentials.
    /// Daca rebuild-ul esueaza, pastram mailer-ul vechi si logam eroarea.
    pub fn update_config(
        &self,
        new_alerting: AlertingConfig,
        new_detection: DetectionConfig,
        new_hostnames: HashMap<IpAddr, String>,
        new_subnets: Vec<SubnetEntry>,
    ) {
        // Rebuild mailer daca email e activat in noua configurare.
        let new_mailer = if new_alerting.email.enabled {
            match build_mailer(&new_alerting.email) {
                Ok(m) => Some(m),
                Err(e) => {
                    display::log_error(&format!(
                        "SIGHUP: rebuild SMTP esuat, pastrez mailer-ul vechi: {:#}",
                        e
                    ));
                    self.config.store(Arc::new(new_alerting));
                    self.detection.store(Arc::new(new_detection));
                    self.hostnames.store(Arc::new(new_hostnames));
                    self.subnets.store(Arc::new(new_subnets));
                    return;
                }
            }
        } else {
            None
        };

        self.config.store(Arc::new(new_alerting));
        self.detection.store(Arc::new(new_detection));
        self.mailer.store(Arc::new(new_mailer));
        self.hostnames.store(Arc::new(new_hostnames));
        self.subnets.store(Arc::new(new_subnets));
    }

    /// Send to the SIEM sink only. Delivery workers use this to isolate
    /// backpressure and retries between output destinations.
    pub async fn send_siem(&self, alert: &Alert) -> Result<()> {
        if self.config.load().siem.enabled {
            self.send_siem_alert(alert).await
        } else {
            Err(SinkUnavailable("SIEM dezactivat").into())
        }
    }

    /// Send to the email sink only.
    ///
    /// `recipients` restrange livrarea la un subset al destinatarilor
    /// configurati (retry dupa un esec partial); `None` = toti.
    pub async fn send_email(&self, alert: &Alert, recipients: Option<&[String]>) -> Result<()> {
        let mailer_guard = self.mailer.load();
        if let Some(ref mailer) = **mailer_guard {
            self.send_email_alert(alert, recipients, mailer).await
        } else {
            Err(SinkUnavailable(
                "mailer SMTP indisponibil (email dezactivat sau eroare la initializare)",
            )
            .into())
        }
    }

    pub fn siem_enabled(&self) -> bool {
        self.config.load().siem.enabled
    }

    pub fn email_enabled(&self) -> bool {
        self.config.load().email.enabled
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
    /// dar Rust/tokio ne forțează sa tratam ca async - consistenta API.
    ///
    async fn send_siem_alert(&self, alert: &Alert) -> Result<()> {
        // Formatam mesajul in format CEF peste Syslog RFC 3164 pentru ArcSight.
        //
        // Structura completa:
        //   <PRIORITY>TIMESTAMP HOSTNAME CEF:0|Vendor|Product|Ver|SigID|Name|Sev|Extensions
        //
        // Prioritate syslog: facility=4 (security) × 8 + severity=6 (info) = 38
        // Câmpuri CEF Extensions: rt, src, cnt, act, msg, cs1Label, cs1

        // Tuple: (SignatureID, EventName, DescriereMsg, SeveritateCEF)
        //
        // Severitatea CEF (campul 7 din header) indica urgenta in ArcSight:
        //   7 = High    → Fast Scan (raspuns imediat necesar)
        //   6 = Medium  → Slow Scan (investigare necesara)
        //   5 = Low     → Accept Scan (poate fi trafic legitim; investigare)
        //
        // Comentariul anterior spunea severitate 5 pentru AcceptScan, dar
        // codul folosea 7 hardcodat pentru toate tipurile — inconsistenta fixata.
        let det = self.detection.load();
        let (sig_id, event_name, scan_label, cef_severity) = match alert.scan_type {
            ScanType::Fast => (
                "1001",
                "Fast Port Scan Detected",
                format!(
                    "Fast Scan detectat: {} porturi unice in {} secunde",
                    alert.unique_ports.len(),
                    det.fast_scan.time_window_secs,
                ),
                7u8,
            ),
            ScanType::Slow => (
                "1002",
                "Slow Port Scan Detected",
                format!(
                    "Slow Scan detectat: {} porturi unice in {} minute",
                    alert.unique_ports.len(),
                    det.slow_scan.time_window_mins,
                ),
                6u8,
            ),
            ScanType::AcceptScan => (
                "1003",
                "Accept Port Scan Detected",
                format!(
                    "Accept Scan detectat: {} porturi deschise accesate in {} secunde",
                    alert.unique_ports.len(),
                    det.accept_scan.time_window_secs,
                ),
                5u8,
            ),
            ScanType::LateralMovement => (
                "1004",
                "Lateral Movement Detected",
                format!(
                    "Lateral Movement detectat: {} destinatii unice in {} secunde",
                    alert.unique_dests.len(),
                    det.lateral_movement.time_window_secs,
                ),
                8u8,
            ),
            ScanType::DistributedScan => (
                "1005",
                "Distributed Port Scan Detected",
                format!(
                    "Distributed Scan detectat: {} surse unice → tinta {} in {} secunde",
                    alert.unique_sources.len(),
                    alert
                        .dest_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "N/A".to_string()),
                    det.distributed_scan.time_window_secs,
                ),
                7u8,
            ),
            ScanType::Beaconing => (
                "1006",
                "Beaconing C2 Callback Detected",
                format!(
                    "Beaconing C2 detectat: {} calluri pe portul {}, interval mediu {:.1}s, CV {:.3}",
                    alert.event_count.unwrap_or(0),
                    alert.beacon_port.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string()),
                    alert.mean_interval_secs.unwrap_or(0.0),
                    alert.cv.unwrap_or(0.0),
                ),
                9u8,
            ),
        };

        // `cs1` retine mereu metrica principala numerica a detectiei (count), pentru
        // filtrare simpla in ArcSight (>=, <=, etc.). Listele mari merg in sample-uri
        // limitate pe cs4/cs6, in functie de tipul alertei.
        let (cs1_label, cs1_value, cnt) = match alert.scan_type {
            ScanType::LateralMovement => (
                "ContactedHostCount",
                alert.unique_dests.len().to_string(),
                alert.unique_dests.len(),
            ),
            ScanType::DistributedScan => {
                let src_list = sorted_ip_list_with_primary(&alert.unique_sources, alert.source_ip);
                let source_count = if src_list.is_empty() {
                    0
                } else {
                    src_list.split(',').count()
                };
                (
                    "AttackingSourceCount",
                    source_count.to_string(),
                    source_count,
                )
            }
            ScanType::Beaconing => {
                let cnt = alert.event_count.unwrap_or(0);
                ("BeaconEventCount", cnt.to_string(), cnt)
            }
            _ => (
                "ScannedPortCount",
                alert.unique_ports.len().to_string(),
                alert.unique_ports.len(),
            ),
        };

        // Includem listele complete in `msg` ca fallback daca operatorul nu are
        // coloanele cs6 afisate in Active Channel.
        let msg_text = match alert.scan_type {
            ScanType::DistributedScan => {
                let sources = sorted_ip_sample(&alert.unique_sources, Some(alert.source_ip), 128);
                if sources.is_empty() {
                    scan_label.clone()
                } else {
                    format!("{} | attacking_sources: {}", scan_label, sources)
                }
            }
            ScanType::LateralMovement => {
                let hosts = sorted_ip_sample(&alert.unique_dests, None, 128);
                if hosts.is_empty() {
                    scan_label.clone()
                } else {
                    format!("{} | contacted_hosts: {}", scan_label, hosts)
                }
            }
            ScanType::Fast | ScanType::Slow | ScanType::AcceptScan => {
                let ports = port_sample(&alert.unique_ports, 256);
                if ports.is_empty() {
                    scan_label.clone()
                } else {
                    format!("{} | scanned_ports: {}", scan_label, ports)
                }
            }
            ScanType::Beaconing => scan_label.clone(),
        };

        // Sanitizare anti-injection pentru event_name (camp header CEF, separator '|').
        let event_name_safe = sanitize_cef_header(event_name);

        // Campul dst (Target Address in ArcSight) — IP-ul tinta al scanarii.
        // Prezent doar daca log-ul sursa l-a furnizat.
        let dst_field = match alert.dest_ip {
            Some(ip) => format!(" dst={}", ip),
            None => String::new(),
        };

        // Campurile shost/dhost (Source/Destination Hostname in ArcSight).
        // Prezente doar daca hostname-ul este configurat in [network.hostnames].
        let hn = self.hostnames.load();
        let shost_field = match hn.get(&alert.source_ip) {
            Some(name) => format!(" shost={}", sanitize_cef_extension(name)),
            None => String::new(),
        };
        let dhost_field = match alert.dest_ip {
            Some(ref ip) => match hn.get(ip) {
                Some(name) => format!(" dhost={}", sanitize_cef_extension(name)),
                None => String::new(),
            },
            None => String::new(),
        };

        // Campurile cs2/cs3 — locatie fizica (etaj/zona) din subnet mapping.
        // cs2 = locatie IP sursa, cs3 = locatie IP destinatie.
        let sn = self.subnets.load();
        let src_location_field = match SubnetEntry::lookup(&sn, &alert.source_ip) {
            Some(loc) => format!(
                " cs2Label=SourceLocation cs2={}",
                sanitize_cef_extension(&loc)
            ),
            None => String::new(),
        };
        let dst_location_field = match alert.dest_ip {
            Some(ref ip) => match SubnetEntry::lookup(&sn, ip) {
                Some(loc) => format!(
                    " cs3Label=DestLocation cs3={}",
                    sanitize_cef_extension(&loc)
                ),
                None => String::new(),
            },
            None => String::new(),
        };
        let extra_fields = match alert.scan_type {
            ScanType::Fast => {
                let sample = alert
                    .unique_ports
                    .iter()
                    .take(20)
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let sample_field = if sample.is_empty() {
                    String::new()
                } else {
                    format!(
                        " cs4Label=PortSample cs4={}",
                        sanitize_cef_extension(&sample)
                    )
                };
                let full_list = port_sample(&alert.unique_ports, 256);
                let full_list_field = if full_list.is_empty() {
                    String::new()
                } else {
                    format!(
                        " cs6Label=ScannedPortList cs6={}",
                        sanitize_cef_extension(&full_list)
                    )
                };
                format!(
                    "{} cs5Label=DetectionWindowSecs cs5={}{}",
                    sample_field, det.fast_scan.time_window_secs, full_list_field
                )
            }
            ScanType::Slow => {
                let sample = alert
                    .unique_ports
                    .iter()
                    .take(20)
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let sample_field = if sample.is_empty() {
                    String::new()
                } else {
                    format!(
                        " cs4Label=PortSample cs4={}",
                        sanitize_cef_extension(&sample)
                    )
                };
                let full_list = port_sample(&alert.unique_ports, 256);
                let full_list_field = if full_list.is_empty() {
                    String::new()
                } else {
                    format!(
                        " cs6Label=ScannedPortList cs6={}",
                        sanitize_cef_extension(&full_list)
                    )
                };
                format!(
                    "{} cs5Label=DetectionWindowMins cs5={}{}",
                    sample_field, det.slow_scan.time_window_mins, full_list_field
                )
            }
            ScanType::AcceptScan => {
                let sample = alert
                    .unique_ports
                    .iter()
                    .take(20)
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let sample_field = if sample.is_empty() {
                    String::new()
                } else {
                    format!(
                        " cs4Label=PortSample cs4={}",
                        sanitize_cef_extension(&sample)
                    )
                };
                let full_list = port_sample(&alert.unique_ports, 256);
                let full_list_field = if full_list.is_empty() {
                    String::new()
                } else {
                    format!(
                        " cs6Label=ScannedPortList cs6={}",
                        sanitize_cef_extension(&full_list)
                    )
                };
                format!(
                    "{} cs5Label=DetectionWindowSecs cs5={}{}",
                    sample_field, det.accept_scan.time_window_secs, full_list_field
                )
            }
            ScanType::LateralMovement => {
                let sample = sorted_ip_list(&alert.unique_dests)
                    .split(',')
                    .take(10)
                    .collect::<Vec<_>>()
                    .join(",");
                let sample_field = if sample.is_empty() {
                    String::new()
                } else {
                    format!(
                        " cs4Label=ContactedHostSample cs4={}",
                        sanitize_cef_extension(&sample)
                    )
                };
                let full_list = sorted_ip_sample(&alert.unique_dests, None, 128);
                let full_list_field = if full_list.is_empty() {
                    String::new()
                } else {
                    format!(
                        " cs6Label=ContactedHostList cs6={}",
                        sanitize_cef_extension(&full_list)
                    )
                };
                format!(
                    "{} cs5Label=DetectionWindowSecs cs5={}{}",
                    sample_field, det.lateral_movement.time_window_secs, full_list_field
                )
            }
            ScanType::DistributedScan => {
                let target_field = match alert.dest_ip {
                    Some(ip) => format!(
                        " cs4Label=TargetAddress cs4={}",
                        sanitize_cef_extension(&ip.to_string())
                    ),
                    None => String::new(),
                };
                let sources = sorted_ip_sample(&alert.unique_sources, Some(alert.source_ip), 128);
                let source_list_field = if sources.is_empty() {
                    String::new()
                } else {
                    format!(
                        " cs6Label=AttackingSourceList cs6={}",
                        sanitize_cef_extension(&sources)
                    )
                };
                format!(
                    "{} cs5Label=DetectionWindowSecs cs5={}{}",
                    target_field, det.distributed_scan.time_window_secs, source_list_field
                )
            }
            ScanType::Beaconing => {
                let mean = alert.mean_interval_secs.unwrap_or(0.0);
                let cv = alert.cv.unwrap_or(0.0);
                let dpt = alert
                    .beacon_port
                    .map(|p| format!(" dpt={}", p))
                    .unwrap_or_default();
                format!(
                    " cs4Label=MeanIntervalSecs cs4={:.3} cs5Label=CV cs5={:.3}{}",
                    mean, cv, dpt
                )
            }
        };

        let syslog_ts = alert.timestamp.format("%b %e %H:%M:%S");
        let rt_ms = alert.timestamp.timestamp_millis();

        let message = format!(
            "<38>{syslog_ts} ids-rs CEF:0|IDS-RS|Network Scanner Detector|1.0\
             |{sig_id}|{event_name}|{sev}\
             |rt={rt_ms} src={src}{shost}{src_loc}{dst}{dhost}{dst_loc}{extra} cnt={cnt} act=alert \
             msg={msg} cs1Label={cs1label} cs1={cs1}",
            sev = cef_severity,
            syslog_ts = syslog_ts,
            sig_id = sig_id,
            event_name = event_name_safe,
            rt_ms = rt_ms,
            src = alert.source_ip,
            shost = shost_field,
            src_loc = src_location_field,
            dst = dst_field,
            dhost = dhost_field,
            dst_loc = dst_location_field,
            extra = extra_fields,
            cnt = cnt,
            msg = sanitize_cef_extension(&msg_text),
            cs1label = cs1_label,
            cs1 = sanitize_cef_extension(&cs1_value),
        );

        // Keep a safety margin below the maximum UDP payload. The list fields
        // above are sampled, so reaching this limit indicates an unexpectedly
        // large administrator-controlled label rather than attack cardinality.
        if message.len() > 60_000 {
            return Err(PermanentFailure(format!(
                "mesajul SIEM are {} bytes si depaseste limita sigura de 60000",
                message.len()
            ))
            .into());
        }

        // Cream un socket UDP efemer (port 0 = OS alege automat).
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Nu pot crea socket UDP pentru SIEM")?;

        let cfg = self.config.load();
        let dest = format!("{}:{}", cfg.siem.host, cfg.siem.port);
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
    async fn send_email_alert(
        &self,
        alert: &Alert,
        recipients: Option<&[String]>,
        mailer: &AsyncSmtpTransport<Tokio1Executor>,
    ) -> Result<()> {
        let alert_cfg = self.config.load();
        let cfg = &alert_cfg.email;

        // Pentru Lateral Movement si Distributed Scan, subject-ul si lista arata diferit.
        let (subject, item_count, list_display) = match alert.scan_type {
            ScanType::DistributedScan => {
                let attacker_list =
                    sorted_ip_list_with_primary(&alert.unique_sources, alert.source_ip);
                let count = if attacker_list.is_empty() {
                    0
                } else {
                    attacker_list.split(',').count()
                };
                let list = comma_to_display_list(&attacker_list);
                let target = alert
                    .dest_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "N/A".to_string());
                let subj = format!(
                    "\u{1F534} [{}][SCANARE COORDONATA] IDS-RS {} surse → {}",
                    alert.scan_type, count, target
                );
                (subj, count, list)
            }
            ScanType::LateralMovement => {
                let dest_list = sorted_ip_list(&alert.unique_dests);
                let count = alert.unique_dests.len();
                let list = comma_to_display_list(&dest_list);
                let subj = format!(
                    "\u{1F534} [{}][MISCARE LATERALA] IDS-RS {} {} destinatii",
                    alert.scan_type, alert.source_ip, count
                );
                (subj, count, list)
            }
            ScanType::Beaconing => {
                // Pentru Beaconing, "lista" arata flow-ul + statisticile.
                let count = alert.event_count.unwrap_or(0);
                let mean = alert.mean_interval_secs.unwrap_or(0.0);
                let cv = alert.cv.unwrap_or(0.0);
                let dst_str = alert
                    .dest_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "N/A".to_string());
                let port_str = alert
                    .beacon_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "?".to_string());
                let list = format!(
                    "Flow: {} → {}:{} | calluri: {} | interval mediu: {:.1}s | CV: {:.3}",
                    alert.source_ip, dst_str, port_str, count, mean, cv
                );
                let subj = format!(
                    "\u{1F534} [{}][BEACON C2] IDS-RS {} → {}:{} ({} calluri)",
                    alert.scan_type, alert.source_ip, dst_str, port_str, count
                );
                (subj, count, list)
            }
            _ => {
                let count = alert.unique_ports.len();
                let list = alert
                    .unique_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let subj = format!(
                    "\u{1F534} [{}][SCANARE RETEA] IDS-RS {} {} porturi",
                    alert.scan_type, alert.source_ip, count
                );
                (subj, count, list)
            }
        };

        // Severitate afisata in email — paralela cu severitatea CEF din send_siem_alert.
        // Fast=7=RIDICATA, Slow=6=MEDIE, AcceptScan=5=MEDIE-MICA, LateralMovement=8=CRITICA.
        let severity = match alert.scan_type {
            ScanType::Fast => "RIDICATA",
            ScanType::Slow => "MEDIE",
            ScanType::AcceptScan => "MEDIE-MICA",
            ScanType::LateralMovement => "CRITICA",
            ScanType::DistributedScan => "RIDICATA",
            ScanType::Beaconing => "CRITICA",
        };

        let dest_ip_display = match alert.dest_ip {
            Some(ip) => ip.to_string(),
            None => "N/A".to_string(),
        };
        let source_ip_display = alert.source_ip.to_string();

        // Hostname-uri din mapping-ul static.
        let hn = self.hostnames.load();
        let src_hostname = hn.get(&alert.source_ip).map(|s| s.as_str()).unwrap_or("");
        let dst_hostname = match alert.dest_ip {
            Some(ref ip) => hn.get(ip).map(|s| s.as_str()).unwrap_or(""),
            None => "",
        };

        // Locatii subnet din mapping-ul static.
        let sn = self.subnets.load();
        let src_location = SubnetEntry::lookup(&sn, &alert.source_ip).unwrap_or_default();
        let dst_location = match alert.dest_ip {
            Some(ref ip) => SubnetEntry::lookup(&sn, ip).unwrap_or_default(),
            None => String::new(),
        };

        let timestamp = alert.timestamp.format("%Y-%m-%d %H:%M:%S");

        // Etichete dinamice in email: adapteaza "Porturi scanate" / "Porturi detectate"
        // la tipul de alerta. Lateral Movement arata destinatii, Distributed arata surse.
        let (count_label, list_label) = match alert.scan_type {
            ScanType::LateralMovement => (
                "Destinatii contactate",
                "Destinatii detectate (set complet)",
            ),
            ScanType::DistributedScan => ("Surse atacatoare", "Surse detectate (set complet)"),
            ScanType::Beaconing => ("Calluri C2", "Detalii beacon"),
            _ => ("Porturi scanate", "Porturi detectate"),
        };

        let scan_type = alert.scan_type.to_string();
        let (
            source_ip,
            dst_ip,
            src_hostname_display,
            src_location_display,
            dst_hostname_display,
            dst_location_display,
        ) = match alert.scan_type {
            // Pentru Distributed, `source_ip` din alerta este doar IP-ul care a
            // declansat pragul; semnalam explicit acest lucru in email.
            ScanType::DistributedScan => (
                format!("MULTIPLE (trigger: {})", source_ip_display),
                dest_ip_display.clone(),
                String::new(),
                String::new(),
                dst_hostname.to_string(),
                dst_location.clone(),
            ),
            // Pentru Lateral, `dest_ip` din alerta este doar destinatia din
            // evenimentul trigger; setul complet este in `Destinatii detectate`.
            ScanType::LateralMovement => (
                source_ip_display.clone(),
                match alert.dest_ip {
                    Some(ip) => format!("MULTIPLE (trigger: {})", ip),
                    None => "MULTIPLE".to_string(),
                },
                src_hostname.to_string(),
                src_location.clone(),
                String::new(),
                String::new(),
            ),
            _ => (
                source_ip_display.clone(),
                dest_ip_display.clone(),
                src_hostname.to_string(),
                src_location.clone(),
                dst_hostname.to_string(),
                dst_location.clone(),
            ),
        };
        let cmd_src_ip = source_ip_display;
        let cmd_dst_ip = dest_ip_display;
        let timestamp = timestamp.to_string();

        let html_body = build_html_body(&HtmlAlertBody {
            scan_type: &scan_type,
            severity,
            src_ip: &source_ip,
            src_hostname: &src_hostname_display,
            src_location: &src_location_display,
            dst_ip: &dst_ip,
            dst_hostname: &dst_hostname_display,
            dst_location: &dst_location_display,
            item_count,
            timestamp: &timestamp,
            items: &list_display,
            footer: &cfg.email_footer,
            count_label,
            list_label,
            cmd_src_ip: &cmd_src_ip,
            cmd_dst_ip: &cmd_dst_ip,
        });

        // Trimitem un email separat catre fiecare destinatar si retinem
        // exact cine NU l-a primit: la retry, cei care l-au primit deja nu
        // trebuie sa primeasca din nou aceeasi alerta.
        //
        // Un destinatar eliminat intre timp din config (SIGHUP) este sarit.
        let targets: Vec<&String> = match recipients {
            Some(subset) => cfg.to.iter().filter(|r| subset.contains(r)).collect(),
            None => cfg.to.iter().collect(),
        };
        let mut pending = Vec::new();
        let mut rejected = Vec::new();
        let mut details = Vec::new();
        for recipient in targets {
            let email: Result<Message> = (|| {
                Message::builder()
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
                    .context("Nu pot construi mesajul email")
            })();
            let email = match email {
                Ok(email) => email,
                Err(error) => {
                    details.push(format!("{}: {:#}", recipient, error));
                    rejected.push(recipient.clone());
                    continue;
                }
            };

            if let Err(error) = mailer.send(email).await {
                details.push(format!("{}: {}", recipient, error));
                if error.is_permanent() {
                    rejected.push(recipient.clone());
                } else {
                    pending.push(recipient.clone());
                }
            }
        }
        if !pending.is_empty() || !rejected.is_empty() {
            return Err(EmailFailure {
                pending,
                rejected,
                details,
            }
            .into());
        }

        display::log_alert_sent("Email", &format!("{}", alert.scan_type));
        Ok(())
    }
}

// =============================================================================
// Teste unitare — sanitize_cef()
// =============================================================================

/// Server SMTP minimal pentru teste: accepta orice destinatar, cu exceptia
/// celor din `responses`, carora le raspunde la RCPT cu codul dat (ex: 550
/// = permanent, 451 = tranzitoriu). Inregistreaza destinatarii carora le-a
/// fost livrat efectiv un mesaj.
#[cfg(test)]
pub(crate) mod test_smtp {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    pub(crate) type Delivered = Arc<Mutex<Vec<String>>>;

    pub(crate) async fn start(responses: HashMap<String, String>) -> (u16, Delivered) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let delivered: Delivered = Arc::default();
        let log = Arc::clone(&delivered);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let responses = responses.clone();
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let (read, mut write) = stream.into_split();
                    let mut lines = BufReader::new(read).lines();
                    let mut accepted = Vec::new();
                    let _ = write.write_all(b"220 fake\r\n").await;
                    while let Ok(Some(line)) = lines.next_line().await {
                        let upper = line.to_ascii_uppercase();
                        let reply = if upper.starts_with("RCPT TO:") {
                            let address = line[8..]
                                .trim()
                                .trim_start_matches('<')
                                .split('>')
                                .next()
                                .unwrap_or_default()
                                .to_string();
                            match responses.get(&address) {
                                Some(code) => format!("{code} nu\r\n"),
                                None => {
                                    accepted.push(address);
                                    "250 ok\r\n".to_string()
                                }
                            }
                        } else if upper == "DATA" {
                            let _ = write.write_all(b"354 go\r\n").await;
                            while let Ok(Some(body)) = lines.next_line().await {
                                if body == "." {
                                    break;
                                }
                            }
                            log.lock().unwrap().append(&mut accepted);
                            "250 ok\r\n".to_string()
                        } else if upper.starts_with("RSET") {
                            accepted.clear();
                            "250 ok\r\n".to_string()
                        } else if upper.starts_with("QUIT") {
                            let _ = write.write_all(b"221 bye\r\n").await;
                            break;
                        } else {
                            "250 ok\r\n".to_string()
                        };
                        if write.write_all(reply.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (port, delivered)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        sanitize_cef_extension, sanitize_cef_header, sorted_ip_sample, Alerter, EmailFailure,
        SinkUnavailable,
    };
    use crate::config::{AppConfig, SubnetEntry};
    use crate::detector::{Alert, ScanType};
    use chrono::Local;
    use std::collections::HashMap;
    use std::net::IpAddr;

    #[test]
    fn test_sanitize_header_newline() {
        assert_eq!(sanitize_cef_header("text\nfals"), "text\\nfals");
    }

    #[test]
    fn test_sanitize_header_carriage_return() {
        assert_eq!(sanitize_cef_header("text\rfals"), "text\\rfals");
    }

    #[test]
    fn test_sanitize_header_pipe() {
        assert_eq!(sanitize_cef_header("camp|fals"), "camp\\|fals");
    }

    #[test]
    fn test_sanitize_header_backslash() {
        assert_eq!(sanitize_cef_header("c:\\path"), "c:\\\\path");
    }

    #[test]
    fn test_sanitize_extension_value_separators() {
        // Spatiile raman (permise de CEF); `=` este escapat, deci "key=value"
        // din valoare nu poate deveni o pereche noua.
        assert_eq!(
            sanitize_cef_extension("host name key=value"),
            "host name key\\=value"
        );
    }

    #[test]
    fn test_sanitize_header_combinat() {
        // Atac complet: injectie linie syslog noua cu camp CEF fals
        let input = "evil\nFeb 18 00:00:00 ids-rs CEF:0|FAKE|Product|1.0|999|Fake|10|";
        let output = sanitize_cef_header(input);
        // Nu trebuie sa contina newline neescape
        assert!(!output.contains('\n'));
        // Nu trebuie sa contina pipe neescape (in afara de cele din escape)
        assert!(!output.contains("CEF:0|FAKE"));
        // Trebuie sa contina versiunea escapata
        assert!(output.contains("\\n"));
        assert!(output.contains("\\|"));
    }

    #[test]
    fn test_sanitize_header_string_curat() {
        // Textul normal nu trebuie modificat
        assert_eq!(
            sanitize_cef_header("Fast Scan detectat: 20 porturi"),
            "Fast Scan detectat: 20 porturi"
        );
    }

    #[test]
    fn test_sanitize_header_backslash_inainte_de_pipe() {
        // Backslash urmat de pipe: trebuie escapeat corect, nu dublu-escapeat
        // Input: "a\|b" => Output: "a\\\\\\|b"  (backslash si pipe ambele escapate)
        let input = "a\\|b";
        let output = sanitize_cef_header(input);
        assert_eq!(output, "a\\\\\\|b");
    }

    #[tokio::test]
    async fn large_alert_is_sampled_below_safe_udp_size() {
        let mut app = AppConfig::load("config.toml").unwrap();
        app.alerting.email.enabled = false;
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.alerting.siem.host = "127.0.0.1".to_string();
        app.alerting.siem.port = receiver.local_addr().unwrap().port();
        let alerter = Alerter::new(
            app.alerting,
            app.detection,
            HashMap::new(),
            SubnetEntry::parse_subnets(&HashMap::new()),
        )
        .unwrap();
        let alert = Alert {
            scan_type: ScanType::Fast,
            source_ip: "192.0.2.1".parse().unwrap(),
            dest_ip: Some("198.51.100.1".parse().unwrap()),
            unique_ports: (0..10_000).collect(),
            unique_dests: Vec::new(),
            unique_sources: Vec::new(),
            timestamp: Local::now(),
            beacon_port: None,
            mean_interval_secs: None,
            cv: None,
            event_count: None,
        };

        alerter.send_siem(&alert).await.unwrap();
        let mut buffer = vec![0u8; 65_507];
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            receiver.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(length <= 60_000);
    }

    #[tokio::test]
    async fn disabled_sinks_report_unavailable_instead_of_success() {
        let mut app = AppConfig::load("config.toml").unwrap();
        app.alerting.email.enabled = false;
        app.alerting.siem.enabled = false;
        let alerter = Alerter::new(
            app.alerting,
            app.detection,
            HashMap::new(),
            SubnetEntry::parse_subnets(&HashMap::new()),
        )
        .unwrap();
        let alert = Alert {
            scan_type: ScanType::Fast,
            source_ip: "192.0.2.1".parse().unwrap(),
            dest_ip: Some("198.51.100.1".parse().unwrap()),
            unique_ports: vec![22, 80],
            unique_dests: Vec::new(),
            unique_sources: Vec::new(),
            timestamp: Local::now(),
            beacon_port: None,
            mean_interval_secs: None,
            cv: None,
            event_count: None,
        };

        let siem = alerter.send_siem(&alert).await.unwrap_err();
        assert!(siem.downcast_ref::<SinkUnavailable>().is_some());
        let email = alerter.send_email(&alert, None).await.unwrap_err();
        assert!(email.downcast_ref::<SinkUnavailable>().is_some());
    }

    #[tokio::test]
    async fn partial_email_failure_reports_only_undelivered_recipients() {
        let (port, delivered) = super::test_smtp::start(HashMap::from([
            ("gone@test.local".to_string(), "550".to_string()),
            ("later@test.local".to_string(), "451".to_string()),
        ]))
        .await;
        let mut app = AppConfig::load("config.toml").unwrap();
        app.alerting.siem.enabled = false;
        app.alerting.email.enabled = true;
        app.alerting.email.smtp_server = "127.0.0.1".to_string();
        app.alerting.email.smtp_port = port;
        app.alerting.email.smtp_tls = false;
        app.alerting.email.to = vec![
            "ok@test.local".to_string(),
            "gone@test.local".to_string(),
            "later@test.local".to_string(),
        ];
        let alerter = Alerter::new(
            app.alerting,
            app.detection,
            HashMap::new(),
            SubnetEntry::parse_subnets(&HashMap::new()),
        )
        .unwrap();
        let alert = Alert {
            scan_type: ScanType::Fast,
            source_ip: "192.0.2.1".parse().unwrap(),
            dest_ip: Some("198.51.100.1".parse().unwrap()),
            unique_ports: vec![22, 80],
            unique_dests: Vec::new(),
            unique_sources: Vec::new(),
            timestamp: Local::now(),
            beacon_port: None,
            mean_interval_secs: None,
            cv: None,
            event_count: None,
        };

        let error = alerter.send_email(&alert, None).await.unwrap_err();
        let failure = error.downcast_ref::<EmailFailure>().unwrap();
        assert_eq!(failure.pending, vec!["later@test.local".to_string()]);
        assert_eq!(failure.rejected, vec!["gone@test.local".to_string()]);
        assert_eq!(
            *delivered.lock().unwrap(),
            vec!["ok@test.local".to_string()]
        );

        // Retry-ul vizeaza doar destinatarul ramas; ok@ nu primeste din nou.
        let pending = failure.pending.clone();
        let _ = alerter.send_email(&alert, Some(&pending)).await;
        assert_eq!(
            *delivered.lock().unwrap(),
            vec!["ok@test.local".to_string()]
        );
    }

    #[test]
    fn ip_sample_always_contains_primary() {
        let sources: Vec<IpAddr> = (1..=300u32)
            .map(|i| IpAddr::from(std::net::Ipv4Addr::from(0xcb00_7100 + i)))
            .collect();
        let primary: IpAddr = "203.0.113.250".parse().unwrap();

        let sample = sorted_ip_sample(&sources, Some(primary), 128);
        let listed: Vec<&str> = sample.split(',').collect();
        assert_eq!(listed.len(), 128);
        assert!(listed.contains(&"203.0.113.250"));

        let small = sorted_ip_sample(&sources[..3], Some(primary), 128);
        assert_eq!(small, "203.0.113.1,203.0.113.2,203.0.113.3,203.0.113.250");
        assert_eq!(
            sorted_ip_sample(&sources, None, 2),
            "203.0.113.1,203.0.113.2"
        );
    }

    #[tokio::test]
    async fn cef_extension_values_keep_plain_spaces() {
        let mut app = AppConfig::load("config.toml").unwrap();
        app.alerting.email.enabled = false;
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.alerting.siem.host = "127.0.0.1".to_string();
        app.alerting.siem.port = receiver.local_addr().unwrap().port();
        let subnets = SubnetEntry::parse_subnets(&HashMap::from([(
            "192.0.2.0/24".to_string(),
            "Etaj 2".to_string(),
        )]));
        let alerter = Alerter::new(app.alerting, app.detection, HashMap::new(), subnets).unwrap();
        let alert = Alert {
            scan_type: ScanType::Fast,
            source_ip: "192.0.2.1".parse().unwrap(),
            dest_ip: Some("198.51.100.1".parse().unwrap()),
            unique_ports: vec![22, 80],
            unique_dests: Vec::new(),
            unique_sources: Vec::new(),
            timestamp: Local::now(),
            beacon_port: None,
            mean_interval_secs: None,
            cv: None,
            event_count: None,
        };

        alerter.send_siem(&alert).await.unwrap();
        let mut buffer = vec![0u8; 65_507];
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            receiver.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        let message = String::from_utf8_lossy(&buffer[..length]);
        assert!(message.contains("cs2=Etaj 2 "), "{message}");
        assert!(
            message.contains("msg=Fast Scan detectat: 2 porturi"),
            "{message}"
        );
        assert!(!message.contains("\\ "), "{message}");
    }
}
