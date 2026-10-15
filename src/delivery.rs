use crate::alerter::{Alerter, EmailFailure, PermanentFailure, SinkUnavailable};
use crate::config::AlertingConfig;
use crate::detector::Alert;
use crate::display;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

static SPOOL_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
enum Sink {
    Siem,
    Email,
}

impl Sink {
    fn name(self) -> &'static str {
        match self {
            Self::Siem => "siem",
            Self::Email => "email",
        }
    }
}

/// O intrare din spool: alerta plus, pentru email, destinatarii care inca
/// nu au primit-o (`None` = toti destinatarii configurati).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpoolRecord {
    alert: Alert,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipients: Option<Vec<String>>,
}

impl SpoolRecord {
    fn new(alert: Alert) -> Self {
        Self {
            alert,
            recipients: None,
        }
    }

    fn for_recipients(&self, recipients: &[String]) -> Self {
        Self {
            alert: self.alert.clone(),
            recipients: Some(recipients.to_vec()),
        }
    }
}

/// Formatul de pe disc. Versiunile anterioare salvau direct `Alert`;
/// acestea sunt citite in continuare ca intrari pentru toti destinatarii.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredRecord {
    Current(SpoolRecord),
    Legacy(Alert),
}

#[derive(Clone)]
struct Spool {
    directory: PathBuf,
    /// Alertele care au esuat definitiv. Nu sunt reincercate automat, dar
    /// raman pe disc pentru inspectie / reinjectare manuala.
    dead_letter: PathBuf,
}

impl Spool {
    fn new(base: &Path, sink: Sink) -> Result<Self> {
        let directory = base.join(sink.name());
        let dead_letter = directory.join("dead");
        fs::create_dir_all(&dead_letter)
            .with_context(|| format!("nu pot crea spool-ul {}", dead_letter.display()))?;
        Ok(Self {
            directory,
            dead_letter,
        })
    }

    fn persist(&self, record: &SpoolRecord) -> Result<()> {
        Self::persist_into(&self.directory, record)
    }

    /// Salveaza direct in dead-letter o alerta care a esuat definitiv.
    fn bury(&self, record: &SpoolRecord) -> Result<()> {
        Self::persist_into(&self.dead_letter, record)
    }

    /// Muta in dead-letter un fisier existent din spool.
    fn bury_file(&self, path: &Path) -> Result<()> {
        let name = path.file_name().context("cale spool fara nume de fisier")?;
        fs::rename(path, self.dead_letter.join(name))?;
        Ok(())
    }

    /// Inlocuieste atomic continutul unui fisier din spool, pastrandu-i
    /// pozitia in coada (numele determina ordinea).
    fn rewrite(&self, path: &Path, record: &SpoolRecord) -> Result<()> {
        let name = path.file_name().context("cale spool fara nume de fisier")?;
        let temporary = self
            .directory
            .join(format!(".{}.tmp", name.to_string_lossy()));
        Self::write_atomic(&temporary, path, record)
    }

    fn persist_into(directory: &Path, record: &SpoolRecord) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sequence = SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let stem = format!("{now:020}-{:010}-{sequence:020}", std::process::id());
        let temporary = directory.join(format!(".{stem}.tmp"));
        let final_path = directory.join(format!("{stem}.json"));
        Self::write_atomic(&temporary, &final_path, record)
    }

    fn write_atomic(temporary: &Path, final_path: &Path, record: &SpoolRecord) -> Result<()> {
        let payload = serde_json::to_vec(record).context("nu pot serializa alerta pentru spool")?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(temporary)
            .with_context(|| format!("nu pot crea {}", temporary.display()))?;
        file.write_all(&payload)?;
        file.sync_all()?;
        fs::rename(temporary, final_path)?;
        Ok(())
    }

    fn oldest(&self) -> Result<Option<(PathBuf, SpoolRecord)>> {
        let mut paths = fs::read_dir(&self.directory)?
            .filter_map(|entry| entry.ok().map(|item| item.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect::<Vec<_>>();
        paths.sort_unstable();

        for path in paths {
            match fs::read(&path)
                .with_context(|| format!("nu pot citi {}", path.display()))
                .and_then(|bytes| {
                    serde_json::from_slice::<StoredRecord>(&bytes)
                        .with_context(|| format!("spool corupt: {}", path.display()))
                }) {
                Ok(StoredRecord::Current(record)) => return Ok(Some((path, record))),
                Ok(StoredRecord::Legacy(alert)) => {
                    return Ok(Some((path, SpoolRecord::new(alert))))
                }
                Err(error) => {
                    let bad = path.with_extension("bad");
                    let _ = fs::rename(&path, &bad);
                    display::log_error(&format!("{}", error));
                }
            }
        }
        Ok(None)
    }
}

pub struct DeliveryManager {
    siem_tx: mpsc::Sender<Alert>,
    email_tx: mpsc::Sender<Alert>,
    siem_spool: Spool,
    email_spool: Spool,
    alerter: Arc<Alerter>,
}

impl DeliveryManager {
    pub fn start(
        config: &AlertingConfig,
        alerter: Arc<Alerter>,
    ) -> Result<(Self, Vec<tokio::task::JoinHandle<()>>)> {
        let capacity = config.queue_capacity;
        let (siem_tx, siem_rx) = mpsc::channel(capacity);
        let (email_tx, email_rx) = mpsc::channel(capacity);
        let base = Path::new(&config.spool_directory);
        let siem_spool = Spool::new(base, Sink::Siem)?;
        let email_spool = Spool::new(base, Sink::Email)?;
        let retry_initial = Duration::from_secs(config.retry_initial_secs);
        let retry_max = Duration::from_secs(config.retry_max_secs);

        let handles = vec![
            tokio::spawn(run_worker(
                Sink::Siem,
                siem_rx,
                Arc::clone(&alerter),
                siem_spool.clone(),
                retry_initial,
                retry_max,
            )),
            tokio::spawn(run_worker(
                Sink::Email,
                email_rx,
                Arc::clone(&alerter),
                email_spool.clone(),
                retry_initial,
                retry_max,
            )),
        ];

        Ok((
            Self {
                siem_tx,
                email_tx,
                siem_spool,
                email_spool,
                alerter,
            },
            handles,
        ))
    }

    pub fn enqueue(&self, alert: &Alert) {
        if self.alerter.siem_enabled() {
            enqueue_or_spool(&self.siem_tx, &self.siem_spool, alert.clone(), "SIEM");
        }
        if self.alerter.email_enabled() {
            enqueue_or_spool(&self.email_tx, &self.email_spool, alert.clone(), "email");
        }
    }
}

fn enqueue_or_spool(sender: &mpsc::Sender<Alert>, spool: &Spool, alert: Alert, label: &str) {
    match sender.try_send(alert) {
        Ok(()) => {}
        Err(TrySendError::Full(alert) | TrySendError::Closed(alert)) => {
            if let Err(error) = spool.persist(&SpoolRecord::new(alert)) {
                display::log_error(&format!(
                    "FATAL: alerta {} nu a putut fi pusa nici in coada, nici in spool: {:#}",
                    label, error
                ));
            } else {
                display::log_warning(&format!(
                    "Coada {} indisponibila/plina; alerta salvata durabil in spool",
                    label
                ));
            }
        }
    }
}

async fn run_worker(
    sink: Sink,
    mut receiver: mpsc::Receiver<Alert>,
    alerter: Arc<Alerter>,
    spool: Spool,
    retry_initial: Duration,
    retry_max: Duration,
) {
    let mut backoff = retry_initial;
    let mut unavailable_reported = false;
    loop {
        match spool.oldest() {
            Ok(Some((path, record))) => {
                let result = deliver(sink, &alerter, &record).await;
                let delivered = result.is_ok();
                match settle(
                    sink,
                    &spool,
                    Some(&path),
                    &record,
                    result,
                    &mut unavailable_reported,
                ) {
                    Settled::Done => {
                        if delivered {
                            backoff = retry_initial;
                        }
                    }
                    Settled::Retry => {
                        tokio::time::sleep(backoff).await;
                        backoff = backoff.saturating_mul(2).min(retry_max);
                    }
                }
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                display::log_error(&format!("Eroare citire spool {}: {:#}", sink.name(), error));
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(retry_max);
                continue;
            }
        }

        let Some(alert) = receiver.recv().await else {
            break;
        };
        let record = SpoolRecord::new(alert);
        let result = deliver(sink, &alerter, &record).await;
        if result.is_ok() {
            backoff = retry_initial;
        }
        settle(
            sink,
            &spool,
            None,
            &record,
            result,
            &mut unavailable_reported,
        );
    }
}

enum Settled {
    /// Intrarea a fost rezolvata (livrata sau mutata in dead-letter).
    Done,
    /// Ceva ramane de reincercat; intrarea e (inca) in spool.
    Retry,
}

/// Aplica rezultatul unei livrari asupra spool-ului.
///
/// `origin` este fisierul din spool din care provine intrarea, sau `None`
/// pentru o alerta venita direct din coada (inca nesalvata pe disc).
fn settle(
    sink: Sink,
    spool: &Spool,
    origin: Option<&Path>,
    record: &SpoolRecord,
    result: Result<()>,
    unavailable_reported: &mut bool,
) -> Settled {
    let error = match result {
        Ok(()) => {
            *unavailable_reported = false;
            if let Some(path) = origin {
                if let Err(error) = fs::remove_file(path) {
                    display::log_error(&format!(
                        "Alerta livrata dar spool-ul {} nu poate fi sters: {}",
                        path.display(),
                        error
                    ));
                }
            }
            return Settled::Done;
        }
        Err(error) => error,
    };

    // Email partial: destinatarii care au primit alerta sunt eliminati,
    // ca un retry sa nu le-o trimita din nou.
    if let Some(failure) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<EmailFailure>())
    {
        if !failure.rejected.is_empty() {
            log_save_error(sink, spool.bury(&record.for_recipients(&failure.rejected)));
        }
        if failure.pending.is_empty() {
            report_permanent(sink, &error);
            if let Some(path) = origin {
                let _ = fs::remove_file(path);
            }
            return Settled::Done;
        }
        report_failure(sink, &error, unavailable_reported);
        let retry = record.for_recipients(&failure.pending);
        log_save_error(
            sink,
            match origin {
                Some(path) => spool.rewrite(path, &retry),
                None => spool.persist(&retry),
            },
        );
        return Settled::Retry;
    }

    if is_permanent(&error) {
        report_permanent(sink, &error);
        let buried = match origin {
            Some(path) => spool.bury_file(path),
            None => spool.bury(record),
        };
        if buried.is_err() {
            log_save_error(sink, buried);
            return Settled::Retry;
        }
        return Settled::Done;
    }

    report_failure(sink, &error, unavailable_reported);
    if origin.is_none() {
        log_save_error(sink, spool.persist(record));
    }
    Settled::Retry
}

fn log_save_error(sink: Sink, result: Result<()>) {
    if let Err(error) = result {
        display::log_error(&format!(
            "FATAL: nu pot salva alerta {} in spool: {:#}",
            sink.name(),
            error
        ));
    }
}

/// Logheaza o livrare esuata. Un canal indisponibil (dezactivat/fara mailer)
/// este raportat o singura data pana la urmatoarea livrare reusita, ca sa nu
/// inunde log-ul la fiecare retry; alertele raman in spool.
fn report_failure(sink: Sink, error: &anyhow::Error, unavailable_reported: &mut bool) {
    if error.downcast_ref::<SinkUnavailable>().is_some() {
        if !*unavailable_reported {
            display::log_warning(&format!(
                "Canal {} indisponibil ({}); alertele raman in spool pana la reactivare",
                sink.name(),
                error
            ));
            *unavailable_reported = true;
        }
    } else {
        display::log_error(&format!("Livrare {} esuata: {:#}", sink.name(), error));
    }
}

fn is_permanent(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<PermanentFailure>())
}

fn report_permanent(sink: Sink, error: &anyhow::Error) {
    display::log_error(&format!(
        "Livrare {} esuata definitiv; alerta mutata in dead-letter: {:#}",
        sink.name(),
        error
    ));
}

async fn deliver(sink: Sink, alerter: &Alerter, record: &SpoolRecord) -> Result<()> {
    match sink {
        Sink::Siem => alerter.send_siem(&record.alert).await,
        Sink::Email => {
            alerter
                .send_email(&record.alert, record.recipients.as_deref())
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::ScanType;
    use chrono::Local;

    fn alert() -> Alert {
        Alert {
            scan_type: ScanType::Fast,
            source_ip: "192.0.2.1".parse().unwrap(),
            dest_ip: Some("198.51.100.1".parse().unwrap()),
            unique_ports: vec![22, 80, 443],
            unique_dests: Vec::new(),
            unique_sources: Vec::new(),
            timestamp: Local::now(),
            beacon_port: None,
            mean_interval_secs: None,
            cv: None,
            event_count: None,
        }
    }

    #[test]
    fn spool_round_trip_is_durable_and_readable() {
        let unique = format!(
            "ids-rs-spool-test-{}-{}",
            std::process::id(),
            SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let base = std::env::temp_dir().join(unique);
        let spool = Spool::new(&base, Sink::Siem).unwrap();
        spool.persist(&SpoolRecord::new(alert())).unwrap();
        let (path, recovered) = spool.oldest().unwrap().unwrap();
        assert!(path.exists());
        assert_eq!(
            recovered.alert.source_ip,
            "192.0.2.1".parse::<std::net::IpAddr>().unwrap()
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn spooled_alert_is_kept_while_sink_is_unavailable() {
        let unique = format!(
            "ids-rs-spool-test-{}-{}",
            std::process::id(),
            SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let base = std::env::temp_dir().join(unique);
        let spool = Spool::new(&base, Sink::Siem).unwrap();
        spool.persist(&SpoolRecord::new(alert())).unwrap();

        let mut app = crate::config::AppConfig::load("config.toml").unwrap();
        app.alerting.siem.enabled = false;
        app.alerting.email.enabled = false;
        let alerter = Arc::new(
            Alerter::new(
                app.alerting,
                app.detection,
                std::collections::HashMap::new(),
                Vec::new(),
            )
            .unwrap(),
        );
        let (_sender, receiver) = mpsc::channel(4);
        let worker = tokio::spawn(run_worker(
            Sink::Siem,
            receiver,
            alerter,
            spool.clone(),
            Duration::from_millis(10),
            Duration::from_millis(10),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        worker.abort();

        assert!(spool.oldest().unwrap().is_some());
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn permanently_failing_alert_does_not_block_the_spool() {
        let unique = format!(
            "ids-rs-spool-test-{}-{}",
            std::process::id(),
            SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let base = std::env::temp_dir().join(unique);
        let spool = Spool::new(&base, Sink::Siem).unwrap();

        // Un hostname urias face mesajul CEF al primei alerte sa depaseasca
        // limita de 60 KB: esec permanent, aflat in capul spool-ului.
        let poisoned = alert();
        let mut healthy = alert();
        healthy.source_ip = "192.0.2.2".parse().unwrap();
        spool.persist(&SpoolRecord::new(poisoned.clone())).unwrap();
        spool.persist(&SpoolRecord::new(healthy)).unwrap();

        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut app = crate::config::AppConfig::load("config.toml").unwrap();
        app.alerting.email.enabled = false;
        app.alerting.siem.host = "127.0.0.1".to_string();
        app.alerting.siem.port = receiver.local_addr().unwrap().port();
        let hostnames = std::collections::HashMap::from([(poisoned.source_ip, "h".repeat(70_000))]);
        let alerter =
            Arc::new(Alerter::new(app.alerting, app.detection, hostnames, Vec::new()).unwrap());
        let (_sender, channel) = mpsc::channel(4);
        let worker = tokio::spawn(run_worker(
            Sink::Siem,
            channel,
            alerter,
            spool.clone(),
            Duration::from_secs(60),
            Duration::from_secs(60),
        ));

        let mut buffer = vec![0u8; 65_507];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buffer))
                .await
                .expect("alerta sanatoasa trebuie livrata fara a astepta retry-ul")
                .unwrap();
        assert!(String::from_utf8_lossy(&buffer[..length]).contains("192.0.2.2"));
        worker.abort();

        assert!(spool.oldest().unwrap().is_none());
        assert_eq!(fs::read_dir(&spool.dead_letter).unwrap().count(), 1);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn legacy_spool_entries_are_still_readable() {
        let unique = format!(
            "ids-rs-spool-test-{}-{}",
            std::process::id(),
            SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let base = std::env::temp_dir().join(unique);
        let spool = Spool::new(&base, Sink::Email).unwrap();
        fs::write(
            spool.directory.join("0-legacy.json"),
            serde_json::to_vec(&alert()).unwrap(),
        )
        .unwrap();

        let (_, record) = spool.oldest().unwrap().unwrap();
        assert!(record.recipients.is_none());
        assert_eq!(record.alert.unique_ports, vec![22, 80, 443]);
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn email_retry_keeps_only_undelivered_recipients() {
        let unique = format!(
            "ids-rs-spool-test-{}-{}",
            std::process::id(),
            SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let base = std::env::temp_dir().join(unique);
        let spool = Spool::new(&base, Sink::Email).unwrap();
        let (port, delivered) =
            crate::alerter::test_smtp::start(std::collections::HashMap::from([
                ("gone@test.local".to_string(), "550".to_string()),
                ("later@test.local".to_string(), "451".to_string()),
            ]))
            .await;

        let mut app = crate::config::AppConfig::load("config.toml").unwrap();
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
            std::collections::HashMap::new(),
            Vec::new(),
        )
        .unwrap();

        let record = SpoolRecord::new(alert());
        let result = deliver(Sink::Email, &alerter, &record).await;
        let mut reported = false;
        assert!(matches!(
            settle(Sink::Email, &spool, None, &record, result, &mut reported),
            Settled::Retry
        ));

        let (path, pending) = spool.oldest().unwrap().unwrap();
        assert_eq!(
            pending.recipients,
            Some(vec!["later@test.local".to_string()])
        );
        let dead = fs::read_dir(&spool.dead_letter)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let buried: SpoolRecord = serde_json::from_slice(&fs::read(dead.path()).unwrap()).unwrap();
        assert_eq!(buried.recipients, Some(vec!["gone@test.local".to_string()]));

        // Retry din spool: ok@ nu primeste a doua oara.
        let result = deliver(Sink::Email, &alerter, &pending).await;
        settle(
            Sink::Email,
            &spool,
            Some(&path),
            &pending,
            result,
            &mut reported,
        );
        assert_eq!(
            *delivered.lock().unwrap(),
            vec!["ok@test.local".to_string()]
        );
        fs::remove_dir_all(base).unwrap();
    }
}
