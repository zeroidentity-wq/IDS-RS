use crate::alerter::{Alerter, PermanentFailure, SinkUnavailable};
use crate::config::AlertingConfig;
use crate::detector::Alert;
use crate::display;
use anyhow::{Context, Result};
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

    fn persist(&self, alert: &Alert) -> Result<()> {
        Self::persist_into(&self.directory, alert)
    }

    /// Salveaza direct in dead-letter o alerta care a esuat definitiv.
    fn bury(&self, alert: &Alert) -> Result<()> {
        Self::persist_into(&self.dead_letter, alert)
    }

    /// Muta in dead-letter un fisier existent din spool.
    fn bury_file(&self, path: &Path) -> Result<()> {
        let name = path.file_name().context("cale spool fara nume de fisier")?;
        fs::rename(path, self.dead_letter.join(name))?;
        Ok(())
    }

    fn persist_into(directory: &Path, alert: &Alert) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sequence = SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let stem = format!("{now:020}-{:010}-{sequence:020}", std::process::id());
        let temporary = directory.join(format!(".{stem}.tmp"));
        let final_path = directory.join(format!("{stem}.json"));
        let payload = serde_json::to_vec(alert).context("nu pot serializa alerta pentru spool")?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("nu pot crea {}", temporary.display()))?;
        file.write_all(&payload)?;
        file.sync_all()?;
        fs::rename(&temporary, &final_path)?;
        Ok(())
    }

    fn oldest(&self) -> Result<Option<(PathBuf, Alert)>> {
        let mut paths = fs::read_dir(&self.directory)?
            .filter_map(|entry| entry.ok().map(|item| item.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect::<Vec<_>>();
        paths.sort_unstable();

        for path in paths {
            match fs::read(&path)
                .with_context(|| format!("nu pot citi {}", path.display()))
                .and_then(|bytes| {
                    serde_json::from_slice(&bytes)
                        .with_context(|| format!("spool corupt: {}", path.display()))
                }) {
                Ok(alert) => return Ok(Some((path, alert))),
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
            if let Err(error) = spool.persist(&alert) {
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
            Ok(Some((path, alert))) => match deliver(sink, &alerter, &alert).await {
                Ok(()) => {
                    if let Err(error) = fs::remove_file(&path) {
                        display::log_error(&format!(
                            "Alerta livrata dar spool-ul {} nu poate fi sters: {}",
                            path.display(),
                            error
                        ));
                    }
                    backoff = retry_initial;
                    unavailable_reported = false;
                    continue;
                }
                Err(error) if is_permanent(&error) => {
                    report_permanent(sink, &error);
                    if let Err(bury_error) = spool.bury_file(&path) {
                        display::log_error(&format!(
                            "FATAL: nu pot muta {} in dead-letter: {:#}",
                            path.display(),
                            bury_error
                        ));
                        tokio::time::sleep(backoff).await;
                        backoff = backoff.saturating_mul(2).min(retry_max);
                    }
                    continue;
                }
                Err(error) => {
                    report_failure(sink, &error, &mut unavailable_reported);
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(retry_max);
                    continue;
                }
            },
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
        if let Err(error) = deliver(sink, &alerter, &alert).await {
            let saved = if is_permanent(&error) {
                report_permanent(sink, &error);
                spool.bury(&alert)
            } else {
                report_failure(sink, &error, &mut unavailable_reported);
                spool.persist(&alert)
            };
            if let Err(spool_error) = saved {
                display::log_error(&format!(
                    "FATAL: nu pot salva alerta {} in spool: {:#}",
                    sink.name(),
                    spool_error
                ));
            }
        } else {
            backoff = retry_initial;
            unavailable_reported = false;
        }
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

async fn deliver(sink: Sink, alerter: &Alerter, alert: &Alert) -> Result<()> {
    match sink {
        Sink::Siem => alerter.send_siem(alert).await,
        Sink::Email => alerter.send_email(alert).await,
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
        spool.persist(&alert()).unwrap();
        let (path, recovered) = spool.oldest().unwrap().unwrap();
        assert!(path.exists());
        assert_eq!(
            recovered.source_ip,
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
        spool.persist(&alert()).unwrap();

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
        spool.persist(&poisoned).unwrap();
        spool.persist(&healthy).unwrap();

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
}
