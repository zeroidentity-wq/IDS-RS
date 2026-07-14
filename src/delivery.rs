use crate::alerter::Alerter;
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
}

impl Spool {
    fn new(base: &Path, sink: Sink) -> Result<Self> {
        let directory = base.join(sink.name());
        fs::create_dir_all(&directory)
            .with_context(|| format!("nu pot crea spool-ul {}", directory.display()))?;
        Ok(Self { directory })
    }

    fn persist(&self, alert: &Alert) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sequence = SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let stem = format!("{now:020}-{:010}-{sequence:020}", std::process::id());
        let temporary = self.directory.join(format!(".{stem}.tmp"));
        let final_path = self.directory.join(format!("{stem}.json"));
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
                    continue;
                }
                Err(error) => {
                    display::log_error(&format!(
                        "Livrare {} esuata; retry in {}s: {:#}",
                        sink.name(),
                        backoff.as_secs(),
                        error
                    ));
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
            display::log_error(&format!("Livrare {} esuata: {:#}", sink.name(), error));
            if let Err(spool_error) = spool.persist(&alert) {
                display::log_error(&format!(
                    "FATAL: nu pot salva alerta {} in spool: {:#}",
                    sink.name(),
                    spool_error
                ));
            }
        } else {
            backoff = retry_initial;
        }
    }
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
}
