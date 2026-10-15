// =============================================================================
// persistence.rs - Fisierul de stare (#32)
// =============================================================================
//
// Salveaza starea detectorului si alertele din dashboard intr-un fisier JSON
// si le restaureaza la pornire. Salvarea se face periodic si la oprire.
//
//   - scriere atomica: fisier temporar in acelasi director + rename, ca un
//     crash in timpul scrierii sa lase intact fisierul anterior;
//   - permisiuni 0600: fisierul contine IP-uri si alerte;
//   - versiune in fisier: un format incompatibil nu este interpretat gresit;
//   - fisier corupt sau incompatibil: redenumit in `<path>.invalid` (pentru
//     diagnostic) si pornire fara stare - IDS-ul nu ramane oprit din cauza lui.
//
// =============================================================================

use crate::detector::{Alert, Detector, DetectorSnapshot};
use crate::web::AlertBuffer;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Versiunea formatului. Se incrementeaza la orice schimbare incompatibila.
const STATE_VERSION: u32 = 1;

/// Salvarea periodica si cea de la oprire scriu acelasi fisier temporar.
static SAVE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Serialize, Deserialize)]
struct StateFile {
    version: u32,
    /// Momentul salvarii (wall clock), pentru a sti cat timp a trecut.
    saved_at_unix_ms: u64,
    detector: DetectorSnapshot,
    /// Alertele din dashboard, cele mai vechi primele.
    alerts: Vec<Alert>,
}

/// Ce s-a restaurat la pornire (pentru mesajul din log).
#[derive(Debug)]
pub struct RestoredState {
    pub tracked_ips: usize,
    pub alerts: usize,
    /// Cat timp a trecut de la salvare.
    pub age: Duration,
}

fn unix_ms(time: SystemTime) -> u64 {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// Salveaza starea detectorului si alertele din dashboard in `path`.
pub fn save(path: &Path, detector: &Detector, alerts: &AlertBuffer) -> Result<()> {
    let _guard = SAVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let state = StateFile {
        version: STATE_VERSION,
        saved_at_unix_ms: unix_ms(SystemTime::now()),
        detector: detector.snapshot(),
        alerts: alerts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect(),
    };

    let temporary = sibling(path, ".tmp");
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&temporary)
        .with_context(|| format!("nu pot crea {}", temporary.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &state).context("nu pot serializa starea")?;
    writer.flush()?;
    writer
        .into_inner()
        .map_err(|e| e.into_error())?
        .sync_all()
        .with_context(|| format!("nu pot scrie {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("nu pot inlocui {}", path.display()))?;
    Ok(())
}

/// Restaureaza starea din `path` in `detector` si `alerts` (pastrand cel mult
/// `max_alerts`). `Ok(None)` daca nu exista inca un fisier de stare.
///
/// Un fisier care nu poate fi folosit este redenumit in `<path>.invalid`,
/// ca salvarea urmatoare sa nu-l suprascrie inainte de a fi investigat.
pub fn load(
    path: &Path,
    detector: &Detector,
    alerts: &AlertBuffer,
    max_alerts: usize,
) -> Result<Option<RestoredState>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("nu pot citi {}", path.display())),
    };

    let state = serde_json::from_reader::<_, StateFile>(BufReader::new(file))
        .map_err(anyhow::Error::from)
        .and_then(|state| {
            if state.version == STATE_VERSION {
                Ok(state)
            } else {
                anyhow::bail!(
                    "versiune {} nesuportata (asteptat {STATE_VERSION})",
                    state.version
                )
            }
        });
    let state = match state {
        Ok(state) => state,
        Err(error) => {
            let invalid = sibling(path, ".invalid");
            let renamed = fs::rename(path, &invalid).is_ok();
            return Err(error).with_context(|| {
                if renamed {
                    format!("{} invalid, mutat in {}", path.display(), invalid.display())
                } else {
                    format!("{} invalid", path.display())
                }
            });
        }
    };

    // Daca ceasul a fost dat inapoi intre timp, consideram ca nu a trecut timp.
    let age =
        Duration::from_millis(unix_ms(SystemTime::now()).saturating_sub(state.saved_at_unix_ms));
    let tracked_ips = state.detector.tracked_ips();
    detector.restore(state.detector, age);

    let skip = state.alerts.len().saturating_sub(max_alerts);
    let restored_alerts = state.alerts.len() - skip;
    alerts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .extend(state.alerts.into_iter().skip(skip));

    Ok(Some(RestoredState {
        tracked_ips,
        alerts: restored_alerts,
        age,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::detector::ScanType;
    use crate::parser::{Action, LogEvent};
    use std::collections::VecDeque;
    use std::sync::Arc;

    /// Director temporar sters la final (si cand testul esueaza).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ids-rs-persistence-{name}-{}-{}",
                std::process::id(),
                unix_ms(SystemTime::now())
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn detection_config() -> crate::config::DetectionConfig {
        let config: AppConfig = toml::from_str(include_str!("../config.toml")).unwrap();
        let mut detection = config.detection;
        detection.fast_scan.port_threshold = 5;
        detection.slow_scan.port_threshold = 1_000;
        detection
    }

    fn drop_event(port: u16) -> LogEvent {
        LogEvent {
            source_ip: "192.168.1.66".parse().unwrap(),
            dest_ip: Some("10.0.0.9".parse().unwrap()),
            dest_port: port,
            protocol: "tcp".to_string(),
            action: Action::Drop,
            raw_log: String::new(),
        }
    }

    fn buffer() -> AlertBuffer {
        Arc::new(std::sync::Mutex::new(VecDeque::new()))
    }

    #[test]
    fn missing_state_file_is_not_an_error() {
        let dir = TempDir::new("missing");
        let restored = load(
            &dir.join("state.json"),
            &Detector::new(detection_config()),
            &buffer(),
            10,
        )
        .unwrap();
        assert!(restored.is_none());
    }

    #[test]
    fn scan_in_progress_continues_after_restart() {
        let dir = TempDir::new("continue");
        let path = dir.join("state.json");

        // Inainte de restart: 4 porturi, sub pragul de 5.
        let before = Detector::new(detection_config());
        for port in 1..=4 {
            assert!(before.process_event(&drop_event(port)).is_empty());
        }
        save(&path, &before, &buffer()).unwrap();

        // Dupa restart: al 5-lea port declanseaza alerta.
        let after = Detector::new(detection_config());
        let restored = load(&path, &after, &buffer(), 10).unwrap().unwrap();
        assert_eq!(restored.tracked_ips, 1);
        assert_eq!(after.tracked_ips(), 1);
        let alerts = after.process_event(&drop_event(5));
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].scan_type, ScanType::Fast));
        assert_eq!(alerts[0].unique_ports, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn cooldown_survives_restart() {
        let dir = TempDir::new("cooldown");
        let path = dir.join("state.json");

        let before = Detector::new(detection_config());
        let fired: usize = (1..=5)
            .map(|port| before.process_event(&drop_event(port)).len())
            .sum();
        assert_eq!(fired, 1);
        save(&path, &before, &buffer()).unwrap();

        // Scanarea continua dupa restart: fara cooldown restaurat, alerta ar
        // fi trimisa din nou.
        let after = Detector::new(detection_config());
        load(&path, &after, &buffer(), 10).unwrap();
        assert!(after.process_event(&drop_event(6)).is_empty());
    }

    #[test]
    fn hits_older_than_the_window_do_not_count_after_a_long_downtime() {
        let before = Detector::new(detection_config());
        for port in 1..=4 {
            before.process_event(&drop_event(port));
        }
        let snapshot = before.snapshot();

        // Restaurat ca si cum ar fi trecut o ora: fereastra Fast Scan (10s) a expirat.
        let after = Detector::new(detection_config());
        after.restore(snapshot, Duration::from_secs(3_600));
        assert!(after.process_event(&drop_event(5)).is_empty());
    }

    #[test]
    fn dashboard_alerts_are_restored_up_to_the_limit() {
        let dir = TempDir::new("alerts");
        let path = dir.join("state.json");
        let detector = Detector::new(detection_config());
        let alerts = buffer();
        for port in 1..=5 {
            alerts
                .lock()
                .unwrap()
                .extend(detector.process_event(&drop_event(port)));
        }
        let second = LogEvent {
            source_ip: "192.168.1.77".parse().unwrap(),
            ..drop_event(0)
        };
        for port in 1..=5 {
            alerts
                .lock()
                .unwrap()
                .extend(detector.process_event(&LogEvent {
                    dest_port: port,
                    ..second.clone()
                }));
        }
        assert_eq!(alerts.lock().unwrap().len(), 2);
        save(&path, &detector, &alerts).unwrap();

        let restored_buffer = buffer();
        let restored = load(
            &path,
            &Detector::new(detection_config()),
            &restored_buffer,
            1,
        )
        .unwrap()
        .unwrap();
        assert_eq!(restored.alerts, 1);
        let kept = restored_buffer.lock().unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].source_ip.to_string(), "192.168.1.77");
    }

    #[test]
    fn invalid_state_file_is_set_aside() {
        let dir = TempDir::new("invalid");
        let path = dir.join("state.json");
        fs::write(&path, b"{ not json").unwrap();

        let error = load(&path, &Detector::new(detection_config()), &buffer(), 10).unwrap_err();
        assert!(format!("{error:#}").contains(".invalid"));
        assert!(!path.exists());
        assert!(dir.join("state.json.invalid").exists());
    }

    #[test]
    fn newer_state_version_is_rejected() {
        let dir = TempDir::new("version");
        let path = dir.join("state.json");
        save(&path, &Detector::new(detection_config()), &buffer()).unwrap();
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        state["version"] = serde_json::json!(STATE_VERSION + 1);
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();

        let error = load(&path, &Detector::new(detection_config()), &buffer(), 10).unwrap_err();
        assert!(format!("{error:#}").contains("nesuportata"));
    }

    #[cfg(unix)]
    #[test]
    fn state_file_is_private_and_written_atomically() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("mode");
        let path = dir.join("state.json");
        save(&path, &Detector::new(detection_config()), &buffer()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!dir.join("state.json.tmp").exists());
    }
}
