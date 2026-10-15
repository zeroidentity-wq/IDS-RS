use super::baseline::BaselineEwma;
use super::beaconing::{BeaconHit, BeaconStats};
use super::distributed::DistributedHit;
use super::*;
use crate::config::{
    AcceptScanConfig, BeaconingConfig, DetectionConfig, DistributedScanConfig,
    DynamicThresholdConfig, FastScanConfig, LateralMovementConfig, SlowScanConfig,
};
use crate::parser::Action;

/// Creeaza o configuratie de test cu praguri mici pentru teste rapide.
fn test_config() -> DetectionConfig {
    DetectionConfig {
        alert_cooldown_secs: 5,
        max_hits_per_ip: 1_000,
        max_tracked_ips: 10_000,
        max_tracked_flows: 20_000,
        max_flows_per_source: 1_000,
        whitelist: Vec::new(),
        exceptions: Default::default(),
        fast_scan: FastScanConfig {
            port_threshold: 3,
            time_window_secs: 10,
        },
        slow_scan: SlowScanConfig {
            port_threshold: 50,
            time_window_mins: 1,
        },
        // Accept Scan cu acelasi prag ca Fast Scan pentru teste simetrice.
        accept_scan: AcceptScanConfig {
            port_threshold: 3,
            time_window_secs: 10,
        },
        // Lateral Movement dezactivat implicit in test_config.
        // Testele specifice folosesc lateral_config().
        lateral_movement: LateralMovementConfig {
            enabled: false,
            unique_dest_threshold: 3,
            time_window_secs: 10,
        },
        // Distributed Scan dezactivat implicit in test_config.
        // Testele specifice folosesc distributed_config().
        distributed_scan: DistributedScanConfig {
            enabled: false,
            unique_sources_threshold: 3,
            time_window_secs: 10,
        },
        dynamic_threshold: DynamicThresholdConfig {
            enabled: false,
            ewma_alpha: 0.1,
            sensitivity_multiplier: 3.0,
            min_samples: 10,
            min_threshold_ratio: 0.5,
            max_threshold_ratio: 3.0,
        },
        beaconing: BeaconingConfig {
            enabled: false,
            min_events: 5,
            time_window_secs: 60,
            cv_threshold: 0.30,
            min_interval_secs: 1,
            max_interval_secs: 60,
        },
    }
}

/// Creeaza o configuratie cu Lateral Movement activat (prag 3 destinatii in 10s).
fn lateral_config() -> DetectionConfig {
    DetectionConfig {
        alert_cooldown_secs: 5,
        max_hits_per_ip: 1_000,
        max_tracked_ips: 10_000,
        max_tracked_flows: 20_000,
        max_flows_per_source: 1_000,
        whitelist: Vec::new(),
        exceptions: Default::default(),
        fast_scan: FastScanConfig {
            port_threshold: 100,
            time_window_secs: 10,
        },
        slow_scan: SlowScanConfig {
            port_threshold: 200,
            time_window_mins: 1,
        },
        accept_scan: AcceptScanConfig {
            port_threshold: 100,
            time_window_secs: 10,
        },
        lateral_movement: LateralMovementConfig {
            enabled: true,
            unique_dest_threshold: 3,
            time_window_secs: 10,
        },
        distributed_scan: DistributedScanConfig {
            enabled: false,
            unique_sources_threshold: 3,
            time_window_secs: 10,
        },
        dynamic_threshold: DynamicThresholdConfig {
            enabled: false,
            ewma_alpha: 0.1,
            sensitivity_multiplier: 3.0,
            min_samples: 10,
            min_threshold_ratio: 0.5,
            max_threshold_ratio: 3.0,
        },
        beaconing: BeaconingConfig {
            enabled: false,
            min_events: 5,
            time_window_secs: 60,
            cv_threshold: 0.30,
            min_interval_secs: 1,
            max_interval_secs: 60,
        },
    }
}

fn make_event(ip: &str, port: u16) -> LogEvent {
    LogEvent {
        source_ip: ip.parse().unwrap(),
        dest_ip: Some("10.0.0.1".parse().unwrap()),
        dest_port: port,
        protocol: "tcp".to_string(),
        action: Action::Drop,
        raw_log: String::new(),
    }
}

/// Creeaza un eveniment drop cu destinatie explicita (pentru corelare src,dst).
fn make_event_with_dest(src_ip: &str, dest_ip: &str, port: u16) -> LogEvent {
    LogEvent {
        source_ip: src_ip.parse().unwrap(),
        dest_ip: Some(dest_ip.parse().unwrap()),
        dest_port: port,
        protocol: "tcp".to_string(),
        action: Action::Drop,
        raw_log: String::new(),
    }
}

/// Creeaza un eveniment accept cu IP destinatie explicit (pentru Lateral Movement).
fn make_lateral_event(src_ip: &str, dest_ip: &str, port: u16) -> LogEvent {
    LogEvent {
        source_ip: src_ip.parse().unwrap(),
        dest_ip: Some(dest_ip.parse().unwrap()),
        dest_port: port,
        protocol: "tcp".to_string(),
        action: Action::Accept,
        raw_log: String::new(),
    }
}

#[test]
fn test_no_alert_below_threshold() {
    let detector = Detector::new(test_config());

    // 2 porturi unice = sub pragul de 3 (>=3 declanseaza alerta).
    for port in 1..=2 {
        let alerts = detector.process_event(&make_event("10.0.0.1", port));
        assert!(alerts.is_empty(), "Nu ar trebui alerta la {} porturi", port);
    }
}

#[test]
fn test_fast_scan_alert() {
    let detector = Detector::new(test_config());

    // 3 porturi unice = egal cu pragul de 3 (>=) -> alerta Fast Scan la al 3-lea.
    for port in 1..=3 {
        let alerts = detector.process_event(&make_event("10.0.0.1", port));
        if port == 3 {
            assert_eq!(alerts.len(), 1);
            assert!(matches!(alerts[0].scan_type, ScanType::Fast));
        }
    }
}

#[test]
fn test_cooldown_prevents_duplicate_alert() {
    let detector = Detector::new(test_config());

    // Trimitem 5 porturi - prima alerta la port 3 (prag >= 3).
    for port in 1..=5 {
        detector.process_event(&make_event("10.0.0.1", port));
    }

    // Al 6-lea port - NU ar trebui sa genereze alerta (cooldown activ).
    let alerts = detector.process_event(&make_event("10.0.0.1", 100));
    assert!(
        alerts.is_empty(),
        "Cooldown-ul ar fi trebuit sa previna alerta"
    );
}

#[test]
fn test_different_ips_tracked_separately() {
    let detector = Detector::new(test_config());

    // IP 1: 4 porturi -> alerta
    for port in 1..=4 {
        detector.process_event(&make_event("10.0.0.1", port));
    }

    // IP 2: 2 porturi -> nicio alerta
    for port in 1..=2 {
        let alerts = detector.process_event(&make_event("10.0.0.2", port));
        assert!(alerts.is_empty());
    }
}

#[test]
fn test_fast_scan_isolated_per_src_dst_pair() {
    let detector = Detector::new(test_config());

    let events = [
        make_event_with_dest("10.9.0.1", "10.0.0.10", 22),
        make_event_with_dest("10.9.0.1", "10.0.0.10", 80),
        make_event_with_dest("10.9.0.1", "10.0.0.20", 443),
        make_event_with_dest("10.9.0.1", "10.0.0.20", 8080),
    ];
    for event in events {
        let alerts = detector.process_event(&event);
        assert!(
            alerts
                .iter()
                .all(|a| !matches!(a.scan_type, ScanType::Fast)),
            "Nu trebuie alerta Fast cand niciuna dintre destinatii nu atinge pragul"
        );
    }

    // Destinatia 10.0.0.10 ajunge la 3 porturi unice -> alerta Fast doar pentru ea.
    let alerts = detector.process_event(&make_event_with_dest("10.9.0.1", "10.0.0.10", 443));
    assert!(
        alerts.iter().any(|a| {
            matches!(a.scan_type, ScanType::Fast) && a.dest_ip == Some("10.0.0.10".parse().unwrap())
        }),
        "Trebuie alerta Fast cand perechea (src,dst) atinge pragul"
    );
}

#[test]
fn test_cleanup_removes_old_entries() {
    let detector = Detector::new(test_config());

    detector.process_event(&make_event("10.0.0.1", 22));
    assert_eq!(detector.tracked_ips(), 1);

    // Hit-uri mai vechi decat orice fereastra de detectie -> sterse.
    backdate_all_hits(&detector, Duration::from_secs(7_200));
    detector.cleanup(Duration::from_secs(60));
    assert_eq!(detector.tracked_ips(), 0);
}

// =========================================================================
// Teste pentru #3 — MAX_HITS_PER_IP si #4 — MAX_TRACKED_IPS
// =========================================================================

#[test]
fn test_max_hits_per_ip_cap() {
    // Configuram o limita mica (5 hits) pentru a testa usor.
    let mut config = test_config();
    config.max_hits_per_ip = 5;
    let detector = Detector::new(config);

    // Trimitem 10 evenimente pe acelasi IP (porturi 1..=10).
    for port in 1..=10u16 {
        detector.process_event(&make_event("10.0.0.1", port));
    }

    // Vec-ul nu trebuie sa depaseasca limita de 5.
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let dst: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let entry = detector.port_scan.drop_hits.get(&(ip, dst)).unwrap();
    assert!(
        entry.len() <= 5,
        "Vec-ul a depasit max_hits_per_ip: are {} intrari",
        entry.len()
    );

    // Trebuie sa contina porturile CELE MAI RECENTE (6..=10), nu pe cele vechi (1..5).
    let ports: Vec<u16> = entry.iter().map(|h| h.port).collect();
    assert!(
        ports.contains(&10),
        "Portul cel mai recent (10) trebuie sa fie prezent"
    );
    assert!(
        !ports.contains(&1),
        "Portul cel mai vechi (1) trebuia eliminat"
    );
}

// =========================================================================
// Teste pentru #10 — Accept Scan Detection
// =========================================================================

/// Construieste un eveniment de tip "accept" (port deschis, permis de firewall).
fn make_accept_event(ip: &str, port: u16) -> LogEvent {
    LogEvent {
        source_ip: ip.parse().unwrap(),
        dest_ip: Some("10.0.0.1".parse().unwrap()),
        dest_port: port,
        protocol: "tcp".to_string(),
        // Diferenta fata de make_event: actiunea este "accept" nu "drop".
        action: Action::Accept,
        raw_log: String::new(),
    }
}

#[test]
fn test_accept_scan_alert() {
    // 3 porturi ACCEPTATE unice cu prag = 3 (>=) → alerta la al 3-lea port.
    let detector = Detector::new(test_config());

    for port in 1..=3 {
        let alerts = detector.process_event(&make_accept_event("10.1.0.1", port));
        if port == 3 {
            assert_eq!(
                alerts.len(),
                1,
                "Trebuia o alerta Accept Scan la {} porturi",
                port
            );
            assert!(
                matches!(alerts[0].scan_type, ScanType::AcceptScan),
                "Tipul alertei trebuie sa fie AcceptScan"
            );
        } else {
            assert!(
                alerts.is_empty(),
                "Fara alerta la {} porturi (sub prag)",
                port
            );
        }
    }
}

#[test]
fn test_drop_events_do_not_trigger_accept_scan() {
    // Evenimentele "drop" NU trebuie sa declanseze Accept Scan.
    // Sunt inregistrate in port_hits, nu in accept_hits.
    let detector = Detector::new(test_config());

    for port in 1..=10 {
        let alerts = detector.process_event(&make_event("10.2.0.1", port));
        for alert in &alerts {
            assert!(
                !matches!(alert.scan_type, ScanType::AcceptScan),
                "Drop events NU trebuie sa declanseze Accept Scan (port {})",
                port
            );
        }
    }
}

#[test]
fn test_accept_events_do_not_trigger_fast_scan() {
    // Evenimentele "accept" NU trebuie sa declanseze Fast/Slow Scan.
    // Sunt inregistrate in accept_hits, nu in port_hits.
    let detector = Detector::new(test_config());

    for port in 1..=10 {
        let alerts = detector.process_event(&make_accept_event("10.3.0.1", port));
        for alert in &alerts {
            assert!(
                !matches!(alert.scan_type, ScanType::Fast),
                "Accept events NU trebuie sa declanseze Fast Scan (port {})",
                port
            );
            assert!(
                !matches!(alert.scan_type, ScanType::Slow),
                "Accept events NU trebuie sa declanseze Slow Scan (port {})",
                port
            );
        }
    }
}

#[test]
fn test_accept_scan_cooldown() {
    // Cooldown-ul Accept Scan este independent de cel Fast Scan.
    let detector = Detector::new(test_config());

    // Generam alerta initiala (4 porturi accept).
    for port in 1..=4 {
        detector.process_event(&make_accept_event("10.4.0.1", port));
    }

    // Al 5-lea port accept → cooldown activ → fara alerta noua.
    let alerts = detector.process_event(&make_accept_event("10.4.0.1", 5));
    assert!(
        alerts.is_empty(),
        "Cooldown-ul Accept Scan trebuia sa previna alerta duplicata"
    );
}

#[test]
fn test_max_tracked_ips_eviction() {
    // Configuram limita mica (2 IP-uri) pentru a testa usor.
    let mut config = test_config();
    config.max_tracked_ips = 2;
    let detector = Detector::new(config);

    // Adaugam 3 IP-uri diferite. Al treilea trebuie sa provoace evictia primului.
    detector.process_event(&make_event("10.0.0.1", 80));
    detector.process_event(&make_event("10.0.0.2", 80));
    detector.process_event(&make_event("10.0.0.3", 80)); // depaseste limita → evictie LRU

    // Trebuie sa avem maxim max_tracked_ips IP-uri urmarite.
    assert!(
        detector.tracked_ips() <= 2,
        "DashMap a depasit max_tracked_ips: urmareste {} IP-uri",
        detector.tracked_ips()
    );

    // IP-ul 10.0.0.1 a fost cel mai vechi → trebuie evictat.
    let ip1: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let dst: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    assert!(
        !detector.port_scan.drop_hits.contains_key(&(ip1, dst)),
        "IP-ul cel mai vechi (10.0.0.1) trebuia evictat"
    );

    // IP-ul 10.0.0.3 (cel mai recent) trebuie sa fie prezent.
    let ip3: std::net::IpAddr = "10.0.0.3".parse().unwrap();
    assert!(
        detector.port_scan.drop_hits.contains_key(&(ip3, dst)),
        "IP-ul cel mai recent (10.0.0.3) trebuie sa fie prezent"
    );
}

// =========================================================================
// Teste pentru Slow Scan (#18)
// =========================================================================
//
// test_config() are slow_scan.port_threshold = 50 — prea mare pentru teste.
// slow_test_config() seteaza prag mic (3) si Fast Scan dezactivat practic
// (prag 1000) pentru a testa Slow Scan izolat.

/// Configuratie dedicata testelor Slow Scan.
///
/// Fast Scan are prag ridicat (1000) astfel incat nu se declanseaza in
/// testele curente (max ~10 porturi). Slow Scan are prag mic (3) pentru
/// teste rapide. Fereastra de 1 minut inseamna ca toate evenimentele
/// din test (milisecunde) sunt in cadrul ferestrei.
fn slow_test_config() -> DetectionConfig {
    DetectionConfig {
        alert_cooldown_secs: 5,
        max_hits_per_ip: 1_000,
        max_tracked_ips: 10_000,
        max_tracked_flows: 20_000,
        max_flows_per_source: 1_000,
        whitelist: Vec::new(),
        exceptions: Default::default(),
        fast_scan: FastScanConfig {
            port_threshold: 1_000, // prag mare — nu se declanseaza in teste slow
            time_window_secs: 10,
        },
        slow_scan: SlowScanConfig {
            port_threshold: 3, // prag mic pentru teste rapide
            time_window_mins: 1,
        },
        accept_scan: AcceptScanConfig {
            port_threshold: 1_000,
            time_window_secs: 60,
        },
        lateral_movement: LateralMovementConfig {
            enabled: false,
            unique_dest_threshold: 3,
            time_window_secs: 10,
        },
        distributed_scan: DistributedScanConfig {
            enabled: false,
            unique_sources_threshold: 3,
            time_window_secs: 10,
        },
        dynamic_threshold: DynamicThresholdConfig {
            enabled: false,
            ewma_alpha: 0.1,
            sensitivity_multiplier: 3.0,
            min_samples: 10,
            min_threshold_ratio: 0.5,
            max_threshold_ratio: 3.0,
        },
        beaconing: BeaconingConfig {
            enabled: false,
            min_events: 5,
            time_window_secs: 60,
            cv_threshold: 0.30,
            min_interval_secs: 1,
            max_interval_secs: 60,
        },
    }
}

#[test]
fn test_slow_scan_alert() {
    // 3 porturi unice (drop) cu prag slow = 3 (>=) → alerta Slow Scan la al 3-lea port.
    let detector = Detector::new(slow_test_config());

    for port in 1..=3u16 {
        let alerts = detector.process_event(&make_event("192.168.1.1", port));
        if port == 3 {
            assert_eq!(
                alerts.len(),
                1,
                "Trebuia o alerta Slow Scan la {} porturi",
                port
            );
            assert!(
                matches!(alerts[0].scan_type, ScanType::Slow),
                "Tipul alertei trebuie sa fie Slow, nu {:?}",
                alerts[0].scan_type
            );
            assert_eq!(alerts[0].unique_ports.len(), 3);
        } else {
            assert!(alerts.is_empty(), "Fara alerta sub prag (port {})", port);
        }
    }
}

#[test]
fn test_slow_scan_cooldown() {
    // Dupa o alerta Slow Scan, porturi suplimentare nu genereaza alerta noua
    // cat timp cooldown-ul este activ.
    let detector = Detector::new(slow_test_config());

    // Generam alerta initiala (3 porturi drop → prag 3 atins cu >=).
    for port in 1..=4u16 {
        detector.process_event(&make_event("192.168.2.1", port));
    }

    // Al 5-lea port → cooldown activ → fara alerta noua.
    let alerts = detector.process_event(&make_event("192.168.2.1", 5));
    assert!(
        alerts.is_empty(),
        "Cooldown-ul Slow Scan trebuia sa previna alerta duplicata"
    );
}

#[test]
fn test_slow_scan_independent_from_fast() {
    // Slow Scan si Fast Scan sunt urmarite independent.
    // Cu slow_test_config: Fast threshold = 1000, Slow threshold = 3.
    // 3+ porturi drop → doar Slow Scan se declanseaza (Fast prag=1000, neatins).
    let detector = Detector::new(slow_test_config());

    let mut got_slow = false;
    let mut got_fast = false;

    for port in 1..=4u16 {
        let alerts = detector.process_event(&make_event("192.168.3.1", port));
        for alert in &alerts {
            match alert.scan_type {
                ScanType::Slow => got_slow = true,
                ScanType::Fast => got_fast = true,
                _ => {}
            }
        }
    }

    assert!(got_slow, "Trebuia o alerta Slow Scan");
    assert!(
        !got_fast,
        "Fast Scan NU trebuia sa se declanseze cu prag 1000"
    );
}

// =========================================================================
// Teste Whitelist (#12)
// =========================================================================

#[test]
fn test_whitelist_single_ip_blocks_alert() {
    // IP-ul 10.0.0.1 este in whitelist → nu trebuie sa genereze alerta.
    let mut config = test_config();
    config.whitelist = vec!["10.0.0.1".to_string()];
    let detector = Detector::new(config);

    // Trimitem 5 porturi (peste prag 3) — fara alerta.
    for port in 1..=5 {
        let alerts = detector.process_event(&make_event("10.0.0.1", port));
        assert!(
            alerts.is_empty(),
            "IP in whitelist nu trebuie sa genereze alerta"
        );
    }
}

#[test]
fn test_whitelist_cidr_blocks_alert() {
    // Subnet-ul 10.0.0.0/24 este in whitelist → 10.0.0.50 nu genereaza alerta.
    let mut config = test_config();
    config.whitelist = vec!["10.0.0.0/24".to_string()];
    let detector = Detector::new(config);

    for port in 1..=5 {
        let alerts = detector.process_event(&make_event("10.0.0.50", port));
        assert!(
            alerts.is_empty(),
            "IP din subnet whitelist nu trebuie sa genereze alerta"
        );
    }
}

#[test]
fn test_whitelist_does_not_block_other_ips() {
    // 10.0.0.1 in whitelist, dar 10.0.0.2 NU — trebuie sa genereze alerta.
    let mut config = test_config();
    config.whitelist = vec!["10.0.0.1".to_string()];
    let detector = Detector::new(config);

    for port in 1..=3 {
        let alerts = detector.process_event(&make_event("10.0.0.2", port));
        if port == 3 {
            assert_eq!(
                alerts.len(),
                1,
                "IP-ul care NU e in whitelist trebuie sa genereze alerta"
            );
        }
    }
}

#[test]
fn test_whitelist_cidr_boundary() {
    // 10.0.1.0/24 in whitelist → 10.0.2.1 NU e acoperit.
    let mut config = test_config();
    config.whitelist = vec!["10.0.1.0/24".to_string()];
    let detector = Detector::new(config);

    for port in 1..=3 {
        let alerts = detector.process_event(&make_event("10.0.2.1", port));
        if port == 3 {
            assert_eq!(
                alerts.len(),
                1,
                "IP din alt subnet nu e acoperit de whitelist"
            );
        }
    }
}

#[test]
fn test_whitelist_accept_scan_blocked() {
    // Whitelist blocheaza si Accept Scan, nu doar Fast/Slow.
    let mut config = test_config();
    config.whitelist = vec!["10.1.0.1".to_string()];
    let detector = Detector::new(config);

    for port in 1..=5 {
        let alerts = detector.process_event(&make_accept_event("10.1.0.1", port));
        assert!(alerts.is_empty(), "Accept Scan trebuie blocat de whitelist");
    }
}

// =========================================================================
// Teste Lateral Movement (#22)
// =========================================================================

#[test]
fn test_lateral_movement_alert() {
    // 3 destinatii diferite pe port 445 (SMB) = egal cu pragul -> alerta.
    let detector = Detector::new(lateral_config());

    let dests = ["10.0.0.10", "10.0.0.11", "10.0.0.12"];
    let mut last_alerts = vec![];
    for dest in &dests {
        last_alerts = detector.process_event(&make_lateral_event("10.0.1.5", dest, 445));
    }

    assert_eq!(last_alerts.len(), 1);
    assert!(
        matches!(last_alerts[0].scan_type, ScanType::LateralMovement),
        "Tipul alertei trebuie sa fie LateralMovement"
    );
    assert_eq!(
        last_alerts[0].unique_dests.len(),
        3,
        "Trebuie sa contina exact 3 destinatii unice"
    );
    assert!(
        last_alerts[0].unique_ports.is_empty(),
        "unique_ports trebuie sa fie gol pentru LateralMovement"
    );
}

#[test]
fn test_lateral_movement_below_threshold_no_alert() {
    // 2 destinatii < prag 3 -> fara alerta.
    let detector = Detector::new(lateral_config());

    for dest in &["10.0.0.10", "10.0.0.11"] {
        let alerts = detector.process_event(&make_lateral_event("10.0.1.5", dest, 445));
        assert!(
            alerts.is_empty(),
            "Nu trebuie alerta sub prag ({} destinatii)",
            dest
        );
    }
}

#[test]
fn test_lateral_movement_any_port_triggers() {
    // Orice port accept declanseaza Lateral Movement — fara filtru de port.
    let detector = Detector::new(lateral_config());

    let dests = ["10.0.0.10", "10.0.0.11", "10.0.0.12"];
    let mut last_alerts = vec![];
    for dest in &dests {
        // Port 80 (HTTP) — nu e "lateral movement tipic", dar detectia e bazata
        // pe comportament (N destinatii), nu pe port.
        last_alerts = detector.process_event(&make_lateral_event("10.0.1.5", dest, 80));
    }

    assert_eq!(last_alerts.len(), 1);
    assert!(
        matches!(last_alerts[0].scan_type, ScanType::LateralMovement),
        "Lateral Movement trebuie detectat pe orice port, nu doar pe porturi predefinite"
    );
}

#[test]
fn test_lateral_movement_cooldown() {
    // Dupa prima alerta, cooldown previne alerta repetata.
    let detector = Detector::new(lateral_config());

    // Prima alerta la a 3-a destinatie.
    let dests = ["10.0.0.10", "10.0.0.11", "10.0.0.12"];
    for dest in &dests {
        detector.process_event(&make_lateral_event("10.0.1.5", dest, 445));
    }

    // A 4-a destinatie — cooldown activ, nu trebuie alerta.
    let alerts = detector.process_event(&make_lateral_event("10.0.1.5", "10.0.0.13", 445));
    let lateral: Vec<_> = alerts
        .iter()
        .filter(|a| matches!(a.scan_type, ScanType::LateralMovement))
        .collect();
    assert!(
        lateral.is_empty(),
        "Cooldown trebuie sa previna alerta repetata Lateral Movement"
    );
}

#[test]
fn test_lateral_movement_disabled_no_alert() {
    // Cand lateral_movement.enabled = false, nicio alerta nu trebuie generata.
    let detector = Detector::new(test_config()); // enabled: false

    for dest in &["10.0.0.10", "10.0.0.11", "10.0.0.12"] {
        let alerts = detector.process_event(&make_lateral_event("10.0.1.5", dest, 445));
        let lateral: Vec<_> = alerts
            .iter()
            .filter(|a| matches!(a.scan_type, ScanType::LateralMovement))
            .collect();
        assert!(
            lateral.is_empty(),
            "Lateral Movement dezactivat nu trebuie sa genereze alerte"
        );
    }
}

// =========================================================================
// Teste Distributed Scan (#23)
// =========================================================================

/// Creeaza o configuratie cu Distributed Scan activat (prag 3 surse in 10s).
/// Fast/Slow/Accept au praguri ridicate pentru a nu se declansa in teste.
fn distributed_config() -> DetectionConfig {
    DetectionConfig {
        alert_cooldown_secs: 5,
        max_hits_per_ip: 1_000,
        max_tracked_ips: 10_000,
        max_tracked_flows: 20_000,
        max_flows_per_source: 1_000,
        whitelist: Vec::new(),
        exceptions: Default::default(),
        fast_scan: FastScanConfig {
            port_threshold: 100,
            time_window_secs: 10,
        },
        slow_scan: SlowScanConfig {
            port_threshold: 200,
            time_window_mins: 1,
        },
        accept_scan: AcceptScanConfig {
            port_threshold: 100,
            time_window_secs: 10,
        },
        lateral_movement: LateralMovementConfig {
            enabled: false,
            unique_dest_threshold: 100,
            time_window_secs: 10,
        },
        distributed_scan: DistributedScanConfig {
            enabled: true,
            unique_sources_threshold: 3,
            time_window_secs: 10,
        },
        dynamic_threshold: DynamicThresholdConfig {
            enabled: false,
            ewma_alpha: 0.1,
            sensitivity_multiplier: 3.0,
            min_samples: 10,
            min_threshold_ratio: 0.5,
            max_threshold_ratio: 3.0,
        },
        beaconing: BeaconingConfig {
            enabled: false,
            min_events: 5,
            time_window_secs: 60,
            cv_threshold: 0.30,
            min_interval_secs: 1,
            max_interval_secs: 60,
        },
    }
}

/// Creeaza un eveniment drop cu sursa si destinatie explicite (pentru Distributed Scan).
fn make_distributed_event(src_ip: &str, dest_ip: &str, port: u16) -> LogEvent {
    LogEvent {
        source_ip: src_ip.parse().unwrap(),
        dest_ip: Some(dest_ip.parse().unwrap()),
        dest_port: port,
        protocol: "tcp".to_string(),
        action: Action::Drop,
        raw_log: String::new(),
    }
}

#[test]
fn test_distributed_scan_alert() {
    // 3 surse diferite → aceeasi tinta (10.0.0.100) = egal cu pragul -> alerta.
    let detector = Detector::new(distributed_config());

    let sources = ["10.0.1.1", "10.0.1.2", "10.0.1.3"];
    let target = "10.0.0.100";
    let mut last_alerts = vec![];
    for src in &sources {
        last_alerts = detector.process_event(&make_distributed_event(src, target, 80));
    }

    assert_eq!(last_alerts.len(), 1);
    assert!(
        matches!(last_alerts[0].scan_type, ScanType::DistributedScan),
        "Tipul alertei trebuie sa fie DistributedScan"
    );
    assert_eq!(
        last_alerts[0].unique_sources.len(),
        3,
        "Trebuie sa contina exact 3 surse unice"
    );
    assert_eq!(
        last_alerts[0].dest_ip,
        Some(target.parse().unwrap()),
        "dest_ip trebuie sa fie tinta scanarii"
    );
}

#[test]
fn test_distributed_scan_below_threshold_no_alert() {
    // 2 surse < prag 3 -> fara alerta.
    let detector = Detector::new(distributed_config());

    for src in &["10.0.1.1", "10.0.1.2"] {
        let alerts = detector.process_event(&make_distributed_event(src, "10.0.0.100", 80));
        assert!(
            alerts
                .iter()
                .all(|a| !matches!(a.scan_type, ScanType::DistributedScan)),
            "Nu trebuie alerta sub prag ({} surse)",
            src
        );
    }
}

#[test]
fn test_distributed_scan_different_targets_independent() {
    // Surse diferite catre tinte DIFERITE nu se cumuleaza.
    let detector = Detector::new(distributed_config());

    // 2 surse → tinta A
    detector.process_event(&make_distributed_event("10.0.1.1", "10.0.0.100", 80));
    detector.process_event(&make_distributed_event("10.0.1.2", "10.0.0.100", 80));

    // 1 sursa → tinta B (diferita)
    let alerts = detector.process_event(&make_distributed_event("10.0.1.3", "10.0.0.200", 80));
    // Tinta A are 2 surse (sub prag), tinta B are 1 sursa (sub prag).
    let dist: Vec<_> = alerts
        .iter()
        .filter(|a| matches!(a.scan_type, ScanType::DistributedScan))
        .collect();
    assert!(
        dist.is_empty(),
        "Tinte diferite nu se cumuleaza — fara alerta"
    );
}

#[test]
fn test_distributed_scan_cooldown() {
    // Dupa prima alerta, cooldown previne alerta repetata.
    let detector = Detector::new(distributed_config());

    // Prima alerta la a 3-a sursa.
    for src in &["10.0.1.1", "10.0.1.2", "10.0.1.3"] {
        detector.process_event(&make_distributed_event(src, "10.0.0.100", 80));
    }

    // A 4-a sursa — cooldown activ, nu trebuie alerta.
    let alerts = detector.process_event(&make_distributed_event("10.0.1.4", "10.0.0.100", 80));
    let dist: Vec<_> = alerts
        .iter()
        .filter(|a| matches!(a.scan_type, ScanType::DistributedScan))
        .collect();
    assert!(
        dist.is_empty(),
        "Cooldown trebuie sa previna alerta repetata Distributed Scan"
    );
}

#[test]
fn test_distributed_scan_disabled_no_alert() {
    // Cand distributed_scan.enabled = false, nicio alerta nu trebuie generata.
    let detector = Detector::new(test_config()); // enabled: false

    for src in &["10.0.1.1", "10.0.1.2", "10.0.1.3"] {
        let alerts = detector.process_event(&make_distributed_event(src, "10.0.0.100", 80));
        let dist: Vec<_> = alerts
            .iter()
            .filter(|a| matches!(a.scan_type, ScanType::DistributedScan))
            .collect();
        assert!(
            dist.is_empty(),
            "Distributed Scan dezactivat nu trebuie sa genereze alerte"
        );
    }
}

#[test]
fn test_distributed_scan_both_actions() {
    // Distributed Scan detecteaza atat drop cat si accept.
    let detector = Detector::new(distributed_config());

    // Sursa 1: drop
    detector.process_event(&make_distributed_event("10.0.1.1", "10.0.0.100", 80));
    // Sursa 2: accept
    detector.process_event(&LogEvent {
        source_ip: "10.0.1.2".parse().unwrap(),
        dest_ip: Some("10.0.0.100".parse().unwrap()),
        dest_port: 80,
        protocol: "tcp".to_string(),
        action: Action::Accept,
        raw_log: String::new(),
    });
    // Sursa 3: drop → ar trebui sa declanseze alerta
    let alerts = detector.process_event(&make_distributed_event("10.0.1.3", "10.0.0.100", 80));

    let dist: Vec<_> = alerts
        .iter()
        .filter(|a| matches!(a.scan_type, ScanType::DistributedScan))
        .collect();
    assert_eq!(
        dist.len(),
        1,
        "Distributed Scan trebuie sa detecteze mix de drop si accept"
    );
}

#[test]
fn test_distributed_scan_ports_collected() {
    // Verificam ca porturile vizate sunt colectate corect in alerta.
    let detector = Detector::new(distributed_config());

    detector.process_event(&make_distributed_event("10.0.1.1", "10.0.0.100", 22));
    detector.process_event(&make_distributed_event("10.0.1.2", "10.0.0.100", 80));
    let alerts = detector.process_event(&make_distributed_event("10.0.1.3", "10.0.0.100", 443));

    let dist: Vec<_> = alerts
        .iter()
        .filter(|a| matches!(a.scan_type, ScanType::DistributedScan))
        .collect();
    assert_eq!(dist.len(), 1);
    // Porturile vizate: 22, 80, 443.
    assert_eq!(dist[0].unique_ports.len(), 3);
    assert!(dist[0].unique_ports.contains(&22));
    assert!(dist[0].unique_ports.contains(&80));
    assert!(dist[0].unique_ports.contains(&443));
}

#[test]
fn test_lateral_movement_drop_events_ignored() {
    // Evenimentele "drop" nu declanseaza Lateral Movement (doar "accept").
    let detector = Detector::new(lateral_config());

    for dest in &["10.0.0.10", "10.0.0.11", "10.0.0.12"] {
        // drop in loc de accept
        let alerts = detector.process_event(&LogEvent {
            source_ip: "10.0.1.5".parse().unwrap(),
            dest_ip: Some(dest.parse().unwrap()),
            dest_port: 445,
            protocol: "tcp".to_string(),
            action: Action::Drop,
            raw_log: String::new(),
        });
        let lateral: Vec<_> = alerts
            .iter()
            .filter(|a| matches!(a.scan_type, ScanType::LateralMovement))
            .collect();
        assert!(
            lateral.is_empty(),
            "Evenimentele drop nu trebuie sa declanseze Lateral Movement"
        );
    }
}

// =========================================================================
// Teste Beaconing C2 (#24)
// =========================================================================

/// Config Beaconing activat: min_events=5, fereastra 60s, CV<=0.30, interval [1,60]s.
fn beaconing_config() -> DetectionConfig {
    let mut cfg = test_config();
    // Dezactivam celelalte detectii ca sa nu interfereze.
    cfg.fast_scan.port_threshold = 1000;
    cfg.slow_scan.port_threshold = 1000;
    cfg.accept_scan.port_threshold = 1000;
    cfg.lateral_movement.enabled = false;
    cfg.distributed_scan.enabled = false;
    cfg.beaconing = BeaconingConfig {
        enabled: true,
        min_events: 5,
        time_window_secs: 60,
        cv_threshold: 0.30,
        min_interval_secs: 1,
        max_interval_secs: 60,
    };
    cfg
}

fn make_beacon_accept(src: &str, dst: &str, port: u16) -> LogEvent {
    LogEvent {
        source_ip: src.parse().unwrap(),
        dest_ip: Some(dst.parse().unwrap()),
        dest_port: port,
        protocol: "tcp".to_string(),
        action: Action::Accept,
        raw_log: String::new(),
    }
}

/// Injecteaza un istoric de timestamp-uri intr-un flow beacon, simuland
/// intervale spatiate la `interval_secs +/- jitter_secs` in trecut.
/// Muta in trecut toate hit-urile de scan/lateral, ca un test de cleanup
/// sa nu depinda de ferestrele de detectie (care limiteaza stergerea).
fn backdate_all_hits(detector: &Detector, by: Duration) {
    let shift = |instant: Instant| instant.checked_sub(by).unwrap_or(instant);
    for mut entry in detector.port_scan.drop_hits.iter_mut() {
        for hit in entry.value_mut() {
            hit.seen_at = shift(hit.seen_at);
        }
    }
    for mut entry in detector.port_scan.accept_hits.iter_mut() {
        for hit in entry.value_mut() {
            hit.seen_at = shift(hit.seen_at);
        }
    }
    for mut entry in detector.lateral.hits.iter_mut() {
        for hit in entry.value_mut() {
            hit.seen_at = shift(hit.seen_at);
        }
    }
}

fn inject_beacon_history(
    detector: &Detector,
    flow_key: (IpAddr, IpAddr, u16),
    count: usize,
    interval_secs: u64,
    jitter_secs: f64,
) {
    let now = Instant::now();
    let mut hits = Vec::with_capacity(count);
    // Asezam timestamp-urile in ordine cronologica: cel mai vechi inapoi in timp.
    for i in 0..count {
        // Cel mai recent hit este la `now - interval_secs` (lasam loc unui
        // eveniment "live" emis ulterior la `now`). Cel mai vechi este la
        // `now - count*interval_secs`.
        let steps_back = (count - i) as u64;
        let base_offset = steps_back * interval_secs;
        // Jitter deterministic alternand semne pentru stabilitatea testului.
        let sign = if i % 2 == 0 { 1.0 } else { -1.0 };
        let offset_f = base_offset as f64 + sign * jitter_secs;
        let offset = Duration::from_secs_f64(offset_f.max(0.0));
        hits.push(BeaconHit {
            seen_at: now.checked_sub(offset).unwrap_or(now),
        });
    }
    detector.beaconing.hits.insert(flow_key, hits);
}

#[test]
fn test_beacon_stats_uniform_intervals() {
    // Intervale perfect uniforme: CV ar trebui sa fie aproape 0.
    let detector = Detector::new(beaconing_config());
    let src: IpAddr = "10.0.1.5".parse().unwrap();
    let dst: IpAddr = "10.0.1.50".parse().unwrap();
    let key = (src, dst, 443);

    inject_beacon_history(&detector, key, 10, 5, 0.0);
    let BeaconStats {
        mean_interval_secs: mean,
        cv,
        count,
    } = detector
        .beaconing
        .stats(&key, Duration::from_secs(60), Instant::now())
        .expect("ar trebui sa avem statistici");

    assert_eq!(count, 10);
    assert!(
        (mean - 5.0).abs() < 0.5,
        "mean asteptat ~5s, primit {}",
        mean
    );
    assert!(
        cv < 0.05,
        "CV asteptat <0.05 pentru intervale uniforme, primit {}",
        cv
    );
}

#[test]
fn test_beacon_stats_high_variance() {
    // Intervale cu jitter mare (50% din interval) → CV mare.
    let detector = Detector::new(beaconing_config());
    let src: IpAddr = "10.0.1.5".parse().unwrap();
    let dst: IpAddr = "10.0.1.50".parse().unwrap();
    let key = (src, dst, 443);

    // 6 timestamp-uri amplasate haotic: 0, 1, 6, 7, 20, 21 secunde in urma.
    let now = Instant::now();
    let offsets = [21u64, 20, 7, 6, 1, 0];
    let hits: Vec<BeaconHit> = offsets
        .iter()
        .map(|s| BeaconHit {
            seen_at: now.checked_sub(Duration::from_secs(*s)).unwrap_or(now),
        })
        .collect();
    detector.beaconing.hits.insert(key, hits);

    let BeaconStats { cv, .. } = detector
        .beaconing
        .stats(&key, Duration::from_secs(60), now)
        .expect("ar trebui sa avem statistici");
    assert!(
        cv > 0.5,
        "CV asteptat > 0.5 pentru intervale haotice, primit {}",
        cv
    );
}

#[test]
fn test_beacon_stats_below_min_events() {
    // Sub min_events → process_event nu trebuie sa emita alerta.
    let detector = Detector::new(beaconing_config());
    let alerts = detector.process_event(&make_beacon_accept("10.0.1.5", "10.0.1.50", 443));
    assert!(
        alerts
            .iter()
            .all(|a| !matches!(a.scan_type, ScanType::Beaconing)),
        "1 eveniment singular nu trebuie sa declanseze Beaconing"
    );
}

#[test]
fn test_beaconing_emits_alert_for_periodic_flow() {
    // Cu istoric uniform suficient pre-injectat, urmatorul accept declanseaza alerta.
    let detector = Detector::new(beaconing_config());
    let src: IpAddr = "10.0.1.5".parse().unwrap();
    let dst: IpAddr = "10.0.1.50".parse().unwrap();
    let port = 443;
    let key = (src, dst, port);

    // 5 evenimente uniforme la 5s interval (jitter 0).
    inject_beacon_history(&detector, key, 5, 5, 0.0);

    // Urmatorul accept reincarca calculul.
    let alerts = detector.process_event(&make_beacon_accept("10.0.1.5", "10.0.1.50", port));
    let beacon: Vec<_> = alerts
        .iter()
        .filter(|a| matches!(a.scan_type, ScanType::Beaconing))
        .collect();
    assert_eq!(beacon.len(), 1, "ar trebui exact 1 alerta Beaconing");
    let a = beacon[0];
    assert_eq!(a.beacon_port, Some(port));
    assert!(a.event_count.unwrap() >= 5);
    assert!(
        a.cv.unwrap() < 0.30,
        "CV ar trebui sub prag, primit {:?}",
        a.cv
    );
}

#[test]
fn test_beaconing_disabled_in_config() {
    let mut cfg = beaconing_config();
    cfg.beaconing.enabled = false;
    let detector = Detector::new(cfg);
    let src: IpAddr = "10.0.1.5".parse().unwrap();
    let dst: IpAddr = "10.0.1.50".parse().unwrap();
    let key = (src, dst, 443);

    inject_beacon_history(&detector, key, 5, 5, 0.0);
    let alerts = detector.process_event(&make_beacon_accept("10.0.1.5", "10.0.1.50", 443));
    assert!(
        alerts
            .iter()
            .all(|a| !matches!(a.scan_type, ScanType::Beaconing)),
        "Beaconing dezactivat in config nu trebuie sa emita alerte"
    );
}

#[test]
fn test_beaconing_mean_outside_range() {
    // Intervale uniforme dar prea mari → mean > max_interval_secs → no alert.
    let mut cfg = beaconing_config();
    cfg.beaconing.max_interval_secs = 3; // interval real va fi 5s, > 3
    let detector = Detector::new(cfg);
    let src: IpAddr = "10.0.1.5".parse().unwrap();
    let dst: IpAddr = "10.0.1.50".parse().unwrap();
    let key = (src, dst, 443);

    inject_beacon_history(&detector, key, 6, 5, 0.0);
    let alerts = detector.process_event(&make_beacon_accept("10.0.1.5", "10.0.1.50", 443));
    assert!(
        alerts
            .iter()
            .all(|a| !matches!(a.scan_type, ScanType::Beaconing)),
        "Mean > max_interval_secs nu trebuie sa declanseze Beaconing"
    );
}

#[test]
fn test_beaconing_high_cv_no_alert() {
    // Intervale neregulate: CV mare → fara alerta chiar daca count >= min_events.
    let detector = Detector::new(beaconing_config());
    let src: IpAddr = "10.0.1.5".parse().unwrap();
    let dst: IpAddr = "10.0.1.50".parse().unwrap();
    let key = (src, dst, 443);

    // Spatiu chaos: 30, 25, 10, 8, 2, 0 secunde in urma → CV >> 0.30.
    let now = Instant::now();
    let offsets = [30u64, 25, 10, 8, 2, 0];
    let hits: Vec<BeaconHit> = offsets
        .iter()
        .map(|s| BeaconHit {
            seen_at: now.checked_sub(Duration::from_secs(*s)).unwrap_or(now),
        })
        .collect();
    detector.beaconing.hits.insert(key, hits);

    let alerts = detector.process_event(&make_beacon_accept("10.0.1.5", "10.0.1.50", 443));
    assert!(
        alerts
            .iter()
            .all(|a| !matches!(a.scan_type, ScanType::Beaconing)),
        "CV mare nu trebuie sa declanseze Beaconing"
    );
}

#[test]
fn test_beaconing_ignore_port() {
    // Port in ignore_beaconing_ports: nici inregistrare, nici alerta.
    let mut cfg = beaconing_config();
    cfg.exceptions.ignore_beaconing_ports = vec![123]; // NTP
    let detector = Detector::new(cfg);

    let src: IpAddr = "10.0.1.5".parse().unwrap();
    let dst: IpAddr = "10.0.1.50".parse().unwrap();
    let key_ntp = (src, dst, 123);

    // Pre-injectam un istoric "curat" — daca process_event ar evalua flow-ul,
    // ar emite alerta. Asteptarea: e ocolit complet.
    inject_beacon_history(&detector, key_ntp, 6, 5, 0.0);
    let alerts = detector.process_event(&make_beacon_accept("10.0.1.5", "10.0.1.50", 123));
    assert!(
        alerts
            .iter()
            .all(|a| !matches!(a.scan_type, ScanType::Beaconing)),
        "Port in ignore_beaconing_ports nu trebuie sa declanseze Beaconing"
    );
}

#[test]
fn test_beaconing_authorized_source() {
    // Sursa in authorized_beaconing_sources: nu declanseaza Beaconing.
    let mut cfg = beaconing_config();
    cfg.exceptions.authorized_beaconing_sources = vec!["10.0.1.5".to_string()];
    let detector = Detector::new(cfg);

    let src: IpAddr = "10.0.1.5".parse().unwrap();
    let dst: IpAddr = "10.0.1.50".parse().unwrap();
    let key = (src, dst, 443);
    inject_beacon_history(&detector, key, 6, 5, 0.0);

    let alerts = detector.process_event(&make_beacon_accept("10.0.1.5", "10.0.1.50", 443));
    assert!(
        alerts
            .iter()
            .all(|a| !matches!(a.scan_type, ScanType::Beaconing)),
        "Sursa autorizata nu trebuie sa declanseze Beaconing"
    );
}

#[test]
fn test_beaconing_cooldown_prevents_duplicate() {
    // Dupa o alerta emisa, urmatorul accept in cooldown nu mai emite alta.
    let detector = Detector::new(beaconing_config());
    let src: IpAddr = "10.0.1.5".parse().unwrap();
    let dst: IpAddr = "10.0.1.50".parse().unwrap();
    let key = (src, dst, 443);

    inject_beacon_history(&detector, key, 5, 5, 0.0);
    let first = detector.process_event(&make_beacon_accept("10.0.1.5", "10.0.1.50", 443));
    assert!(
        first
            .iter()
            .any(|a| matches!(a.scan_type, ScanType::Beaconing)),
        "Prima alerta Beaconing ar trebui emisa"
    );

    // Al doilea eveniment imediat: cooldown activ.
    let second = detector.process_event(&make_beacon_accept("10.0.1.5", "10.0.1.50", 443));
    assert!(
        second
            .iter()
            .all(|a| !matches!(a.scan_type, ScanType::Beaconing)),
        "Cooldown trebuie sa previna a doua alerta Beaconing"
    );
}

#[test]
fn test_beaconing_drop_action_ignored() {
    // Evenimentele "drop" nu se inregistreaza ca beacon hits.
    let detector = Detector::new(beaconing_config());
    let drop_event = LogEvent {
        source_ip: "10.0.1.5".parse().unwrap(),
        dest_ip: Some("10.0.1.50".parse().unwrap()),
        dest_port: 443,
        protocol: "tcp".to_string(),
        action: Action::Drop,
        raw_log: String::new(),
    };
    for _ in 0..10 {
        let _ = detector.process_event(&drop_event);
    }
    let key = (
        "10.0.1.5".parse::<IpAddr>().unwrap(),
        "10.0.1.50".parse::<IpAddr>().unwrap(),
        443,
    );
    assert!(
        detector.beaconing.hits.get(&key).is_none(),
        "Drop-urile nu trebuie sa populeze beacon_hits"
    );
}

#[test]
fn test_scan_flow_cardinality_limits_are_enforced() {
    let mut cfg = test_config();
    cfg.max_tracked_flows = 3;
    cfg.max_flows_per_source = 2;
    let detector = Detector::new(cfg);

    for target in ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"] {
        detector.process_event(&make_event_with_dest("192.0.2.10", target, 80));
    }
    assert!(
        detector
            .port_scan
            .scan_flow_count_for_source("192.0.2.10".parse().unwrap())
            <= 2
    );

    detector.process_event(&make_event_with_dest("192.0.2.11", "10.0.1.1", 80));
    detector.process_event(&make_event_with_dest("192.0.2.12", "10.0.1.2", 80));
    assert!(detector.port_scan.drop_hits.len() + detector.port_scan.accept_hits.len() <= 3);
}

#[test]
fn test_scan_flow_index_tracks_eviction_and_cleanup() {
    let mut cfg = test_config();
    cfg.max_flows_per_source = 80;
    let detector = Detector::new(cfg);
    let source: IpAddr = "192.0.2.10".parse().unwrap();

    for i in 0..1_000u32 {
        let target = format!("10.1.{}.{}", i / 256, i % 256);
        detector.process_event(&make_event_with_dest("192.0.2.10", &target, 80));
        let tracked = detector.port_scan.scan_flow_count_for_source(source);
        assert!(tracked <= 80);
        assert_eq!(
            tracked,
            detector
                .port_scan
                .drop_hits
                .iter()
                .filter(|entry| entry.key().0 == source)
                .count()
        );
    }
    // Fluxul cel mai recent nu este niciodata evacuat.
    assert!(detector
        .port_scan
        .drop_hits
        .contains_key(&(source, "10.1.3.231".parse().unwrap())));

    backdate_all_hits(&detector, Duration::from_secs(7_200));
    detector.cleanup(Duration::from_secs(60));
    assert_eq!(detector.port_scan.scan_flow_count_for_source(source), 0);
    assert!(detector.port_scan.source_flows.is_empty());
}

#[test]
fn test_horizontal_sweep_at_flow_limit_is_not_quadratic() {
    // Inainte: fiecare flux nou parcurgea toate fluxurile (de 2-4 ori),
    // deci 40k evenimente x 10k fluxuri ~ 10^9 pasi. Acum evictia in lot
    // amortizeaza parcurgerea; testul ar dura minute in varianta veche.
    let mut cfg = test_config();
    cfg.max_tracked_flows = 10_000;
    cfg.max_flows_per_source = 10_000;
    let detector = Detector::new(cfg);

    let started = Instant::now();
    for i in 0..40_000u32 {
        let target = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i));
        detector.process_event(&make_event_with_dest("192.0.2.10", &target.to_string(), 80));
    }
    assert!(detector.port_scan.drop_hits.len() + detector.port_scan.accept_hits.len() <= 10_000);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "sweep-ul a durat {:?}",
        started.elapsed()
    );
}

#[test]
fn test_source_eviction_removes_cross_indexed_state() {
    let mut cfg = test_config();
    cfg.max_tracked_ips = 1;
    let detector = Detector::new(cfg);
    let old_src: IpAddr = "192.0.2.20".parse().unwrap();
    let dst: IpAddr = "10.0.0.10".parse().unwrap();
    detector.process_event(&make_event_with_dest("192.0.2.20", "10.0.0.10", 80));
    detector.distributed.hits.insert(
        dst,
        vec![DistributedHit {
            source_ip: old_src,
            port: 80,
            seen_at: Instant::now(),
        }],
    );
    detector.beaconing.hits.insert(
        (old_src, dst, 443),
        vec![BeaconHit {
            seen_at: Instant::now(),
        }],
    );

    detector.process_event(&make_event_with_dest("192.0.2.21", "10.0.0.11", 80));

    assert!(detector
        .distributed
        .hits
        .get(&dst)
        .is_none_or(|hits| hits.iter().all(|hit| hit.source_ip != old_src)));
    assert!(!detector
        .beaconing
        .hits
        .iter()
        .any(|entry| entry.key().0 == old_src));
}

#[test]
fn test_source_lru_eviction_keeps_newest_and_cleans_state() {
    let mut cfg = test_config();
    cfg.max_tracked_ips = 64;
    let detector = Detector::new(cfg);
    let dst = "10.9.9.9";

    for i in 0..1_000u32 {
        let source = IpAddr::from(std::net::Ipv4Addr::from(0xc000_0200 + i)).to_string();
        detector.process_event(&make_event_with_dest(&source, dst, 80));
        assert!(detector.tracked_ips() <= 64);
    }
    let newest: IpAddr = IpAddr::from(std::net::Ipv4Addr::from(0xc000_0200 + 999));
    assert!(detector.last_seen.contains_key(&newest));
    // Starea per sursa ramane coerenta cu last_seen.
    for entry in detector.port_scan.drop_hits.iter() {
        assert!(detector.last_seen.contains_key(&entry.key().0));
    }
    for entry in detector.port_scan.source_flows.iter() {
        assert!(detector.last_seen.contains_key(entry.key()));
    }
}

#[test]
fn test_spoofed_source_flood_at_ip_limit_is_not_quadratic() {
    // Inainte: fiecare IP nou peste limita parcurgea last_seen si apoi
    // ~10 tabele intregi (~35s pentru acest scenariu). Evictia in lot
    // amortizeaza parcurgerea (<1s).
    let mut cfg = test_config();
    cfg.max_tracked_ips = 5_000;
    let detector = Detector::new(cfg);

    let started = Instant::now();
    for i in 0..60_000u32 {
        let source = IpAddr::from(std::net::Ipv4Addr::from(0x0b00_0000 + i)).to_string();
        detector.process_event(&make_event_with_dest(&source, "10.9.9.9", 80));
    }
    assert!(detector.tracked_ips() <= 5_000);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "flood-ul a durat {:?}",
        started.elapsed()
    );
}

#[test]
fn test_distributed_and_beacon_caps_evict_in_batches() {
    let mut cfg = beaconing_config();
    cfg.max_tracked_ips = 16;
    cfg.distributed_scan.enabled = true;
    let detector = Detector::new(cfg);

    for i in 0..200u32 {
        let target = IpAddr::from(std::net::Ipv4Addr::from(0x0a05_0000 + i)).to_string();
        detector.process_event(&make_beacon_accept("10.0.1.5", &target, 443));
        assert!(detector.beaconing.hits.len() <= 16);
        assert!(detector.distributed.hits.len() <= 16);
    }
    let newest: IpAddr = IpAddr::from(std::net::Ipv4Addr::from(0x0a05_0000 + 199));
    let source: IpAddr = "10.0.1.5".parse().unwrap();
    assert!(detector.beaconing.hits.contains_key(&(source, newest, 443)));
    assert!(detector.distributed.hits.contains_key(&newest));
}

#[test]
fn test_cleanup_keeps_beacon_history_for_the_whole_window() {
    // Valorile implicite din config.toml: fereastra beaconing 3600s,
    // interval maxim 3600s, cleanup.max_entry_age_secs = 600s.
    let mut cfg = beaconing_config();
    cfg.beaconing.min_events = 8;
    cfg.beaconing.time_window_secs = 3600;
    cfg.beaconing.max_interval_secs = 3600;
    let detector = Detector::new(cfg);
    let key = (
        "10.0.1.5".parse::<IpAddr>().unwrap(),
        "203.0.113.9".parse::<IpAddr>().unwrap(),
        443,
    );
    // Beacon la 2 minute: 10 hit-uri acopera 20 de minute > max_age.
    inject_beacon_history(&detector, key, 10, 120, 0.0);

    detector.cleanup(Duration::from_secs(600));
    assert_eq!(detector.beaconing.hits.get(&key).unwrap().len(), 10);

    let alerts = detector.process_event(&make_beacon_accept("10.0.1.5", "203.0.113.9", 443));
    assert!(alerts
        .iter()
        .any(|alert| matches!(alert.scan_type, ScanType::Beaconing)));
}

#[test]
fn test_cleanup_still_prunes_beyond_the_detection_window() {
    let mut cfg = beaconing_config();
    cfg.beaconing.time_window_secs = 300;
    let detector = Detector::new(cfg);
    let key = (
        "10.0.1.5".parse::<IpAddr>().unwrap(),
        "203.0.113.9".parse::<IpAddr>().unwrap(),
        443,
    );
    // Hit-uri la 110..1100s in urma: raman doar cele din ultimele
    // max(600, 300) secunde (110, 220, 330, 440, 550).
    inject_beacon_history(&detector, key, 10, 110, 0.0);
    detector.cleanup(Duration::from_secs(600));
    assert_eq!(detector.beaconing.hits.get(&key).unwrap().len(), 5);
}

#[test]
fn test_dynamic_threshold_bounds_without_integer_between_them() {
    let dt = DynamicThresholdConfig {
        enabled: true,
        ewma_alpha: 0.1,
        sensitivity_multiplier: 3.0,
        min_samples: 1,
        min_threshold_ratio: 0.5,
        max_threshold_ratio: 0.6,
    };
    let mut baseline = BaselineEwma::new();
    baseline.update(1.0, dt.ewma_alpha);
    // ceil(3 * 0.5) = 2 > floor(3 * 0.6) = 1: inainte, panica in clamp.
    assert_eq!(effective_threshold_value(3, &baseline, &dt), 2);

    baseline.update(100.0, dt.ewma_alpha);
    assert_eq!(effective_threshold_value(3, &baseline, &dt), 2);
}
