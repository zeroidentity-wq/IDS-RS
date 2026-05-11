// =============================================================================
// web.rs - Web Dashboard Module (#25)
// =============================================================================
//
// Server HTTP embedded care serveste un dashboard read-only cu:
//   GET /           → pagina HTML cu graf D3.js force-directed al retelei
//   GET /api/alerts → JSON cu ultimele N alerte din buffer-ul circular
//   GET /api/graph  → JSON cu noduri (IP-uri) si muchii (conexiuni) pentru graf
//
// Arhitectura:
//   - Ruleaza ca task tokio separat, fara impact asupra detectiei
//   - Datele vin dintr-un buffer circular Arc<Mutex<VecDeque<Alert>>>
//   - Mutex-ul este tinut doar cateva microsecunde (push/clone)
//   - Dashboard-ul este read-only — nu modifica starea detectorului
//
// NOTA: D3.js este servit inline (nu de pe CDN) pentru a functiona in
// retele izolate / air-gapped fara acces la internet.
//
// =============================================================================

use crate::config::WebDashboardConfig;
use crate::detector::{Alert, ScanType};
use crate::display;
use axum::{
    extract::{Query, State},
    response::Html,
    routing::get,
    Json, Router,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Buffer circular de alerte partajat intre detection loop si web server.
///
/// Arc:      shared ownership intre task-uri async
/// Mutex:    sincronizare la scriere/citire (lock scurt, microsecunde)
/// VecDeque: deque cu push_back + pop_front = buffer circular eficient
pub type AlertBuffer = Arc<Mutex<VecDeque<Alert>>>;

/// Stare partajata injectata in fiecare handler axum via `State` extractor.
#[derive(Clone)]
struct AppState {
    alerts: AlertBuffer,
}

// =============================================================================
// Server HTTP
// =============================================================================

/// Porneste serverul HTTP al dashboard-ului pe un task tokio separat.
pub async fn start_web_server(
    config: &WebDashboardConfig,
    alerts: AlertBuffer,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let state = AppState { alerts };

    let app = Router::new()
        .route("/", get(get_dashboard))
        .route("/static/d3.min.js", get(get_d3_js))
        .route("/api/alerts", get(get_alerts))
        .route("/api/graph", get(get_graph))
        .route("/api/ip/{ip}", get(get_ip_dossier))
        .with_state(state);

    let bind_addr = format!("{}:{}", config.bind, config.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Nu pot face bind pe {}: {}", bind_addr, e))?;

    display::log_info(&format!("Web dashboard activ: http://{}", bind_addr));

    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            display::log_error(&format!("Web dashboard server error: {:#}", e));
        }
    });

    Ok(handle)
}

// =============================================================================
// API Handlers
// =============================================================================

/// GET / — Serveste pagina HTML cu graful D3.js.
async fn get_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

/// GET /static/d3.min.js — D3.js v7 servit local (fara CDN, functioneaza air-gapped).
///
/// `include_str!` imbeddeaza fisierul in binar la compile-time. Zero I/O la runtime,
/// zero dependente externe. Adauga ~273KB la dimensiunea binarului.
async fn get_d3_js() -> (
    [(axum::http::header::HeaderName, &'static str); 1],
    &'static str,
) {
    static D3_JS: &str = include_str!("../static/d3.v7.min.js");
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        D3_JS,
    )
}

/// Parametri de query pentru filtrarea alertelor si grafului.
/// GET /api/alerts?ip=10.10.1.50 → returneaza doar alertele in care IP-ul apare
/// ca sursa, destinatie, unique_dest sau unique_source.
#[derive(serde::Deserialize, Default)]
struct AlertQuery {
    ip: Option<String>,
}

/// Snapshot rapid al buffer-ului de alerte: clonam continutul sub lock si
/// returnam un Vec independent. Lock-ul este eliberat la final de functie,
/// inainte de orice .await sau iteratie costisitoare in handler.
///
/// Motivatie: `state.alerts` este `Arc<Mutex<VecDeque<Alert>>>` (std::sync::Mutex).
/// Daca tinem lock-ul pe toata durata handler-ului axum:
///   - blocheaza worker thread-ul tokio cat dureaza serializarea JSON
///   - sub presiune (mai multi clienti web, buffer mare) blocheaza si producator-ul
///     din main loop care vrea sa push_back o alerta noua
///
/// Pretul snapshot-ului: o clona a VecDeque (~1000 Alert-uri default ~ cateva KB),
/// platit o singura data per request. Lock-ul este tinut microsecunde, nu milisecunde.
fn snapshot_alerts(buffer: &Mutex<VecDeque<Alert>>) -> Vec<Alert> {
    let guard = buffer.lock().unwrap_or_else(|e| e.into_inner());
    guard.iter().cloned().collect()
}

/// Verifica daca o alerta implica un IP dat (sursa, destinatie, lateral dest, distributed source).
fn alert_matches_ip(alert: &Alert, ip: IpAddr) -> bool {
    if alert.source_ip == ip {
        return true;
    }
    if alert.dest_ip == Some(ip) {
        return true;
    }
    if alert.unique_dests.contains(&ip) {
        return true;
    }
    if alert.unique_sources.contains(&ip) {
        return true;
    }
    false
}

/// GET /api/alerts — Returneaza ultimele alerte din buffer (newest first).
/// Optional: ?ip=X filtreaza doar alertele care implica IP-ul X.
async fn get_alerts(
    State(state): State<AppState>,
    Query(params): Query<AlertQuery>,
) -> Json<serde_json::Value> {
    // Snapshot rapid sub lock; eliberam lock-ul inainte de filter/serializare.
    let alerts_snapshot = snapshot_alerts(&state.alerts);

    let filter_ip: Option<IpAddr> = params.ip.as_deref().and_then(|s| s.parse::<IpAddr>().ok());

    let alerts: Vec<&Alert> = match filter_ip {
        Some(ip) => alerts_snapshot
            .iter()
            .rev()
            .filter(|a| alert_matches_ip(a, ip))
            .collect(),
        None => alerts_snapshot.iter().rev().collect(),
    };
    Json(serde_json::json!(alerts))
}

/// Structura unui nod in graf (IP).
#[derive(serde::Serialize)]
struct GraphNode {
    id: String,
    role: &'static str,
    alert_count: usize,
    scan_types: Vec<String>,
    last_seen: String,
}

/// Structura unei muchii in graf (conexiune atacator → tinta).
#[derive(serde::Serialize)]
struct GraphEdge {
    source: String,
    target: String,
    scan_type: String,
    count: usize,
    ports: Vec<u16>,
}

/// Acumulator intern pentru construirea muchiilor din graf.
#[derive(Default)]
struct EdgeAccum {
    count: usize,
    ports: HashSet<u16>,
}

/// Structura raspunsului /api/graph.
#[derive(serde::Serialize)]
struct GraphResponse {
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
    stats: GraphStats,
}

/// Statistici generale afisate in header-ul dashboard-ului.
#[derive(serde::Serialize)]
struct GraphStats {
    total_alerts: usize,
    unique_attackers: usize,
    unique_targets: usize,
}

/// Acumulator intern pentru construirea nodurilor din graf.
#[derive(Default)]
struct NodeAccum {
    alert_count: usize,
    scan_types: HashSet<String>,
    last_seen: String,
}

/// GET /api/graph — Transforma alertele in structura graf (noduri + muchii).
/// Optional: ?ip=X returneaza "egocentric network" — doar IP-ul X si conexiunile lui directe.
async fn get_graph(
    State(state): State<AppState>,
    Query(params): Query<AlertQuery>,
) -> Json<GraphResponse> {
    // Snapshot rapid sub lock; eliberam lock-ul inainte de constructia grafului.
    let buffer = snapshot_alerts(&state.alerts);
    let filter_ip: Option<IpAddr> = params.ip.as_deref().and_then(|s| s.parse::<IpAddr>().ok());

    let mut attackers: HashMap<IpAddr, NodeAccum> = HashMap::new();
    let mut targets: HashMap<IpAddr, NodeAccum> = HashMap::new();
    // Deduplicam muchiile: (src, dst, scan_type) → count + porturi
    let mut edge_map: HashMap<(String, String, String), EdgeAccum> = HashMap::new();

    for alert in buffer.iter().filter(|a| match filter_ip {
        Some(ip) => alert_matches_ip(a, ip),
        None => true,
    }) {
        let ts = alert.timestamp.to_rfc3339();
        let stype = alert.scan_type.to_string();

        // Acumulam date atacator. DistributedScan este inversat: sursele reale
        // sunt deduplicate in branch-ul dedicat de mai jos.
        if !matches!(alert.scan_type, ScanType::DistributedScan) {
            let a = attackers.entry(alert.source_ip).or_default();
            a.alert_count += 1;
            a.scan_types.insert(stype.clone());
            a.last_seen = ts.clone();
        }

        // Muchie + tinta standard (dest_ip). DistributedScan este tratat separat
        // mai jos ca sa nu dublam sursa care apare si in `unique_sources`.
        if !matches!(alert.scan_type, ScanType::DistributedScan) {
            if let Some(dest) = alert.dest_ip {
                let t = targets.entry(dest).or_default();
                t.alert_count += 1;
                t.scan_types.insert(stype.clone());
                t.last_seen = ts.clone();

                let key = (alert.source_ip.to_string(), dest.to_string(), stype.clone());
                let accum = edge_map.entry(key).or_default();
                accum.count += 1;
                for &p in &alert.unique_ports {
                    accum.ports.insert(p);
                }
            }
        }

        // LateralMovement: fiecare unique_dest e o tinta separata
        match alert.scan_type {
            ScanType::LateralMovement => {
                for dest in &alert.unique_dests {
                    let t = targets.entry(*dest).or_default();
                    t.alert_count += 1;
                    t.last_seen = ts.clone();

                    let key = (alert.source_ip.to_string(), dest.to_string(), stype.clone());
                    edge_map.entry(key).or_default().count += 1;
                }
            }
            ScanType::DistributedScan => {
                if let Some(dest) = alert.dest_ip {
                    let t = targets.entry(dest).or_default();
                    t.alert_count += 1;
                    t.scan_types.insert(stype.clone());
                    t.last_seen = ts.clone();
                }

                let mut sources: HashSet<IpAddr> = alert.unique_sources.iter().copied().collect();
                sources.insert(alert.source_ip);

                // Fiecare sursa unica este atacator; alert.source_ip poate fi deja in lista.
                for src in sources {
                    let a = attackers.entry(src).or_default();
                    a.alert_count += 1;
                    a.scan_types.insert(stype.clone());
                    a.last_seen = ts.clone();

                    if let Some(dest) = alert.dest_ip {
                        let key = (src.to_string(), dest.to_string(), stype.clone());
                        let accum = edge_map.entry(key).or_default();
                        accum.count += 1;
                        for &p in &alert.unique_ports {
                            accum.ports.insert(p);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Construim lista de noduri — IP-urile care sunt SI atacator SI tinta raman atacator
    let mut nodes: Vec<GraphNode> = Vec::new();

    for (ip, acc) in &attackers {
        nodes.push(GraphNode {
            id: ip.to_string(),
            role: "attacker",
            alert_count: acc.alert_count,
            scan_types: acc.scan_types.iter().cloned().collect(),
            last_seen: acc.last_seen.clone(),
        });
    }

    for (ip, acc) in &targets {
        if !attackers.contains_key(ip) {
            nodes.push(GraphNode {
                id: ip.to_string(),
                role: "target",
                alert_count: acc.alert_count,
                scan_types: acc.scan_types.iter().cloned().collect(),
                last_seen: acc.last_seen.clone(),
            });
        }
    }

    // Construim muchiile (cu porturile sortate)
    let edges: Vec<GraphEdge> = edge_map
        .into_iter()
        .map(|((source, target, scan_type), accum)| {
            let mut ports: Vec<u16> = accum.ports.into_iter().collect();
            ports.sort_unstable();
            GraphEdge {
                source,
                target,
                scan_type,
                count: accum.count,
                ports,
            }
        })
        .collect();

    let stats = GraphStats {
        total_alerts: buffer.len(),
        unique_attackers: attackers.len(),
        unique_targets: targets.len(),
    };

    Json(GraphResponse {
        nodes,
        edges,
        stats,
    })
}

/// Raspuns IP Dossier — istoric complet al unui IP din alerte.
#[derive(serde::Serialize)]
struct IpDossier {
    ip: String,
    roles: Vec<&'static str>,
    total_alerts: usize,
    as_attacker: usize,
    as_target: usize,
    scan_types: Vec<String>,
    ports_accessed: Vec<u16>,
    connected_ips: Vec<String>,
    timeline: Vec<DossierEvent>,
}

#[derive(serde::Serialize)]
struct DossierEvent {
    timestamp: String,
    scan_type: String,
    role: &'static str,
    peer_ip: String,
    ports: Vec<u16>,
}

/// GET /api/ip/{ip} — Returneaza dosarul complet al unui IP (rol, porturi, timeline, peers).
async fn get_ip_dossier(
    State(state): State<AppState>,
    axum::extract::Path(ip_str): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return Json(serde_json::json!({"error": "IP invalid"})),
    };

    // Snapshot rapid sub lock; eliberam lock-ul inainte de constructia dosarului.
    let buffer = snapshot_alerts(&state.alerts);

    let mut as_attacker: usize = 0;
    let mut as_target: usize = 0;
    let mut scan_types: HashSet<String> = HashSet::new();
    let mut ports: HashSet<u16> = HashSet::new();
    let mut peers: HashSet<IpAddr> = HashSet::new();
    let mut timeline: Vec<DossierEvent> = Vec::new();

    for alert in buffer.iter() {
        let is_src = match alert.scan_type {
            ScanType::DistributedScan => {
                alert.source_ip == ip || alert.unique_sources.contains(&ip)
            }
            _ => alert.source_ip == ip,
        };
        let is_dst = match alert.scan_type {
            ScanType::DistributedScan => alert.dest_ip == Some(ip),
            ScanType::LateralMovement => {
                alert.dest_ip == Some(ip) || alert.unique_dests.contains(&ip)
            }
            _ => alert.dest_ip == Some(ip),
        };

        if !is_src && !is_dst {
            continue;
        }

        let stype = alert.scan_type.to_string();
        scan_types.insert(stype.clone());

        if is_src {
            as_attacker += 1;
            if let Some(d) = alert.dest_ip {
                peers.insert(d);
            }
            for d in &alert.unique_dests {
                peers.insert(*d);
            }
            for &p in &alert.unique_ports {
                ports.insert(p);
            }
            let peer = alert.dest_ip.map(|d| d.to_string()).unwrap_or_default();
            timeline.push(DossierEvent {
                timestamp: alert.timestamp.to_rfc3339(),
                scan_type: stype.clone(),
                role: "attacker",
                peer_ip: peer,
                ports: alert.unique_ports.clone(),
            });
        }

        if is_dst {
            as_target += 1;
            peers.insert(alert.source_ip);
            for s in &alert.unique_sources {
                peers.insert(*s);
            }
            let peer = alert.source_ip.to_string();
            timeline.push(DossierEvent {
                timestamp: alert.timestamp.to_rfc3339(),
                scan_type: stype,
                role: "target",
                peer_ip: peer,
                ports: alert.unique_ports.clone(),
            });
        }
    }

    let mut roles = Vec::new();
    if as_attacker > 0 {
        roles.push("attacker");
    }
    if as_target > 0 {
        roles.push("target");
    }

    let mut ports_vec: Vec<u16> = ports.into_iter().collect();
    ports_vec.sort_unstable();
    let mut peers_vec: Vec<String> = peers.into_iter().map(|p| p.to_string()).collect();
    peers_vec.sort();
    let mut scan_types_vec: Vec<String> = scan_types.into_iter().collect();
    scan_types_vec.sort();

    // Timeline: newest first.
    timeline.reverse();

    let dossier = IpDossier {
        ip: ip.to_string(),
        roles,
        total_alerts: as_attacker + as_target,
        as_attacker,
        as_target,
        scan_types: scan_types_vec,
        ports_accessed: ports_vec,
        connected_ips: peers_vec,
        timeline,
    };

    Json(serde_json::json!(dossier))
}

// =============================================================================
// Dashboard HTML (imbeddeat via include_str!, functioneaza in retele air-gapped)
// =============================================================================

/// Pagina HTML completa cu graf D3.js force-directed, tabel alerte si auto-refresh.
///
/// Sursa HTML/CSS/JS este in `static/dashboard.html` (#15 — extras din literalul
/// inline initial pentru a tine `web.rs` la dimensiuni rezonabile). `include_str!`
/// o imbeddeaza in binar la compile-time:
///   - functioneaza in retele air-gapped (zero I/O la runtime)
///   - permite editing cu syntax highlight HTML/JS in IDE
///
/// D3.js v7 e servit separat ca asset static la `/static/d3.min.js` via `get_d3_js`.
const DASHBOARD_HTML: &str = include_str!("../static/dashboard.html");
