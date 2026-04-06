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
use axum::{extract::{Query, State}, response::Html, routing::get, Json, Router};
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

    display::log_info(&format!(
        "Web dashboard activ: http://{}",
        bind_addr
    ));

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
async fn get_d3_js() -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
    static D3_JS: &str = include_str!("../static/d3.v7.min.js");
    ([(axum::http::header::CONTENT_TYPE, "application/javascript")], D3_JS)
}

/// Parametri de query pentru filtrarea alertelor si grafului.
/// GET /api/alerts?ip=10.10.1.50 → returneaza doar alertele in care IP-ul apare
/// ca sursa, destinatie, unique_dest sau unique_source.
#[derive(serde::Deserialize, Default)]
struct AlertQuery {
    ip: Option<String>,
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
    let buffer = state.alerts.lock().unwrap_or_else(|e| e.into_inner());

    let filter_ip: Option<IpAddr> = params.ip.as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok());

    let alerts: Vec<&Alert> = match filter_ip {
        Some(ip) => buffer.iter().rev().filter(|a| alert_matches_ip(a, ip)).collect(),
        None => buffer.iter().rev().collect(),
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
    let buffer = state.alerts.lock().unwrap_or_else(|e| e.into_inner());
    let filter_ip: Option<IpAddr> = params.ip.as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok());

    let mut attackers: HashMap<IpAddr, NodeAccum> = HashMap::new();
    let mut targets: HashMap<IpAddr, NodeAccum> = HashMap::new();
    // Deduplicam muchiile: (src, dst, scan_type) → count + porturi
    let mut edge_map: HashMap<(String, String, String), EdgeAccum> = HashMap::new();

    for alert in buffer.iter().filter(|a| {
        match filter_ip {
            Some(ip) => alert_matches_ip(a, ip),
            None => true,
        }
    }) {
        let ts = alert.timestamp.to_rfc3339();
        let stype = alert.scan_type.to_string();

        // Acumulam date atacator
        let a = attackers.entry(alert.source_ip).or_default();
        a.alert_count += 1;
        a.scan_types.insert(stype.clone());
        a.last_seen = ts.clone();

        // Muchie + tinta standard (dest_ip)
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
                // Fiecare unique_source e un atacator suplimentar
                for src in &alert.unique_sources {
                    let a = attackers.entry(*src).or_default();
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

    let buffer = state.alerts.lock().unwrap_or_else(|e| e.into_inner());

    let mut as_attacker: usize = 0;
    let mut as_target: usize = 0;
    let mut scan_types: HashSet<String> = HashSet::new();
    let mut ports: HashSet<u16> = HashSet::new();
    let mut peers: HashSet<IpAddr> = HashSet::new();
    let mut timeline: Vec<DossierEvent> = Vec::new();

    for alert in buffer.iter() {
        let is_src = alert.source_ip == ip;
        let is_dst = alert.dest_ip == Some(ip)
            || alert.unique_dests.contains(&ip)
            || alert.unique_sources.contains(&ip);

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
    if as_attacker > 0 { roles.push("attacker"); }
    if as_target > 0 { roles.push("target"); }

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
// Dashboard HTML (inline — functioneaza in retele air-gapped)
// =============================================================================

/// Pagina HTML completa cu graf D3.js force-directed, tabel alerte si auto-refresh.
///
/// D3.js v7 este inclus inline via CDN fallback — pentru retele complet izolate,
/// poate fi inlocuit cu include_str!("../static/d3.v7.min.js").
const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IDS-RS — Network Dashboard</title>
<style>
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --text-dim: #8b949e;
  --accent: #58a6ff;
  --red: #f85149;
  --yellow: #d29922;
  --magenta: #bc8cff;
  --orange: #d18616;
  --cyan: #39d353;
  --green: #3fb950;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Cascadia Code', 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 13px;
  overflow-x: hidden;
}

/* Header */
.header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.header h1 {
  font-size: 16px;
  color: var(--accent);
  font-weight: 600;
}
.stats {
  display: flex;
  gap: 24px;
  align-items: center;
}
.stat {
  text-align: center;
}
.stat-val {
  font-size: 22px;
  font-weight: 700;
}
.stat-label {
  font-size: 11px;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.stat-val.red { color: var(--red); }
.stat-val.cyan { color: var(--cyan); }
.stat-val.accent { color: var(--accent); }

/* Omnisearch */
.search-box {
  display: flex;
  align-items: center;
  gap: 6px;
}
.search-box input {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  padding: 6px 12px;
  font-family: inherit;
  font-size: 12px;
  width: 200px;
  outline: none;
}
.search-box input:focus { border-color: var(--accent); }
.search-box input::placeholder { color: var(--text-dim); }
.search-box button {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--accent);
  padding: 6px 10px;
  cursor: pointer;
  font-family: inherit;
  font-size: 11px;
}
.search-box button:hover { border-color: var(--accent); }
.search-active-tag {
  display: none;
  align-items: center;
  gap: 4px;
  background: var(--accent);
  color: var(--bg);
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
}
.search-active-tag .close-tag {
  cursor: pointer;
  margin-left: 4px;
  font-weight: 700;
}

/* Layout */
.container {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 56px);
}
.graph-area {
  flex: 1;
  position: relative;
  min-height: 0;
}
.graph-area svg {
  width: 100%;
  height: 100%;
  display: block;
}

/* Tooltip */
.tooltip {
  position: absolute;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.15s;
  max-width: 320px;
  z-index: 10;
  font-size: 12px;
  line-height: 1.5;
}
.tooltip .ip { color: var(--accent); font-weight: 700; font-size: 14px; }
.tooltip .role { color: var(--text-dim); font-size: 11px; text-transform: uppercase; }
.tooltip .detail { color: var(--text); margin-top: 4px; }
.tooltip .scan-badge {
  display: inline-block;
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 10px;
  font-weight: 600;
  margin: 2px 2px 0 0;
}

/* Alert Table */
.table-area {
  height: 240px;
  background: var(--surface);
  border-top: 1px solid var(--border);
  overflow-y: auto;
}
.table-area table {
  width: 100%;
  border-collapse: collapse;
}
.table-area th {
  position: sticky;
  top: 0;
  background: var(--bg);
  color: var(--text-dim);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 6px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
.table-area td {
  padding: 4px 12px;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
.table-area tr:hover { background: rgba(88,166,255,0.05); }
.table-area tr.cluster-header { cursor: pointer; }
.table-area tr.cluster-header td:first-child::before {
  content: "\25B6 ";
  font-size: 9px;
  color: var(--text-dim);
}
.table-area tr.cluster-header.expanded td:first-child::before {
  content: "\25BC ";
}
.table-area tr.cluster-child { display: none; }
.table-area tr.cluster-child.visible { display: table-row; }
.table-area tr.cluster-child td { padding-left: 28px; color: var(--text-dim); }
.type-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 600;
  color: #fff;
}
.ip-link {
  color: var(--accent);
  cursor: pointer;
  text-decoration: none;
}
.ip-link:hover { text-decoration: underline; }

/* Legend */
.legend {
  position: absolute;
  bottom: 12px;
  left: 12px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px 12px;
  font-size: 11px;
  display: flex;
  gap: 12px;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
}
.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}

/* Pinned node indicator */
.node-pinned {
  stroke: var(--accent) !important;
  stroke-width: 3px !important;
}

/* Status indicator */
.status {
  font-size: 11px;
  color: var(--text-dim);
}
.status .dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--green);
  margin-right: 4px;
  animation: pulse 2s infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

/* Empty state */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--text-dim);
}
.empty-state .icon { font-size: 48px; margin-bottom: 12px; opacity: 0.3; }
.empty-state .msg { font-size: 14px; }

/* IP Dossier Modal */
.modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.7);
  z-index: 100;
  justify-content: center;
  align-items: center;
}
.modal-overlay.open { display: flex; }
.modal {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  width: 600px;
  max-width: 90vw;
  max-height: 80vh;
  overflow-y: auto;
  padding: 24px;
}
.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.modal-header h2 {
  font-size: 18px;
  color: var(--accent);
}
.modal-close {
  background: none;
  border: none;
  color: var(--text-dim);
  font-size: 20px;
  cursor: pointer;
}
.modal-close:hover { color: var(--text); }
.dossier-section {
  margin-bottom: 14px;
}
.dossier-section h3 {
  font-size: 12px;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 6px;
}
.dossier-badges { display: flex; gap: 6px; flex-wrap: wrap; }
.dossier-kv {
  display: grid;
  grid-template-columns: 120px 1fr;
  gap: 4px 12px;
  font-size: 12px;
}
.dossier-kv .k { color: var(--text-dim); }
.dossier-kv .v { color: var(--text); }
.dossier-timeline {
  font-size: 12px;
  width: 100%;
  border-collapse: collapse;
}
.dossier-timeline th {
  text-align: left;
  color: var(--text-dim);
  font-size: 11px;
  padding: 4px 8px;
  border-bottom: 1px solid var(--border);
}
.dossier-timeline td {
  padding: 3px 8px;
  border-bottom: 1px solid rgba(48,54,61,0.5);
}
</style>
</head>
<body>

<div class="header">
  <h1>IDS-RS — Network Dashboard</h1>
  <div class="search-box">
    <input type="text" id="omnisearch" placeholder="Cauta IP... (Enter)" autocomplete="off">
    <button id="btn-search" title="Filtreaza graf si alerte dupa IP">&#128270;</button>
    <span class="search-active-tag" id="search-tag">
      <span id="search-tag-ip"></span>
      <span class="close-tag" id="search-tag-close">&times;</span>
    </span>
  </div>
  <div class="stats">
    <div class="stat">
      <div class="stat-val accent" id="stat-alerts">0</div>
      <div class="stat-label">Alerte</div>
    </div>
    <div class="stat">
      <div class="stat-val red" id="stat-attackers">0</div>
      <div class="stat-label">Atacatori</div>
    </div>
    <div class="stat">
      <div class="stat-val cyan" id="stat-targets">0</div>
      <div class="stat-label">Tinte</div>
    </div>
    <div class="stat">
      <span class="status"><span class="dot"></span>Live — <span id="last-update">-</span></span>
    </div>
  </div>
</div>

<div class="container">
  <div class="graph-area" id="graph-area">
    <svg id="graph-svg"></svg>
    <div class="tooltip" id="tooltip"></div>
    <div style="position:absolute;top:12px;right:12px;display:flex;gap:6px;z-index:10;">
      <button id="btn-fit" style="background:var(--surface);
        border:1px solid var(--border);border-radius:6px;padding:6px 14px;color:var(--accent);
        cursor:pointer;font-family:inherit;font-size:11px;"
        title="Centreaza graful in viewport">&#8982; Fit</button>
    </div>
    <div class="legend">
      <div class="legend-item"><span class="legend-dot" style="background:#f85149"></span> Atacator</div>
      <div class="legend-item"><span class="legend-dot" style="background:#8b949e"></span> Tinta</div>
      <div class="legend-item"><span class="legend-dot" style="background:#f85149;width:20px;height:3px;border-radius:1px"></span> Fast</div>
      <div class="legend-item"><span class="legend-dot" style="background:#d29922;width:20px;height:3px;border-radius:1px"></span> Slow</div>
      <div class="legend-item"><span class="legend-dot" style="background:#bc8cff;width:20px;height:3px;border-radius:1px"></span> Accept</div>
      <div class="legend-item"><span class="legend-dot" style="background:#d18616;width:20px;height:3px;border-radius:1px"></span> Lateral</div>
      <div class="legend-item"><span class="legend-dot" style="background:#39d353;width:20px;height:3px;border-radius:1px"></span> Distributed</div>
      <div class="legend-item" style="margin-left:8px;color:var(--text-dim)">Drag=Pin | DblClick=Unpin</div>
    </div>
  </div>
  <div class="table-area">
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Tip</th>
          <th>Sursa</th>
          <th>Destinatie</th>
          <th>Detalii</th>
        </tr>
      </thead>
      <tbody id="alert-tbody"></tbody>
    </table>
  </div>
</div>

<!-- IP Dossier Modal -->
<div class="modal-overlay" id="dossier-modal">
  <div class="modal">
    <div class="modal-header">
      <h2 id="dossier-title">IP Dossier</h2>
      <button class="modal-close" id="dossier-close">&times;</button>
    </div>
    <div id="dossier-body"></div>
  </div>
</div>

<script src="/static/d3.min.js"></script>
<script>
const SCAN_COLORS = {
  "Fast Scan":        "#f85149",
  "Slow Scan":        "#d29922",
  "Accept Scan":      "#bc8cff",
  "Lateral Movement": "#d18616",
  "Distributed Scan": "#39d353",
};

function scanColor(type) {
  return SCAN_COLORS[type] || "#8b949e";
}

// ==== State ====
let simulation = null;
let svg, linkGroup, nodeGroup, labelGroup, zoom;
let currentNodes = [];
let currentLinks = [];
let width, height;
let activeSearchIp = null;  // IP filtrat in omnisearch (null = fara filtru)

// ==== D3 Graph ====

function initGraph() {
  if (typeof d3 === "undefined") return;

  const area = document.getElementById("graph-area");
  width = area.clientWidth;
  height = area.clientHeight;

  svg = d3.select("#graph-svg")
    .attr("viewBox", [0, 0, width, height]);

  linkGroup  = svg.append("g").attr("class", "links");
  nodeGroup  = svg.append("g").attr("class", "nodes");
  labelGroup = svg.append("g").attr("class", "labels");

  zoom = d3.zoom()
    .scaleExtent([0.2, 5])
    .on("zoom", (event) => {
      linkGroup.attr("transform", event.transform);
      nodeGroup.attr("transform", event.transform);
      labelGroup.attr("transform", event.transform);
    });
  svg.call(zoom);

  // Sarcina 1: Forte echilibrate — collision previne suprapunerea,
  // charge repinge moderat, alpha decay mare = oprire rapida.
  simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(80))
    .force("charge", d3.forceManyBody().strength(-150).distanceMax(400))
    .force("center", d3.forceCenter(width / 2, height / 2).strength(0.05))
    .force("collide", d3.forceCollide().radius(d => nodeRadius(d) + 8).strength(0.8))
    .force("x", d3.forceX(width / 2).strength(0.04))
    .force("y", d3.forceY(height / 2).strength(0.04))
    .alphaDecay(0.03)       // Mai rapid decat default (0.0228) — se opreste mai repede
    .alphaMin(0.005)        // Pragul sub care simularea se opreste
    .velocityDecay(0.4)     // Frictiune mai mare — nodurile se opresc mai repede
    .on("tick", ticked);

  window.zoomToFit = function() {
    if (currentNodes.length === 0) return;
    const pad = 60;
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    currentNodes.forEach(n => {
      const r = nodeRadius(n);
      if (n.x - r < x0) x0 = n.x - r;
      if (n.y - r < y0) y0 = n.y - r;
      if (n.x + r > x1) x1 = n.x + r;
      if (n.y + r > y1) y1 = n.y + r;
    });
    const bw = x1 - x0, bh = y1 - y0;
    if (bw <= 0 || bh <= 0) return;
    const scale = Math.min((width - 2*pad) / bw, (height - 2*pad) / bh, 2.5);
    const tx = (width - bw * scale) / 2 - x0 * scale;
    const ty = (height - bh * scale) / 2 - y0 * scale;
    svg.transition().duration(500).call(
      zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale)
    );
  };
  document.getElementById("btn-fit").addEventListener("click", window.zoomToFit);
}

function nodeRadius(d) {
  return Math.max(6, Math.sqrt(d.alert_count || 1) * 5);
}

function nodeColor(d) {
  return d.role === "attacker" ? "#f85149" : "#8b949e";
}

function ticked() {
  linkGroup.selectAll("line")
    .attr("x1", d => d.source.x)
    .attr("y1", d => d.source.y)
    .attr("x2", d => d.target.x)
    .attr("y2", d => d.target.y);

  nodeGroup.selectAll("circle")
    .attr("cx", d => d.x)
    .attr("cy", d => d.y);

  labelGroup.selectAll("text")
    .attr("x", d => d.x)
    .attr("y", d => d.y - nodeRadius(d) - 5);
}

function updateGraph(data) {
  if (!simulation) return;

  // Preservam pozitiile + pinned state
  const oldMap = {};
  currentNodes.forEach(n => {
    oldMap[n.id] = { x: n.x, y: n.y, vx: n.vx, vy: n.vy, fx: n.fx, fy: n.fy };
  });

  const nodes = data.nodes.map(n => {
    const old = oldMap[n.id];
    if (old) return { ...n, ...old };
    return { ...n, x: width/2 + Math.random()*100-50, y: height/2 + Math.random()*100-50 };
  });

  const links = data.edges.map(e => ({
    source: e.source,
    target: e.target,
    scan_type: e.scan_type,
    count: e.count,
    ports: e.ports || [],
  }));

  currentNodes = nodes;
  currentLinks = links;

  // Forte adaptive
  const n = nodes.length;
  const chargeStr = n > 100 ? -80 : n > 50 ? -120 : -150;
  const linkDist = n > 100 ? 50 : n > 50 ? 65 : 80;
  simulation.force("charge").strength(chargeStr).distanceMax(400);
  simulation.force("link").distance(linkDist);

  // Links
  const link = linkGroup.selectAll("line").data(links, d => {
    const s = typeof d.source === 'object' ? d.source.id : d.source;
    const t = typeof d.target === 'object' ? d.target.id : d.target;
    return s + "-" + t + "-" + d.scan_type;
  });
  link.exit().remove();
  link.enter().append("line")
    .attr("stroke-width", d => Math.min(5, 1.5 + d.count * 0.5))
    .attr("stroke", d => scanColor(d.scan_type))
    .attr("stroke-opacity", 0.6)
    .style("pointer-events", "stroke")
    .style("cursor", "pointer")
    .on("mouseover", showEdgeTooltip)
    .on("mousemove", moveTooltip)
    .on("mouseout", hideTooltip)
    .merge(link);

  // Nodes — Sarcina 1: drag pins, dblclick unpins, click opens dossier
  const node = nodeGroup.selectAll("circle").data(nodes, d => d.id);
  node.exit().remove();
  const entered = node.enter().append("circle")
    .attr("r", nodeRadius)
    .attr("fill", nodeColor)
    .attr("stroke", "#0d1117")
    .attr("stroke-width", 2)
    .attr("cursor", "pointer")
    .call(drag(simulation))
    .on("mouseover", showTooltip)
    .on("mousemove", moveTooltip)
    .on("mouseout", hideTooltip)
    .on("click", (event, d) => { openDossier(d.id); })
    .on("dblclick", (event, d) => {
      // Sarcina 1: dublu-click elibereaza nodul (unpin)
      d.fx = null;
      d.fy = null;
      d3.select(event.currentTarget).classed("node-pinned", false);
      simulation.alpha(0.1).restart();
    })
    .on("contextmenu", (event, d) => {
      // Click-dreapta: unpin (alternativa la dblclick)
      event.preventDefault();
      d.fx = null;
      d.fy = null;
      d3.select(event.currentTarget).classed("node-pinned", false);
      simulation.alpha(0.1).restart();
    });

  entered.merge(node)
    .attr("r", nodeRadius)
    .attr("fill", nodeColor)
    .classed("node-pinned", d => d.fx != null);

  // Labels
  const showAll = nodes.length < 40;
  const labelData = showAll ? nodes : nodes.filter(d => d.alert_count >= 3 || d.role === "attacker");
  const label = labelGroup.selectAll("text").data(labelData, d => d.id);
  label.exit().remove();
  label.enter().append("text")
    .attr("text-anchor", "middle")
    .attr("fill", "#8b949e")
    .attr("font-size", "10px")
    .attr("font-family", "monospace")
    .text(d => d.id)
    .merge(label);

  simulation.nodes(nodes);
  simulation.force("link").links(links);

  // Sarcina 1: alpha mic la update (nu re-agita graful puternic),
  // doar daca au aparut noduri noi.
  const hasNewNodes = nodes.some(n => !oldMap[n.id]);
  simulation.alpha(hasNewNodes ? 0.3 : 0.05).restart();
}

// Sarcina 1: Drag PINEAZA nodul (fx/fy raman setate dupa drag end).
// Dublu-click sau click-dreapta elibereaza nodul.
function drag(simulation) {
  return d3.drag()
    .on("start", (event, d) => {
      if (!event.active) simulation.alphaTarget(0.1).restart();
      d.fx = d.x;
      d.fy = d.y;
    })
    .on("drag", (event, d) => {
      d.fx = event.x;
      d.fy = event.y;
    })
    .on("end", (event, d) => {
      if (!event.active) simulation.alphaTarget(0);
      // NODE PINNING: NU resetam fx/fy — nodul ramane fixat!
      d3.select(event.sourceEvent.target).classed("node-pinned", true);
    });
}

// ==== Tooltip ====
const tooltip = document.getElementById("tooltip");

function showEdgeTooltip(event, d) {
  const srcId = typeof d.source === 'object' ? d.source.id : d.source;
  const tgtId = typeof d.target === 'object' ? d.target.id : d.target;
  let portsHtml = '';
  if (d.ports && d.ports.length > 0) {
    const shown = d.ports.slice(0, 20).join(', ');
    const extra = d.ports.length > 20 ? ` +${d.ports.length - 20}` : '';
    portsHtml = `<div class="detail" style="color:var(--accent)">${d.ports.length} porturi: ${shown}${extra}</div>`;
  }
  tooltip.innerHTML = `
    <div class="ip">${srcId} &rarr; ${tgtId}</div>
    <div class="role">${d.scan_type}</div>
    <div class="detail">Alerte: ${d.count}</div>
    ${portsHtml}
  `;
  tooltip.style.opacity = 1;
}

function showTooltip(event, d) {
  const badges = d.scan_types.map(t =>
    `<span class="scan-badge" style="background:${scanColor(t)}">${t}</span>`
  ).join(" ");
  tooltip.innerHTML = `
    <div class="ip">${d.id}</div>
    <div class="role">${d.role === "attacker" ? "ATACATOR" : "TINTA"}</div>
    <div class="detail">Alerte: ${d.alert_count}</div>
    <div class="detail">${badges}</div>
    <div class="detail" style="color:#8b949e;font-size:11px">Ultima: ${formatTime(d.last_seen)}</div>
    <div class="detail" style="color:#8b949e;font-size:10px">Click = Dossier | DblClick = Unpin</div>
  `;
  tooltip.style.opacity = 1;
}

function moveTooltip(event) {
  tooltip.style.left = (event.pageX + 14) + "px";
  tooltip.style.top  = (event.pageY - 14) + "px";
}

function hideTooltip() {
  tooltip.style.opacity = 0;
}

// ==== IP Dossier Modal (Sarcina 2) ====

async function openDossier(ip) {
  const modal = document.getElementById("dossier-modal");
  const title = document.getElementById("dossier-title");
  const body  = document.getElementById("dossier-body");
  title.textContent = "IP Dossier: " + ip;
  body.innerHTML = '<div style="color:var(--text-dim)">Se incarca...</div>';
  modal.classList.add("open");

  try {
    const res = await fetch("/api/ip/" + encodeURIComponent(ip));
    const d = await res.json();
    if (d.error) { body.innerHTML = `<div style="color:var(--red)">${d.error}</div>`; return; }

    const rolesBadges = d.roles.map(r =>
      `<span class="type-badge" style="background:${r === 'attacker' ? 'var(--red)' : 'var(--text-dim)'}">${r === 'attacker' ? 'ATACATOR' : 'TINTA'}</span>`
    ).join(' ');

    const scanBadges = d.scan_types.map(t =>
      `<span class="type-badge" style="background:${scanColor(t)}">${t}</span>`
    ).join(' ');

    const portsStr = d.ports_accessed.length > 0
      ? d.ports_accessed.slice(0, 30).join(', ') + (d.ports_accessed.length > 30 ? ` +${d.ports_accessed.length - 30}` : '')
      : 'N/A';

    const peersHtml = d.connected_ips.slice(0, 20).map(p =>
      `<span class="ip-link" onclick="openDossier('${p}')">${p}</span>`
    ).join(', ') + (d.connected_ips.length > 20 ? ` +${d.connected_ips.length - 20}` : '');

    const timelineRows = d.timeline.slice(0, 50).map(e => `
      <tr>
        <td style="color:var(--text-dim)">${formatTime(e.timestamp)}</td>
        <td><span class="type-badge" style="background:${scanColor(e.scan_type)};font-size:10px;padding:1px 6px">${e.scan_type}</span></td>
        <td>${e.role === 'attacker' ? 'ATK' : 'TGT'}</td>
        <td><span class="ip-link" onclick="openDossier('${e.peer_ip}')">${e.peer_ip}</span></td>
        <td style="color:var(--text-dim)">${e.ports.slice(0,10).join(', ')}</td>
      </tr>
    `).join('');

    body.innerHTML = `
      <div class="dossier-section">
        <div class="dossier-kv">
          <span class="k">IP</span><span class="v" style="color:var(--accent);font-weight:700">${d.ip}</span>
          <span class="k">Rol</span><span class="v">${rolesBadges}</span>
          <span class="k">Total alerte</span><span class="v">${d.total_alerts} (${d.as_attacker} atk / ${d.as_target} tgt)</span>
          <span class="k">Tipuri scan</span><span class="v">${scanBadges}</span>
          <span class="k">Porturi accesate</span><span class="v">${portsStr}</span>
          <span class="k">IP-uri conectate</span><span class="v">${peersHtml || 'N/A'}</span>
        </div>
      </div>
      <div class="dossier-section">
        <h3>Timeline alerte (${d.timeline.length})</h3>
        <table class="dossier-timeline">
          <thead><tr><th>Ora</th><th>Tip</th><th>Rol</th><th>Peer</th><th>Porturi</th></tr></thead>
          <tbody>${timelineRows || '<tr><td colspan="5" style="color:var(--text-dim)">Nicio alerta</td></tr>'}</tbody>
        </table>
      </div>
    `;
  } catch (e) {
    body.innerHTML = `<div style="color:var(--red)">Eroare: ${e.message}</div>`;
  }
}

document.getElementById("dossier-close").addEventListener("click", () => {
  document.getElementById("dossier-modal").classList.remove("open");
});
document.getElementById("dossier-modal").addEventListener("click", (e) => {
  if (e.target === e.currentTarget) e.currentTarget.classList.remove("open");
});

// ==== Alert Table cu Clustering (Sarcina 2) ====

function updateTable(alerts) {
  const tbody = document.getElementById("alert-tbody");

  // Clustering: grupam alertele consecutive cu acelasi (scan_type + source_ip).
  const clusters = [];
  let currentCluster = null;
  for (const a of alerts.slice(0, 200)) {
    const key = a.scan_type + "|" + a.source_ip;
    if (currentCluster && currentCluster.key === key) {
      currentCluster.items.push(a);
    } else {
      currentCluster = { key, items: [a] };
      clusters.push(currentCluster);
    }
  }

  let html = '';
  for (const cluster of clusters) {
    const a = cluster.items[0];
    const color = scanColor(a.scan_type);
    const dest = a.dest_ip || "N/A";
    const detail = alertDetail(a);

    if (cluster.items.length === 1) {
      // Rand simplu (fara cluster)
      html += `<tr>
        <td style="color:#8b949e">${formatTime(a.timestamp)}</td>
        <td><span class="type-badge" style="background:${color}">${a.scan_type}</span></td>
        <td><span class="ip-link" onclick="openDossier('${a.source_ip}')">${a.source_ip}</span></td>
        <td><span class="ip-link" onclick="openDossier('${dest}')">${dest}</span></td>
        <td style="color:#8b949e">${detail}</td>
      </tr>`;
    } else {
      // Cluster header (expandable)
      const cid = 'c' + Math.random().toString(36).slice(2, 8);
      html += `<tr class="cluster-header" onclick="toggleCluster('${cid}', this)">
        <td style="color:#8b949e">${formatTime(a.timestamp)}</td>
        <td><span class="type-badge" style="background:${color}">${a.scan_type}</span></td>
        <td><span class="ip-link" onclick="event.stopPropagation();openDossier('${a.source_ip}')">${a.source_ip}</span></td>
        <td colspan="2" style="color:var(--yellow)">&#215;${cluster.items.length} alerte grupate (click pentru expand)</td>
      </tr>`;
      for (const child of cluster.items) {
        const cd = child.dest_ip || "N/A";
        html += `<tr class="cluster-child ${cid}">
          <td style="color:#8b949e">${formatTime(child.timestamp)}</td>
          <td><span class="type-badge" style="background:${color};font-size:10px">${child.scan_type}</span></td>
          <td><span class="ip-link" onclick="openDossier('${child.source_ip}')">${child.source_ip}</span></td>
          <td><span class="ip-link" onclick="openDossier('${cd}')">${cd}</span></td>
          <td style="color:#8b949e">${alertDetail(child)}</td>
        </tr>`;
      }
    }
  }
  tbody.innerHTML = html;
}

function alertDetail(a) {
  if (a.scan_type === "Lateral Movement" && a.unique_dests && a.unique_dests.length > 0) {
    const ips = a.unique_dests.slice(0, 8).join(", ");
    const extra = a.unique_dests.length > 8 ? ` +${a.unique_dests.length - 8}` : "";
    return `\u2192 ${a.unique_dests.length} tinte: ${ips}${extra}`;
  }
  if (a.scan_type === "Distributed Scan" && a.unique_sources && a.unique_sources.length > 0) {
    const ips = a.unique_sources.slice(0, 8).join(", ");
    const extra = a.unique_sources.length > 8 ? ` +${a.unique_sources.length - 8}` : "";
    return `\u2190 ${a.unique_sources.length} atacatori: ${ips}${extra}`;
  }
  if (a.unique_ports && a.unique_ports.length > 0) {
    const ports = a.unique_ports.slice(0, 10).join(", ");
    const extra = a.unique_ports.length > 10 ? ` +${a.unique_ports.length - 10}` : "";
    return `${a.unique_ports.length} porturi: ${ports}${extra}`;
  }
  return "";
}

window.toggleCluster = function(cid, header) {
  const rows = document.querySelectorAll('.' + cid);
  const expanded = header.classList.toggle("expanded");
  rows.forEach(r => r.classList.toggle("visible", expanded));
};

function formatTime(ts) {
  if (!ts) return "-";
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("ro-RO", { hour12: false }) + "." +
           String(d.getMilliseconds()).padStart(3, "0");
  } catch { return ts; }
}

// ==== Omnisearch (Sarcina 2) ====

function doSearch() {
  const input = document.getElementById("omnisearch");
  const val = input.value.trim();
  if (!val) { clearSearch(); return; }
  activeSearchIp = val;
  input.value = '';
  document.getElementById("search-tag").style.display = "flex";
  document.getElementById("search-tag-ip").textContent = val;
  refresh();
}

function clearSearch() {
  activeSearchIp = null;
  document.getElementById("search-tag").style.display = "none";
  document.getElementById("omnisearch").value = '';
  refresh();
}

document.getElementById("btn-search").addEventListener("click", doSearch);
document.getElementById("omnisearch").addEventListener("keydown", e => {
  if (e.key === "Enter") doSearch();
  if (e.key === "Escape") clearSearch();
});
document.getElementById("search-tag-close").addEventListener("click", clearSearch);

// ==== Refresh Loop ====
async function refresh() {
  try {
    const ipParam = activeSearchIp ? "?ip=" + encodeURIComponent(activeSearchIp) : "";
    const [graphRes, alertsRes] = await Promise.all([
      fetch("/api/graph" + ipParam),
      fetch("/api/alerts" + ipParam),
    ]);
    const graph = await graphRes.json();
    const alerts = await alertsRes.json();

    document.getElementById("stat-alerts").textContent    = graph.stats.total_alerts;
    document.getElementById("stat-attackers").textContent  = graph.stats.unique_attackers;
    document.getElementById("stat-targets").textContent    = graph.stats.unique_targets;
    document.getElementById("last-update").textContent     = new Date().toLocaleTimeString("ro-RO", { hour12: false });

    updateGraph(graph);
    updateTable(alerts);

    const area = document.getElementById("graph-area");
    if (graph.nodes.length === 0 && !document.querySelector(".empty-state")) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.innerHTML = '<div class="icon">&#9737;</div><div class="msg">Nicio alerta detectata inca</div>';
      area.appendChild(empty);
    } else if (graph.nodes.length > 0) {
      const empty = area.querySelector(".empty-state");
      if (empty) empty.remove();
    }
  } catch (e) {
    console.error("Refresh error:", e);
  }
}

// ==== Init ====
document.addEventListener("DOMContentLoaded", () => {
  initGraph();
  refresh();
  setInterval(refresh, 5000);
});

window.addEventListener("resize", () => {
  if (!simulation) return;
  const area = document.getElementById("graph-area");
  width = area.clientWidth;
  height = area.clientHeight;
  d3.select("#graph-svg").attr("viewBox", [0, 0, width, height]);
  simulation.force("center", d3.forceCenter(width / 2, height / 2).strength(0.05));
  simulation.force("x", d3.forceX(width / 2).strength(0.04));
  simulation.force("y", d3.forceY(height / 2).strength(0.04));
  simulation.alpha(0.1).restart();
});
</script>
</body>
</html>"##;
