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

    let filter_ip: Option<IpAddr> = params.ip.as_deref().and_then(|s| s.parse::<IpAddr>().ok());

    let alerts: Vec<&Alert> = match filter_ip {
        Some(ip) => buffer
            .iter()
            .rev()
            .filter(|a| alert_matches_ip(a, ip))
            .collect(),
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
/* B3/B4 fix: cand containerul intra in fullscreen, ia tot ecranul iar panourile
   (dossier, workspace, toast, cmdk) raman vizibile pentru ca sunt descendente. */
.container:fullscreen,
.container:-webkit-full-screen {
  height: 100vh;
  background: var(--bg);
  padding: 0;
}
.container:fullscreen .side-panel,
.container:-webkit-full-screen .side-panel,
.container:fullscreen .workspace-panel,
.container:-webkit-full-screen .workspace-panel,
.container:fullscreen .workspace-toggle,
.container:-webkit-full-screen .workspace-toggle,
.container:fullscreen .toast-container,
.container:-webkit-full-screen .toast-container,
.container:fullscreen .cmdk-overlay,
.container:-webkit-full-screen .cmdk-overlay {
  position: absolute;
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
.tooltip .peer-list { color: var(--text); font-size: 11px; }
.tooltip .peer-list .peer { color: var(--accent); }
.tooltip .mini-spark { margin-top: 4px; }
.tooltip .mini-spark-label { color: var(--text-dim); font-size: 10px; margin-bottom: 2px; }
.tooltip .subnet { color: var(--text-dim); font-size: 11px; font-style: italic; }

/* Alert Table */
.table-area {
  height: 280px;
  background: var(--surface);
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
}
.table-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 6px 14px;
  border-bottom: 1px solid var(--border);
  background: var(--bg);
}
.table-toolbar .table-title {
  color: var(--text-dim);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.table-toolbar .table-title b { color: var(--accent); font-weight: 600; margin-left: 4px; }
.density-toggle {
  display: inline-flex;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
}
.density-toggle button {
  background: transparent;
  border: none;
  border-right: 1px solid var(--border);
  color: var(--text-dim);
  padding: 4px 10px;
  cursor: pointer;
  font-family: inherit;
  font-size: 11px;
  transition: background .12s, color .12s;
}
.density-toggle button:last-child { border-right: none; }
.density-toggle button:hover { color: var(--text); }
.density-toggle button.active {
  background: var(--accent);
  color: var(--bg);
  font-weight: 600;
}
.table-scroll {
  flex: 1;
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
.table-area.density-comfortable td { padding: 8px 14px; font-size: 13px; }
.table-area.density-comfortable th { padding: 8px 14px; }
.table-area.density-compact   td { padding: 4px 12px; font-size: 12px; }
.table-area.density-dense     td { padding: 1px 10px; font-size: 11px; line-height: 1.4; }
.table-area.density-dense     th { padding: 4px 10px; font-size: 10px; }

/* MITRE ATT&CK tags (Tier 2 #9) */
.mitre-tag {
  display: inline-block;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-dim);
  padding: 1px 6px;
  margin-left: 4px;
  border-radius: 3px;
  font-size: 10px;
  font-family: inherit;
  font-weight: 500;
  cursor: pointer;
  transition: color .1s, border-color .1s, background .1s;
  vertical-align: middle;
  white-space: nowrap;
}
.mitre-tag:hover {
  color: var(--accent);
  border-color: var(--accent);
  background: rgba(88, 166, 255, 0.08);
}
.mitre-tag.small { font-size: 9px; padding: 0 4px; margin-left: 2px; }

/* Triage (Tier 2 #6) */
.table-area tr.alert-row { transition: opacity .15s; }
.table-area tr.alert-row[data-status="ack"] {
  box-shadow: inset 3px 0 0 0 var(--green);
}
.table-area tr.alert-row[data-status="escalated"] {
  box-shadow: inset 3px 0 0 0 var(--red);
  background: rgba(248, 81, 73, 0.04);
}
.table-area tr.alert-row[data-status="dismissed"] {
  opacity: 0.4;
}
.table-area tr.alert-row.hover-key {
  outline: 1px dashed var(--accent);
  outline-offset: -1px;
}
.triage {
  display: inline-flex;
  gap: 3px;
  align-items: center;
}
.triage-btn {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-dim);
  width: 22px;
  height: 20px;
  padding: 0;
  border-radius: 3px;
  cursor: pointer;
  font-family: inherit;
  font-size: 11px;
  line-height: 1;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transition: border-color .1s, color .1s, background .1s;
}
.triage-btn:hover { color: var(--text); border-color: var(--accent); }
.triage-btn[data-action="ack"].active       { background: var(--green);  color: #0d1117; border-color: var(--green); }
.triage-btn[data-action="dismiss"].active   { background: var(--text-dim); color: var(--bg); border-color: var(--text-dim); }
.triage-btn[data-action="escalate"].active  { background: var(--red);    color: #fff; border-color: var(--red); }
.cluster-badge {
  display: inline-flex;
  gap: 4px;
  align-items: center;
  font-size: 10px;
  color: var(--text-dim);
}
.cluster-badge .dot-sm {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
}
.cluster-badge .dot-sm.new  { background: var(--accent); }
.cluster-badge .dot-sm.ack  { background: var(--green); }
.cluster-badge .dot-sm.esc  { background: var(--red); }
.cluster-badge .dot-sm.dis  { background: var(--text-dim); }
.triage-summary {
  display: inline-flex;
  gap: 10px;
  font-size: 10px;
  color: var(--text-dim);
  margin-left: 10px;
  padding-left: 10px;
  border-left: 1px solid var(--border);
}
.triage-summary span b { color: var(--accent); font-weight: 600; }
.triage-summary .s-ack b  { color: var(--green); }
.triage-summary .s-esc b  { color: var(--red); }
.triage-summary .s-dis b  { color: var(--text-dim); }
.hide-dismissed-toggle {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
  color: var(--text-dim);
  cursor: pointer;
  margin-right: 10px;
  user-select: none;
}
.hide-dismissed-toggle input { accent-color: var(--accent); cursor: pointer; }
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
  stroke-opacity: 1 !important;
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

/* Graph Toolbar */
.graph-toolbar {
  position: absolute;
  top: 12px;
  right: 12px;
  display: flex;
  gap: 6px;
  z-index: 10;
}
.graph-toolbar button {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 6px 12px;
  color: var(--accent);
  cursor: pointer;
  font-family: inherit;
  font-size: 11px;
  transition: border-color 0.15s, background 0.15s;
}
.graph-toolbar button:hover { border-color: var(--accent); }
.graph-toolbar button.active {
  background: var(--accent);
  color: var(--bg);
  border-color: var(--accent);
}

/* Scan Type Filter Bar */
.filter-bar {
  display: flex;
  gap: 6px;
  padding: 6px 24px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  align-items: center;
}

/* Heatmap 24h (Tier 1 #5) */
.heatmap-24 {
  display: inline-flex;
  gap: 2px;
  align-items: center;
  margin-left: auto;
  padding-left: 12px;
}
.heatmap-24-label {
  font-size: 10px;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-right: 6px;
}
.heatmap-cell {
  width: 10px;
  height: 18px;
  border-radius: 2px;
  position: relative;
  background: rgba(139, 148, 158, 0.18);
  transition: transform .1s, outline-color .1s;
  outline: 1px solid transparent;
}
.heatmap-cell:hover {
  transform: scaleY(1.15);
  outline-color: var(--accent);
  z-index: 20;
}
.heatmap-cell.sev-critical { background: var(--red); }
.heatmap-cell.sev-high     { background: var(--orange); }
.heatmap-cell.sev-medium   { background: var(--yellow); }
.heatmap-cell.sev-low      { background: var(--green); opacity: 0.65; }
.heatmap-cell.sev-none     { background: rgba(139, 148, 158, 0.18); }
.heatmap-tooltip {
  position: absolute;
  bottom: calc(100% + 6px);
  left: 50%;
  transform: translateX(-50%);
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 4px 8px;
  font-size: 10px;
  color: var(--text);
  white-space: nowrap;
  pointer-events: none;
  opacity: 0;
  transition: opacity .1s;
  z-index: 30;
}
.heatmap-cell:hover .heatmap-tooltip { opacity: 1; }
.heatmap-tooltip b { color: var(--accent); }
.filter-label {
  font-size: 11px;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-right: 4px;
}
.filter-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 10px;
  border-radius: 4px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text);
  font-family: inherit;
  font-size: 11px;
  cursor: pointer;
  transition: opacity 0.15s, border-color 0.15s;
}
.filter-btn .fdot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
}
.filter-btn.off { opacity: 0.3; }
.filter-btn:hover { border-color: var(--accent); }

/* Negative filters (Tier 2 #8) */
.filter-btn.neg {
  opacity: 1;
  border-color: var(--red);
  color: var(--red);
  text-decoration: line-through;
  background: rgba(248, 81, 73, 0.06);
}
.filter-btn.neg .fdot { filter: saturate(0.3); }
.filter-btn.neg::before {
  content: "\2298";
  margin-right: 4px;
  color: var(--red);
  font-weight: 700;
  text-decoration: none;
  display: inline-block;
}
.sev-label.neg {
  background: transparent !important;
  border: 1px dashed var(--red);
  color: var(--red) !important;
  text-decoration: line-through;
  opacity: 1;
}
.sev-label.neg::before {
  content: "\2298 ";
  margin-right: 2px;
}

/* Glow pulse for recent alerts */
@keyframes glow-pulse {
  0%, 100% { filter: drop-shadow(0 0 3px var(--glow-color)) drop-shadow(0 0 6px var(--glow-color)); }
  50% { filter: drop-shadow(0 0 8px var(--glow-color)) drop-shadow(0 0 16px var(--glow-color)); }
}
.node-glow { animation: glow-pulse 2s ease-in-out infinite; }

/* Hover neighborhood highlighting */
.links.dimmed line { stroke-opacity: 0.04 !important; }
.nodes.dimmed circle { opacity: 0.08 !important; }
.labels.dimmed text { opacity: 0.05 !important; }
.link-hl { stroke-opacity: 0.9 !important; }
.node-hl { opacity: 1 !important; }
.label-hl { opacity: 1 !important; }

/* Bug B2 fix: pin SVG text weight, prevent inheritance drift on drag/hover */
#graph-svg text {
  font-weight: 400;
  text-rendering: geometricPrecision;
  -webkit-font-smoothing: antialiased;
  paint-order: stroke fill;
}
#graph-svg g.hull-labels text { font-weight: 600; }

/* Animated edge flow */
@keyframes edge-flow {
  to { stroke-dashoffset: -12; }
}
.edge-flow { stroke-dasharray: 6 3; animation: edge-flow 0.8s linear infinite; }

/* Side Panel (replaces modal) */
.side-panel {
  position: fixed;
  top: 0;
  right: -420px;
  width: 420px;
  height: 100vh;
  background: var(--surface);
  border-left: 1px solid var(--border);
  z-index: 50;
  transition: right 0.3s ease;
  overflow-y: auto;
  padding: 20px;
  box-shadow: -4px 0 20px rgba(0,0,0,0.4);
}
.side-panel.open { right: 0; }
.side-panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.side-panel-header h2 { font-size: 16px; color: var(--accent); }
.side-panel-close {
  background: none;
  border: none;
  color: var(--text-dim);
  font-size: 18px;
  cursor: pointer;
}
.side-panel-close:hover { color: var(--text); }

/* Investigation Workspace (Tier 3 #11) */
.workspace-toggle {
  position: fixed;
  right: 16px;
  bottom: 16px;
  z-index: 45;
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 14px;
  border-radius: 20px;
  font-size: 12px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.4);
}
.workspace-toggle:hover { border-color: var(--accent); color: var(--accent); }
.workspace-toggle .ws-count {
  background: var(--accent);
  color: #0d1117;
  border-radius: 10px;
  padding: 1px 6px;
  font-size: 10px;
  font-weight: 700;
  min-width: 18px;
  text-align: center;
}
.workspace-panel {
  position: fixed;
  left: -380px;
  top: 0;
  width: 380px;
  height: 100vh;
  background: var(--surface);
  border-right: 1px solid var(--border);
  z-index: 48;
  transition: left 0.3s ease;
  overflow-y: auto;
  padding: 18px;
  box-shadow: 4px 0 20px rgba(0,0,0,0.4);
}
.workspace-panel.open { left: 0; }
.workspace-empty { color: var(--text-dim); font-size: 12px; font-style: italic; padding: 20px 0; text-align: center; }
.ws-item {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px;
  margin-bottom: 10px;
  background: var(--surface-alt, rgba(255,255,255,0.02));
}
.ws-item-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
}
.ws-item-ip {
  font-weight: 700;
  color: var(--accent);
  font-size: 13px;
  cursor: pointer;
}
.ws-item-ip:hover { text-decoration: underline; }
.ws-item-meta { color: var(--text-dim); font-size: 10px; }
.ws-item-actions { display: flex; gap: 6px; }
.ws-btn {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-dim);
  font-size: 10px;
  padding: 2px 6px;
  border-radius: 3px;
  cursor: pointer;
}
.ws-btn:hover { color: var(--red); border-color: var(--red); }
.ws-note {
  width: 100%;
  min-height: 50px;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 4px;
  padding: 6px 8px;
  font-size: 11px;
  font-family: inherit;
  resize: vertical;
}
.ws-note:focus { outline: none; border-color: var(--accent); }
.ws-tags {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin-top: 6px;
}
.ws-tag {
  font-size: 9px;
  padding: 1px 5px;
  border-radius: 3px;
  background: rgba(88, 166, 255, 0.15);
  color: var(--accent);
  border: 1px solid rgba(88, 166, 255, 0.3);
}
.pin-btn {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-dim);
  padding: 3px 8px;
  border-radius: 3px;
  font-size: 11px;
  cursor: pointer;
  margin-left: 8px;
}
.pin-btn:hover { color: var(--accent); border-color: var(--accent); }
.pin-btn.pinned { color: var(--yellow); border-color: var(--yellow); }

/* Replay Mode (Tier 3 #12) */
.replay-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 14px;
  background: var(--surface);
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
  font-size: 11px;
  color: var(--text-dim);
}
.replay-bar.active { background: linear-gradient(90deg, rgba(88,166,255,0.08), transparent); }
.replay-bar button {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text);
  padding: 3px 8px;
  border-radius: 3px;
  cursor: pointer;
  font-size: 11px;
}
.replay-bar button:hover { border-color: var(--accent); color: var(--accent); }
.replay-bar button.primary { background: var(--accent); color: #0d1117; border-color: var(--accent); font-weight: 600; }
.replay-bar button.primary:hover { color: #0d1117; }
.replay-bar input[type=range] {
  flex: 1;
  min-width: 180px;
  accent-color: var(--accent);
}
.replay-bar select {
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 2px 6px;
  font-size: 11px;
}
.replay-time { color: var(--accent); font-weight: 600; font-family: monospace; }
.replay-range { color: var(--text-dim); font-family: monospace; font-size: 10px; }
.replay-hint { color: var(--text-dim); font-style: italic; }

/* Aerial Subnet Grouping (Tier 3 #13) */
.subnet-hull {
  fill-opacity: 0.08;
  stroke-opacity: 0.55;
  stroke-width: 1.5;
  stroke-dasharray: 4 3;
  pointer-events: none;
  transition: opacity 0.25s ease;
}
.subnet-hull-label {
  font-size: 10px;
  fill: var(--text-dim);
  font-weight: 600;
  pointer-events: none;
  text-anchor: middle;
  letter-spacing: 0.4px;
}
.graph-toolbar button.aerial-active {
  color: var(--accent);
  border-color: var(--accent);
  background: rgba(88,166,255,0.12);
}

/* Severity group labels in filter bar */
.sev-group {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.sev-label {
  font-size: 10px;
  font-weight: 600;
  padding: 2px 6px;
  border-radius: 3px;
  cursor: pointer;
  border: 1px solid transparent;
  transition: opacity 0.15s;
  color: #fff;
}
.sev-label:hover { opacity: 0.8; }
.sev-label.off { opacity: 0.3; }
.filter-sep {
  width: 1px;
  height: 20px;
  background: var(--border);
  margin: 0 4px;
}

/* Multi-select */
.node-selected {
  stroke: var(--yellow) !important;
  stroke-width: 3px !important;
  stroke-opacity: 1 !important;
}

/* Stats trend */
.stat-trend {
  font-size: 11px;
  margin-left: 2px;
  font-weight: 400;
}
.stat-trend.up { color: var(--red); }
.stat-trend.down { color: var(--green); }
@keyframes countUp {
  from { opacity: 0.5; transform: translateY(-4px); }
  to { opacity: 1; transform: translateY(0); }
}
.stat-val.changed { animation: countUp 0.3s ease-out; }

/* Light theme */
:root.light {
  --bg: #ffffff;
  --surface: #f6f8fa;
  --border: #d0d7de;
  --text: #1f2328;
  --text-dim: #656d76;
  --accent: #0969da;
  --red: #cf222e;
  --yellow: #9a6700;
  --magenta: #8250df;
  --orange: #bc4c00;
  --cyan: #1a7f37;
  --green: #1a7f37;
}

/* Fullscreen graph */
.graph-area:fullscreen, .graph-area:-webkit-full-screen {
  background: var(--bg);
  height: 100vh;
}

/* Sound toggle active */
.btn-sound-on { color: var(--green) !important; border-color: var(--green) !important; }

/* Toasts Critical (Tier 1 #3) */
.toast-container {
  position: fixed;
  bottom: 16px;
  right: 16px;
  z-index: 900;
  display: flex;
  flex-direction: column;
  gap: 10px;
  pointer-events: none;
  max-width: 380px;
}
.toast {
  background: var(--surface);
  border: 1px solid var(--red);
  border-left: 4px solid var(--red);
  border-radius: 6px;
  padding: 10px 14px;
  box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
  color: var(--text);
  pointer-events: auto;
  cursor: pointer;
  animation: toast-in .22s ease-out;
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12px;
  min-width: 300px;
  position: relative;
}
.toast::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: 6px;
  box-shadow: 0 0 0 2px rgba(248, 81, 73, 0);
  pointer-events: none;
  animation: toast-pulse 1.4s ease-out 1;
}
@keyframes toast-pulse {
  0%   { box-shadow: 0 0 0 0 rgba(248, 81, 73, 0.55); }
  100% { box-shadow: 0 0 0 12px rgba(248, 81, 73, 0); }
}
.toast.removing { animation: toast-out .22s ease-out forwards; }
@keyframes toast-in {
  from { transform: translateX(110%); opacity: 0; }
  to   { transform: translateX(0);    opacity: 1; }
}
@keyframes toast-out {
  to { transform: translateX(110%); opacity: 0; }
}
.toast-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.toast-title {
  color: var(--red);
  font-weight: 600;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.toast-time { color: var(--text-dim); font-size: 10px; font-family: inherit; }
.toast-body { color: var(--text); }
.toast-body b { color: var(--accent); font-weight: 600; }
.toast-hint { color: var(--text-dim); font-size: 10px; margin-top: 2px; }

/* Sparkline 60 min (Tier 1 #2) */
.sparkline-wrap {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  min-width: 120px;
}
.sparkline-svg {
  width: 120px;
  height: 34px;
  display: block;
  overflow: visible;
}
.sparkline-svg .spark-path {
  fill: none;
  stroke: var(--accent);
  stroke-width: 1.5;
  stroke-linejoin: round;
}
.sparkline-svg .spark-area { fill: var(--accent); opacity: 0.18; }
.sparkline-svg .spark-dot  { fill: var(--accent); }
.sparkline-caption {
  font-size: 10px;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  white-space: nowrap;
}
.sparkline-caption b { color: var(--accent); font-weight: 600; }

/* Command Palette (Cmd/Ctrl+K) */
.cmdk-trigger {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-dim);
  padding: 4px 8px;
  font-family: inherit;
  font-size: 11px;
  cursor: pointer;
  transition: border-color .15s, color .15s;
}
.cmdk-trigger:hover { border-color: var(--accent); color: var(--text); }
.cmdk-trigger .cmdk-kbd {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 1px 5px;
  font-size: 10px;
  color: var(--accent);
}
.cmdk-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.55);
  backdrop-filter: blur(3px);
  -webkit-backdrop-filter: blur(3px);
  z-index: 1000;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: 12vh;
  animation: cmdk-fade .12s ease-out;
}
.cmdk-overlay[hidden] { display: none; }
@keyframes cmdk-fade {
  from { opacity: 0; }
  to   { opacity: 1; }
}
.cmdk-panel {
  width: min(620px, 92vw);
  max-height: 70vh;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  box-shadow: 0 16px 48px rgba(0, 0, 0, 0.55), 0 2px 8px rgba(0, 0, 0, 0.3);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  animation: cmdk-slide .14s ease-out;
}
@keyframes cmdk-slide {
  from { transform: translateY(-8px); opacity: 0; }
  to   { transform: translateY(0); opacity: 1; }
}
.cmdk-input {
  background: transparent;
  border: none;
  border-bottom: 1px solid var(--border);
  color: var(--text);
  padding: 14px 18px;
  font-family: inherit;
  font-size: 14px;
  outline: none;
}
.cmdk-input::placeholder { color: var(--text-dim); }
.cmdk-list {
  overflow-y: auto;
  padding: 6px 0;
  flex: 1;
}
.cmdk-list::-webkit-scrollbar { width: 8px; }
.cmdk-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
.cmdk-cat {
  padding: 6px 18px 4px;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  color: var(--text-dim);
  font-weight: 600;
}
.cmdk-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 18px;
  cursor: pointer;
  border-left: 2px solid transparent;
  transition: background .1s;
}
.cmdk-item:hover { background: rgba(88, 166, 255, 0.06); }
.cmdk-item.active {
  background: rgba(88, 166, 255, 0.12);
  border-left-color: var(--accent);
}
.cmdk-item .cmdk-icon {
  width: 18px;
  text-align: center;
  color: var(--accent);
  font-size: 13px;
  flex-shrink: 0;
}
.cmdk-item .cmdk-label { flex: 1; color: var(--text); font-size: 13px; }
.cmdk-item .cmdk-sub { color: var(--text-dim); font-size: 11px; margin-left: 6px; }
.cmdk-item .cmdk-kbd {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 1px 6px;
  font-size: 10px;
  color: var(--text-dim);
  font-family: inherit;
}
.cmdk-item.active .cmdk-kbd { color: var(--accent); border-color: var(--accent); }
.cmdk-empty {
  padding: 28px 18px;
  text-align: center;
  color: var(--text-dim);
  font-size: 12px;
}
.cmdk-footer {
  display: flex;
  justify-content: flex-end;
  gap: 14px;
  padding: 8px 18px;
  border-top: 1px solid var(--border);
  background: var(--bg);
  color: var(--text-dim);
  font-size: 10px;
}
.cmdk-footer .cmdk-kbd {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 1px 5px;
  font-size: 10px;
  color: var(--accent);
  margin-right: 4px;
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
    <button class="cmdk-trigger" id="cmdk-trigger" title="Command palette (Ctrl+K)">
      <span>Commands</span><span class="cmdk-kbd">&#8984;K</span>
    </button>
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
    <div class="stat sparkline-wrap" title="Alerte/minut, ultimele 60 minute">
      <svg class="sparkline-svg" id="sparkline" viewBox="0 0 120 34" preserveAspectRatio="none">
        <path class="spark-area" id="spark-area"></path>
        <path class="spark-path" id="spark-path"></path>
        <circle class="spark-dot" id="spark-dot" r="2.2" cx="0" cy="0"></circle>
      </svg>
      <div class="sparkline-caption">60 min &middot; peak <b id="spark-peak">0</b>/min</div>
    </div>
    <div class="stat">
      <span class="status"><span class="dot"></span>Live — <span id="last-update">-</span></span>
    </div>
  </div>
</div>

<div class="container" id="dashboard-root">
  <div class="filter-bar" id="filter-bar">
    <span class="filter-label">Filtre:</span>
    <span class="sev-group">
      <span class="sev-label" style="background:#f85149" data-sev="Critical" onclick="toggleSevFilter(this, event)">CRITICAL</span>
      <button class="filter-btn" data-scan="Lateral Movement" onclick="toggleScanFilter(this, event)"><span class="fdot" style="background:#d18616"></span> Lateral</button>
    </span>
    <span class="filter-sep"></span>
    <span class="sev-group">
      <span class="sev-label" style="background:#d18616" data-sev="High" onclick="toggleSevFilter(this, event)">HIGH</span>
      <button class="filter-btn" data-scan="Fast Scan" onclick="toggleScanFilter(this, event)"><span class="fdot" style="background:#f85149"></span> Fast</button>
      <button class="filter-btn" data-scan="Distributed Scan" onclick="toggleScanFilter(this, event)"><span class="fdot" style="background:#39d353"></span> Distributed</button>
    </span>
    <span class="filter-sep"></span>
    <span class="sev-group">
      <span class="sev-label" style="background:#d29922" data-sev="Medium" onclick="toggleSevFilter(this, event)">MEDIUM</span>
      <button class="filter-btn" data-scan="Slow Scan" onclick="toggleScanFilter(this, event)"><span class="fdot" style="background:#d29922"></span> Slow</button>
      <button class="filter-btn" data-scan="Accept Scan" onclick="toggleScanFilter(this, event)"><span class="fdot" style="background:#bc8cff"></span> Accept</button>
    </span>
    <div class="heatmap-24" id="heatmap-24" title="Severitate maxima / ora, ultimele 24h">
      <span class="heatmap-24-label">24h</span>
    </div>
  </div>
  <div class="graph-area" id="graph-area">
    <svg id="graph-svg"></svg>
    <div class="tooltip" id="tooltip"></div>
    <div class="graph-toolbar">
      <button id="btn-isolate" style="display:none" title="Izoleaza selectia">Isolate</button>
      <button id="btn-clear-sel" style="display:none" title="Sterge selectia">Clear Sel</button>
      <button id="btn-freeze" title="Freeze/Play simulare">&#10074;&#10074; Freeze</button>
      <button id="btn-pin-all" title="Fixeaza toate nodurile">Pin All</button>
      <button id="btn-unpin-all" title="Elibereaza toate nodurile">Unpin All</button>
      <button id="btn-aerial" title="Grupare aeriana pe subnet /24 (Shift+G)">&#9711; Aerial</button>
      <button id="btn-fit" title="Centreaza graful">&#8982; Fit</button>
      <button id="btn-fullscreen" title="Fullscreen (F11)">&#9974; Full</button>
      <button id="btn-export" title="Export graf ca PNG">&#128247; PNG</button>
      <button id="btn-theme" title="Dark/Light mode (T)">&#9788; Theme</button>
      <button id="btn-sound" title="Alert sound on/off">&#128264; Sound</button>
    </div>
    <div class="legend">
      <div class="legend-item"><span class="legend-dot" style="background:#f85149"></span> Atacator</div>
      <div class="legend-item"><span class="legend-dot" style="background:#8b949e"></span> Tinta</div>
      <div class="legend-item"><span class="legend-dot" style="background:#f85149;width:20px;height:3px;border-radius:1px"></span> Fast</div>
      <div class="legend-item"><span class="legend-dot" style="background:#d29922;width:20px;height:3px;border-radius:1px"></span> Slow</div>
      <div class="legend-item"><span class="legend-dot" style="background:#bc8cff;width:20px;height:3px;border-radius:1px"></span> Accept</div>
      <div class="legend-item"><span class="legend-dot" style="background:#d18616;width:20px;height:3px;border-radius:1px"></span> Lateral</div>
      <div class="legend-item"><span class="legend-dot" style="background:#39d353;width:20px;height:3px;border-radius:1px"></span> Distributed</div>
      <div class="legend-item" style="margin-left:8px;color:var(--text-dim)">Drag=Pin | DblClick=Unpin | F=Fit Space=Freeze T=Theme 1-5=Filters | Shift+Click filtru=Exclude | A/D/E=Triage | Shift+P=Workspace Shift+G=Aerial</div>
    </div>
  </div>
  <div class="replay-bar" id="replay-bar">
    <button id="replay-toggle" title="Activeaza/dezactiveaza replay mode">&#9654; Replay</button>
    <button id="replay-play" title="Play/Pause" disabled>&#10074;&#10074;</button>
    <button id="replay-rewind" title="Inapoi la inceput" disabled>&#124;&#9664;</button>
    <input type="range" id="replay-slider" min="0" max="100" value="100" disabled />
    <span class="replay-time" id="replay-time">--:--:--</span>
    <label class="replay-hint">Window:
      <select id="replay-window" disabled>
        <option value="1">1 min</option>
        <option value="5">5 min</option>
        <option value="10" selected>10 min</option>
        <option value="30">30 min</option>
        <option value="60">60 min</option>
      </select>
    </label>
    <label class="replay-hint">Speed:
      <select id="replay-speed" disabled>
        <option value="500">0.5&times;</option>
        <option value="250" selected>1&times;</option>
        <option value="100">2.5&times;</option>
        <option value="50">5&times;</option>
      </select>
    </label>
    <span class="replay-range" id="replay-range"></span>
  </div>
  <div class="table-area density-compact" id="table-area">
    <div class="table-toolbar">
      <span class="table-title">
        Alerte<b id="alert-count">0</b>
        <span class="triage-summary" id="triage-summary" hidden>
          <span class="s-new"><b id="ts-new">0</b> new</span>
          <span class="s-ack"><b id="ts-ack">0</b> ack</span>
          <span class="s-esc"><b id="ts-esc">0</b> esc</span>
          <span class="s-dis"><b id="ts-dis">0</b> dis</span>
        </span>
      </span>
      <div style="display:flex;align-items:center;gap:8px">
        <label class="hide-dismissed-toggle" title="Ascunde alertele marcate Dismiss">
          <input type="checkbox" id="hide-dismissed" checked>
          <span>Ascunde Dismissed</span>
        </label>
        <div class="density-toggle" role="group" aria-label="Densitate tabel">
          <button data-density="comfortable" title="Confortabil (10 vizibile)">Confortabil</button>
          <button data-density="compact" title="Compact (20 vizibile)">Compact</button>
          <button data-density="dense" title="Dens (40 vizibile)">Dens</button>
        </div>
      </div>
    </div>
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Tip</th>
            <th>Sursa</th>
            <th>Destinatie</th>
            <th>Detalii</th>
            <th title="Triage: A=Ack, D=Dismiss, E=Escalate">Status</th>
          </tr>
        </thead>
        <tbody id="alert-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- Panels mutate inside .container (B3/B4 fix: fullscreen pe #dashboard-root) -->
  <div class="toast-container" id="toast-container"></div>

  <div class="cmdk-overlay" id="cmdk-overlay" hidden>
    <div class="cmdk-panel" role="dialog" aria-label="Command palette">
      <input type="text" class="cmdk-input" id="cmdk-input"
             placeholder="Scrie o comanda sau un IP..."
             autocomplete="off" spellcheck="false">
      <div class="cmdk-list" id="cmdk-list"></div>
      <div class="cmdk-footer">
        <span><span class="cmdk-kbd">&#8593;&#8595;</span>Navigheaza</span>
        <span><span class="cmdk-kbd">Enter</span>Executa</span>
        <span><span class="cmdk-kbd">Esc</span>Inchide</span>
      </div>
    </div>
  </div>

  <div class="side-panel" id="dossier-panel">
    <div class="side-panel-header">
      <h2 id="dossier-title">IP Dossier</h2>
      <button class="side-panel-close" id="dossier-close">&times;</button>
    </div>
    <div id="dossier-body"></div>
  </div>

  <button class="workspace-toggle" id="workspace-toggle" title="Investigation workspace (pinned IPs + notes)">
    <span>&#128269;</span> Investigation
    <span class="ws-count" id="ws-count">0</span>
  </button>
  <div class="workspace-panel" id="workspace-panel">
    <div class="side-panel-header">
      <h2>&#128269; Investigation Workspace</h2>
      <button class="side-panel-close" id="workspace-close">&times;</button>
    </div>
    <div style="display:flex;gap:6px;margin-bottom:12px">
      <button class="ws-btn" id="ws-export" title="Export JSON">Export</button>
      <button class="ws-btn" id="ws-clear" title="Sterge tot workspace-ul">Clear all</button>
    </div>
    <div id="workspace-body"></div>
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
let svg, hullGroup, hullLabelGroup, linkGroup, nodeGroup, labelGroup, zoom;
let aerialEnabled = false;
let currentNodes = [];
let currentLinks = [];
let width, height;
let activeSearchIp = null;  // IP filtrat in omnisearch (null = fara filtru)
let isFrozen = false;
let rawGraphData = null;
let rawAlertData = null;
let activeScanTypes = new Set(Object.keys(SCAN_COLORS));
let excludedScanTypes = new Set();
let selectedNodes = new Set();
let isolatedMode = false;
let prevStats = null;
let soundEnabled = false;
let prevAlertCount = 0;
let audioCtx = null;

const SEVERITY_MAP = {
  "Lateral Movement": { level: "Critical", color: "#f85149", value: 8 },
  "Fast Scan":        { level: "High",     color: "#d18616", value: 7 },
  "Distributed Scan": { level: "High",     color: "#d18616", value: 7 },
  "Slow Scan":        { level: "Medium",   color: "#d29922", value: 6 },
  "Accept Scan":      { level: "Medium",   color: "#d29922", value: 5 },
};
const SEV_TO_TYPES = {
  Critical: ["Lateral Movement"],
  High: ["Fast Scan", "Distributed Scan"],
  Medium: ["Slow Scan", "Accept Scan"],
};

function maxSeverityColor(node) {
  let maxVal = 0, color = "#30363d";
  (node.scan_types || []).forEach(st => {
    const s = SEVERITY_MAP[st];
    if (s && s.value > maxVal) { maxVal = s.value; color = s.color; }
  });
  return color;
}

// ==== D3 Graph ====

function initGraph() {
  if (typeof d3 === "undefined") return;

  const area = document.getElementById("graph-area");
  width = area.clientWidth;
  height = area.clientHeight;

  svg = d3.select("#graph-svg")
    .attr("viewBox", [0, 0, width, height]);

  // Arrow markers per scan type
  const defs = svg.append("defs");
  Object.entries(SCAN_COLORS).forEach(([type, color]) => {
    defs.append("marker")
      .attr("id", "arrow-" + type.replace(/\s+/g, "-"))
      .attr("viewBox", "0 -4 8 8")
      .attr("refX", 12)
      .attr("refY", 0)
      .attr("markerWidth", 5)
      .attr("markerHeight", 5)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-4L8,0L0,4Z")
      .attr("fill", color);
  });

  hullGroup      = svg.append("g").attr("class", "hulls");
  hullLabelGroup = svg.append("g").attr("class", "hull-labels");
  linkGroup  = svg.append("g").attr("class", "links");
  nodeGroup  = svg.append("g").attr("class", "nodes");
  labelGroup = svg.append("g").attr("class", "labels");

  zoom = d3.zoom()
    .scaleExtent([0.2, 5])
    .on("zoom", (event) => {
      hullGroup.attr("transform", event.transform);
      hullLabelGroup.attr("transform", event.transform);
      linkGroup.attr("transform", event.transform);
      nodeGroup.attr("transform", event.transform);
      labelGroup.attr("transform", event.transform);
    });
  svg.call(zoom);

  simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(80))
    .force("charge", d3.forceManyBody().strength(-150).distanceMax(400))
    .force("center", d3.forceCenter(width / 2, height / 2).strength(0.05))
    .force("collide", d3.forceCollide().radius(d => nodeRadius(d) + 8).strength(0.8))
    .force("x", d3.forceX(width / 2).strength(0.04))
    .force("y", d3.forceY(height / 2).strength(0.04))
    .alphaDecay(0.04)
    .alphaMin(0.001)
    .velocityDecay(0.65)
    .on("tick", ticked);

  document.getElementById("btn-fit").addEventListener("click", zoomToFit);
  document.getElementById("btn-freeze").addEventListener("click", toggleFreeze);
  document.getElementById("btn-pin-all").addEventListener("click", pinAll);
  document.getElementById("btn-unpin-all").addEventListener("click", unpinAll);
  document.getElementById("btn-isolate").addEventListener("click", isolateSelection);
  document.getElementById("btn-clear-sel").addEventListener("click", clearSelection);
  const aerialBtn = document.getElementById("btn-aerial");
  if (aerialBtn) aerialBtn.addEventListener("click", toggleAerial);
}

function zoomToFit() {
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
}

function nodeRadius(d) {
  return Math.max(6, Math.sqrt(d.alert_count || 1) * 5);
}

function nodeColor(d) {
  return d.role === "attacker" ? "#f85149" : "#8b949e";
}

// ==== Aerial Subnet Grouping (Tier 3 #13) ====
function subnetKey(ip) {
  const parts = (ip || "").split(".");
  if (parts.length !== 4) return null;
  return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
}

function subnetColor(key) {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) >>> 0;
  const hue = h % 360;
  return "hsl(" + hue + ", 65%, 60%)";
}

function toggleAerial() {
  aerialEnabled = !aerialEnabled;
  const btn = document.getElementById("btn-aerial");
  if (btn) btn.classList.toggle("aerial-active", aerialEnabled);
  if (!aerialEnabled) {
    hullGroup.selectAll("path").remove();
    hullLabelGroup.selectAll("text").remove();
  } else if (simulation) {
    simulation.alpha(0.1).restart();
  }
}

function roundedHullPath(points, pad) {
  if (points.length < 3) return null;
  const hull = d3.polygonHull(points);
  if (!hull) return null;
  const cx = hull.reduce((s, p) => s + p[0], 0) / hull.length;
  const cy = hull.reduce((s, p) => s + p[1], 0) / hull.length;
  const padded = hull.map(([x, y]) => {
    const dx = x - cx, dy = y - cy;
    const len = Math.sqrt(dx*dx + dy*dy) || 1;
    return [x + (dx/len) * pad, y + (dy/len) * pad];
  });
  let d = "M" + padded[0][0].toFixed(1) + "," + padded[0][1].toFixed(1);
  for (let i = 1; i < padded.length; i++) {
    d += "L" + padded[i][0].toFixed(1) + "," + padded[i][1].toFixed(1);
  }
  return d + "Z";
}

function updateHulls() {
  if (!hullGroup) return;
  if (!aerialEnabled) {
    hullGroup.selectAll("path").remove();
    hullLabelGroup.selectAll("text").remove();
    return;
  }
  const groups = {};
  for (const n of currentNodes) {
    const k = subnetKey(n.id);
    if (!k) continue;
    if (!groups[k]) groups[k] = [];
    groups[k].push(n);
  }
  const entries = Object.entries(groups).filter(([_, ns]) => ns.length >= 2);

  const paths = hullGroup.selectAll("path.subnet-hull").data(entries, d => d[0]);
  paths.exit().remove();
  const pathsEnter = paths.enter().append("path").attr("class", "subnet-hull");
  pathsEnter.merge(paths)
    .attr("stroke", ([k]) => subnetColor(k))
    .attr("fill", ([k]) => subnetColor(k))
    .attr("d", ([, ns]) => {
      if (ns.length < 3) {
        const x = ns.reduce((s, n) => s + n.x, 0) / ns.length;
        const y = ns.reduce((s, n) => s + n.y, 0) / ns.length;
        const maxR = Math.max(...ns.map(n => nodeRadius(n))) + 28;
        const d0 = ns.length === 1 ? maxR : Math.max(maxR, Math.hypot(ns[0].x - ns[1].x, ns[0].y - ns[1].y) / 2 + 20);
        return "M " + (x - d0) + "," + y +
               " a " + d0 + "," + d0 + " 0 1,0 " + (2*d0) + ",0" +
               " a " + d0 + "," + d0 + " 0 1,0 " + (-2*d0) + ",0 Z";
      }
      return roundedHullPath(ns.map(n => [n.x, n.y]), 22);
    });

  const labels = hullLabelGroup.selectAll("text.subnet-hull-label").data(entries, d => d[0]);
  labels.exit().remove();
  const labelsEnter = labels.enter().append("text").attr("class", "subnet-hull-label");
  labelsEnter.merge(labels)
    .attr("fill", ([k]) => subnetColor(k))
    .attr("x", ([, ns]) => ns.reduce((s, n) => s + n.x, 0) / ns.length)
    .attr("y", ([, ns]) => {
      const ys = ns.map(n => n.y);
      return Math.min(...ys) - 18;
    })
    .text(([k, ns]) => k + "  \u00B7  " + ns.length);
}

function ticked() {
  linkGroup.selectAll("line").each(function(d) {
    const dx = d.target.x - d.source.x;
    const dy = d.target.y - d.source.y;
    const dist = Math.sqrt(dx*dx + dy*dy) || 1;
    const offset = nodeRadius(d.target) + 4;
    this.setAttribute("x1", d.source.x);
    this.setAttribute("y1", d.source.y);
    this.setAttribute("x2", d.target.x - (dx/dist) * offset);
    this.setAttribute("y2", d.target.y - (dy/dist) * offset);
  });

  nodeGroup.selectAll("circle")
    .attr("cx", d => d.x)
    .attr("cy", d => d.y);

  labelGroup.selectAll("text")
    .attr("x", d => d.x)
    .attr("y", d => d.y - nodeRadius(d) - 5);

  if (aerialEnabled) updateHulls();
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
  const linkEnter = link.enter().append("line")
    .attr("stroke-width", d => Math.min(5, 1.5 + d.count * 0.5))
    .attr("stroke", d => scanColor(d.scan_type))
    .attr("stroke-opacity", 0.6)
    .attr("marker-end", d => "url(#arrow-" + d.scan_type.replace(/\s+/g, "-") + ")")
    .classed("edge-flow", true)
    .style("pointer-events", "stroke")
    .style("cursor", "pointer")
    .on("mouseover", showEdgeTooltip)
    .on("mousemove", moveTooltip)
    .on("mouseout", hideTooltip);
  linkEnter.merge(link)
    .attr("stroke-width", d => Math.min(5, 1.5 + d.count * 0.5));

  const now = Date.now();
  const GLOW_MS = 30000;
  const node = nodeGroup.selectAll("circle").data(nodes, d => d.id);
  node.exit().remove();
  const entered = node.enter().append("circle")
    .attr("r", nodeRadius)
    .attr("fill", nodeColor)
    .attr("stroke", d => maxSeverityColor(d))
    .attr("stroke-width", 2.5)
    .attr("stroke-opacity", 0.7)
    .attr("cursor", "pointer")
    .call(drag(simulation))
    .on("mouseover", function(event, d) { showTooltip(event, d); highlightNeighborhood(d.id); })
    .on("mousemove", moveTooltip)
    .on("mouseout", function() { hideTooltip(); clearHighlight(); })
    .on("click", (event, d) => {
      if (event.shiftKey) { toggleNodeSelection(d.id); }
      else { openDossier(d.id); }
    })
    .on("dblclick", (event, d) => {
      d.fx = null;
      d.fy = null;
      d3.select(event.currentTarget).classed("node-pinned", false);
      if (!isFrozen) simulation.alpha(0.1).restart();
    })
    .on("contextmenu", (event, d) => {
      event.preventDefault();
      d.fx = null;
      d.fy = null;
      d3.select(event.currentTarget).classed("node-pinned", false);
      if (!isFrozen) simulation.alpha(0.1).restart();
    });

  entered.merge(node)
    .attr("r", nodeRadius)
    .attr("fill", nodeColor)
    .attr("stroke", d => maxSeverityColor(d))
    .classed("node-pinned", d => d.fx != null)
    .classed("node-selected", d => selectedNodes.has(d.id))
    .style("--glow-color", d => nodeColor(d))
    .classed("node-glow", d => {
      if (!d.last_seen) return false;
      return (now - new Date(d.last_seen).getTime()) < GLOW_MS;
    });

  // Labels (B2 fix: reaplic atributele pe merge ca sa nu ramana textul fara font-weight explicit)
  const showAll = nodes.length < 40;
  const labelData = showAll ? nodes : nodes.filter(d => d.alert_count >= 3 || d.role === "attacker");
  const label = labelGroup.selectAll("text").data(labelData, d => d.id);
  label.exit().remove();
  const labelEnter = label.enter().append("text")
    .attr("text-anchor", "middle")
    .attr("font-family", "monospace");
  labelEnter.merge(label)
    .attr("fill", "#8b949e")
    .attr("font-size", "10px")
    .attr("font-weight", 400)
    .text(d => d.id);

  simulation.nodes(nodes);
  simulation.force("link").links(links);

  const newNodeSet = new Set(nodes.map(n => n.id));
  const hasNewNodes = nodes.some(n => !(n.id in oldMap));
  const hasRemovedNodes = Object.keys(oldMap).some(id => !newNodeSet.has(id));
  if (!isFrozen && (hasNewNodes || hasRemovedNodes)) {
    simulation.alpha(0.3).restart();
  } else {
    ticked();
  }
}

function drag(sim) {
  return d3.drag()
    .on("start", (event, d) => {
      if (!event.active && !isFrozen) sim.alphaTarget(0.1).restart();
      d.fx = d.x;
      d.fy = d.y;
    })
    .on("drag", (event, d) => {
      d.fx = event.x;
      d.fy = event.y;
      if (isFrozen) ticked();
    })
    .on("end", (event, d) => {
      if (!event.active) sim.alphaTarget(0);
      d3.select(event.sourceEvent.target).classed("node-pinned", true);
    });
}

// ==== Graph Controls ====

function toggleFreeze() {
  const btn = document.getElementById("btn-freeze");
  isFrozen = !isFrozen;
  if (isFrozen) {
    simulation.stop();
    btn.classList.add("active");
    btn.innerHTML = "&#9654; Play";
  } else {
    simulation.alpha(0.15).restart();
    btn.classList.remove("active");
    btn.innerHTML = "&#10074;&#10074; Freeze";
  }
}

function pinAll() {
  currentNodes.forEach(n => { n.fx = n.x; n.fy = n.y; });
  nodeGroup.selectAll("circle").classed("node-pinned", true);
}

function unpinAll() {
  currentNodes.forEach(n => { n.fx = null; n.fy = null; });
  nodeGroup.selectAll("circle").classed("node-pinned", false);
  if (!isFrozen) simulation.alpha(0.15).restart();
}

function highlightNeighborhood(nodeId) {
  const neighbors = new Set([nodeId]);
  currentLinks.forEach(l => {
    const s = typeof l.source === "object" ? l.source.id : l.source;
    const t = typeof l.target === "object" ? l.target.id : l.target;
    if (s === nodeId) neighbors.add(t);
    if (t === nodeId) neighbors.add(s);
  });
  linkGroup.classed("dimmed", true);
  nodeGroup.classed("dimmed", true);
  labelGroup.classed("dimmed", true);
  linkGroup.selectAll("line").classed("link-hl", l => {
    const s = typeof l.source === "object" ? l.source.id : l.source;
    const t = typeof l.target === "object" ? l.target.id : l.target;
    return s === nodeId || t === nodeId;
  });
  nodeGroup.selectAll("circle").classed("node-hl", d => neighbors.has(d.id));
  labelGroup.selectAll("text").classed("label-hl", d => neighbors.has(d.id));
}

function clearHighlight() {
  linkGroup.classed("dimmed", false);
  nodeGroup.classed("dimmed", false);
  labelGroup.classed("dimmed", false);
  linkGroup.selectAll("line").classed("link-hl", false);
  nodeGroup.selectAll("circle").classed("node-hl", false);
  labelGroup.selectAll("text").classed("label-hl", false);
}

window.toggleScanFilter = function(btn, evt) {
  const st = btn.dataset.scan;
  const shift = !!(evt && evt.shiftKey);
  if (shift) {
    if (excludedScanTypes.has(st)) {
      excludedScanTypes.delete(st);
      activeScanTypes.add(st);
    } else {
      activeScanTypes.delete(st);
      excludedScanTypes.add(st);
    }
  } else {
    if (excludedScanTypes.has(st)) {
      excludedScanTypes.delete(st);
      activeScanTypes.add(st);
    } else if (activeScanTypes.has(st)) {
      activeScanTypes.delete(st);
    } else {
      activeScanTypes.add(st);
    }
  }
  syncFilterUi();
  reapplyFilters();
};

window.toggleSevFilter = function(label, evt) {
  const types = SEV_TO_TYPES[label.dataset.sev];
  const shift = !!(evt && evt.shiftKey);
  if (shift) {
    const allNeg = types.every(t => excludedScanTypes.has(t));
    types.forEach(t => {
      if (allNeg) {
        excludedScanTypes.delete(t);
        activeScanTypes.add(t);
      } else {
        activeScanTypes.delete(t);
        excludedScanTypes.add(t);
      }
    });
  } else {
    const anyExcluded = types.some(t => excludedScanTypes.has(t));
    if (anyExcluded) {
      types.forEach(t => { excludedScanTypes.delete(t); activeScanTypes.add(t); });
    } else {
      const allOn = types.every(t => activeScanTypes.has(t));
      types.forEach(t => {
        if (allOn) activeScanTypes.delete(t);
        else activeScanTypes.add(t);
      });
    }
  }
  syncFilterUi();
  reapplyFilters();
};

function reapplyFilters() {
  if (rawGraphData) {
    updateGraph(applyGraphFilters(rawGraphData));
    updateTable(applyAlertFilters(rawAlertData));
  }
  updateUrlFromFilters();
}

// ==== Saved Views + URL state (Tier 2 #7) ====
const VIEWS = {
  all:         new Set(["Lateral Movement", "Fast Scan", "Slow Scan", "Accept Scan", "Distributed Scan"]),
  criticals:   new Set(["Lateral Movement"]),
  high:        new Set(["Lateral Movement", "Fast Scan", "Distributed Scan"]),
  scans:       new Set(["Fast Scan", "Slow Scan", "Accept Scan", "Distributed Scan"]),
  lateral:     new Set(["Lateral Movement"]),
  distributed: new Set(["Distributed Scan"]),
};

function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

function currentViewName() {
  for (const [name, set] of Object.entries(VIEWS)) {
    if (setsEqual(activeScanTypes, set)) return name;
  }
  return null;
}

function applyView(name) {
  const v = VIEWS[name];
  if (!v) return false;
  activeScanTypes = new Set(v);
  excludedScanTypes = new Set();
  syncFilterUi();
  reapplyFilters();
  return true;
}

function syncFilterUi() {
  document.querySelectorAll(".filter-btn").forEach(b => {
    const t = b.dataset.scan;
    const isOn   = activeScanTypes.has(t);
    const isNeg  = excludedScanTypes.has(t);
    b.classList.toggle("off", !isOn && !isNeg);
    b.classList.toggle("neg", isNeg);
  });
  document.querySelectorAll(".sev-label").forEach(l => {
    const types = SEV_TO_TYPES[l.dataset.sev];
    const allNeg = types.every(t => excludedScanTypes.has(t));
    const anyOn = types.some(t => activeScanTypes.has(t));
    l.classList.toggle("off", !anyOn && !allNeg);
    l.classList.toggle("neg", allNeg);
  });
}

function updateUrlFromFilters() {
  try {
    const u = new URL(window.location);
    u.searchParams.delete("view");
    u.searchParams.delete("scans");
    u.searchParams.delete("exclude");
    const hasExcl = excludedScanTypes.size > 0;
    const view = !hasExcl ? currentViewName() : null;
    if (view && view !== "all") {
      u.searchParams.set("view", view);
    } else {
      if (!setsEqual(activeScanTypes, VIEWS.all) || hasExcl) {
        if (!setsEqual(activeScanTypes, VIEWS.all)) {
          u.searchParams.set("scans", [...activeScanTypes].sort().join(","));
        }
        if (hasExcl) {
          u.searchParams.set("exclude", [...excludedScanTypes].sort().join(","));
        }
      }
    }
    window.history.replaceState({}, "", u);
  } catch {}
}

function loadFiltersFromUrl() {
  try {
    const u = new URL(window.location);
    const view = u.searchParams.get("view");
    if (view && VIEWS[view]) {
      activeScanTypes = new Set(VIEWS[view]);
      excludedScanTypes = new Set();
      syncFilterUi();
      return;
    }
    const scans = u.searchParams.get("scans");
    const excl  = u.searchParams.get("exclude");
    const allowed = new Set(Object.keys(SCAN_COLORS));
    if (scans) {
      const set = new Set(scans.split(",").map(s => s.trim()).filter(s => allowed.has(s)));
      if (set.size > 0) activeScanTypes = set;
    }
    if (excl) {
      excludedScanTypes = new Set(excl.split(",").map(s => s.trim()).filter(s => allowed.has(s)));
      excludedScanTypes.forEach(t => activeScanTypes.delete(t));
    }
    syncFilterUi();
  } catch {}
}

function applyGraphFilters(data) {
  let edges = data.edges.filter(e => activeScanTypes.has(e.scan_type));
  if (replayActive) {
    const allowed = replayAllowedEdgeSet();
    edges = edges.filter(e => allowed.has(e.source + "|" + e.target + "|" + e.scan_type));
  }
  let nodes;
  if (isolatedMode && selectedNodes.size > 0) {
    nodes = data.nodes.filter(n => selectedNodes.has(n.id));
    edges = edges.filter(e => selectedNodes.has(e.source) && selectedNodes.has(e.target));
  } else {
    const ids = new Set();
    edges.forEach(e => { ids.add(e.source); ids.add(e.target); });
    nodes = data.nodes.filter(n => ids.has(n.id));
  }
  return { nodes, edges, stats: data.stats };
}

function applyAlertFilters(alerts) {
  let out = alerts.filter(a => activeScanTypes.has(a.scan_type));
  if (hideDismissed) {
    out = out.filter(a => getStatus(alertKey(a)) !== "dismissed");
  }
  if (replayActive) {
    out = out.filter(a => inReplayWindow(a.timestamp));
  }
  return out;
}

// ==== Multi-select ====

function toggleNodeSelection(nodeId) {
  if (selectedNodes.has(nodeId)) selectedNodes.delete(nodeId);
  else selectedNodes.add(nodeId);
  nodeGroup.selectAll("circle").classed("node-selected", d => selectedNodes.has(d.id));
  updateSelectionUI();
}

function updateSelectionUI() {
  const has = selectedNodes.size > 0;
  document.getElementById("btn-isolate").style.display = has ? "" : "none";
  document.getElementById("btn-clear-sel").style.display = has ? "" : "none";
  if (has) document.getElementById("btn-isolate").textContent = "Isolate (" + selectedNodes.size + ")";
}

function isolateSelection() {
  if (selectedNodes.size < 1) return;
  isolatedMode = true;
  document.getElementById("btn-isolate").classList.add("active");
  reapplyFilters();
}

function clearSelection() {
  selectedNodes.clear();
  isolatedMode = false;
  nodeGroup.selectAll("circle").classed("node-selected", false);
  document.getElementById("btn-isolate").classList.remove("active");
  updateSelectionUI();
  reapplyFilters();
}

function updateStatWithTrend(id, val, prev) {
  const el = document.getElementById(id);
  if (prev != null && val !== prev) {
    const d = val - prev;
    const cls = d > 0 ? "up" : "down";
    const arrow = d > 0 ? "\u25B2+" + d : "\u25BC" + d;
    el.innerHTML = val + ' <span class="stat-trend ' + cls + '">' + arrow + '</span>';
    el.classList.add("changed");
    setTimeout(() => el.classList.remove("changed"), 300);
    setTimeout(() => { const t = el.querySelector(".stat-trend"); if (t) t.remove(); }, 10000);
  } else {
    el.textContent = val;
  }
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

function enrichNodeStats(ip, role) {
  const out = { count24h: 0, topPeers: [], buckets: new Array(60).fill(0), subnetGuess: "" };
  if (!Array.isArray(rawAlertData)) return out;
  const now = Date.now();
  const cutoff24 = now - 24 * 60 * 60 * 1000;
  const cutoff60 = now - 60 * 60 * 1000;
  const peerCount = {};
  for (const a of rawAlertData) {
    const isSrc = a.source_ip === ip;
    const isDst = a.dest_ip === ip;
    if (!isSrc && !isDst) continue;
    const ts = Date.parse(a.timestamp);
    if (isNaN(ts)) continue;
    if (ts >= cutoff24) out.count24h++;
    if (ts >= cutoff60) {
      const bucket = Math.floor((now - ts) / 60000);
      if (bucket >= 0 && bucket < 60) out.buckets[59 - bucket]++;
    }
    const peer = isSrc ? a.dest_ip : a.source_ip;
    if (peer) peerCount[peer] = (peerCount[peer] || 0) + 1;
  }
  out.topPeers = Object.entries(peerCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([p, c]) => ({ ip: p, count: c }));
  const parts = ip.split(".");
  if (parts.length === 4) out.subnetGuess = parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
  return out;
}

function miniSparklineSvg(buckets) {
  const w = 140, h = 22;
  const max = Math.max(1, ...buckets);
  const step = w / (buckets.length - 1);
  const pts = buckets.map((v, i) => {
    const x = i * step;
    const y = h - 2 - (v / max) * (h - 4);
    return x.toFixed(1) + "," + y.toFixed(1);
  }).join(" ");
  return '<svg class="mini-spark" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">' +
         '<polyline fill="none" stroke="var(--accent)" stroke-width="1.2" points="' + pts + '" />' +
         '</svg>';
}

function showTooltip(event, d) {
  const badges = d.scan_types.map(t =>
    `<span class="scan-badge" style="background:${scanColor(t)}">${t}</span>`
  ).join(" ");
  const stats = enrichNodeStats(d.id, d.role);
  const peersHtml = stats.topPeers.length > 0
    ? '<div class="detail peer-list">Top peers: ' + stats.topPeers.map(p =>
        '<span class="peer">' + p.ip + '</span>&nbsp;<span style="color:var(--text-dim)">&times;' + p.count + '</span>'
      ).join(", ") + '</div>'
    : "";
  const sparkHtml = stats.count24h > 0
    ? '<div class="mini-spark-label">Ultimele 60 min</div>' + miniSparklineSvg(stats.buckets)
    : "";
  const subnetHtml = stats.subnetGuess ? '<div class="subnet">Subnet: ' + stats.subnetGuess + '</div>' : "";
  tooltip.innerHTML = `
    <div class="ip">${d.id}</div>
    <div class="role">${d.role === "attacker" ? "ATACATOR" : "TINTA"}</div>
    ${subnetHtml}
    <div class="detail">Alerte total: ${d.alert_count} &middot; 24h: ${stats.count24h}</div>
    <div class="detail">${badges}</div>
    ${peersHtml}
    ${sparkHtml}
    <div class="detail" style="color:#8b949e;font-size:11px">Ultima: ${formatTime(d.last_seen)}</div>
    <div class="detail" style="color:#8b949e;font-size:10px">Click=Dossier | Shift=Select | DblClick=Unpin</div>
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
  const panel = document.getElementById("dossier-panel");
  const title = document.getElementById("dossier-title");
  const body  = document.getElementById("dossier-body");
  title.innerHTML = "IP Dossier: " + ip + pinButtonHtml(ip);
  body.innerHTML = '<div style="color:var(--text-dim)">Se incarca...</div>';
  panel.classList.add("open");

  try {
    const res = await fetch("/api/ip/" + encodeURIComponent(ip));
    const d = await res.json();
    if (d.error) { body.innerHTML = `<div style="color:var(--red)">${d.error}</div>`; return; }

    const rolesBadges = d.roles.map(r =>
      `<span class="type-badge" style="background:${r === 'attacker' ? 'var(--red)' : 'var(--text-dim)'}">${r === 'attacker' ? 'ATACATOR' : 'TINTA'}</span>`
    ).join(' ');

    const scanBadges = d.scan_types.map(t =>
      `<span class="type-badge" style="background:${scanColor(t)}">${t}</span>${mitreBadgeHtml(t, true)}`
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
        <td><span class="type-badge" style="background:${scanColor(e.scan_type)};font-size:10px;padding:1px 6px">${e.scan_type}</span>${mitreBadgeHtml(e.scan_type, true)}</td>
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
  document.getElementById("dossier-panel").classList.remove("open");
});

// ==== Investigation Workspace (Tier 3 #11) ====
const WORKSPACE_KEY = "ids-workspace";
let workspace = {};

function loadWorkspace() {
  try { workspace = JSON.parse(localStorage.getItem(WORKSPACE_KEY) || "{}"); }
  catch { workspace = {}; }
}

function saveWorkspace() {
  try { localStorage.setItem(WORKSPACE_KEY, JSON.stringify(workspace)); } catch {}
  updateWorkspaceCount();
}

function updateWorkspaceCount() {
  const el = document.getElementById("ws-count");
  if (el) el.textContent = Object.keys(workspace).length;
}

function pinIp(ip) {
  if (!ip) return;
  if (!workspace[ip]) {
    workspace[ip] = { ip, pinnedAt: new Date().toISOString(), note: "" };
    saveWorkspace();
    renderWorkspace();
  }
  const title = document.getElementById("dossier-title");
  if (title && title.textContent.includes(ip)) {
    title.innerHTML = "IP Dossier: " + ip + pinButtonHtml(ip);
  }
}

function unpinIp(ip) {
  if (workspace[ip]) {
    delete workspace[ip];
    saveWorkspace();
    renderWorkspace();
    const title = document.getElementById("dossier-title");
    if (title && title.textContent.includes(ip)) {
      title.innerHTML = "IP Dossier: " + ip + pinButtonHtml(ip);
    }
  }
}

function pinButtonHtml(ip) {
  const pinned = !!workspace[ip];
  const cls = pinned ? "pin-btn pinned" : "pin-btn";
  const label = pinned ? "&#9733; Pinned" : "&#9734; Pin";
  return '<button class="' + cls + '" data-pin-ip="' + ip + '" title="Investigation workspace">' + label + '</button>';
}

function summarizeWorkspaceItem(ip) {
  if (!Array.isArray(rawAlertData)) return { alerts: 0, scanTypes: [], lastSeen: null };
  let count = 0;
  let lastSeen = null;
  const stypes = new Set();
  for (const a of rawAlertData) {
    if (a.source_ip !== ip && a.dest_ip !== ip) continue;
    count++;
    stypes.add(a.scan_type);
    if (!lastSeen || a.timestamp > lastSeen) lastSeen = a.timestamp;
  }
  return { alerts: count, scanTypes: [...stypes], lastSeen };
}

function renderWorkspace() {
  const body = document.getElementById("workspace-body");
  if (!body) return;
  const ips = Object.keys(workspace).sort((a, b) => (workspace[b].pinnedAt || "").localeCompare(workspace[a].pinnedAt || ""));
  if (ips.length === 0) {
    body.innerHTML = '<div class="workspace-empty">Niciun IP pinned. Deschide un dosar si apasa Pin, sau Shift+P pe nod.</div>';
    updateWorkspaceCount();
    return;
  }
  let html = "";
  for (const ip of ips) {
    const item = workspace[ip];
    const s = summarizeWorkspaceItem(ip);
    const tags = s.scanTypes.map(t =>
      '<span class="ws-tag" style="color:' + scanColor(t) + ';border-color:' + scanColor(t) + '55">' + t + '</span>'
    ).join("");
    const last = s.lastSeen ? formatTime(s.lastSeen) : "N/A";
    const noteEsc = (item.note || "").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    html += '<div class="ws-item" data-ws-ip="' + ip + '">' +
      '<div class="ws-item-head">' +
        '<span class="ws-item-ip" data-ws-open="' + ip + '">' + ip + '</span>' +
        '<div class="ws-item-actions">' +
          '<button class="ws-btn" data-ws-remove="' + ip + '" title="Unpin">&times;</button>' +
        '</div>' +
      '</div>' +
      '<div class="ws-item-meta">Alerte: ' + s.alerts + ' &middot; ultima: ' + last + '</div>' +
      (tags ? '<div class="ws-tags">' + tags + '</div>' : '') +
      '<textarea class="ws-note" data-ws-note="' + ip + '" placeholder="Notite investigatie (salvat automat)...">' + noteEsc + '</textarea>' +
    '</div>';
  }
  body.innerHTML = html;
  updateWorkspaceCount();
}

function exportWorkspace() {
  const payload = { exportedAt: new Date().toISOString(), items: workspace };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "ids-workspace-" + Date.now() + ".json";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
}

function toggleWorkspace() {
  const panel = document.getElementById("workspace-panel");
  if (!panel) return;
  const opening = !panel.classList.contains("open");
  panel.classList.toggle("open");
  if (opening) renderWorkspace();
}

function initWorkspace() {
  loadWorkspace();
  updateWorkspaceCount();
  const btn = document.getElementById("workspace-toggle");
  if (btn) btn.addEventListener("click", toggleWorkspace);
  const closeBtn = document.getElementById("workspace-close");
  if (closeBtn) closeBtn.addEventListener("click", toggleWorkspace);
  const exportBtn = document.getElementById("ws-export");
  if (exportBtn) exportBtn.addEventListener("click", exportWorkspace);
  const clearBtn = document.getElementById("ws-clear");
  if (clearBtn) clearBtn.addEventListener("click", () => {
    if (Object.keys(workspace).length === 0) return;
    if (confirm("Sterg " + Object.keys(workspace).length + " IP-uri din workspace?")) {
      workspace = {};
      saveWorkspace();
      renderWorkspace();
    }
  });

  document.addEventListener("click", e => {
    const pinBtn = e.target.closest("[data-pin-ip]");
    if (pinBtn) {
      e.stopPropagation();
      const ip = pinBtn.dataset.pinIp;
      workspace[ip] ? unpinIp(ip) : pinIp(ip);
      return;
    }
    const openBtn = e.target.closest("[data-ws-open]");
    if (openBtn) { openDossier(openBtn.dataset.wsOpen); return; }
    const rmBtn = e.target.closest("[data-ws-remove]");
    if (rmBtn) { e.stopPropagation(); unpinIp(rmBtn.dataset.wsRemove); return; }
  });

  document.addEventListener("input", e => {
    const noteEl = e.target.closest("[data-ws-note]");
    if (!noteEl) return;
    const ip = noteEl.dataset.wsNote;
    if (!workspace[ip]) return;
    workspace[ip].note = noteEl.value;
    saveWorkspace();
  });
}

// ==== Replay Mode (Tier 3 #12) ====
let replayActive = false;
let replayPlaying = false;
let replayCursorMs = 0;
let replayMinMs = 0;
let replayMaxMs = 0;
let replayWindowMin = 10;
let replaySpeedStepMs = 250;
let replayTimer = null;

function computeReplayBounds() {
  if (!Array.isArray(rawAlertData) || rawAlertData.length === 0) {
    replayMinMs = 0; replayMaxMs = 0; return;
  }
  let mn = Infinity, mx = -Infinity;
  for (const a of rawAlertData) {
    const t = Date.parse(a.timestamp);
    if (isNaN(t)) continue;
    if (t < mn) mn = t;
    if (t > mx) mx = t;
  }
  replayMinMs = isFinite(mn) ? mn : 0;
  replayMaxMs = isFinite(mx) ? mx : 0;
}

function inReplayWindow(ts) {
  const t = Date.parse(ts);
  if (isNaN(t)) return false;
  const start = replayCursorMs - replayWindowMin * 60000;
  return t >= start && t <= replayCursorMs;
}

function replayAllowedEdgeSet() {
  const set = new Set();
  if (!Array.isArray(rawAlertData)) return set;
  for (const a of rawAlertData) {
    if (!inReplayWindow(a.timestamp)) continue;
    if (!a.dest_ip) continue;
    set.add(a.source_ip + "|" + a.dest_ip + "|" + a.scan_type);
  }
  return set;
}

function fmtReplayTime(ms) {
  if (!ms) return "--:--:--";
  const d = new Date(ms);
  const pad = n => String(n).padStart(2, "0");
  return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
}

function fmtReplayRange() {
  if (!replayMinMs || !replayMaxMs) return "";
  return fmtReplayTime(replayMinMs) + " &rarr; " + fmtReplayTime(replayMaxMs);
}

function updateReplayUi() {
  const slider = document.getElementById("replay-slider");
  const timeEl = document.getElementById("replay-time");
  const rangeEl = document.getElementById("replay-range");
  const bar = document.getElementById("replay-bar");
  const toggle = document.getElementById("replay-toggle");
  const play = document.getElementById("replay-play");
  const rewind = document.getElementById("replay-rewind");
  const winSel = document.getElementById("replay-window");
  const spdSel = document.getElementById("replay-speed");
  if (!slider) return;
  const enabled = replayActive;
  slider.disabled = !enabled;
  play.disabled = !enabled;
  rewind.disabled = !enabled;
  winSel.disabled = !enabled;
  spdSel.disabled = !enabled;
  bar.classList.toggle("active", enabled);
  toggle.textContent = enabled ? "\u2715 Exit Replay" : "\u25B6 Replay";
  toggle.classList.toggle("primary", enabled);
  play.innerHTML = replayPlaying ? "&#10074;&#10074;" : "&#9654;";
  if (replayMaxMs > replayMinMs) {
    const pct = ((replayCursorMs - replayMinMs) / (replayMaxMs - replayMinMs)) * 100;
    slider.value = String(Math.max(0, Math.min(100, pct)));
  }
  timeEl.textContent = fmtReplayTime(replayCursorMs);
  rangeEl.innerHTML = fmtReplayRange();
}

function enterReplay() {
  computeReplayBounds();
  if (replayMaxMs <= replayMinMs) {
    alert("Nu sunt alerte suficiente pentru replay.");
    return;
  }
  replayActive = true;
  replayCursorMs = replayMinMs + replayWindowMin * 60000;
  if (replayCursorMs > replayMaxMs) replayCursorMs = replayMaxMs;
  updateReplayUi();
  reapplyFilters();
}

function exitReplay() {
  replayActive = false;
  replayPlaying = false;
  if (replayTimer) { clearInterval(replayTimer); replayTimer = null; }
  updateReplayUi();
  reapplyFilters();
}

function toggleReplay() { replayActive ? exitReplay() : enterReplay(); }

function toggleReplayPlay() {
  if (!replayActive) return;
  replayPlaying = !replayPlaying;
  if (replayTimer) { clearInterval(replayTimer); replayTimer = null; }
  if (replayPlaying) {
    replayTimer = setInterval(() => {
      const step = 15000;
      replayCursorMs += step;
      if (replayCursorMs >= replayMaxMs) {
        replayCursorMs = replayMaxMs;
        replayPlaying = false;
        if (replayTimer) { clearInterval(replayTimer); replayTimer = null; }
      }
      updateReplayUi();
      reapplyFilters();
    }, replaySpeedStepMs);
  }
  updateReplayUi();
}

function replayRewind() {
  if (!replayActive) return;
  replayCursorMs = replayMinMs + replayWindowMin * 60000;
  if (replayCursorMs > replayMaxMs) replayCursorMs = replayMaxMs;
  updateReplayUi();
  reapplyFilters();
}

function initReplay() {
  const toggle = document.getElementById("replay-toggle");
  const play = document.getElementById("replay-play");
  const rewind = document.getElementById("replay-rewind");
  const slider = document.getElementById("replay-slider");
  const winSel = document.getElementById("replay-window");
  const spdSel = document.getElementById("replay-speed");
  if (!toggle) return;
  toggle.addEventListener("click", toggleReplay);
  play.addEventListener("click", toggleReplayPlay);
  rewind.addEventListener("click", replayRewind);
  slider.addEventListener("input", () => {
    if (!replayActive || replayMaxMs <= replayMinMs) return;
    const pct = Number(slider.value) / 100;
    replayCursorMs = replayMinMs + pct * (replayMaxMs - replayMinMs);
    updateReplayUi();
    reapplyFilters();
  });
  winSel.addEventListener("change", () => {
    replayWindowMin = Number(winSel.value) || 10;
    if (replayActive) { updateReplayUi(); reapplyFilters(); }
  });
  spdSel.addEventListener("change", () => {
    replaySpeedStepMs = Number(spdSel.value) || 250;
    if (replayPlaying) {
      if (replayTimer) clearInterval(replayTimer);
      replayPlaying = false;
      toggleReplayPlay();
    }
  });
  updateReplayUi();
}

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
      const k = alertKey(a);
      const st = getStatus(k);
      html += `<tr class="alert-row" data-alert-key="${k}" data-status="${st}">
        <td style="color:#8b949e">${formatTime(a.timestamp)}</td>
        <td><span class="type-badge" style="background:${color}">${a.scan_type}</span>${mitreBadgeHtml(a.scan_type, true)}</td>
        <td><span class="ip-link" onclick="openDossier('${a.source_ip}')">${a.source_ip}</span></td>
        <td><span class="ip-link" onclick="openDossier('${dest}')">${dest}</span></td>
        <td style="color:#8b949e">${detail}</td>
        <td>${triageCellHtml(k)}</td>
      </tr>`;
    } else {
      const cid = 'c' + Math.random().toString(36).slice(2, 8);
      const childKeys = cluster.items.map(alertKey);
      const joinedKeys = childKeys.join("\u0001");
      html += `<tr class="cluster-header" data-cluster-keys="${joinedKeys}" onclick="toggleCluster('${cid}', this)">
        <td style="color:#8b949e">${formatTime(a.timestamp)}</td>
        <td><span class="type-badge" style="background:${color}">${a.scan_type}</span>${mitreBadgeHtml(a.scan_type, true)}</td>
        <td><span class="ip-link" onclick="event.stopPropagation();openDossier('${a.source_ip}')">${a.source_ip}</span></td>
        <td colspan="2" style="color:var(--yellow)">&#215;${cluster.items.length} alerte grupate (click pentru expand)</td>
        <td>${clusterStatusBadge(childKeys)}</td>
      </tr>`;
      for (const child of cluster.items) {
        const cd = child.dest_ip || "N/A";
        const ck = alertKey(child);
        const cs = getStatus(ck);
        html += `<tr class="cluster-child alert-row ${cid}" data-alert-key="${ck}" data-status="${cs}">
          <td style="color:#8b949e">${formatTime(child.timestamp)}</td>
          <td><span class="type-badge" style="background:${color};font-size:10px">${child.scan_type}</span>${mitreBadgeHtml(child.scan_type, true)}</td>
          <td><span class="ip-link" onclick="openDossier('${child.source_ip}')">${child.source_ip}</span></td>
          <td><span class="ip-link" onclick="openDossier('${cd}')">${cd}</span></td>
          <td style="color:#8b949e">${alertDetail(child)}</td>
          <td>${triageCellHtml(ck)}</td>
        </tr>`;
      }
    }
  }
  tbody.innerHTML = html;
  updateTriageSummary(alerts);
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

    rawGraphData = graph;
    rawAlertData = alerts;

    updateStatWithTrend("stat-alerts", graph.stats.total_alerts, prevStats ? prevStats.alerts : null);
    updateStatWithTrend("stat-attackers", graph.stats.unique_attackers, prevStats ? prevStats.attackers : null);
    updateStatWithTrend("stat-targets", graph.stats.unique_targets, prevStats ? prevStats.targets : null);
    prevStats = { alerts: graph.stats.total_alerts, attackers: graph.stats.unique_attackers, targets: graph.stats.unique_targets };
    if (soundEnabled && prevAlertCount > 0 && graph.stats.total_alerts > prevAlertCount) playAlertBeep();
    prevAlertCount = graph.stats.total_alerts;
    document.getElementById("last-update").textContent     = new Date().toLocaleTimeString("ro-RO", { hour12: false });
    updateSparkline(alerts);
    updateHeatmap(alerts);
    processCriticalToasts(alerts);
    const cnt = document.getElementById("alert-count");
    if (cnt) cnt.textContent = Array.isArray(alerts) ? alerts.length : 0;

    updateGraph(applyGraphFilters(graph));
    updateTable(applyAlertFilters(alerts));

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

// ==== Fullscreen (D14 + fix B3/B4) ====
// Facem fullscreen pe #dashboard-root (include graph, replay-bar, tabel alerte,
// dossier-panel si workspace) ca sa nu dispara panourile laterale / bara alerte.
function toggleFullscreen() {
  const area = document.getElementById("dashboard-root") || document.getElementById("graph-area");
  if (!document.fullscreenElement) {
    (area.requestFullscreen || area.webkitRequestFullscreen || area.msRequestFullscreen).call(area);
  } else {
    (document.exitFullscreen || document.webkitExitFullscreen || document.msExitFullscreen).call(document);
  }
}
document.addEventListener("fullscreenchange", () => {
  const btn = document.getElementById("btn-fullscreen");
  btn.innerHTML = document.fullscreenElement ? "&#10005; Exit" : "&#9974; Full";
});

// ==== Export PNG (D15 + bugfix B1) ====
// Bug B1: PNG download returning 0 bytes.
// Root cause 1: SVG elements styled via document <style> (CSS classes) have no inline
//   attributes. Cand SVG-ul este incarcat ca <img>, document-ul extern de CSS nu se
//   aplica — conturul/textul raman default (fill:none, stroke:none) si imaginea e goala.
// Root cause 2: `canvas.toDataURL` poate returna "data:," pe canvas taintat sau pe
//   eroare silentioasa, rezultand download 0 bytes. `canvas.toBlob` raporteaza null
//   explicit, asa avem error handling real.
const SVG_STYLE_PROPS = [
  "fill", "fill-opacity", "stroke", "stroke-width", "stroke-opacity",
  "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin",
  "opacity", "visibility",
  "font-family", "font-size", "font-weight", "text-anchor", "dominant-baseline"
];

function inlineSvgStyles(source, clone) {
  const srcAll = source.querySelectorAll("*");
  const cloneAll = clone.querySelectorAll("*");
  const n = Math.min(srcAll.length, cloneAll.length);
  for (let i = 0; i < n; i++) {
    const cs = getComputedStyle(srcAll[i]);
    const existing = cloneAll[i].getAttribute("style") || "";
    let css = "";
    for (const p of SVG_STYLE_PROPS) {
      const v = cs.getPropertyValue(p);
      if (v) css += p + ":" + v + ";";
    }
    cloneAll[i].setAttribute("style", css + existing);
  }
}

function exportPNG() {
  const svgEl = document.getElementById("graph-svg");
  if (!svgEl) return;
  const vbRaw = svgEl.getAttribute("viewBox");
  if (!vbRaw) return;
  const vb = vbRaw.split(/\s+/);
  const w = parseInt(vb[2], 10);
  const h = parseInt(vb[3], 10);
  if (!w || !h) return;

  const clone = svgEl.cloneNode(true);
  inlineSvgStyles(svgEl, clone);

  clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  clone.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");
  clone.setAttribute("width", w);
  clone.setAttribute("height", h);

  const bgColor = getComputedStyle(document.documentElement)
    .getPropertyValue("--bg").trim() || "#0d1117";
  const bgRect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  bgRect.setAttribute("width", w);
  bgRect.setAttribute("height", h);
  bgRect.setAttribute("fill", bgColor);
  clone.insertBefore(bgRect, clone.firstChild);

  const xml = new XMLSerializer().serializeToString(clone);
  const svgDoc = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml;
  const svgBlob = new Blob([svgDoc], { type: "image/svg+xml;charset=utf-8" });
  const svgUrl = URL.createObjectURL(svgBlob);

  const img = new Image();
  img.onload = () => {
    try {
      const canvas = document.createElement("canvas");
      canvas.width = w * 2;
      canvas.height = h * 2;
      const ctx = canvas.getContext("2d");
      ctx.scale(2, 2);
      ctx.drawImage(img, 0, 0, w, h);
      canvas.toBlob((pngBlob) => {
        URL.revokeObjectURL(svgUrl);
        if (!pngBlob || pngBlob.size === 0) {
          console.error("exportPNG: toBlob a returnat gol (canvas taintat?)");
          alert("Export PNG a esuat. Vezi consola.");
          return;
        }
        const pngUrl = URL.createObjectURL(pngBlob);
        const a = document.createElement("a");
        a.download = "ids-rs-graph-"
          + new Date().toISOString().slice(0, 19).replace(/:/g, "-") + ".png";
        a.href = pngUrl;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(pngUrl), 1500);
      }, "image/png");
    } catch (err) {
      URL.revokeObjectURL(svgUrl);
      console.error("exportPNG error:", err);
      alert("Export PNG a esuat: " + err.message);
    }
  };
  img.onerror = (e) => {
    URL.revokeObjectURL(svgUrl);
    console.error("exportPNG: imaginea SVG nu s-a incarcat", e);
    alert("Export PNG a esuat: SVG invalid.");
  };
  img.src = svgUrl;
}

// ==== Dark/Light Theme (D17) ====
function toggleTheme() {
  const root = document.documentElement;
  root.classList.toggle("light");
  const isLight = root.classList.contains("light");
  document.getElementById("btn-theme").innerHTML = isLight ? "&#9790; Theme" : "&#9788; Theme";
  localStorage.setItem("ids-theme", isLight ? "light" : "dark");
}

// ==== Alert Sound (D18) ====
function playAlertBeep() {
  if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  const osc = audioCtx.createOscillator();
  const gain = audioCtx.createGain();
  osc.connect(gain);
  gain.connect(audioCtx.destination);
  osc.type = "sine";
  osc.frequency.setValueAtTime(880, audioCtx.currentTime);
  gain.gain.setValueAtTime(0.3, audioCtx.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);
  osc.start(audioCtx.currentTime);
  osc.stop(audioCtx.currentTime + 0.3);
}

function toggleSound() {
  soundEnabled = !soundEnabled;
  const btn = document.getElementById("btn-sound");
  btn.classList.toggle("btn-sound-on", soundEnabled);
  btn.innerHTML = soundEnabled ? "&#128266; Sound" : "&#128264; Sound";
}

// ==== Heatmap 24h (Tier 1 #5) ====
function severityLevelForValue(v) {
  if (v >= 8) return { cls: "critical", label: "Critical" };
  if (v === 7) return { cls: "high",     label: "High" };
  if (v === 6) return { cls: "medium",   label: "Medium" };
  if (v >= 1) return { cls: "low",       label: "Low" };
  return { cls: "none", label: "-" };
}

function updateHeatmap(alerts) {
  const HOURS = 24;
  const now = new Date();
  const currentHourMs = new Date(
    now.getFullYear(), now.getMonth(), now.getDate(), now.getHours()
  ).getTime();
  const firstMs = currentHourMs - (HOURS - 1) * 3600000;
  const counts = new Array(HOURS).fill(0);
  const maxSev = new Array(HOURS).fill(0);

  for (const a of (alerts || [])) {
    const t = new Date(a.timestamp).getTime();
    if (Number.isNaN(t)) continue;
    const idx = Math.floor((t - firstMs) / 3600000);
    if (idx < 0 || idx >= HOURS) continue;
    counts[idx]++;
    const sv = SEVERITY_MAP[a.scan_type];
    if (sv && sv.value > maxSev[idx]) maxSev[idx] = sv.value;
  }

  const cont = document.getElementById("heatmap-24");
  const label = cont.querySelector(".heatmap-24-label");
  cont.innerHTML = "";
  if (label) cont.appendChild(label);

  for (let i = 0; i < HOURS; i++) {
    const sev = severityLevelForValue(maxSev[i]);
    const start = new Date(firstMs + i * 3600000);
    const hh = String(start.getHours()).padStart(2, "0");
    const cell = document.createElement("div");
    cell.className = "heatmap-cell sev-" + sev.cls;
    const tip = hh + ":00 &middot; <b>" + counts[i] + "</b> alerte &middot; " + sev.label;
    cell.innerHTML = '<span class="heatmap-tooltip">' + tip + '</span>';
    cont.appendChild(cell);
  }
}

// ==== MITRE ATT&CK tags (Tier 2 #9) ====
const MITRE_MAP = {
  "Fast Scan":        { id: "T1046",     name: "Network Service Discovery" },
  "Slow Scan":        { id: "T1046",     name: "Network Service Discovery" },
  "Accept Scan":      { id: "T1046",     name: "Network Service Discovery (passive)" },
  "Distributed Scan": { id: "T1595.001", name: "Active Scanning: Scanning IP Blocks" },
  "Lateral Movement": { id: "T1021",     name: "Remote Services" },
};

function mitreBadgeHtml(scanType, small) {
  const m = MITRE_MAP[scanType];
  if (!m) return "";
  const cls = small ? "mitre-tag small" : "mitre-tag";
  const title = "MITRE ATT&CK " + m.id + " &ndash; " + m.name + " (click pentru filtrare)";
  return '<span class="' + cls + '" data-ttp="' + m.id + '" title="' + title + '">' + m.id + '</span>';
}

function filterByTtp(ttp) {
  const matching = Object.keys(MITRE_MAP).filter(k => MITRE_MAP[k].id === ttp);
  if (matching.length === 0) return;
  activeScanTypes = new Set(matching);
  excludedScanTypes = new Set();
  syncFilterUi();
  reapplyFilters();
}

function initMitreClicks() {
  document.addEventListener("click", e => {
    const tag = e.target.closest(".mitre-tag[data-ttp]");
    if (!tag) return;
    e.stopPropagation();
    filterByTtp(tag.dataset.ttp);
  });
}

// ==== Triage state (Tier 2 #6) ====
const ALERT_STATUS_KEY = "ids-alert-status";
const ALERT_STATUS_MAX = 500;
let alertStatus = {};
let hideDismissed = true;
let hoverAlertKey = null;
let hoverClusterKeys = null;

function loadTriage() {
  try { alertStatus = JSON.parse(localStorage.getItem(ALERT_STATUS_KEY) || "{}"); }
  catch { alertStatus = {}; }
  try {
    const raw = localStorage.getItem("ids-hide-dismissed");
    hideDismissed = raw === null ? true : raw === "true";
  } catch {}
  const cb = document.getElementById("hide-dismissed");
  if (cb) cb.checked = hideDismissed;
}

function saveTriage() {
  const entries = Object.entries(alertStatus);
  if (entries.length > ALERT_STATUS_MAX) {
    alertStatus = Object.fromEntries(entries.slice(-ALERT_STATUS_MAX));
  }
  try { localStorage.setItem(ALERT_STATUS_KEY, JSON.stringify(alertStatus)); } catch {}
}

function getStatus(key) { return alertStatus[key] || "new"; }

function setStatus(key, status) {
  if (!key) return;
  if (!status || status === "new") delete alertStatus[key];
  else alertStatus[key] = status;
  saveTriage();
  reapplyFilters();
}

function bulkSetStatus(keys, status) {
  if (!keys || keys.length === 0) return;
  for (const k of keys) {
    if (!status || status === "new") delete alertStatus[k];
    else alertStatus[k] = status;
  }
  saveTriage();
  reapplyFilters();
}

function triageCellHtml(key) {
  const st = getStatus(key);
  return '<div class="triage">'
    + '<button class="triage-btn' + (st === "ack" ? " active" : "") + '" data-action="ack" title="Ack (A)">&#10003;</button>'
    + '<button class="triage-btn' + (st === "dismissed" ? " active" : "") + '" data-action="dismiss" title="Dismiss (D)">&#10005;</button>'
    + '<button class="triage-btn' + (st === "escalated" ? " active" : "") + '" data-action="escalate" title="Escalate (E)">&#9650;</button>'
    + '</div>';
}

function clusterStatusBadge(keys) {
  const counts = { new: 0, ack: 0, dismissed: 0, escalated: 0 };
  for (const k of keys) counts[getStatus(k)]++;
  const parts = [];
  if (counts.new > 0)        parts.push('<span class="dot-sm new"></span>' + counts.new);
  if (counts.ack > 0)        parts.push('<span class="dot-sm ack"></span>' + counts.ack);
  if (counts.escalated > 0)  parts.push('<span class="dot-sm esc"></span>' + counts.escalated);
  if (counts.dismissed > 0)  parts.push('<span class="dot-sm dis"></span>' + counts.dismissed);
  return '<div class="cluster-badge" title="Triage in cluster: A/D/E bulk">' + parts.join(" ") + '</div>';
}

function updateTriageSummary(alerts) {
  const el = document.getElementById("triage-summary");
  if (!el) return;
  const c = { new: 0, ack: 0, dismissed: 0, escalated: 0 };
  for (const a of alerts || []) c[getStatus(alertKey(a))]++;
  el.hidden = (alerts || []).length === 0;
  document.getElementById("ts-new").textContent = c.new;
  document.getElementById("ts-ack").textContent = c.ack;
  document.getElementById("ts-esc").textContent = c.escalated;
  document.getElementById("ts-dis").textContent = c.dismissed;
}

function initTriage() {
  loadTriage();
  const tbody = document.getElementById("alert-tbody");

  tbody.addEventListener("click", e => {
    const btn = e.target.closest(".triage-btn");
    if (!btn) return;
    const row = btn.closest("[data-alert-key]");
    if (!row) return;
    e.stopPropagation();
    const key = row.dataset.alertKey;
    const action = btn.dataset.action;
    const targetMap = { ack: "ack", dismiss: "dismissed", escalate: "escalated" };
    const target = targetMap[action];
    const cur = getStatus(key);
    setStatus(key, cur === target ? "new" : target);
  });

  tbody.addEventListener("mouseover", e => {
    const row = e.target.closest("tr.alert-row, tr.cluster-header");
    if (!row) return;
    document.querySelectorAll(".hover-key").forEach(r => r.classList.remove("hover-key"));
    if (row.dataset.alertKey) {
      hoverAlertKey = row.dataset.alertKey;
      hoverClusterKeys = null;
      row.classList.add("hover-key");
    } else if (row.dataset.clusterKeys) {
      hoverAlertKey = null;
      hoverClusterKeys = row.dataset.clusterKeys.split("\u0001");
    }
  });
  tbody.addEventListener("mouseleave", () => {
    hoverAlertKey = null;
    hoverClusterKeys = null;
    document.querySelectorAll(".hover-key").forEach(r => r.classList.remove("hover-key"));
  });

  const cb = document.getElementById("hide-dismissed");
  if (cb) {
    cb.addEventListener("change", () => {
      hideDismissed = cb.checked;
      try { localStorage.setItem("ids-hide-dismissed", String(hideDismissed)); } catch {}
      reapplyFilters();
    });
  }
}

function handleTriageKey(e) {
  if (e.ctrlKey || e.metaKey || e.altKey) return false;
  const k = e.key.toLowerCase();
  if (k !== "a" && k !== "d" && k !== "e") return false;
  const map = { a: "ack", d: "dismissed", e: "escalated" };
  const target = map[k];
  if (hoverAlertKey) {
    e.preventDefault();
    const cur = getStatus(hoverAlertKey);
    setStatus(hoverAlertKey, cur === target ? "new" : target);
    return true;
  }
  if (hoverClusterKeys) {
    e.preventDefault();
    bulkSetStatus(hoverClusterKeys, target);
    return true;
  }
  return false;
}

// ==== Density toggle (Tier 1 #4) ====
const DENSITIES = ["comfortable", "compact", "dense"];

function setDensity(name) {
  if (!DENSITIES.includes(name)) name = "compact";
  const area = document.getElementById("table-area");
  DENSITIES.forEach(d => area.classList.remove("density-" + d));
  area.classList.add("density-" + name);
  document.querySelectorAll(".density-toggle button").forEach(b => {
    b.classList.toggle("active", b.dataset.density === name);
  });
  try { localStorage.setItem("ids-density", name); } catch {}
}

function initDensity() {
  let saved = "compact";
  try { saved = localStorage.getItem("ids-density") || "compact"; } catch {}
  setDensity(saved);
  document.querySelectorAll(".density-toggle button").forEach(b => {
    b.addEventListener("click", () => setDensity(b.dataset.density));
  });
}

// ==== Toasts Critical (Tier 1 #3) ====
const SEEN_CRITICALS = new Set();
let seenCriticalsInit = false;
const MAX_TOASTS = 3;
const TOAST_TTL_MS = 8000;

function alertKey(a) {
  return a.timestamp + "|" + a.source_ip + "|" + (a.dest_ip || "") + "|" + a.scan_type;
}

function processCriticalToasts(alerts) {
  if (!seenCriticalsInit) {
    for (const a of alerts || []) {
      if (SEVERITY_MAP[a.scan_type] && SEVERITY_MAP[a.scan_type].level === "Critical") {
        SEEN_CRITICALS.add(alertKey(a));
      }
    }
    seenCriticalsInit = true;
    return;
  }
  const fresh = [];
  for (const a of alerts || []) {
    const sev = SEVERITY_MAP[a.scan_type];
    if (!sev || sev.level !== "Critical") continue;
    const k = alertKey(a);
    if (!SEEN_CRITICALS.has(k)) {
      SEEN_CRITICALS.add(k);
      fresh.push(a);
    }
  }
  fresh.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  for (const a of fresh.slice(-MAX_TOASTS)) showToast(a);
}

function showToast(a) {
  const cont = document.getElementById("toast-container");
  while (cont.children.length >= MAX_TOASTS) {
    cont.removeChild(cont.firstChild);
  }
  const t = document.createElement("div");
  t.className = "toast";
  const dest = a.dest_ip || "-";
  const time = formatTime(a.timestamp);
  t.innerHTML =
    '<div class="toast-header">' +
      '<span class="toast-title">&#9888; Critical &middot; ' + a.scan_type + '</span>' +
      '<span class="toast-time">' + time + '</span>' +
    '</div>' +
    '<div class="toast-body"><b>' + a.source_ip + '</b> &rarr; <b>' + dest + '</b></div>' +
    '<div class="toast-hint">Click pentru dosier</div>';
  t.addEventListener("click", () => {
    dismissToast(t);
    openDossier(a.source_ip);
  });
  cont.appendChild(t);
  setTimeout(() => dismissToast(t), TOAST_TTL_MS);
}

function dismissToast(t) {
  if (!t.parentNode) return;
  if (t.classList.contains("removing")) return;
  t.classList.add("removing");
  setTimeout(() => { if (t.parentNode) t.parentNode.removeChild(t); }, 220);
}

// ==== Sparkline 60 min (Tier 1 #2) ====
function updateSparkline(alerts) {
  const BUCKETS = 60;
  const WINDOW_MS = BUCKETS * 60 * 1000;
  const now = Date.now();
  const buckets = new Array(BUCKETS).fill(0);
  for (const a of (alerts || [])) {
    const t = new Date(a.timestamp).getTime();
    if (Number.isNaN(t)) continue;
    const diff = now - t;
    if (diff < 0 || diff >= WINDOW_MS) continue;
    const idx = BUCKETS - 1 - Math.floor(diff / 60000);
    if (idx >= 0 && idx < BUCKETS) buckets[idx]++;
  }
  const peak = Math.max(1, ...buckets);
  const W = 120, H = 34, PAD = 2;
  const stepX = (W - 2 * PAD) / (BUCKETS - 1);
  const pts = buckets.map((v, i) => [
    PAD + i * stepX,
    H - PAD - ((H - 2 * PAD) * v) / peak,
  ]);
  let line = "M " + pts[0][0].toFixed(1) + " " + pts[0][1].toFixed(1);
  for (let i = 1; i < pts.length; i++) {
    line += " L " + pts[i][0].toFixed(1) + " " + pts[i][1].toFixed(1);
  }
  const area = line
    + " L " + (W - PAD).toFixed(1) + " " + (H - PAD).toFixed(1)
    + " L " + PAD.toFixed(1) + " " + (H - PAD).toFixed(1) + " Z";
  document.getElementById("spark-path").setAttribute("d", line);
  document.getElementById("spark-area").setAttribute("d", area);
  const last = pts[pts.length - 1];
  const dot = document.getElementById("spark-dot");
  dot.setAttribute("cx", last[0].toFixed(1));
  dot.setAttribute("cy", last[1].toFixed(1));
  document.getElementById("spark-peak").textContent =
    Math.max(...buckets);
}

// ==== Command Palette (Tier 1 #1) ====
const IP_RE = /^\d{1,3}(\.\d{1,3}){0,3}$/;

function toggleScanByName(name) {
  const btn = document.querySelector('.filter-btn[data-scan="' + name + '"]');
  if (btn) window.toggleScanFilter(btn);
}
function toggleSevByName(name) {
  const lbl = document.querySelector('.sev-label[data-sev="' + name + '"]');
  if (lbl) window.toggleSevFilter(lbl);
}
function resetAllFilters() {
  activeScanTypes = new Set(Object.keys(SCAN_COLORS));
  excludedScanTypes = new Set();
  syncFilterUi();
  reapplyFilters();
}
function searchIp(ip) {
  const input = document.getElementById("omnisearch");
  input.value = ip;
  doSearch();
}

const COMMANDS = [
  { id: "fit",          cat: "Graph",  icon: "\u2316", label: "Fit graph",                   sub: "Centreaza si ajusteaza zoom",   kbd: "F",     run: zoomToFit },
  { id: "freeze",       cat: "Graph",  icon: "\u23F8", label: "Freeze / Play simulation",    sub: "Opreste/porneste fortele",      kbd: "Space", run: toggleFreeze },
  { id: "pin-all",      cat: "Graph",  icon: "\u{1F4CC}", label: "Pin all nodes",            sub: "Fixeaza toate nodurile",                     run: pinAll },
  { id: "unpin-all",    cat: "Graph",  icon: "\u2205", label: "Unpin all nodes",             sub: "Elibereaza toate nodurile",                  run: unpinAll },
  { id: "isolate",      cat: "Graph",  icon: "\u25EF", label: "Isolate selection",           sub: "Arata doar nodurile selectate",              run: isolateSelection },
  { id: "clear-sel",    cat: "Graph",  icon: "\u2715", label: "Clear selection",             sub: "Deselecteaza nodurile",         kbd: "Esc",  run: clearSelection },

  { id: "fullscreen",   cat: "View",   icon: "\u26F6", label: "Toggle fullscreen",           sub: "Extinde graful pe tot ecranul", kbd: "F11",  run: toggleFullscreen },
  { id: "theme",        cat: "View",   icon: "\u263E", label: "Toggle light / dark theme",                                         kbd: "T",    run: toggleTheme },
  { id: "export",       cat: "View",   icon: "\u{1F4F7}", label: "Export graph as PNG",      sub: "Descarca vizualizarea curenta",              run: exportPNG },
  { id: "sound",        cat: "View",   icon: "\u{1F509}", label: "Toggle alert sound",                                                             run: toggleSound },

  { id: "f-lateral",    cat: "Filter", icon: "\u25CF", label: "Toggle Lateral Movement",     sub: "Scan type filter",              kbd: "1",    run: () => toggleScanByName("Lateral Movement") },
  { id: "f-fast",       cat: "Filter", icon: "\u25CF", label: "Toggle Fast Scan",            sub: "Scan type filter",              kbd: "2",    run: () => toggleScanByName("Fast Scan") },
  { id: "f-slow",       cat: "Filter", icon: "\u25CF", label: "Toggle Slow Scan",            sub: "Scan type filter",              kbd: "3",    run: () => toggleScanByName("Slow Scan") },
  { id: "f-accept",     cat: "Filter", icon: "\u25CF", label: "Toggle Accept Scan",          sub: "Scan type filter",              kbd: "4",    run: () => toggleScanByName("Accept Scan") },
  { id: "f-distrib",    cat: "Filter", icon: "\u25CF", label: "Toggle Distributed Scan",     sub: "Scan type filter",              kbd: "5",    run: () => toggleScanByName("Distributed Scan") },
  { id: "s-critical",   cat: "Filter", icon: "\u25A0", label: "Toggle Critical severity",                                                        run: () => toggleSevByName("Critical") },
  { id: "s-high",       cat: "Filter", icon: "\u25A0", label: "Toggle High severity",                                                            run: () => toggleSevByName("High") },
  { id: "s-medium",     cat: "Filter", icon: "\u25A0", label: "Toggle Medium severity",                                                          run: () => toggleSevByName("Medium") },
  { id: "reset-filter", cat: "Filter", icon: "\u21BB", label: "Reset all filters",           sub: "Activeaza toate tipurile",                   run: resetAllFilters },

  { id: "v-all",         cat: "Views", icon: "\u25A3", label: "View: All",                    sub: "Toate tipurile active",                      run: () => applyView("all") },
  { id: "v-criticals",   cat: "Views", icon: "\u25A0", label: "View: Criticals only",         sub: "Doar Lateral Movement",                      run: () => applyView("criticals") },
  { id: "v-high",        cat: "Views", icon: "\u25A0", label: "View: High + Critical",        sub: "Lateral + Fast + Distributed",               run: () => applyView("high") },
  { id: "v-scans",       cat: "Views", icon: "\u25A0", label: "View: Scans only",             sub: "Fast + Slow + Accept + Distributed",         run: () => applyView("scans") },
  { id: "v-lateral",     cat: "Views", icon: "\u25A0", label: "View: Lateral only",                                                              run: () => applyView("lateral") },
  { id: "v-distributed", cat: "Views", icon: "\u25A0", label: "View: Distributed only",                                                          run: () => applyView("distributed") },
  { id: "v-share",       cat: "Views", icon: "\u{1F517}", label: "Copy shareable URL",        sub: "Copiaza URL cu filtrele curente",            run: copyShareUrl },

  { id: "clear-search", cat: "Search", icon: "\u2715", label: "Clear IP search",             sub: "Sterge filtrul omnisearch",                  run: clearSearch },

  { id: "ws-toggle",     cat: "Workspace", icon: "\u{1F50D}", label: "Toggle investigation workspace", sub: "Panel cu IP-uri pinned + notite", kbd: "Shift+P", run: toggleWorkspace },
  { id: "ws-export",     cat: "Workspace", icon: "\u{1F4E4}", label: "Export workspace (JSON)",        sub: "Descarca pinned IPs + notite",                    run: exportWorkspace },

  { id: "replay-toggle", cat: "Replay", icon: "\u23EF", label: "Toggle replay mode",        sub: "Timeline slider peste alerte",        run: toggleReplay },
  { id: "replay-play",   cat: "Replay", icon: "\u25B6", label: "Replay: play / pause",      sub: "Avansare automata cursor",             run: toggleReplayPlay },
  { id: "replay-rewind", cat: "Replay", icon: "\u23EE", label: "Replay: rewind",            sub: "Mergi la inceputul istoricului",       run: replayRewind },

  { id: "aerial",        cat: "Graph",  icon: "\u25EF", label: "Toggle aerial subnet grouping", sub: "Convex hulls per /24", kbd: "Shift+G", run: toggleAerial },
];

function copyShareUrl() {
  updateUrlFromFilters();
  const url = window.location.href;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(
      () => console.info("URL copiat:", url),
      () => window.prompt("Copiaza URL:", url)
    );
  } else {
    window.prompt("Copiaza URL:", url);
  }
}

const CAT_ORDER = ["Search", "Views", "Workspace", "Replay", "Graph", "Filter", "View"];
let cmdkActiveIdx = 0;
let cmdkVisible = [];

function fuzzyScore(query, text) {
  if (!query) return 1;
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (t.includes(q)) return 100 - (t.indexOf(q));
  let qi = 0, score = 0;
  for (let i = 0; i < t.length && qi < q.length; i++) {
    if (t[i] === q[qi]) { score += 1; qi++; }
  }
  return qi === q.length ? score : 0;
}

function renderCmdkList() {
  const input = document.getElementById("cmdk-input");
  const list  = document.getElementById("cmdk-list");
  const q = input.value.trim();
  const dynamic = [];

  if (IP_RE.test(q)) {
    dynamic.push({ id: "search-ip", cat: "Search", icon: "\u{1F50D}",
      label: "Filtreaza dupa IP " + q, sub: "Aplica omnisearch",
      run: () => searchIp(q) });
  }

  const scored = COMMANDS
    .map(c => ({ c, score: fuzzyScore(q, c.label + " " + (c.sub || "") + " " + c.cat) }))
    .filter(x => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .map(x => x.c);

  cmdkVisible = dynamic.concat(scored);

  if (cmdkVisible.length === 0) {
    list.innerHTML = '<div class="cmdk-empty">Niciun rezultat</div>';
    return;
  }

  cmdkActiveIdx = Math.min(cmdkActiveIdx, cmdkVisible.length - 1);

  const groups = {};
  cmdkVisible.forEach((c, i) => {
    (groups[c.cat] = groups[c.cat] || []).push({ c, i });
  });

  let html = "";
  const cats = Object.keys(groups).sort((a, b) => {
    const ai = CAT_ORDER.indexOf(a), bi = CAT_ORDER.indexOf(b);
    return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
  });
  for (const cat of cats) {
    html += '<div class="cmdk-cat">' + cat + '</div>';
    for (const {c, i} of groups[cat]) {
      const active = i === cmdkActiveIdx ? " active" : "";
      const kbd = c.kbd ? '<span class="cmdk-kbd">' + c.kbd + '</span>' : '';
      const sub = c.sub ? '<span class="cmdk-sub">' + c.sub + '</span>' : '';
      html += '<div class="cmdk-item' + active + '" data-idx="' + i + '">'
           + '<span class="cmdk-icon">' + c.icon + '</span>'
           + '<span class="cmdk-label">' + c.label + sub + '</span>'
           + kbd
           + '</div>';
    }
  }
  list.innerHTML = html;

  const activeEl = list.querySelector(".cmdk-item.active");
  if (activeEl) activeEl.scrollIntoView({ block: "nearest" });
}

function openCmdk() {
  const overlay = document.getElementById("cmdk-overlay");
  const input = document.getElementById("cmdk-input");
  overlay.hidden = false;
  input.value = "";
  cmdkActiveIdx = 0;
  renderCmdkList();
  setTimeout(() => input.focus(), 0);
}

function closeCmdk() {
  document.getElementById("cmdk-overlay").hidden = true;
}

function runActiveCmdk() {
  const cmd = cmdkVisible[cmdkActiveIdx];
  if (!cmd) return;
  closeCmdk();
  try { cmd.run(); } catch (err) { console.error("cmdk run error", err); }
}

function handleCmdkKey(e) {
  if (e.key === "ArrowDown") {
    e.preventDefault();
    cmdkActiveIdx = Math.min(cmdkActiveIdx + 1, cmdkVisible.length - 1);
    renderCmdkList();
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    cmdkActiveIdx = Math.max(cmdkActiveIdx - 1, 0);
    renderCmdkList();
  } else if (e.key === "Enter") {
    e.preventDefault();
    runActiveCmdk();
  } else if (e.key === "Escape") {
    e.preventDefault();
    closeCmdk();
  }
}

// ==== Keyboard Shortcuts (D16) ====
function handleKeyboard(e) {
  if ((e.key === "k" || e.key === "K") && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    const overlay = document.getElementById("cmdk-overlay");
    if (overlay.hidden) openCmdk(); else closeCmdk();
    return;
  }
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
  if (handleTriageKey(e)) return;
  switch(e.key.toLowerCase()) {
    case "f":
      if (!e.ctrlKey && !e.metaKey) { e.preventDefault(); zoomToFit(); }
      break;
    case " ":
      e.preventDefault(); toggleFreeze();
      break;
    case "escape":
      clearSearch(); clearSelection();
      break;
    case "t":
      if (!e.ctrlKey && !e.metaKey) toggleTheme();
      break;
    case "p":
      if (e.shiftKey && !e.ctrlKey && !e.metaKey) { e.preventDefault(); toggleWorkspace(); }
      break;
    case "g":
      if (e.shiftKey && !e.ctrlKey && !e.metaKey) { e.preventDefault(); toggleAerial(); }
      break;
    case "1": case "2": case "3": case "4": case "5": {
      const types = Object.keys(SCAN_COLORS);
      const idx = parseInt(e.key) - 1;
      if (idx < types.length) {
        const btn = document.querySelector('.filter-btn[data-scan="' + types[idx] + '"]');
        if (btn) toggleScanFilter(btn);
      }
      break;
    }
    case "f11":
      e.preventDefault(); toggleFullscreen();
      break;
  }
}

// ==== Init ====
document.addEventListener("DOMContentLoaded", () => {
  if (localStorage.getItem("ids-theme") === "light") {
    document.documentElement.classList.add("light");
    document.getElementById("btn-theme").innerHTML = "&#9790; Theme";
  }
  document.getElementById("btn-fullscreen").addEventListener("click", toggleFullscreen);
  document.getElementById("btn-export").addEventListener("click", exportPNG);
  document.getElementById("btn-theme").addEventListener("click", toggleTheme);
  document.getElementById("btn-sound").addEventListener("click", toggleSound);
  document.addEventListener("keydown", handleKeyboard);

  initDensity();
  initTriage();
  initMitreClicks();
  initWorkspace();
  initReplay();
  loadFiltersFromUrl();

  // Command palette wiring
  document.getElementById("cmdk-trigger").addEventListener("click", openCmdk);
  document.getElementById("cmdk-input").addEventListener("input", () => {
    cmdkActiveIdx = 0;
    renderCmdkList();
  });
  document.getElementById("cmdk-input").addEventListener("keydown", handleCmdkKey);
  document.getElementById("cmdk-list").addEventListener("click", e => {
    const item = e.target.closest(".cmdk-item");
    if (!item) return;
    cmdkActiveIdx = parseInt(item.dataset.idx, 10);
    runActiveCmdk();
  });
  document.getElementById("cmdk-overlay").addEventListener("click", e => {
    if (e.target.id === "cmdk-overlay") closeCmdk();
  });
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
  if (!isFrozen) simulation.alpha(0.1).restart();
});
</script>
</body>
</html>"##;
