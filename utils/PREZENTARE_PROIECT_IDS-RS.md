# IDS-RS — Intrusion Detection System

## Sistem de detectie si corelare a comportamentelor din log-uri de firewall

---

## DISCURS PREZENTARE — 7 minute

> Text complet — se citeste sau se parafraseaza.
> Continutul de mai jos acopera tot ce e in document.

---

### MINUTUL 1 — Problema si ce am construit

Firewall-ul intern genereaza log-uri pentru fiecare conexiune pe care
o blocheaza. Aceste log-uri nu sunt corelate automat. Firewall-ul
lucreaza per-conexiune — blocheaza un IP pe portul 22, apoi acelasi
IP pe 443, apoi pe 3389, si tot asa. Dar nu coreleaza ca toate vin
de la aceeasi sursa, in cateva secunde, pe zeci de porturi diferite.

Informatia exista in log-uri — nu o procesam.

Am construit un sistem care rezolva asta. IDS-RS este un Intrusion
Detection System scris in Rust. Primeste log-urile de la firewall pe
UDP, le parseaza, le coreleaza si detecteaza automat comportamente
suspicioase: scanari de porturi, miscare laterala, atac coordonat si
beaconing (callback periodic).

Cand un IP bate la 20 de porturi diferite in 10 secunde sau cand un host
incepe sa contacteze rapid multe destinatii interne, sistemul trimite
alerta in timp real — catre SIEM, email si dashboard web.

---

### MINUTUL 2 — Cum functioneaza: parseri, detectie, praguri

Sistemul asculta pe un port UDP si intelege trei formate de log:
Checkpoint Gaia nativ, CEF prin ArcSight, si un format combinat
Gaia-CEF pentru cazul in care ArcSight pune evenimentul brut in
campul Name sau rawEvent.

Din fiecare log extrage: IP sursa, IP destinatie, port, protocol
si actiunea — drop sau accept.

Detectia functioneaza pe sase niveluri:
- Fast Scan — peste 15 porturi unice in 10 secunde (nmap, masscan)
- Slow Scan — peste 30 de porturi in 5 minute (scanare discreta)
- Accept Scan — porturi care raspund, nu doar cele blocate
- Lateral Movement — 1 sursa → N destinatii unice (conexiuni acceptate)
- Distributed Scan — N surse → 1 tinta (atac coordonat)
- Beaconing C2 — flow periodic (coeficient de variatie pe intervale)

Toate pragurile si ferestrele de timp se configureaza din config.toml.

---

### MINUTUL 3 — Ce primeste echipa cand se detecteaza ceva

Alerta pleaca simultan pe trei canale.

In SIEM ajunge un eveniment CEF standard — cu Source Address,
Target Address, numarul de porturi, lista porturilor si severitate.
Se coreleaza direct cu orice altceva din ArcSight.

Pe email primiti un mesaj HTML structurat cu IP sursa, IP tinta,
lista porturilor sau surse/destinatii (in functie de detectie), timestamp
si comenzi gata de executat pentru RHEL —
ss, grep in log-uri, tcpdump, firewall-cmd pentru blocare imediata.
Copy-paste direct in terminal.

In dashboard-ul web vedeti alertele intr-un graf D3.js (atacatori, tinte,
conexiuni), cu auto-refresh. D3.js este servit local, deci functioneaza si
in retele izolate fara internet.

Dashboard-ul arata ca un instrument SOC: tema dark, header cu 3 metrici
(Alerte / Atacatori / Tinte), un sparkline pe ultimele 60 minute,
filtre pe severitate si tip, si jos un tabel cu ultimele alerte.
Click pe un IP deschide un "IP dossier" cu rol (attacker/target),
porturi, peer-i si un timeline al evenimentelor. Exista si un workspace
local (pinned IPs + notite) pentru triage rapid in timpul investigatiei.

Fiecare IP / flow are cooldown — o singura alerta per IP (sau per flow),
per tip de detectie.

---

### MINUTUL 4 — Securitatea sistemului si beneficii

Sistemul se protejeaza singur: Rate Limiting cu Token Bucket impotriva
flood-ului UDP, limita de memorie per IP (10.000, FIFO), limita globala
de IP-uri (100.000, LRU), whitelist IP/CIDR + exceptii pentru reducerea
fals-pozitivelor, sanitizare CEF anti-injection, si validari semantice
la pornire.

Are hot reload la SIGHUP pentru configuratie (praguri/whitelist/alertare),
si graceful shutdown la SIGTERM.

78 de teste unitare, toate trec. Dezvoltat intern — zero licente, zero
dependenta de vendor.

Din punct de vedere de conformitate — demonstram monitorizare activa a
retelei interne, cerinta in ISO 27001 si NIS2.

---

### MINUTUL 5 — Ce putem face in plus cu acces la mai multe log-uri

Platforma e modulara. Cu acces la alte surse de log-uri adaugam
detectii noi fara sa rescriem ce exista.

Din log-uri firewall: brute-force, port-knocking, policy violations
(inter-segment), exfiltrare (volume/anomalii), plus praguri dinamice
calibrate pe baseline (optional).

Din log-uri switching: dispozitive neautorizate (MAC necunoscut),
MAC spoofing, port security violations, DHCP rogue, anomalii STP.

Din log-uri routing: adiacente OSPF pierdute, rute neautorizate,
ACL violations.

Impreuna — firewall, switching, routing — acopera Layer 2 la Layer 7.

---

### MINUTUL 6 — Ce avem nevoie (30s)

Sistemul este pregatit pentru rulare operationala pe log-urile de firewall.

Pentru extindere: acces la export syslog de pe switch-uri si routere,
timp de dezvoltare pentru parseri noi, coordonare cu echipa de retea.

Implementare graduala, fara impact asupra serviciilor.

Aveti documentul complet cu toate detaliile tehnice.

---

> *Dupa discurs: porneste IDS-RS si ruleaza
> `python3 tester/tester.py fast` — audienta va vedea o alerta generata
> in timp real. Optional: deschide dashboard-ul web (`http://127.0.0.1:8080`).*

---
---

## 1. PROBLEMA

### Ce se intampla acum

Firewall-ul intern genereaza log-uri pentru fiecare conexiune blocata.
Aceste log-uri nu sunt corelate automat — firewall-ul raporteaza
fiecare blocaj individual, fara sa identifice tipare.

Un IP care incearca 50 de porturi in 10 secunde genereaza 50 de log-uri
separate. Fiecare log e corect, dar nimeni nu le coreleaza.

### Problema concreta

- Log-urile exista dar nu sunt procesate in timp real
- Nu exista corelare automata a evenimentelor per IP sursa
- Echipa afla despre scanari dupa fapt, nu in momentul in care se intampla
- O statie compromisa poate scana reteaua zile fara sa fie detectata

### Statistici relevante

- **60%** din incidentele de securitate au origine interna
- **204 zile** — timpul mediu de detectie a unei compromitere interne (IBM 2023)
- **83%** din compromiterile reussite au fost precedate de scanare de retea

---

## 2. SOLUTIA: IDS-RS

### Ce este

IDS-RS — Intrusion Detection System scris in Rust. Primeste log-uri
de la firewall pe UDP, le parseaza, le coreleaza si detecteaza automat:
scanari (fast/slow/accept), miscare laterala, scanare distribuita si
beaconing C2. Trimite alerte pe SIEM, email si dashboard web.

### Flux de procesare

```
  Firewall (syslog UDP)
       |
       v
  IDS-RS :5555
  ┌─────────────────────────┐
  │  Parser                 │   Checkpoint Gaia / CEF / Gaia-CEF
  │  ↓                      │
  │  Detector (DashMap)     │   Corelare per IP / tinta / flow
  │  ↓                      │   Fast/Slow/Accept + Lateral/Distributed/Beaconing
  │  Alerter                │   Cand pragul e depasit
  └────────┬────────┬───────┘
           │        │
           v        v
     SIEM (CEF)   Email (SMTP)
     ArcSight     Echipa IT
           |
           v
     Web Dashboard (HTTP)
```

### Scenarii de conectare

**Direct de la firewall:**
```
  Checkpoint Gaia  ──syslog──>  IDS-RS :5555   parser = "gaia"
```

**Prin ArcSight:**
```
  Firewall  ──>  ArcSight SmartConnector  ──>  IDS-RS :5555   parser = "cef"
```

**Prin ArcSight Forwarder (raw syslog):**
```
  ArcSight Forwarder  ──raw syslog──>  IDS-RS :5555   parser = "gaia_cef"
```

---

## 3. DETECTIE — Ce detecteaza si cum

### Tipuri de detectie

| Tip | Prag default | Fereastra | Ce inseamna |
|-----|-------------|-----------|-------------|
| **Fast Scan** | 15 porturi unice | 10 secunde | Scanare agresiva (nmap -F, masscan) |
| **Slow Scan** | 30 porturi unice | 5 minute | Scanare discreta, evaziune praguri |
| **Accept Scan** | 5 porturi unice | 30 secunde | Enumerare servicii active (porturi deschise) |
| **Lateral Movement** | 5 destinatii unice (default) | 60 secunde | 1 sursa → N destinatii (propagare/miscare laterala) |
| **Distributed Scan** | 5 surse unice (default) | 60 secunde | N surse → aceeasi tinta (atac coordonat) |
| **Beaconing C2** | 8 evenimente (min) | 1 ora | flow periodic detectat prin CV pe intervale |

Toate pragurile si ferestrele de timp sunt configurabile in config.toml.

### Cum functioneaza detectia

Pentru fiecare log primit, IDS-RS:
1. Parseaza linia si extrage: IP sursa, IP destinatie, port, protocol, actiune
2. Adauga hit-ul in structurile de corelare (DashMap), in functie de detectie
3. Verifica pragurile si ferestrele de timp din config.toml (inclusiv exceptii)
4. Daca pragul e depasit — genereaza alerta si activeaza cooldown

### Cooldown per IP / flow

Dupa o alerta, acelasi IP (sau flow, pentru Beaconing) nu genereaza alta
alerta de acelasi tip pentru o perioada configurabila. Previne sute de
alerte identice.

---

## 4. ALERTARE — Ce primeste echipa

### Alerta in SIEM (ArcSight)

Eveniment CEF standard:

```
+-----------------+-----------------+------+----------+------------------------------------+
| Source Address  | Target Address  | Cnt  | Priority | Message                            |
+-----------------+-----------------+------+----------+------------------------------------+
| 192.168.10.45   | 10.0.0.1       |  20  | High     | Fast Scan: 20 porturi in 10s       |
|                 |                 |      |          | ports: 21,22,23,80,443,...          |
+-----------------+-----------------+------+----------+------------------------------------+
```

Campuri disponibile:
- **Source Address** — IP-ul care scaneaza
- **Target Address** — IP-ul scanat
- **Cnt** — numarul de porturi unice
- **cs1 (ScannedPorts)** — lista completa a porturilor

### Alerta pe email

Email HTML structurat cu:

```
  DETALII EVENIMENT
  ─────────────────
  Tip:              Fast Scan
  Severitate:       RIDICATA
  IP Sursa:         192.168.10.45
  IP Destinatie:    10.0.0.1
  Porturi scanate:  20
  Timestamp:        2026-02-26 14:30:00

  PORTURI DETECTATE
  21, 22, 23, 25, 53, 80, 110, 443, 3389, 8080, ...

  COMENZI RAPIDE — RHEL
  ──────────────────────
  ss -tnp | grep 192.168.10.45
  grep 192.168.10.45 /var/log/secure /var/log/messages
  tcpdump -i any host 192.168.10.45 -n -c 30
  firewall-cmd --add-rich-rule='rule family="ipv4"
       source address="192.168.10.45" drop' --permanent
  ip neigh show | grep 192.168.10.45
```

Comenzile sunt gata de copy-paste — inginerul nu trebuie sa compuna nimic.

### Web Dashboard (HTTP) — cum arata si ce face

Dashboard-ul este o pagina web servita direct de IDS-RS (server HTTP embedded).
Este read-only: afiseaza alertele deja generate de motorul de detectie si nu
modifica starea detectorului.

Cum arata:
- tema dark (cu toggle optional light)
- header cu: Alerte / Atacatori / Tinte + sparkline "alerte/minut" (60 min)
- bara de filtre: severitate (Critical/High/Medium), tip detectie, heatmap 24h
- graf D3.js force-directed: noduri IP si muchii (atacator → tinta), colorate pe tip
- tabel jos cu ultimele alerte (newest first), cu badge de tip si actiuni de triage
- side-panel "IP dossier" pentru investigatie: rol, top peers, porturi, timeline
- "Investigation workspace": pinned IP-uri + notite, persistate local (browser)

Ce face (functional):
- refresh automat la 5 secunde (citeste API JSON)
- cautare/filtrare dupa IP (graful + tabelul se restrang la acel IP)
- filtre pe tipuri de alerta si pe severitati (inclusiv exclude cu Shift)
- click pe nod: deschide IP dossier (date complete pentru acel IP)
- zoom/pan, freeze/play simulare, pin/unpin noduri, fullscreen
- export PNG al grafului pentru raportare
- D3.js servit local la `/static/d3.min.js` (fara CDN, merge air-gapped)

Unde il accesam:
`http://127.0.0.1:8080` (configurabil in `config.toml`).

### Tipuri de alerta

| Tip detectie | Severitate CEF | Signature ID |
|-------------|----------------|--------------|
| **Fast Scan** | 7 (High) | 1001 |
| **Slow Scan** | 6 (Medium) | 1002 |
| **Accept Scan** | 5 (Low) | 1003 |
| **Lateral Movement** | 8 (Critical) | 1004 |
| **Distributed Scan** | 7 (High) | 1005 |
| **Beaconing C2** | 9 (Critical) | 1006 |

---

## 5. SECURITATEA SISTEMULUI

### Vectori de atac si protectii implementate

| Vector de atac | Protectie | Cum functioneaza |
|---------------|-----------|-----------------|
| **Flood UDP** (IP spoofing, amplificare) | Rate Limiting — Token Bucket | Limiteaza rata de procesare, ignora excesul |
| **Scanner agresiv** (OOM per IP) | MAX_HITS_PER_IP = 10.000 | FIFO — elimina cele mai vechi, pastreaza cele recente |
| **Milioane de IP-uri spoofate** (OOM global) | MAX_TRACKED_IPS = 100.000 | LRU eviction — elimina IP-ul cel mai vechi |
| **Injectie alerte false** in SIEM | Sanitizare CEF | Escape `\|`, `\n`, `\r`, `\\` in campuri text |
| **Config gresita** → crash | Validari la pornire | Raporteaza toate erorile simultan, nu porneste |

Toate valorile sunt configurabile in config.toml.

### Teste

- **78 teste unitare** — parseri, detector, alerter, sanitizare, detectii noi
- **Tester Python** — simulator trafic: fast, slow, normal, lateral, distributed, beaconing
- **Clippy** — 0 warnings noi din codul aplicatiei

---

## 6. BENEFICII

### Tehnice

- Detectie automata 24/7 — nu depinde de disponibilitatea unui analist
- Timp de raspuns: de la zile/saptamani la secunde
- Corelare automata a evenimentelor per IP sursa
- Comenzi de reactie gata de executat in fiecare alerta

### Operationale

- Un singur fisier de configurare (config.toml)
- Curatare automata a datelor expirate
- Compatibil cu infrastructura existenta (Checkpoint + ArcSight)
- Implementare graduala, fara impact asupra serviciilor

### Financiare

- Dezvoltat intern — zero licente recurente
- Zero dependenta de furnizor extern
- Echivalentul comercial (Darktrace, Vectra, ExtraHop): zeci de mii EUR/an

### Conformitate

- Monitorizare activa a retelei interne — cerinta ISO 27001, NIS2
- Audit trail complet — fiecare alerta inregistrata in SIEM
- Evidenta concreta pentru audituri de securitate

---

## 7. PARSERI IMPLEMENTATI

| Parser | Format | Sursa | Status |
|--------|--------|-------|--------|
| **Checkpoint Gaia** | Syslog nativ Checkpoint | Direct de la firewall | Implementat |
| **CEF / ArcSight** | Common Event Format | Prin SmartConnector | Implementat |
| **Gaia-CEF** | LEA blob in CEF Name / rawEvent / raw | Prin ArcSight Forwarder | Implementat |
| **FortiGate** | Format nativ Fortinet | Direct de la firewall | Planificat |

### Gaia-CEF — trei scenarii acceptate automat

Parser-ul `gaia_cef` detecteaza automat formatul cu fallback:

1. **Blob LEA in CEF Name** (index 5) — ArcSight pune blob-ul in campul Name
2. **Blob LEA in extensia CEF** (rawEvent= sau cs6=) — cu unescape `\=` → `=`
3. **Blob LEA raw** — fara wrapper CEF, direct `key="value"` sau `key=value`

Accepta valori cu si fara ghilimele. Boundary check — `rule_action` nu se
confunda cu `action`, `service_id` nu se confunda cu `service`.

---

## 8. ARHITECTURA SI STRUCTURA

### Componente

```
ids-rs/
├── config.toml             # Configurare completa (un singur fisier)
├── static/
│   ├── dashboard.html       # UI dashboard (D3.js)
│   └── d3.v7.min.js         # D3.js servit local (air-gapped)
├── src/
│   ├── main.rs             # UDP listener, orchestrare async (tokio)
│   ├── config.rs           # Deserializare TOML + validari semantice
│   ├── detector.rs         # DashMap per IP, Fast/Slow/Accept Scan, cooldown
│   ├── alerter.rs          # SIEM (UDP CEF) + Email (SMTP async, lettre)
│   ├── display.rs          # Output terminal colorat (colored)
│   ├── web.rs              # Server HTTP dashboard (axum)
│   └── parser/
│       ├── mod.rs          # Trait LogParser + factory create_parser()
│       ├── gaia.rs         # Parser Checkpoint Gaia (regex)
│       ├── cef.rs          # Parser CEF (split pipe + key=value)
│       └── gaia_cef.rs     # Parser Gaia-CEF (3 strategii, boundary check)
└── tester/
    ├── tester.py           # Simulator trafic: preset-uri + generare dinamica
    ├── smtp_server.py      # SMTP server local (pentru demo/test)
    └── sample_*.log        # 9 fisiere sample pre-generate
```

### Stack tehnic

| Componenta | Librarie |
|-----------|---------|
| Async runtime | tokio |
| Web dashboard | axum |
| Structuri concurente | DashMap |
| Parsare config | serde + toml |
| Email SMTP | lettre (async) |
| JSON | serde_json |
| Hot reload config | arc-swap |
| Regex | regex |
| Timestamp | chrono |
| Logging | tracing |
| Erori | anyhow |
| Output colorat | colored |

---

## 8.1 WEB DASHBOARD — implementare si integrare cu IDS-RS

### Cum este integrat

Dashboard-ul nu este o aplicatie separata. Este pornit din acelasi binar `ids-rs`:

1. `main.rs` creeaza un `AlertBuffer` comun (`Arc<Mutex<VecDeque<Alert>>>`).
2. La fiecare alerta generata, IDS-RS face `push_back(alert)` in buffer (buffer circular, limitat la `web_dashboard.max_alerts`).
3. Daca `[web_dashboard].enabled = true`, IDS-RS porneste serverul HTTP (Axum) intr-un task tokio separat.
4. Dashboard-ul citeste buffer-ul, face snapshot rapid sub lock si returneaza JSON catre browser.

### Server-side (Rust)

Implementarea este in `src/web.rs`:
- Router Axum cu:
  - `GET /` → `static/dashboard.html` (imbeddeat in binar cu `include_str!`)
  - `GET /static/d3.min.js` → D3.js v7 (imbeddeat in binar)
  - `GET /api/alerts` → ultimele alerte (optional `?ip=...` pentru filtrare)
  - `GET /api/graph` → noduri/muchii agregate din alerte (optional `?ip=...`)
  - `GET /api/ip/{ip}` → IP dossier (roluri, porturi, peers, timeline)

Constructia grafului trateaza explicit cazurile:
- Lateral Movement: o alerta produce muchii catre fiecare destinatie din `unique_dests`
- Distributed Scan: o alerta produce muchii pentru toate sursele din `unique_sources`

### Client-side (HTML/JS)

UI-ul este in `static/dashboard.html`:
- D3 force simulation pentru layout-ul grafului
- refresh loop cu `fetch("/api/graph")` si `fetch("/api/alerts")` la 5s
- filtre si state in URL + localStorage (triage/workspace/theme)
- interactiuni: click IP → dossier, selectii, isolate, export PNG, fullscreen

### Configurare si securitate

Configurarea este in `[web_dashboard]` in `config.toml`:
- `enabled`: porneste/oprire dashboard
- `bind`: implicit `127.0.0.1` (doar local); `0.0.0.0` daca vrei acces din retea
- `port`: implicit `8080`
- `max_alerts`: dimensiunea buffer-ului circular

Nota operationala: schimbarea `bind/port` necesita restart (nu se aplica la SIGHUP).

## 9. POTENTIAL DE DEZVOLTARE

### 9.1 Extindere detectii din log-uri FIREWALL (sursa actuala)

Detectii deja implementate din log-uri firewall:
- Lateral Movement
- Beaconing C2
- Distributed Scan

Detectii suplimentare propuse:

| Detectie | Logica | Aplicabilitate |
|----------|--------|---------------|
| **Brute-force** | multe conexiuni repetate pe acelasi port catre aceeasi tinta | SSH/RDP brute-force |
| **Port-knocking** | secventa de porturi accesate in ordine | backdoors, acces ascuns |
| **Policy violation** | acces inter-segment interzis (ex: Workstations → DMZ direct) | misconfig / intentie |
| **Exfiltrare** | volum outbound anormal, ore non-lucru, porturi neobisnuite | data exfiltration |

### 9.2 Detectii noi din log-uri SWITCHING (viitor)

| Detectie | Ce apare in log | Aplicabilitate |
|----------|----------------|---------------|
| **Dispozitiv neautorizat** | MAC necunoscut pe un port switch | Rogue device, laptop personal |
| **MAC spoofing** | Acelasi MAC pe doua porturi diferite | Man-in-the-middle |
| **Port security violation** | Max MAC exceeded / MAC not in allowed list | Echipament neautorizat + port fizic |
| **DHCP rogue** | DHCP OFFER de pe port non-trusted | Redirectare trafic |
| **Anomalii STP** | Root Bridge change, Topology Change | Atac L2, interceptare trafic |
| **Link Up/Down suspect** | Conectari/deconectari repetate in afara programului | Manipulare fizica |

### 9.3 Detectii noi din log-uri ROUTING (viitor)

| Detectie | Ce apare in log | Aplicabilitate |
|----------|----------------|---------------|
| **Adiacenta pierduta** | OSPF/BGP Neighbor DOWN | Defectiune sau atac routing |
| **Ruta neautorizata** | Ruta noua anuntata via OSPF/BGP | Route hijacking |
| **Route flapping** | Ruta UP/DOWN repetat | Echipament defect sau DoS |
| **ACL violation** | Pachet blocat de ACL pe router | Tentativa acces inter-segment |

### 9.4 Rezumat acoperire

```
  SURSA LOG-URI          ACUM                    POTENTIAL
  ════════════════       ═══════════════         ═════════════════════════
  Firewall               Corelare + detectie:    + Brute-force
  (ACTIV)                fast/slow/accept        + Exfiltrare
                         + lateral movement      + Policy violations
                         + distributed scan
                         + beaconing C2
                         + dashboard web
                                                 + Exfiltrare
                                                 + Policy violations

  Switching              —                       Dispozitive neautorizate
  (VIITOR)                                       MAC spoofing
                                                 Port security
                                                 DHCP rogue
                                                 Anomalii STP

  Routing                —                       Adiacente pierdute
  (VIITOR)                                       Rute neautorizate
                                                 Route flapping
                                                 ACL violations
```

Firewall + Switching + Routing = acoperire Layer 2 — Layer 7.

Platforma IDS-RS suporta deja mai multi parseri si tipuri de detectie.
Extinderea este naturala — parseri noi, detectori noi, aceeasi alertare.

---

## 10. CERERE

Sistemul este pregatit pentru rulare operationala pe log-urile de firewall.

**Ce avem nevoie pentru extindere:**

- Acces la export syslog de pe switch-uri si routere (UDP)
- Timp de dezvoltare pentru parseri noi
- Coordonare cu echipa de retea pentru configurarea initiala

**Ce livram:**

- Sistem functional, testat (78 teste), documentat
- Dezvoltat intern — zero costuri de licenta
- Implementare graduala, fara impact asupra serviciilor
- Compatibil cu infrastructura existenta

---
