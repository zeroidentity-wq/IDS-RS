# IDS-RS — Intrusion Detection System

Sistem de detectie a intruziunilor bazat pe analiza log-urilor de firewall, scris in Rust.
Detecteaza scanari de retea (Fast Scan, Slow Scan si Accept Scan) si trimite alerte catre SIEM si email.

---

## Cuprins

- [Stare proiect](#stare-proiect)
- [Arhitectura](#arhitectura)
- [Cerinte sistem](#cerinte-sistem)
- [Compilare](#compilare)
- [Configurare](#configurare)
- [Formate de log — Anatomie si flux](#formate-de-log--anatomie-si-flux)
- [Calatoria unui eveniment — De la firewall la SIEM](#calatoria-unui-eveniment--de-la-firewall-la-siem)
- [Rulare](#rulare)
- [Testare](#testare)
- [Structura proiect](#structura-proiect)
- [Protectie memorie — MAX\_HITS\_PER\_IP](#protectie-memorie--max_hits_per_ip)
- [Protectie DashMap — MAX\_TRACKED\_IPS si LRU Eviction](#protectie-dashmap--max_tracked_ips-si-lru-eviction)
- [Securitate — Sanitizare campuri CEF anti-injection](#securitate--sanitizare-campuri-cef-anti-injection)
- [Rate Limiting UDP — Token Bucket](#rate-limiting-udp--token-bucket)
- [Concepte Rust acoperite](#concepte-rust-acoperite)

---

## Stare proiect

| Categorie | Detalii |
|-----------|---------|
| **Detectie** | Fast Scan, Slow Scan, Accept Scan — toate funcționale |
| **Parseri** | Checkpoint Gaia, CEF/ArcSight |
| **Alertare** | SIEM (UDP CEF), Email (SMTP async) |
| **Securitate** | Sanitizare CEF, Rate Limiting UDP, MAX_HITS_PER_IP, MAX_TRACKED_IPS LRU |
| **Validare** | 16 constrângeri semantice la startup |
| **Teste** | 33 teste unitare — toate trec |
| **Clippy** | 7 warnings pre-existente (cosmetice, niciuna funcțională) |

### Implementat

- [x] Detectie Fast Scan + Slow Scan + Accept Scan
- [x] Parseri Gaia si CEF
- [x] Alertare SIEM (UDP CEF) si Email (SMTP async cu cache transport)
- [x] Sanitizare campuri CEF anti-injection
- [x] Rate Limiting UDP (Token Bucket)
- [x] Protectie memorie: MAX_HITS_PER_IP (FIFO) + MAX_TRACKED_IPS (LRU eviction)
- [x] Validare config cu raportare cumulata (16 constrangeri)
- [x] Teste unitare: 33 passed (parseri, detector, alerter)

### De implementat

- [ ] Parser FortiGate (format Fortinet)
- [ ] Raport zilnic email cu clasificare subretele
- [ ] Whitelist IP-uri (IP + CIDR)
- [ ] Webhook alerting (Slack/Teams)
- [ ] Statistici live in terminal (AtomicU64 counters)
- [ ] Hot reload config la SIGHUP

---

## Arhitectura

```
                          +-------------------+
  Firewall (Gaia/CEF) -->| UDP :5555         |
  log-uri syslog         | LogParser (trait)  |
                          |   - GaiaParser    |
                          |   - CefParser     |
                          +--------+----------+
                                   |
                                   v
                          +-------------------+
                          | Detector          |
                          | DashMap per IP    |
                          | Fast Scan check   |
                          | Slow Scan check   |
                          | Accept Scan check |
                          +--------+----------+
                                   |
                            Alerta detectata?
                           /                \
                          v                  v
                  +---------------+   +---------------+
                  | SIEM (UDP)    |   | Email (SMTP)  |
                  | ArcSight :514 |   | lettre async  |
                  +---------------+   +---------------+
```

**Fluxul de date:**

1. Firewall-ul trimite log-uri syslog pe UDP catre portul configurat (default `5555`)
2. Pachetele UDP sunt receptionate asincron (`tokio`) si splituite pe newline (buffer coalescing)
3. Fiecare linie este parsata cu parser-ul activ (`gaia` sau `cef`), selectat din `config.toml`
4. Evenimentele de tip `drop` si `accept` sunt inregistrate in detectorul thread-safe (`DashMap`)
5. Daca un IP depaseste pragul de porturi unice intr-o fereastra de timp, se genereaza o alerta (Fast/Slow/Accept Scan)
6. Alerta este afisata in terminal (colorat ANSI) si trimisa catre SIEM / email
7. Un task de cleanup periodic sterge datele vechi din memorie

---

## Cerinte sistem

### RHEL 9.6

```bash
# Compilator Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Dependente sistem (pentru native-tls / OpenSSL)
sudo dnf install -y gcc openssl-devel pkg-config
```

### Windows 10/11

- [Rust](https://rustup.rs/) (include cargo)
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) cu componenta "C++ build tools"

### Verificare instalare

```bash
cargo --version    # cargo 1.x.x
rustc --version    # rustc 1.x.x
python3 --version  # Python 3.10+ (pentru tester)
```

---

## Compilare

```bash
# Debug (compilare rapida, fara optimizari)
cargo check        # doar verificare sintaxa + tipuri
cargo build        # compilare completa

# Release (optimizat pentru productie)
cargo build --release

# Teste unitare
cargo test
```

Binarele se gasesc in:
- Debug: `target/debug/ids-rs`
- Release: `target/release/ids-rs`

---

## Configurare

Toate setarile sunt in `config.toml`. Nicio valoare nu este hardcodata.

### Validare automata la pornire

La incarcare, `AppConfig::validate()` verifica semantic toate valorile din configurare.
Daca exista erori, aplicatia nu porneste si listeaza **toate problemele** dintr-o singura data:

```
FATAL: config.toml contine 3 erori de configurare:
  1. detection.fast_scan.port_threshold = 0: orice pachet va declansa alerta Fast Scan
  2. detection.slow_scan.time_window_mins (1 min = 60s) trebuie sa fie mai mare decat
     detection.fast_scan.time_window_secs (300s)
  3. cleanup.max_entry_age_secs (30) este mai mic decat fereastra Slow Scan (5 min = 300s):
     datele necesare detectiei Slow Scan vor fi sterse prematur
```

Constrangerile validate:

| Camp | Constrangere |
|------|-------------|
| `network.listen_port` | ≠ 0 |
| `network.parser` | `"gaia"` sau `"cef"` |
| `detection.alert_cooldown_secs` | ≥ 1 |
| `detection.fast_scan.port_threshold` | ≥ 1 |
| `detection.fast_scan.time_window_secs` | ≥ 1 |
| `detection.slow_scan.port_threshold` | ≥ 1 |
| `detection.slow_scan.time_window_mins` | ≥ 1 |
| `detection.accept_scan.port_threshold` | ≥ 1 |
| `detection.accept_scan.time_window_secs` | ≥ 1 |
| Fereastra Slow Scan | > fereastra Fast Scan |
| `cleanup.interval_secs` | ≥ 1 |
| `cleanup.max_entry_age_secs` | ≥ fereastra Slow Scan |
| `alerting.siem.port` (daca enabled) | ≠ 0 |
| `alerting.siem.host` (daca enabled) | nenul |
| `alerting.email.smtp_port` (daca enabled) | ≠ 0 |
| `alerting.email.smtp_server` (daca enabled) | nenul |
| `alerting.email.from` (daca enabled) | nenul |
| `alerting.email.to` (daca enabled) | cel putin un destinatar |
| `network.udp_burst_size` (daca `udp_rate_limit` > 0) | ≥ 1 |
| `network.udp_burst_size` (daca `udp_rate_limit` > 0) | ≥ `udp_rate_limit` (warning) |

```toml
[network]
listen_address = "0.0.0.0"    # Interfata de ascultare
listen_port = 5555             # Port UDP pentru receptie log-uri
parser = "gaia"                # Parser activ: "gaia" sau "cef"
# debug = true                 # Mod debug: afiseaza fiecare pachet cu validare parsare

[detection]
alert_cooldown_secs = 300      # Cooldown intre alerte pentru acelasi IP

[detection.fast_scan]
port_threshold = 15            # Alerta daca IP acceseaza > N porturi unice...
time_window_secs = 10          # ...in acest interval (secunde)

[detection.slow_scan]
port_threshold = 30            # Alerta daca IP acceseaza > N porturi unice...
time_window_mins = 5           # ...in acest interval (minute)

[detection.accept_scan]
port_threshold = 5             # Alerta daca IP acceseaza > N porturi DESCHISE unice...
time_window_secs = 30          # ...in acest interval (secunde)

[alerting.siem]
enabled = true
host = "127.0.0.1"            # Adresa SIEM (ArcSight)
port = 514                     # Port UDP syslog

[alerting.email]
enabled = false
smtp_server = "smtp.example.com"
smtp_port = 587
smtp_tls = true
from = "ids-rs@example.com"
to = ["it-security@example.com"]
username = "ids-rs@example.com"
password = "changeme"

[cleanup]
interval_secs = 60            # Frecventa task cleanup
max_entry_age_secs = 600      # Sterge date mai vechi de N secunde
```

### Formate de log suportate

**Checkpoint Gaia (Raw)** — format real cu header complet:
```
Sep 3 15:12:20 192.168.99.1 Checkpoint: 3Sep2007 15:12:08 drop 192.168.11.7 >eth8 rule: 113; rule_uid: {AAAA-...}; service_id: http; src: 192.168.11.34; dst: 4.23.34.126; proto: tcp; product: VPN-1 & FireWall-1; service: 80; s_port: 2854;
```

**CEF / ArcSight** (cu syslog header):
```
<134>Feb 17 11:32:44 gw-hostname CEF:0|CheckPoint|VPN-1 & FireWall-1|R81.20|100|Drop|5|src=192.168.11.7 dst=10.0.0.1 dpt=443 proto=TCP act=drop
```

---

## Formate de log — Anatomie si flux

Aceasta sectiune explica structura exacta a fiecarui format suportat si cum ajung
datele de la firewall pana la IDS-RS.

---

### Formatul Checkpoint GAIA (Raw)

Checkpoint GAIA este un firewall enterprise. Cand blocheaza sau permite o conexiune,
genereaza un eveniment pe care il trimite prin **syslog** (UDP, port 514 implicit)
catre un server de logging. Un rand arata astfel:

```
Sep  3 15:12:20 192.168.99.1 Checkpoint: 3Sep2007 15:12:08 drop 192.168.11.7 >eth8 rule: 113; src: 192.168.11.34; dst: 4.23.34.126; proto: tcp; service: 80; s_port: 2854;
```

Anatomia unui rand GAIA:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         UN RAND DE LOG GAIA                             │
├───────────────────┬──────────────┬──────────────────────────────────────┤
│   HEADER SYSLOG   │              │         CORPUL CHECKPOINT            │
│  (adaugat de      │              │   (generat de firewall)              │
│   syslog daemon)  │              │                                      │
├───────────────────┤              ├──────────┬──────────┬────┬───────────┤
│ Sep  3 15:12:20   │ 192.168.99.1 │ 3Sep2007 │ 15:12:08 │drop│ src: ... │
│ (cand a PRIMIT    │ (cine a      │ (cand a  │          │    │ dst: ... │
│  serverul log-ul) │  trimis)     │  GENERAT │          │    │ service: │
│                   │              │  fw-ul)  │          │    │ 80       │
└───────────────────┴──────────────┴──────────┴──────────┴────┴───────────┘
```

**Diferenta dintre cele doua timestamp-uri** este intentionata si normala:
- Header syslog (`15:12:20`) — momentul in care serverul de logging a **primit** mesajul
- Timestamp Checkpoint (`15:12:08`) — momentul in care firewall-ul a **generat** evenimentul

Diferenta de ~12 secunde reprezinta latenta de retea si buffering-ul syslog. In log-uri
reale (ex: `sample2_gaia.log`) vei vedea ca secundele difera tocmai din acest motiv.

**Formatul datei `3Sep2007`** este formatul intern compact al Checkpoint:
`<zi><LunăAbreviere><an>` concatenat fara separatori. Nu este o greseala.

Campurile cheie-valoare din coada liniei sunt separate prin `;` si parsate de `gaia.rs`:

| Camp | Exemplu | Semnificatie |
|------|---------|--------------|
| `src` | `192.168.11.34` | IP-ul care a initiat conexiunea (atacatorul) |
| `dst` | `4.23.34.126` | IP-ul destinatie |
| `proto` | `tcp` | Protocolul |
| `service` | `80` | Portul destinatie (cel scanat) |
| `s_port` | `2854` | Portul sursa (ales aleator de OS) |

---

### Formatul CEF (Common Event Format)

CEF a fost creat de ArcSight pentru a **standardiza** log-urile de la zeci de
producatori diferiti (Checkpoint, Cisco, Palo Alto, etc.) intr-un format unic,
usor de parsat de SIEM-uri.

Structura este fixa, cu `|` ca separator intre campuri:

```
<prefix_syslog> CEF:Versiune|Vendor|Produs|VersiuneProdus|SignatureID|Nume|Severitate|Extensii
```

Un exemplu concret:

```
<134>Feb 17 11:32:44 gw-checkpoint CEF:0|CheckPoint|VPN-1 & FireWall-1|R81.20|100|Drop|5|src=192.168.11.34 dst=4.23.34.126 dpt=80 proto=TCP act=drop
```

Anatomia unui rand CEF:

```
<134>            → prioritate syslog (facility=16, severity=6)
Feb 17 11:32:44  → timestamp syslog
gw-checkpoint    → hostname-ul dispozitivului
CEF:0            → versiunea formatului (0 = prima versiune)
CheckPoint       → vendor (producatorul)
VPN-1 & FW-1    → produsul
R81.20           → versiunea produsului
100              → ID-ul regulii / evenimentului
Drop             → numele evenimentului
5                → severitatea (0=scazuta ... 10=critica)
                 → extensii (key=value, separate prin spatiu):
  src=192.168.11.34  → IP sursa
  dst=4.23.34.126    → IP destinatie
  dpt=80             → destination port (portul scanat)
  proto=TCP          → protocolul
  act=drop           → actiunea firewall-ului
```

Parsatorul nostru (`cef.rs`) cauta `CEF:` oriunde in linie (prefix-ul syslog poate
lipsi sau varia), apoi desparte cu `|` si itereaza extensiile ca perechi `cheie=valoare`.

---

### Cum ajung datele pe portul 5555 — Fluxul real cu ArcSight Forwarder

In productie, exista doua scenarii posibile:

#### Scenariul A — Firewall direct catre IDS-RS (format GAIA)

```
Checkpoint          syslog GAIA          IDS-RS
Firewall     ──────────────────────▶    UDP :5555
             UDP :514 (sau alt port)    parser = "gaia"
```

Firewall-ul este configurat sa trimita log-urile direct pe portul 5555 al IDS-RS.
IDS-RS le primeste in format GAIA si le parseaza cu `GaiaParser`.

#### Scenariul B — Prin ArcSight SmartConnector / Forwarder (format CEF)

```
Checkpoint     syslog GAIA    ArcSight         CEF           IDS-RS
Firewall  ───────────────▶  SmartConnector ───────────────▶  UDP :5555
          UDP :514           (normalizeaza)   UDP :5555       parser = "cef"
```

**ArcSight SmartConnector** (numit si Forwarder) este un agent software care:
1. **Primeste** log-urile raw GAIA de la firewall pe UDP 514
2. **Normalizeaza** — le converteste in format CEF standard
3. **Retrimite** in CEF catre destinatia configurata (IDS-RS) pe UDP 5555

Acesta este scenariul tipic in organizatii cu SIEM ArcSight deja instalat.
IDS-RS-ul nostru vede doar CEF, nu stie ca log-urile au venit initial in GAIA.

**Ce ajunge efectiv in buffer-ul UDP pe portul 5555:**

Fiecare pachet UDP contine unul sau mai multe randuri de log, separate prin `\n`
(parametrul `--batch` din tester controleaza cate randuri intra intr-un pachet):

```
Pachet UDP #1  →  <134>Feb 17 11:32:44 gw CEF:0|...|src=10.0.0.1 dpt=80 act=drop\n

Pachet UDP #2  →  <134>Feb 17 11:32:45 gw CEF:0|...|src=10.0.0.1 dpt=443 act=drop\n
                  <134>Feb 17 11:32:45 gw CEF:0|...|src=10.0.0.2 dpt=22 act=accept\n
```

IDS-RS primeste pachetul, il imparte pe `\n`, si parseaza fiecare linie independent.

#### Cum alegi scenariul in config.toml

```toml
[network]
parser = "gaia"   # Scenariul A: firewall trimite GAIA direct la IDS-RS
parser = "cef"    # Scenariul B: ArcSight Forwarder trimite CEF la IDS-RS
```

In productie reala vei folosi cel mai probabil `parser = "cef"` daca ai deja
un ArcSight SmartConnector instalat, deoarece acesta normalizeaza totul la CEF.
Modul `"gaia"` este util cand conectezi firewall-ul **direct** la IDS-RS, fara intermediar.

---

## Calatoria unui eveniment — De la firewall la SIEM

Aceasta sectiune urmareste un eveniment real pas cu pas, de la momentul in care
firewall-ul blocheaza o conexiune pana cand alerta apare in interfata ArcSight.

---

### Etapa 1 — Firewall trimite log-ul, IDS-RS il primeste

Un atacator de la `192.168.11.7` bate la 20 de porturi diferite. Firewall-ul
Checkpoint blocheaza fiecare conexiune si trimite cate un log pe UDP:

```
Sep 3 15:12:08 192.168.99.1 Checkpoint: 3Sep2007 15:12:08 drop 192.168.11.7 >eth8
rule: 113; src: 192.168.11.7; dst: 10.0.0.1; proto: tcp; service: 443; s_port: 2854;
```

Pachetul UDP ajunge la IDS-RS pe portul 5555. In `main.rs`:

```rust
result = socket.recv_from(&mut buf)          // primim bytes bruti
let data = String::from_utf8_lossy(&buf[..len]); // bytes -> text
for line in data.lines() { ... }            // separam log-urile pe \n (buffer coalescing)
```

Daca in acelasi pachet UDP au venit mai multe log-uri lipite (batch), `.lines()`
le separa si le proceseaza pe rand.

---

### Etapa 2 — Parserul extrage ce ne intereseaza

Fiecare linie trece prin parser (`main.rs:306`):

```rust
if let Some(event) = parser.parse(line) { ... }
```

Parser-ul GAIA (`gaia.rs`) face doua lucruri:
1. Gaseste cuvantul `drop` sau `accept` dupa `Checkpoint:` cu un regex
2. Extrage campurile `src:`, `dst:`, `proto:`, `service:` prin split dupa `;`

- Daca actiunea este `reject` sau alta valoare necunoscuta → returneaza `None`, linia este ignorata
- Daca actiunea este `drop` sau `accept` → returneaza un `LogEvent`:

```rust
LogEvent {
    source_ip:  192.168.11.7,    // atacatorul
    dest_ip:    Some(10.0.0.1),  // IP-ul tinta (din campul dst:)
    dest_port:  443,              // portul pe care a batut
    protocol:   "tcp",
    action:     "drop",          // sau "accept" pentru porturi deschise
    raw_log:    "Sep 3 15:12..."  // linia originala, pastrata pentru audit
}
```

---

### Etapa 3 — Detectorul numara si decide

`LogEvent`-ul intra in detector (`main.rs:324`):

```rust
let alerts = detector.process_event(&event);
```

Detectorul tine in memorie (DashMap) un jurnal per IP sursa:

```
192.168.11.7  →  [ port:80 la t=0s, port:443 la t=1s, port:22 la t=2s, ... ]
```

Evenimentele `drop` sunt stocate in `port_hits`, evenimentele `accept` in `accept_hits`
(harti separate pentru a nu contamina detectia). La fiecare eveniment nou verifica
**trei ferestre de timp** independente:

```
Fast Scan:   cate porturi UNICE BLOCATE (drop) a atins IP-ul in ultimele 10 secunde?
             daca > 15  →  ALERTA Fast Scan (SigID 1001, severitate High)

Slow Scan:   cate porturi UNICE BLOCATE (drop) a atins IP-ul in ultimele 5 minute?
             daca > 30  →  ALERTA Slow Scan (SigID 1002, severitate Medium)

Accept Scan: cate porturi UNICE ACCEPTATE (accept) a atins IP-ul in ultimele 30 secunde?
             daca > 5   →  ALERTA Accept Scan (SigID 1003, severitate Low-Medium)
```

Cand pragul este depasit, creeaza un struct `Alert`:

```rust
Alert {
    scan_type:    ScanType::Fast,        // sau Slow, sau AcceptScan
    source_ip:    192.168.11.7,
    dest_ip:      Some(10.0.0.1),        // IP-ul tinta (din log)
    unique_ports: [21, 22, 23, 25, 53, 80, 110, 443, ...],
    timestamp:    2026-02-18T12:06:16
}
```

Dupa prima alerta, seteaza un **cooldown de 5 minute** pentru acel IP — daca
atacatorul continua, nu se genereaza sute de alerte identice.

---

### Etapa 4 — Construim mesajul CEF si il trimitem

Alerta intra in `alerter.rs` (`main.rs:332`):

```rust
alerter.send_alert(&alert).await;
```

Functia `send_siem_alert()` construieste mesajul in trei pasi:

**Pas 1** — Determina tipul scanarii si alege Signature ID si textul:

```rust
match alert.scan_type {
    ScanType::Fast      => (sig_id = "1001", name = "Fast Port Scan Detected",   severity = 7)
    ScanType::Slow      => (sig_id = "1002", name = "Slow Port Scan Detected",   severity = 6)
    ScanType::AcceptScan => (sig_id = "1003", name = "Accept Port Scan Detected", severity = 5)
}
```

**Pas 2** — Construieste lista de porturi:
```
port_list = "21,22,23,25,53,80,110,443,445,3389,..."
```

**Pas 3** — Asambleaza mesajul CEF complet. Acesta este **exact ce zboara
pe retea** ca pachet UDP catre `127.0.0.1:514`:

```
<38>Feb 18 12:06:16 ids-rs CEF:0|IDS-RS|Network Scanner Detector|1.0|1001|Fast Port Scan Detected|7|rt=1739876776000 src=192.168.11.7 cnt=20 act=alert msg=Fast Scan detectat: 20 porturi unice in 10 secunde cs1Label=ScannedPorts cs1=21,22,23,25,53,80,110,443,445,3389,8080,8443,3306,1433,5432,27017,6379,11211,9200,5601
```

> **Nota:** Valorile din mesaj (`10 secunde`, `5 minute`) sunt citite din `config.toml`
> (`detection.fast_scan.time_window_secs` / `detection.slow_scan.time_window_mins`),
> nu sunt hardcodate. Daca modifici pragurile in configurare, mesajele SIEM reflecta
> automat noile valori.
>
> Campul `dst` (Target Address) este populat din informatia `dst` a log-ului firewall.
> Campul `msg` include porturile scanate (trunchiat la 512 caractere).
> Campul `cs1=ScannedPorts` contine intotdeauna lista completa de porturi.

---

### Etapa 5 — ArcSight primeste si parseaza

ArcSight asculta pe UDP 514. Cand primeste pachetul, il proceseaza in straturi:

**Stratul 1 — Syslog header (RFC 3164):**

```
<38>             → facility=4 (security) × 8 + severity=6 → categoria evenimentului
Feb 18 12:06:16  → timestamp syslog
ids-rs           → hostname-ul sursei (cine a trimis alerta)
```

**Stratul 2 — CEF header (7 campuri separate prin `|`):**

```
CEF:0                    → versiunea formatului CEF
IDS-RS                   → Device Vendor
Network Scanner Detector → Device Product
1.0                      → Device Version
1001                     → Signature ID (1001=Fast, 1002=Slow, 1003=AcceptScan) — folosit in reguli
Fast Port Scan Detected  → Event Name
7                        → Severity → apare ca "Priority: High" in ArcSight
```

**Stratul 3 — CEF Extensions (campuri key=value separate prin spatiu):**

```
rt=1739876776000    → Receipt Time in ms — ArcSight sorteaza evenimentele dupa asta
src=192.168.11.7    → Source Address    → "Attacker Address" in ArcSight
dst=10.0.0.1        → Target Address    → IP-ul tinta al scanarii (din campul dst al log-ului)
cnt=20              → Event Count       → numarul de porturi unice detectate
act=alert           → Device Action     → folosit pentru filtrare si categorisire
msg=Fast Scan...    → Message           → descriere + lista porturi (vizibila direct in Event List)
cs1Label=Scanned... → numele coloanei custom cs1
cs1=21,22,23,80...  → ScannedPorts      → lista completa porturi (pana la 4000 chars)
```

Campul `msg` include porturile scanate direct, trunchiate la 512 caractere pentru
compatibilitate cu syslog RFC 3164. Campul `cs1` contine intotdeauna lista completa.

**Cum arata in interfata ArcSight (Active Channel / Event List):**

```
┌──────────────────┬─────────────────┬─────────────────┬──────┬──────────┬─────────────────────────────────────────────┐
│ Time             │ Source Address  │ Target Address  │ Cnt  │ Priority │ Message                                     │
├──────────────────┼─────────────────┼─────────────────┼──────┼──────────┼─────────────────────────────────────────────┤
│ Feb 18 12:06:16  │ 192.168.11.7   │ 10.0.0.1        │  20  │ High     │ Fast Scan detectat: 20 porturi unice in 10s │
│                  │                 │                 │      │          │ | ports: 21,22,23,80,443,8080,...            │
└──────────────────┴─────────────────┴─────────────────┴──────┴──────────┴─────────────────────────────────────────────┘
```

Click pe eveniment → detalii complete, inclusiv coloana **ScannedPorts** cu
lista tuturor porturilor vizate de atacator.

---

### Rezumat vizual al intregului flux

```
Firewall                IDS-RS                              ArcSight SIEM
────────                ──────                              ─────────────

drop tcp                recv_from()     ← UDP :5555
src: 192.168.11.7:443   parse()         → LogEvent
                        process_event() → Alert
                        build CEF msg
                        send_to()       → UDP :514   →     parse syslog header
                                                           parse CEF header
                                                           parse extensions
                                                           map to schema
                                                           show in Active Channel
```

Fiecare componenta face un singur lucru bine:
`main.rs` orchestreaza, `parser/` intelege formatele, `detector.rs` decide,
`alerter.rs` comunica cu lumea exterioara.

---

## Rulare

```bash
# Cu config.toml din directorul curent
./target/release/ids-rs

# Cu cale explicita catre config
./target/release/ids-rs /etc/ids-rs/config.toml

# Cu debug logging intern (tracing)
RUST_LOG=debug ./target/release/ids-rs
```

### Mod Debug (diagnostic parsare)

Pentru a vedea exact ce vine pe port si daca parsarea reuseste, seteaza `debug = true` in `config.toml`:

```toml
[network]
debug = true
```

Output-ul arata fiecare pachet primit (RAW), rezultatul parsarii (OK/FAIL) si, in caz de esec, formatul asteptat:

```
[2026-02-18 12:00:01]  RAW   <134>Feb 17 12:00:01 gw CEF:0|CheckPoint|VPN-1|R81|100|Drop|5|src=1.2.3.4 dst=10.0.0.1 dpt=443 proto=TCP act=Drop
[2026-02-18 12:00:01]   OK   src=1.2.3.4 dpt=443 proto=tcp action=drop
[2026-02-18 12:00:01]  DROP  Src=1.2.3.4 DstPort=443 Proto=tcp Action=drop

[2026-02-18 12:00:02]  RAW   17Feb2026 11:32:44 ethx.x Log Drop 11.11.11.11 ...
[2026-02-18 12:00:02]  FAIL  Parsare esuata! (parser: CEF (ArcSight))
                              Primit:   "17Feb2026 11:32:44 ethx.x Log Drop 11.11.11.11 ..."
                              Asteptat: "<PRI>Mon DD HH:MM:SS hostname CEF:0|Vendor|...|src=IP dst=IP dpt=PORT proto=PROTO act=ACTION"
```

### Exemplu output

```
==============================================================
  IDS-RS  ::  Intrusion Detection System
  Network Scan Detector v0.1.0
==============================================================
  Parser:  GAIA           Listen:  UDP/5555
  SIEM:    127.0.0.1:514  Email:   OFF
  Fast:    >15 ports/10s  Slow:    >30 ports/5min
==============================================================

[2025-01-15 14:30:00] [INFO] Parser activ: Checkpoint Gaia (Raw)
[2025-01-15 14:30:00] [INFO] Detector initializat (DashMap thread-safe)
[2025-01-15 14:30:00] [INFO] Ascult pe UDP 0.0.0.0:5555
[2025-01-15 14:30:00] [INFO] Astept log-uri de la firewall... (Ctrl+C pentru oprire)
--------------------------------------------------------------
[2025-01-15 14:30:12] [ALERT] [IP: 192.168.11.7] Fast Scan detectat!
  20 porturi unice in fereastra de timp
  Porturi: 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, ...
--------------------------------------------------------------
```

---

## Testare

Testerul (`tester/tester.py`) trimite log-uri simulate pe UDP catre IDS-RS.
Exista doua metode de testare: cu **fisiere sample** (replay) sau cu **generare automata**.

### Pas 0 — Porneste IDS-RS

Deschide un terminal si ruleaza:

```bash
cargo build && ./target/debug/ids-rs
```

Lasa-l pornit. Toate comenzile de mai jos se ruleaza intr-un **al doilea terminal**.

### Pas 1 — Teste unitare (fara IDS-RS pornit)

Ruleaza testele unitare Rust pentru a verifica parserii si detectorul:

```bash
cargo test
```

Rezultat asteptat: `test result: ok. 33 passed`

Testele acopera:
- Parser GAIA: drop valid, accept parsat (nu ignorat), broadcast fara src, ICMP fara service, format invalid
- Parser CEF: drop valid, accept parsat, syslog header, syslog priority header, non-CEF, campuri incomplete
- Detector Fast Scan: alert, sub prag, cooldown, cleanup, IP-uri separate, max_hits_per_ip, max_tracked_ips LRU
- Detector Slow Scan: alert dedicat, cooldown, independenta fata de Fast Scan (`slow_test_config()`)
- Detector Accept Scan: alert accept, drop nu declanseaza accept scan, accept nu declanseaza fast scan, cooldown accept
- Alerter: 7 teste sanitize_cef (anti-injection CEF)

---

### Fisiere sample disponibile

Proiectul include fisiere de log pre-generate, gata de replay:

| Fisier | Format | Linii | Ce contine | Rezultat asteptat |
|--------|--------|-------|------------|-------------------|
| `sample_fast_gaia.log` | GAIA | 20 | 20 drop-uri, porturi unice, acelasi IP | Alerta Fast Scan |
| `sample_fast_cef.log` | CEF | 20 | Acelasi scenariu, format CEF | Alerta Fast Scan |
| `sample_slow_gaia.log` | GAIA | 35 | 35 drop-uri, porturi unice, acelasi IP | Alerta Slow Scan |
| `sample_slow_cef.log` | CEF | 35 | Acelasi scenariu, format CEF | Alerta Slow Scan |
| `sample_normal_gaia.log` | GAIA | 5 | 5 drop-uri pe porturi comune (sub prag) | Fara alerta |
| `sample_normal_cef.log` | CEF | 5 | Acelasi scenariu, format CEF | Fara alerta |
| `sample2_gaia.log` | GAIA | 56 | Log-uri reale Checkpoint (accept + drop mixt) | Depinde de continut |

---

### Pas 2 — Fast Scan (trebuie sa declanseze alerta)

```bash
# GAIA (config.toml: parser = "gaia")
python3 tester/tester.py fast

# CEF (config.toml: parser = "cef")
python3 tester/tester.py fast --cef
```

IDS-RS ar trebui sa afiseze o alerta `Fast Scan detectat!` in terminalul sau.

### Pas 3 — Slow Scan (trebuie sa declanseze alerta)

```bash
# GAIA
python3 tester/tester.py slow

# CEF
python3 tester/tester.py slow --cef
```

IDS-RS ar trebui sa afiseze o alerta `Slow Scan detectat!`.

### Pas 4 — Accept Scan (trebuie sa declanseze alerta)

```bash
# Genereaza accept-uri pe porturi unice — simuleaza enumerarea serviciilor deschise
python3 tester/tester.py accept-scan --format gaia --ports 10 --delay 0.05

# Format CEF
python3 tester/tester.py accept-scan --format cef --ports 10 --delay 0.05
```

IDS-RS ar trebui sa afiseze o alerta `Accept Scan` cu badge **magenta** in terminal.
Diferenta fata de Fast Scan: evenimentele trimise au `action=accept`, nu `action=drop`.

### Pas 5 — Trafic normal (NU trebuie sa declanseze alerta)

```bash
# GAIA
python3 tester/tester.py normal

# CEF
python3 tester/tester.py normal --cef
```

IDS-RS **nu** ar trebui sa genereze nicio alerta.

### Pas 6 — Replay log-uri reale Checkpoint

Fisierul `sample2_gaia.log` contine 56 de log-uri reale Checkpoint GAIA (accept + drop mixt).
Accept-urile sunt acum procesate pentru detectia Accept Scan (nu mai sunt ignorate):

```bash
python3 tester/tester.py replay tester/sample2_gaia.log --delay 0.05
```

IDS-RS va procesa fiecare linie si va genera alerte daca detecteaza scanari.

---

### Moduri avansate

#### Generare dinamica (fast-scan / slow-scan)

Genereaza log-uri din mers, util pentru scenarii custom:

```bash
python3 tester/tester.py fast-scan --format gaia --ports 20 --delay 0.1
python3 tester/tester.py fast-scan --format cef --ports 20 --delay 0.1
python3 tester/tester.py slow-scan --format gaia --ports 40
python3 tester/tester.py slow-scan --format cef --ports 40 --delay 3
python3 tester/tester.py accept-scan --format gaia --ports 10 --delay 0.1
python3 tester/tester.py accept-scan --format cef --ports 10 --delay 0.1
```

#### Sample Mode

Citeste log-uri GAIA dintr-un fisier, le parseaza, si le poate retrimite
in alt format sau le poate folosi ca baza pentru generarea de scanari noi:

```bash
python3 tester/tester.py sample tester/sample2_gaia.log raw-gaia
python3 tester/tester.py sample tester/sample2_gaia.log raw-cef
python3 tester/tester.py sample tester/sample2_gaia.log scan-gaia
python3 tester/tester.py sample tester/sample2_gaia.log fast-cef
```

| Mod | Ce face | Parser necesar |
|-----|---------|----------------|
| `raw-gaia` | Trimite liniile as-is din fisier | `gaia` |
| `raw-cef` | Parseaza GAIA, converteste la CEF, trimite | `cef` |
| `scan-gaia` | Genereaza log-uri GAIA noi din drop-urile gasite (scan lent) | `gaia` |
| `scan-cef` | Genereaza log-uri CEF noi din drop-urile gasite (scan lent) | `cef` |
| `fast-gaia` | Genereaza log-uri GAIA noi, trimise rapid (fast scan) | `gaia` |
| `fast-cef` | Genereaza log-uri CEF noi, trimise rapid (fast scan) | `cef` |

---

```
┌──────────────────────────────────────────┬──────────────────────────────────────────────┐
│                  Command                 │                  What it does                │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ tester.py fast                           │ Replay sample_fast_gaia.log (drop events)    │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ tester.py fast --cef                     │ Replay sample_fast_cef.log                   │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ tester.py slow                           │ Replay sample_slow_gaia.log (drop events)    │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ tester.py normal                         │ Replay sample_normal_gaia.log (no alert)     │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ tester.py fast-scan --ports N --delay S  │ Generate fast scan (drop events)             │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ tester.py slow-scan --ports N --delay S  │ Generate slow scan (drop events)             │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ tester.py accept-scan --ports N          │ Generate accept scan (accept events)         │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ tester.py replay <file>                  │ Replay from any file                         │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ tester.py sample <file> <mode>           │ Advanced sample mode                         │
└──────────────────────────────────────────┴──────────────────────────────────────────────┘
```

### Parametri comuni

| Parametru | Default | Descriere |
|-----------|---------|-----------|
| `--host` | `127.0.0.1` | Adresa IP a IDS-RS |
| `--port` | `5555` | Portul UDP al IDS-RS |
| `--cef` | `false` | Format CEF in loc de GAIA (preset-uri) |
| `--format` | `gaia` | Formatul log-urilor: `gaia` sau `cef` (fast-scan/slow-scan) |
| `--source` | `192.168.11.7` | IP-ul sursa simulat (fast-scan/slow-scan) |
| `--ports` | `20` / `40` / `10` | Numar de porturi unice (fast-scan/slow-scan/accept-scan) |
| `--delay` | variabil | Delay intre batch-uri in secunde |
| `--batch` | `1` | Log-uri per pachet UDP |

### Schimbare parser in config.toml

Testele GAIA functioneaza cu `parser = "gaia"`, iar testele CEF cu `parser = "cef"`.
Schimba in `config.toml` si reporneste IDS-RS:

```toml
[network]
parser = "cef"    # in loc de "gaia"
```

---

## Structura proiect

```
ids-rs/
├── Cargo.toml              # Dependente si metadata proiect
├── Cargo.lock              # Versiuni exacte blocate (generat automat)
├── config.toml             # Fisier de configurare
├── README.md               # Acest fisier
├── src/
│   ├── main.rs             # Entry point: UDP listener, orchestrare async
│   ├── config.rs           # Structuri de configurare (serde + toml)
│   ├── display.rs          # Output CLI colorat (ANSI): banner, alerte, stats
│   ├── detector.rs         # Motor detectie: DashMap, Fast/Slow Scan, cleanup
│   ├── alerter.rs          # Trimitere alerte: SIEM (UDP) + Email (SMTP async)
│   └── parser/
│       ├── mod.rs          # Trait LogParser, LogEvent, factory function
│       ├── gaia.rs         # Parser Checkpoint Gaia (format real syslog)
│       └── cef.rs          # Parser CEF / ArcSight
└── tester/
    ├── tester.py              # Script Python de testare (fast/slow/normal/replay/sample)
    ├── sample_fast_gaia.log   # 20 drop-uri GAIA (Fast Scan)
    ├── sample_fast_cef.log    # 20 drop-uri CEF  (Fast Scan)
    ├── sample_slow_gaia.log   # 35 drop-uri GAIA (Slow Scan)
    ├── sample_slow_cef.log    # 35 drop-uri CEF  (Slow Scan)
    ├── sample_normal_gaia.log # 5 drop-uri GAIA  (sub prag, trafic normal)
    ├── sample_normal_cef.log  # 5 drop-uri CEF   (sub prag, trafic normal)
    └── sample2_gaia.log       # 56 log-uri reale Checkpoint GAIA (accept + drop mixt)
```

### Dependente principale

| Crate               | Scop                                            |
|----------------------|-------------------------------------------------|
| `tokio`              | Runtime async (UDP, timers, signals)            |
| `serde` + `toml`    | Deserializare config.toml                       |
| `dashmap`            | HashMap concurent thread-safe (lock-free shards)|
| `regex`              | Parsare log-uri Gaia cu expresii regulate       |
| `lettre`             | Client SMTP async pentru email                  |
| `colored`            | Culori ANSI in terminal                         |
| `chrono`             | Timestamps formatate                            |
| `tracing`            | Logging structurat (debug/diagnostic)           |
| `anyhow`             | Error handling ergonomic                        |

---

## Concepte Rust acoperite

Codul este comentat extensiv in romana, explicand fiecare concept la prima utilizare.

| Concept                | Unde in cod                          |
|------------------------|--------------------------------------|
| Ownership si Borrowing | `parser/gaia.rs`, `detector.rs`      |
| Traits si impl         | `parser/mod.rs`, `parser/gaia.rs`    |
| Trait Objects (dyn)     | `parser/mod.rs`, `main.rs`           |
| Generics               | `config.rs` (`AsRef<Path>`)          |
| Enums si Pattern Match  | `detector.rs` (`ScanType`, `match`) |
| Option si Result       | toate fisierele                      |
| Operatorul ?           | `config.rs`, `parser/gaia.rs`        |
| Arc (shared ownership)  | `main.rs`                           |
| Interior Mutability    | `detector.rs` (`DashMap`)            |
| Send + Sync            | `parser/mod.rs`, `detector.rs`       |
| Async / Await          | `main.rs`, `alerter.rs`             |
| tokio::spawn           | `main.rs` (cleanup task)            |
| tokio::select!         | `main.rs` (main loop)               |
| Move Closures          | `main.rs` (spawn)                   |
| Iteratori              | `detector.rs`, `display.rs`         |
| Derive Macros          | `config.rs`                          |
| Modules                | `parser/mod.rs`, `main.rs`          |
| Lifetime-uri           | `parser/gaia.rs` (`extract_field`)  |
| Unit Tests             | `parser/gaia.rs`, `parser/cef.rs`, `detector.rs` |

---

## Extindere

### Adaugare parser nou

1. Creeaza `src/parser/noul_format.rs`
2. Implementeaza `trait LogParser` (`parse` + `name` + `expected_format`)
3. Adauga `pub mod noul_format;` in `src/parser/mod.rs`
4. Adauga o intrare in `match` din `create_parser()`
5. Seteaza `parser = "noul_format"` in `config.toml`

### Adaugare canal de alerta nou

1. Adauga sectiunea in `config.rs` si `config.toml`
2. Implementeaza metoda async in `alerter.rs`
3. Apeleaz-o din `send_alert()`

---

## Changelog

### Implementat — toate verificate si testate

- [x] **#1 — Mesaje SIEM hardcodate** (`alerter.rs`) — valorile ferestrei de timp (`10 secunde`,
  `5 minute`) din mesajul CEF trimis catre SIEM erau hardcodate. Acum `Alerter` primeste
  `DetectionConfig` si citeste `time_window_secs` / `time_window_mins` direct din configurare.

- [x] **#17 — Cleanup task: primul tick imediat** (`main.rs`) — `tokio::time::interval()` face
  primul tick imediat la creare, ruland un cleanup inutil la startup. Inlocuit cu un loop
  simplu `sleep`-first: asteapta intai intervalul complet, apoi curata.

- [x] **Target Address si porturi in mesajul SIEM** — campul `dst` (Target Address in ArcSight)
  adaugat in extensiile CEF din informatia `dst` a log-ului firewall. Campul `msg` include
  acum si lista porturilor scanate (trunchiat la 512 caractere pentru compatibilitate syslog).
  Campul `cs1=ScannedPorts` contine in continuare lista completa. `dest_ip` adaugat in
  `LogEvent` si `Alert`; extras de ambii parseri (Gaia si CEF).

- [x] **#7 — Validare config post-deserializare** (`config.rs`) — adaugata `AppConfig::validate()`
  apelata automat din `load()`. Verifica 16 constrangeri semantice (valori zero invalide,
  consistenta ferestre de timp, campuri obligatorii conditionale) si raporteaza toate
  erorile simultan la pornire, inainte ca aplicatia sa inceapa sa asculte pe UDP.

- [x] **#3 — Limitare memorie per IP — MAX_HITS_PER_IP** (`detector.rs`, `config.rs`) — `Vec<PortHit>`
  era nelimitata intre cleanup cycle-uri. Adaugat camp `max_hits_per_ip` in `DetectionConfig`
  (implicit 10.000). La depasire, cele mai vechi intrari sunt eliminate (FIFO via `drain(..N)`).
  Retrocompatibil prin `#[serde(default)]`. Adaugat test unitar `test_max_hits_per_ip_cap`.

- [x] **#4 — Limitare globala IP-uri — MAX_TRACKED_IPS cu LRU Eviction** (`detector.rs`, `config.rs`)
  — DashMap-ul creste nelimitat la IP spoofing flood. Adaugat camp `max_tracked_ips` (implicit
  100.000) si structura auxiliara `last_seen: DashMap<IpAddr, Instant>`. Cand limita e atinsa,
  IP-ul cel mai vechi (LRU) este evictat din toate structurile interne. Cleanup actualizat sa
  sincronizeze `last_seen`. Adaugat test unitar `test_max_tracked_ips_eviction`.

- [x] **#8 — Sanitizare CEF anti-injection** (`alerter.rs`) — `sanitize_cef()` escapeaza `\`, `|`,
  `\n`, `\r` pe campurile cu text dinamic. 7 teste unitare.

- [x] **#9 — Rate Limiting UDP** (`main.rs`) — Token Bucket cu `udp_rate_limit` si `udp_burst_size`
  in `config.toml`. Afisare periodica drop-uri cu badge `RATE`.

- [x] **#10 — Detectie Accept Scan — ScanType::AcceptScan** (`detector.rs`, `config.rs`, `alerter.rs`,
  `display.rs`, parseri) — IDS-RS analiza exclusiv evenimentele `drop`. Un atacator care scaneaza
  **porturile deschise** (trafic `accept`) trecea complet neobservat. Implementat:
  - Parserii GAIA si CEF procesa acum si actiunea `accept` (nu mai ignora)
  - `detector.rs`: DashMap separat `accept_hits`, cooldown propriu `accept_cooldowns`,
    `ScanType::AcceptScan` cu detectie independenta de Fast/Slow Scan
  - `config.rs`: `AcceptScanConfig` cu `port_threshold` si `time_window_secs`; 2 validari noi
  - `alerter.rs`: Signature ID `1003`, severitate CEF `5` (Low-Medium); email severitate `MEDIE-MICA`
  - `display.rs`: alerta magenta distincta; badge `ACCPT` verde pentru evenimente accept
  - `tester.py`: comanda `accept-scan`, functie `simulate_accept_scan()`, optiune in meniu
  - 4 teste unitare noi in `detector.rs`: alert, no cross-contamination drop↔accept, cooldown

- [x] **#2 — Cache transport SMTP** (`alerter.rs`) — `AsyncSmtpTransport` construit o singura data
  in `Alerter::new()`. Erorile SMTP detectate la startup.

- [x] **#18 — Teste unitare Slow Scan** (`detector.rs`) — 3 teste dedicate. Total: **33 passed**.

---

## Protectie memorie — MAX_HITS_PER_IP

### Ce problema rezolva

Fiecare IP sursa are in memorie un `Vec<PortHit>` — o lista cu toate porturile accesate
si momentul in care le-a accesat. Fara limita, un scanner agresiv care trimite zeci de
mii de pachete pe secunda ar umple aceasta lista nelimitat intre doua cleanup cycle-uri
(implicit: 60 de secunde).

**Calcul worst-case fara limita:**

```
Un scanner trimite 10.000 pachete/s cu porturi unice.
In 60s (un cleanup interval) = 600.000 PortHit-uri per IP.
Fiecare PortHit = port (u16, 2 bytes) + Instant (~16 bytes) = ~18-24 bytes.
600.000 × 24 bytes = ~14 MB per IP atacator.
10 IP-uri atacatoare simultan = ~140 MB. 1000 IP-uri = ~14 GB → OOM.
```

### Cum functioneaza solutia

In `config.toml`:
```toml
[detection]
max_hits_per_ip = 10000   # maxim port-hits in memorie per IP sursa
```

In `detector.rs`, dupa fiecare `push()`:
```rust
let max_hits = self.config.max_hits_per_ip;
if hits.len() > max_hits {
    let overflow = hits.len() - max_hits;
    hits.drain(..overflow);   // sterge de la inceput (oldest first)
}
```

**Principiul FIFO (First In, First Out):** Vec-ul este ordonat cronologic —
noile intrari sunt adaugate la final (`.push()`), iar cele vechi sunt eliminate
de la inceput (`.drain(..N)`). Astfel pastrezi mereu cele **mai recente** `max_hits_per_ip`
accesuri — exact cele relevante pentru detectie (fereastra de 10s / 5min).

### Concepte Rust explicate

#### `.drain(..N)` — stergere in-place eficienta

`drain(range)` sterge elementele din range si le returneaza ca iterator.
Elementele ramase sunt **compactate in stanga** (nu se realoca Vec-ul).

```rust
let mut v = vec![1, 2, 3, 4, 5];
v.drain(..2);       // sterge primele 2 elemente
// v == [3, 4, 5]  (compactat, fara realocare daca capacitatea o permite)
```

Alternative si de ce nu le-am ales:
- `v.remove(0)` repetat N ori — O(n²), muta elementele de fiecare data
- `v.truncate(max)` — sterge de la final (am pierde cele MAI RECENTE, invers de ce vrem)
- `Vec::new()` si reconstruct — mai costisitor, realoca

#### Blocul `{}` explicit — eliberarea lock-ului DashMap

```rust
{
    let mut hits = self.port_hits.entry(ip).or_default(); // ia write-lock pe shard
    hits.push(...);
    hits.drain(..);
}  // <-- hits (RefMut) este dropit AICI → lock-ul este eliberat
// Urmatoarele operatii pe DashMap pot rula fara conflict
```

`entry()` pe DashMap returneaza un `RefMut` — un guard care tine un **write-lock**
pe shard-ul intern. In Rust, lock-urile sunt eliberate automat (RAII) cand
variabila iese din scope. Blocul `{}` forteaza iesirea din scope mai devreme.

#### `usize` — tipul natural pentru marimi de colectii

`max_hits_per_ip: usize` (nu `u32` sau `u64`) pentru ca:
- `.len()` returneaza `usize` — comparatia `hits.len() > max_hits` nu necesita conversie
- `usize` are dimensiunea unui pointer (32-bit pe sisteme 32-bit, 64-bit pe sisteme 64-bit)
- Conventional in Rust: toate indexarile si marimile colectiilor sunt `usize`

#### `#[serde(default = "fn")]` — campuri optionale in TOML

```rust
#[serde(default = "default_max_hits_per_ip")]
pub max_hits_per_ip: usize,

fn default_max_hits_per_ip() -> usize { 10_000 }
```

Fara acest atribut, daca lipseste `max_hits_per_ip` din `config.toml`,
serde ar returna o eroare. Cu `default`, serde apeleaza functia si foloseste
valoarea returnata — **retrocompatibil** cu configuratii vechi.

### Impactul asupra detectiei

Limita nu afecteaza acuratetea detectiei in scenarii normale:
- **Fast Scan** cauta porturi in fereastra de **10 secunde** — cel mult cateva sute de hits
- **Slow Scan** cauta porturi in fereastra de **5 minute** — cateva mii de hits
- Limita de 10.000 este cu mult peste ce genereaza un scanner real in aceste ferestre

Daca un scanner este **extrem** de agresiv (>10.000 porturi in fereastra),
alerta va fi oricum generata — cele mai vechi hits (in afara ferestrei)
sunt primele eliminate, deci detectia nu este afectata.

---

## Protectie DashMap — MAX_TRACKED_IPS si LRU Eviction

### Ce problema rezolva

`DashMap<IpAddr, Vec<PortHit>>` tine in memorie cate o intrare per IP sursa vazut.
In mod normal, cleanup-ul periodic sterge IP-urile fara activitate recenta. Dar cleanup-ul
nu limiteaza **numarul total** de IP-uri simultane.

**Atacul IP Spoofing Flood:**
Un atacator poate trimite pachete UDP cu IP-uri sursa false (spoofate), generate aleatoriu.
Fiecare IP nou creeaza o intrare noua in DashMap. Cu 1 milion de IP-uri spoofate:

```
1.000.000 intrari × (IpAddr ~16B + Vec overhead ~24B) = ~40 MB doar pentru cheile DashMap
+ hit-urile per IP = potential GB de RAM → Out Of Memory / crash server IDS
```

Cleanup-ul nu ajuta: sterge doar entries **vechi**, nu limiteaza numarul total.
Daca atacatorul trimite cate 1 pachet per IP nou la fiecare secunda, cleanup-ul
(la 60s interval) nu va sterge nimic — toate intrarile sunt "recente".

### Algoritmul LRU Eviction

**LRU = Least Recently Used** — strategia de a elimina elementul care nu a mai
fost accesat de cel mai mult timp.

```
Situatie: max_tracked_ips = 3, avem deja IP-urile A, B, C.

         last_seen:
           A → t=1s  ← cel mai vechi (LRU)
           B → t=5s
           C → t=9s

Soseste IP nou D (t=10s):
  1. Detectam: D nu exista AND len(3) >= max(3)  → evictie necesara
  2. Gasim minimul din last_seen: A (t=1s)
  3. Stergem A din port_hits, last_seen, fast_cooldowns, slow_cooldowns
  4. Inseram D

Rezultat:
  B → t=5s
  C → t=9s
  D → t=10s  ← nou inserat
```

### Implementarea in Rust

In `config.toml`:
```toml
max_tracked_ips = 100000   # maxim IP-uri urmarite simultan
```

Structura noua in `Detector`:
```rust
last_seen: DashMap<IpAddr, Instant>,  // ultimul moment cand IP-ul a fost vazut
```

In `process_event()`:
```rust
// Verificam dupa last_seen (nu port_hits) — acopera si IP-urile care trimit
// exclusiv "accept" (care nu apar in port_hits, dar sunt urmarite in last_seen).
let is_new_ip = !self.last_seen.contains_key(&ip);
if is_new_ip && self.last_seen.len() >= self.config.max_tracked_ips {

    // Gasim IP-ul cu cel mai vechi last_seen (LRU)
    let lru_ip: Option<IpAddr> = self.last_seen
        .iter()
        .min_by_key(|e| *e.value())
        .map(|e| *e.key());

    if let Some(old_ip) = lru_ip {
        // Evictam din TOATE structurile: drop hits, accept hits, cooldowns
        self.port_hits.remove(&old_ip);
        self.accept_hits.remove(&old_ip);
        self.last_seen.remove(&old_ip);
        self.fast_cooldowns.remove(&old_ip);
        self.slow_cooldowns.remove(&old_ip);
        self.accept_cooldowns.remove(&old_ip);
    }
}
// Actualizam last_seen pentru IP-ul curent (drop sau accept)
self.last_seen.insert(ip, now);
```

### Concepte Rust explicate

#### `!self.last_seen.contains_key(&ip)` — short-circuit evaluation

Verificam mai intai daca IP-ul este nou (`is_new_ip`) **inainte** de a verifica
limita. Motivul: evictia are sens doar pentru IP-uri **noi** — un IP existent
nu creste numarul de intrari, deci nu necesita evictie.

Folosim `last_seen` (nu `port_hits`) deoarece un IP poate trimite exclusiv evenimente
`accept` — care nu apar in `port_hits` ci in `accept_hits`. Fara aceasta corectare,
IP-urile pure-accept ar parea mereu "noi" si ar declansa evictii false.

In Rust (ca si in C/Java), `&&` evalueaza lazy (short-circuit):
- Daca `is_new_ip` e `false` → a doua conditie **nu se evalueaza** → fara overhead

#### `.iter().min_by_key(...)` pe DashMap — parcurgere O(n)

```rust
self.last_seen
    .iter()                         // iterator peste toate (key, value) perechile
    .min_by_key(|entry| *entry.value())  // gaseste minimul dupa valoare (Instant)
    .map(|entry| *entry.key())      // extrage cheia (IpAddr este Copy → * copiaza)
```

`min_by_key` parcurge **tot** DashMap-ul — O(n). Dar:
- Se apeleaza **rar**: doar cand `port_hits.len() >= max_tracked_ips` SI soseste IP nou
- In functionare normala (trafic real, nu flood), limita nu este atinsa
- Chiar si la flood: O(100.000) operatii atomice DashMap < 1ms pe hardware modern

#### De ce `last_seen` este o structura separata?

Alternativa: pentru a gasi LRU-ul, am putea parcurge `port_hits` si sa luam
`hits.last().seen_at` pentru fiecare IP. Dezavantaj:
- Necesita read-lock pe FIECARE shard al `port_hits` in timp ce cautam minimul
- Conflicte de lock posibile cu thread-ul care scrie in `port_hits`

Cu `last_seen` separat:
- Scriem in `last_seen` dupa ce eliberam lock-ul pe `port_hits` (blocuri `{}` separate)
- Citim din `last_seen` pentru LRU fara a bloca `port_hits`
- Overhead: ~50 bytes per IP in plus (IpAddr + Instant in DashMap)

#### De ce stergem din `fast_cooldowns` si `slow_cooldowns` la evictie?

Daca nu am sterge cooldown-ul unui IP evictat, urmatoarea data cand acel IP
reapare (dupa ce a fost re-inserat), cooldown-ul sau expirat ar mai fi in memorie.
Asta nu cauzeaza o eroare — `in_cooldown()` verifica si `elapsed()` — dar
lasa date "zombie" care se acumuleaza in cooldown maps.

Curatand la evictie: consistenta completa, fara date orfane.

#### Cleanup actualizat pentru `last_seen`

In `cleanup()`, dupa ce sterg `port_hits` si `accept_hits` vechi, sincronizam `last_seen`
cu un `retain` care verifica amandoua hartile:

```rust
self.last_seen.retain(|ip, _| {
    self.port_hits.contains_key(ip) || self.accept_hits.contains_key(ip)
});
```

Un IP este pastrat in `last_seen` cat timp apare in cel putin una din cele doua harti.
Daca dispare din amandoua (datele expira), este sters si din `last_seen`.
Fara aceasta sincronizare, `last_seen` ar retine intrari "zombie" si evictia LRU
ar putea selecta IP-uri deja sterse.

### Trade-off: LRU O(n) vs. structuri dedicate

O implementare LRU "perfecta" ar folosi o structura dedicata (ex: `linked_hash_map`,
crate `lru`) cu O(1) pentru get/insert/evict. Avantaj major la volume mari.

Am ales O(n) scan pentru simplitate si fara dependente noi:
- La 100.000 IP-uri, `min_by_key` = ~100k comparatii de `Instant` (< 1ms)
- Evictia apare **cel mult** o data per pachet, si doar dupa atingerea limitei
- Codul ramane simplu, usor de inteles si de testat

Daca in viitor se doreste O(1) LRU: se poate adauga crate-ul `lru` si inlocui
`DashMap<IpAddr, Instant>` cu `LruCache<IpAddr, ()>` (thread-safe cu Mutex).

---

## Securitate — Sanitizare campuri CEF anti-injection

> **SECURITATE ANTI-INJECTION** — Implementat in `src/alerter.rs`, functia `sanitize_cef()`.

### Problema

Mesajul trimis la SIEM este construit cu `format!()` in format **CEF peste Syslog RFC 3164**:

```
<38>Feb 18 12:06:16 ids-rs CEF:0|IDS-RS|Network Scanner Detector|1.0|1001|Fast Port Scan Detected|7|rt=... msg=... cs1=...
```

Formatul CEF foloseste caractere speciale cu semnificatie structurala:

| Caracter | Rol in CEF | Risc daca neescape |
|----------|------------|--------------------|
| `\|` | Separator intre campurile header | Injecteaza camp header fals |
| `\n` | Separator intre linii syslog | Injecteaza o linie syslog complet noua |
| `\r` | Carriage return | Trunchieaza linia, injecteaza continut fals |
| `\\` | Caracter de escape CEF | Interpretat gresit de parser-ul SIEM |

### Vector de atac concret

Un firewall poate include in log-ul sau campuri text controlate indirect de atacator
(hostname sursa, useragent, etc.). Daca aceste campuri ar fi incluse neescapate in
mesajul SIEM, un atacator ar putea injecta:

```
# Input malitios intr-un camp text din log:
"evil_host\nFeb 18 00:00:00 ids-rs CEF:0|FAKE_VENDOR|Fake|1.0|9999|Breach|10|src=10.0.0.1"
```

Fara sanitizare, mesajul UDP trimis la SIEM ar contine **doua linii syslog**:
- Linia 1: alerta reala (trunchiat la `\n`)
- Linia 2: alerta falsa complet fabricata de atacator

### Solutia implementata

Functia `sanitize_cef(input: &str) -> String` in `alerter.rs` aplica escape-uri
in urmatoarea ordine (ordinea conteaza — backslash **primul**):

```rust
fn sanitize_cef(input: &str) -> String {
    input
        .replace('\\', "\\\\")   // 1. backslash  ->  \\
        .replace('|',  "\\|")    // 2. pipe       ->  \|
        .replace('\n', "\\n")    // 3. newline     ->  \n  (literal)
        .replace('\r', "\\r")    // 4. CR          ->  \r  (literal)
}
```

**De ce backslash primul?** Daca am escapa `|` primul, `\|` devine `\\|` in pasul
urmator — dublu-escape incorect. Escapand `\` primul, toate secventele de escape
ulterioare raman corecte.

### Campuri sanitizate

| Camp CEF | Zona mesaj | De ce este sanitizat |
|----------|-----------|----------------------|
| `event_name` | Header (`\|` separator) | `\|` neescape = camp header fals |
| `scan_label` (parte din `msg=`) | Extensie | `\n`/`\r` = injectie linie syslog. **Separatorul ` \| ports:` este al nostru si nu se sanitizeaza** — altfel apare `\|` in ArcSight |
| `cs1=` (ScannedPorts) | Extensie | **Nu sanitizat** — porturile sunt `Vec<u16>` → cifre+virgule, imposibil sa contina caractere speciale |

### Campuri sigure prin tip (nu necesita sanitizare)

- `src` / `dst` — `IpAddr` (tip Rust, nu poate contine caractere speciale)
- `rt` — `i64` timestamp milisecunde
- `cnt` — `usize` numar intregi
- `sig_id` — literal static (`"1001"`, `"1002"`, `"1003"`)

### Teste unitare

7 teste in `alerter::tests` acopera:
- escape `\n`, `\r`, `|`, `\\` individual
- atac combinat (linie syslog injectata)
- string curat (fara modificari nedorite)
- backslash urmat de pipe (ordine corecta a escape-urilor)

```bash
cargo test sanitize
# running 7 tests ... ok
```

---

## Rate Limiting UDP — Token Bucket

> **PROTECTIE CPU** — Implementat in `src/main.rs`, struct `TokenBucket`.

### Problema

Main loop-ul proceseaza **fiecare pachet UDP** primit pe socket. Un flood UDP (pachete false, amplificare DNS/NTP, sau un scanner agresiv) poate satura CPU-ul IDS-ului, cauzand:

- Pierderea alertelor reale (detectorul nu mai proceseaza la timp)
- Cresterea latentei de procesare
- Consum excesiv de memorie (acumulare de PortHit-uri)

### Solutia: Token Bucket

**Analogie:** Imaginati-va un paznic la intrarea intr-un club care are un bol cu jetoane.
Fiecare persoana (pachet UDP) care vrea sa intre trebuie sa ia un jeton din bol.
Daca bolul are jetoane — intri. Daca e gol — esti respins. Cineva reumple bolul constant
cu un numar fix de jetoane pe secunda (`udp_rate_limit`), dar bolul nu poate depasi
capacitatea maxima (`udp_burst_size`).

- **Trafic normal** (500 pachete/sec): bolul e mereu plin, totul trece. Nimeni nu simte nimic.
- **Burst legitim** (8.000 pachete intr-o secunda): bolul era plin cu 10.000, deci toate trec. Bolul scade la 2.000, dar se reumple treptat.
- **Flood/atac** (100.000 pachete/sec): primele 10.000 trec (bolul era plin), apoi se proceseaza doar ~5.000/sec (rata de reumplere). Restul sunt aruncate — CPU-ul e protejat.

Daca `udp_rate_limit = 0` in config — paznicul nu exista, totul trece ca inainte.

Algoritmul **Token Bucket** permite burst-uri scurte legitime dar limiteaza rata medie:

```
   refill_rate (tokens/sec)
         |
         v
  ┌──────────────┐
  │  Token Bucket │  max_tokens = burst_size
  │  ████████░░░░ │
  └──────┬───────┘
         │ consume 1 token per pachet
         v
   [accept]  sau  [drop daca bucket gol]
```

1. Bucket-ul porneste plin (`burst_size` tokeni).
2. La fiecare secunda se adauga `refill_rate` tokeni (nu depaseste `max_tokens`).
3. Fiecare pachet procesat consuma 1 token.
4. Daca bucket-ul e gol → pachetul este dropat silentios.
5. La fiecare 30 secunde, IDS-ul afiseaza cate pachete au fost dropate.

### Configurare

```toml
[network]
# Pachete acceptate per secunda (0 = dezactivat, fara limita).
udp_rate_limit = 5000
# Capacitate burst: permite varfuri scurte peste rata medie.
udp_burst_size = 10000
```

| Parametru | Efect |
|-----------|-------|
| `udp_rate_limit = 0` | Rate limiting dezactivat (backward compatible) |
| `udp_rate_limit = 5000` | Maxim 5.000 pachete/secunda in medie |
| `udp_burst_size = 10000` | Permite burst de 10.000 pachete imediat |

### Comportament

- **Fara rate limiting** (`udp_rate_limit = 0`): comportament identic cu versiunile anterioare.
- **Cu rate limiting activ**: la pornire se afiseaza rata si burst-ul configurat. Periodic (la 30s), daca au existat drop-uri, se afiseaza numarul de pachete dropate cu badge-ul `[ RATE ]`.
- **Validare config**: daca `udp_rate_limit > 0` si `udp_burst_size = 0`, configuratia este respinsa. Daca `udp_burst_size < udp_rate_limit`, se emite un warning (burst prea mic pentru a absorbi varfuri).

---

## TODO — Securitate si hardening

### Medie

- [ ] **Parola SMTP in plaintext** (`config.toml`) — credentialele SMTP sunt stocate in clar in fisierul de configurare. Oricine cu acces read la fisier le poate citi. *Mitigare: citire din environment variable (`SMTP_PASSWORD`) sau secrets manager.*

- [ ] **SMTP fara TLS** (`alerter.rs`) — cand `smtp_tls = false`, se foloseste `builder_dangerous()` care trimite credentiale (username + password) in clar pe retea. *Mitigare: warning la startup cand TLS e dezactivat.*

### Scazuta

- [ ] **Debug mode disk fill** — modul debug afiseaza fiecare pachet in stdout. In productie cu volum mare si stdout redirectat la fisier, poate umple disk-ul. *Mitigare: dezactivare automata dupa N minute sau limita de linii.*

- [ ] **Verificare permisiuni config.toml** (`config.rs`) — daca fisierul este world-readable (`644`), oricine pe sistem poate citi credentialele SMTP. *Mitigare: warning la startup daca permisiunile sunt prea largi.*

---

## TODO — Functionalitati viitoare

### Impact ridicat

- [ ] **#12 — Whitelist IP-uri** — in retea interna exista scanere de vulnerabilitati legitime (Nessus, OpenVAS), agenti de monitoring sau echipa de securitate care face pentest intern. Fara whitelist, toate genereaza false positives. *Implementare: `[detection.whitelist]` in `config.toml` cu lista de IP-uri/CIDR excluse din detectie.*

- [ ] **#11 — Raport zilnic prin email catre echipa IT/Security** — un task async
  programat sa ruleze o data pe zi (ex: la 08:00) care compileaza si trimite
  un email de sinteza cu activitatea din ultimele 24 de ore. Design complet gandit:
  clasificare subretele (`[network.segments]`), Accept Scan = lateral movement in retea
  izolata. Raportul include:
  - Lista IP-urilor care au generat alerte (Fast/Slow Scan, Accept Scan)
  - Numarul total de porturi unice scanate per IP si tipul actiunii (accept/drop)
  - IP-urile cele mai active (top 10 atacatori)
  - Starea sistemului: uptime IDS-RS, pachete procesate, alerte generate

  *Implementare: adauga `[alerting.daily_report]` in `config.toml` cu*
  *`enabled`, `send_at = "08:00"`, `recipients = [...]`; creeaza un task*
  *tokio cu calcul pana la urmatorul HH:MM; stocheaza statisticile zilnice*
  *intr-un struct protejat de `Arc<Mutex<...>>`; genereaza si trimite prin SMTP.*

- [ ] **Alert fallback la fisier local** — daca SMTP-ul intern sau SIEM-ul este unreachable, alertele se pierd silentios. *Mitigare: scriere alerte intr-un fisier local ca fallback.*

### Impact mediu

- [ ] **#19 — Parser FortiGate (Fortinet)** — format propriu, diferit de Gaia si CEF. Adaugat ca optiune `parser = "fortigate"` in `config.toml`. Implementeaza `trait LogParser` in `src/parser/fortigate.rs`.

- [ ] **#13 — Webhook alerting (Slack/Teams)** — trimitere alerte prin HTTP POST catre webhook-uri Slack sau Microsoft Teams. *Implementare: `[alerting.webhook]` in `config.toml` cu `enabled`, `url`, `format` (slack/teams).*

- [ ] **#16 — SIGHUP config reload** — reincarca `config.toml` fara restart, fara pierdere de context din memorie.

- [ ] **#15 — Statistici live in terminal** — counteri `AtomicU64` pentru pachete procesate, alerte generate, IP-uri tracked. Afisare periodica in terminal fara impact pe performanta.

- [ ] **Diferentiere IP intern vs extern** — RFC1918 (`10.x`, `192.168.x`, `172.16-31.x`) vs IP-uri publice. Un atac din interior merita severitate/label diferit in SIEM si email.

- [ ] **Graceful shutdown SIGTERM** — flushaza alertele pending inainte de oprire.

### Impact scazut

- [ ] **Systemd service file** — restart automat la crash, logging prin journald, start la boot.

- [ ] **Stats periodice la fisier** — dump periodic (ex: la fiecare 5 minute) al unui JSON cu uptime, pachete procesate, alerte generate, IP-uri tracked. Poate fi citit de Nagios/Zabbix intern fara a interoga procesul.

---

## Rezolvat

### Securitate si hardening

| # | Descriere | Sectiune |
|---|-----------|----------|
| #3 | MAX_HITS_PER_IP — FIFO per IP | [Protectie memorie](#protectie-memorie--max_hits_per_ip) |
| #4 | MAX_TRACKED_IPS — LRU eviction | [Protectie DashMap](#protectie-dashmap--max_tracked_ips-si-lru-eviction) |
| #7 | Validare config — 16 constrangeri | [Validare automata](#validare-automata-la-pornire) |
| #8 | Sanitizare CEF anti-injection | [Securitate CEF](#securitate--sanitizare-campuri-cef-anti-injection) |
| #9 | Rate Limiting UDP — Token Bucket | [Rate Limiting](#rate-limiting-udp--token-bucket) |

### Functionalitati

| # | Descriere |
|---|-----------|
| #1 | Mesaje SIEM citesc time_window din config (nu hardcodate) |
| #10 | Accept Scan — `accept_hits` separate, SigID 1003, magenta CLI |
| #17 | Cleanup task sleep-first (nu interval tick imediat) |
| — | `dest_ip` in LogEvent/Alert, `dst=` in CEF, porturi in `msg` |

### Calitate cod

| # | Descriere |
|---|-----------|
| #2 | Cache SMTP transport (construit o data in `new()`) |
| #18 | Teste unitare Slow Scan (3 teste). **Total: 33 passed** |
