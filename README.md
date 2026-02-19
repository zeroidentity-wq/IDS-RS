# IDS-RS — Intrusion Detection System

Sistem de detectie a intruziunilor bazat pe analiza log-urilor de firewall, scris in Rust.
Detecteaza scanari de retea (Fast Scan si Slow Scan) si trimite alerte catre SIEM si email.

---

## Cuprins

- [Arhitectura](#arhitectura)
- [Cerinte sistem](#cerinte-sistem)
- [Compilare](#compilare)
- [Configurare](#configurare)
- [Formate de log — Anatomie si flux](#formate-de-log--anatomie-si-flux)
- [Calatoria unui eveniment — De la firewall la SIEM](#calatoria-unui-eveniment--de-la-firewall-la-siem)
- [Rulare](#rulare)
- [Testare](#testare)
- [Structura proiect](#structura-proiect)
- [Concepte Rust acoperite](#concepte-rust-acoperite)

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
4. Evenimentele de tip `drop` sunt inregistrate in detectorul thread-safe (`DashMap`)
5. Daca un IP depaseste pragul de porturi unice intr-o fereastra de timp, se genereaza o alerta
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
| Fereastra Slow Scan | > fereastra Fast Scan |
| `cleanup.interval_secs` | ≥ 1 |
| `cleanup.max_entry_age_secs` | ≥ fereastra Slow Scan |
| `alerting.siem.port` (daca enabled) | ≠ 0 |
| `alerting.siem.host` (daca enabled) | nenul |
| `alerting.email.smtp_port` (daca enabled) | ≠ 0 |
| `alerting.email.smtp_server` (daca enabled) | nenul |
| `alerting.email.from` (daca enabled) | nenul |
| `alerting.email.to` (daca enabled) | cel putin un destinatar |

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
1. Gaseste cuvantul `drop` dupa `Checkpoint:` cu un regex
2. Extrage campurile `src:`, `proto:`, `service:` prin split dupa `;`

- Daca actiunea este `accept` → returneaza `None`, linia este ignorata complet
- Daca actiunea este `drop` → returneaza un `LogEvent`:

```rust
LogEvent {
    source_ip:  192.168.11.7,    // atacatorul
    dest_port:  443,              // portul pe care a batut
    protocol:   "tcp",
    action:     "drop",
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

La fiecare eveniment nou verifica **doua ferestre de timp** independente:

```
Fast Scan: cate porturi UNICE a atins acest IP in ultimele 10 secunde?
           daca > 15  →  ALERTA Fast Scan

Slow Scan: cate porturi UNICE a atins acest IP in ultimele 5 minute?
           daca > 30  →  ALERTA Slow Scan
```

Cand pragul este depasit, creeaza un struct `Alert`:

```rust
Alert {
    scan_type:    ScanType::Fast,
    source_ip:    192.168.11.7,
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
    ScanType::Fast => sig_id = "1001", name = "Fast Port Scan Detected"
    ScanType::Slow => sig_id = "1002", name = "Slow Port Scan Detected"
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
1001                     → Signature ID (1001=Fast, 1002=Slow) — folosit in reguli
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

Rezultat asteptat: `test result: ok. 17 passed`

Testele acopera:
- Parser GAIA: drop valid, accept ignorat, broadcast fara src, ICMP fara service, format invalid
- Parser CEF: drop valid, accept ignorat, syslog header, syslog priority header, non-CEF, campuri incomplete
- Detector: fast scan alert, sub prag, cooldown, cleanup, IP-uri separate

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

### Pas 4 — Trafic normal (NU trebuie sa declanseze alerta)

```bash
# GAIA
python3 tester/tester.py normal

# CEF
python3 tester/tester.py normal --cef
```

IDS-RS **nu** ar trebui sa genereze nicio alerta.

### Pas 5 — Replay log-uri reale Checkpoint

Fisierul `sample2_gaia.log` contine 56 de log-uri reale Checkpoint GAIA (accept + drop mixt):

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
┌────────────────────────────────┬───────────────────────────────┐
│            Command             │         What it does          │
├────────────────────────────────┼───────────────────────────────┤
│ tester.py fast                 │ Replay sample_fast_gaia.log   │
├────────────────────────────────┼───────────────────────────────┤
│ tester.py fast --cef           │ Replay sample_fast_cef.log    │
├────────────────────────────────┼───────────────────────────────┤
│ tester.py slow                 │ Replay sample_slow_gaia.log   │
├────────────────────────────────┼───────────────────────────────┤
│ tester.py normal               │ Replay sample_normal_gaia.log │
├────────────────────────────────┼───────────────────────────────┤
│ tester.py replay <file>        │ Replay from any file          │
├────────────────────────────────┼───────────────────────────────┤
│ tester.py sample <file> <mode> │ Advanced sample mode          │
└────────────────────────────────┴───────────────────────────────┘

```

### Parametri comuni

| Parametru | Default | Descriere |
|-----------|---------|-----------|
| `--host` | `127.0.0.1` | Adresa IP a IDS-RS |
| `--port` | `5555` | Portul UDP al IDS-RS |
| `--cef` | `false` | Format CEF in loc de GAIA (preset-uri) |
| `--format` | `gaia` | Formatul log-urilor: `gaia` sau `cef` (fast-scan/slow-scan) |
| `--source` | `192.168.11.7` | IP-ul sursa simulat (fast-scan/slow-scan) |
| `--ports` | `20` / `40` | Numar de porturi unice (fast-scan/slow-scan) |
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

### [Nerealizat] — Imbunatatiri in curs de implementare

- [x] **Mesaje SIEM hardcodate** (`alerter.rs`) — valorile ferestrei de timp (`10 secunde`,
  `5 minute`) din mesajul CEF trimis catre SIEM erau hardcodate. Acum `Alerter` primeste
  `DetectionConfig` si citeste `time_window_secs` / `time_window_mins` direct din configurare.

- [x] **Cleanup task: primul tick imediat** (`main.rs`) — `tokio::time::interval()` face
  primul tick imediat la creare, rulând un cleanup inutil la startup. Inlocuit cu un loop
  simplu `sleep`-first: asteapta intai intervalul complet, apoi curata.

- [x] **Target Address si porturi in mesajul SIEM** — campul `dst` (Target Address in ArcSight)
  adaugat in extensiile CEF din informatia `dst` a log-ului firewall. Campul `msg` include
  acum si lista porturilor scanate (trunchiat la 512 caractere pentru compatibilitate syslog).
  Campul `cs1=ScannedPorts` contine in continuare lista completa. `dest_ip` adaugat in
  `LogEvent` si `Alert`; extras de ambii parseri (Gaia si CEF).

- [x] **Validare config post-deserializare** (`config.rs`) — adaugata `AppConfig::validate()`
  apelata automat din `load()`. Verifica 16 constrangeri semantice (valori zero invalide,
  consistenta ferestre de timp, campuri obligatorii conditionale) si raporteaza toate
  erorile simultan la pornire, inainte ca aplicatia sa inceapa sa asculte pe UDP.

---

## TODO — Securitate si hardening

Probleme identificate si planificate pentru rezolvare, ordonate dupa prioritate.

### Critica

- [ ] **Memorie neboundata per IP** (`detector.rs`) — `Vec<PortHit>` creste nelimitat pentru fiecare IP sursa pana la urmatorul cleanup cycle. Un atacator care trimite ~100k pachete/s cu porturi unice poate consuma GB de RAM in 60s. *Mitigare: limita max entries per IP (ex: 10.000, drop oldest).*

- [ ] **IP spoofing -> DashMap flood** (`detector.rs`) — un atacator care spoofs milioane de IP-uri sursa diferite umple `DashMap`-ul fara limita. Cleanup-ul sterge doar entries vechi, nu limiteaza numarul total. *Mitigare: limita globala pe numarul de IP-uri tracked (ex: 100.000, LRU eviction).*

### Medie

- [ ] **Parola SMTP in plaintext** (`config.toml`) — credentialele SMTP sunt stocate in clar in fisierul de configurare. Oricine cu acces read la fisier le poate citi. *Mitigare: citire din environment variable (`SMTP_PASSWORD`) sau secrets manager.*

- [ ] **SMTP fara TLS** (`alerter.rs`) — cand `smtp_tls = false`, se foloseste `builder_dangerous()` care trimite credentiale (username + password) in clar pe retea. *Mitigare: warning la startup cand TLS e dezactivat; forteaza STARTTLS.*

- [x] **Lipsa validare config** (`config.rs`) — rezolvat. `AppConfig::validate()` verifica toate constrangerile semantice la pornire. Vezi sectiunea [Validare automata la pornire](#validare-automata-la-pornire).

### Scazuta

- [ ] **SIEM alert injection** (`alerter.rs`) — mesajul SIEM este construit cu `format!()`. Daca in viitor se adauga campuri text din log-ul raw (hostname, etc.), un atacator ar putea injecta mesaje syslog false in SIEM. *Mitigare: sanitizare/escape campuri text inainte de includere in mesajul SIEM.*

- [ ] **Debug mode disk fill** — modul debug afiseaza fiecare pachet in stdout. In productie cu volum mare si stdout redirectat la fisier, poate umple disk-ul. *Mitigare: dezactivare automata dupa N minute sau limita de linii.*

- [ ] **Lipsa rate-limiting pe receptie UDP** (`main.rs`) — main loop-ul proceseaza pachete fara limita. Un flood UDP poate satura CPU-ul. *Mitigare: token bucket / rate limiter pe receptie.*

---

## TODO — Functionalitati viitoare

Idei de extindere planificate, ordonate dupa impact operational.

### Impact ridicat

- [ ] **Detectie scanare porturi deschise (accept scan)** — in prezent IDS-RS
  analizeaza exclusiv evenimentele `drop`. Un atacator sofisticat poate scana
  **porturile deschise** (servicii active) generand exclusiv trafic `accept`,
  trecand complet neobservat. Exemplu: un tool care bate metodic porturile
  22, 80, 443, 3306 ale tuturor host-urilor din retea va genera doar accept-uri.
  *Implementare: extinde `LogParser` si `Detector` sa proceseze si actiunea*
  *`accept`; adauga praguri separate pentru accept-scan in `config.toml`;*
  *creeaza `ScanType::AcceptScan` in `detector.rs`; alerta distincta in SIEM*
  *cu Signature ID nou (ex: 1003) pentru diferentiere fata de drop-scan.*

- [ ] **Raport zilnic prin email catre echipa IT/Security** — un task async
  programat sa ruleze o data pe zi (ex: la 08:00) care compileaza si trimite
  un email de sinteza cu activitatea din ultimele 24 de ore. Raportul include:
  - Lista IP-urilor care au generat alerte (Fast/Slow Scan, Accept Scan)
  - Numarul total de porturi unice scanate per IP si tipul actiunii (accept/drop)
  - IP-urile cele mai active (top 10 atacatori)
  - Comparatie cu ziua precedenta (IP-uri noi vs. recurente)
  - Starea sistemului: uptime IDS-RS, pachete procesate, alerte generate

  *Implementare: adauga `[alerting.daily_report]` in `config.toml` cu*
  *`enabled`, `send_at = "08:00"`, `recipients = [...]`; creeaza un task*
  *tokio cu `tokio::time::interval` de 24h sau calcul pana la urmatorul HH:MM;*
  *stocheaza statisticile zilnice intr-un struct protejat de `Arc<Mutex<...>>`*
  *actualizat de `Detector` la fiecare eveniment; genereaza corpul emailului*
  *in `alerter.rs` si trimite prin SMTP-ul deja configurat.*
