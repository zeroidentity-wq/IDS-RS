# IDS-RS — Intrusion Detection System

Sistem de detectie a intruziunilor bazat pe analiza log-urilor de firewall, scris in Rust.
Detecteaza scanari de retea (Fast Scan, Slow Scan, Accept Scan, Distributed Scan), Lateral Movement
si Beaconing C2, si trimite alerte catre SIEM si email.

---

## Cuprins

- [Stare proiect](#stare-proiect)
- [Arhitectura](#arhitectura)
- [Cerinte sistem](#cerinte-sistem)
- [Compilare](#compilare)
- [Configurare](#configurare)
- [Formate de log — Anatomie si flux](#formate-de-log--anatomie-si-flux)
- [Loguri de la alte firewall-uri — Parser custom](#loguri-de-la-alte-firewall-uri--parser-custom)
- [Calatoria unui eveniment — De la firewall la SIEM](#calatoria-unui-eveniment--de-la-firewall-la-siem)
- [Rulare](#rulare)
- [Instalare ca serviciu (RHEL 9)](#instalare-ca-serviciu-rhel-9)
- [Web Dashboard](#web-dashboard)
- [Testare](#testare)
- [Structura proiect](#structura-proiect)
- [Protectie memorie — MAX\_HITS\_PER\_IP](#protectie-memorie--max_hits_per_ip)
- [Protectie DashMap — MAX\_TRACKED\_IPS si LRU Eviction](#protectie-dashmap--max_tracked_ips-si-lru-eviction)
- [Securitate — Sanitizare campuri CEF anti-injection](#securitate--sanitizare-campuri-cef-anti-injection)
- [Rate Limiting UDP — Token Bucket](#rate-limiting-udp--token-bucket)
- [Livrare alerte — Cozi, spool si dead-letter](#livrare-alerte--cozi-spool-si-dead-letter)
- [Persistenta la restart](#persistenta-la-restart)
- [Hostname Resolve — Mapping Static IP→Hostname](#hostname-resolve--mapping-static-iphostname)
- [Subnet Mapping — Mapping CIDR→Locatie](#subnet-mapping--mapping-cidrlocatie)
- [Concepte Rust acoperite](#concepte-rust-acoperite)

---

## Stare proiect

| Categorie | Detalii |
|-----------|---------|
| **Detectie** | Fast Scan, Slow Scan, Accept Scan, Lateral Movement, Distributed Scan, Beaconing C2 — toate funcționale |
| **Parseri** | Checkpoint Gaia, CEF/ArcSight, Gaia-CEF (LEA blob in CEF Name), Custom configurabil (cheie=valoare / CSV — FortiGate, iptables, Palo Alto etc.) |
| **Alertare** | SIEM (UDP CEF), Email (SMTP async) |
| **Securitate** | Sanitizare CEF, Rate Limiting UDP, MAX_HITS_PER_IP, MAX_TRACKED_IPS LRU |
| **Validare** | 16 constrângeri semantice la startup |
| **Livrare** | Cozi separate SIEM/email, spool durabil pe disc, dead-letter, retry per destinatar |
| **Teste** | 162 teste (157 biblioteca + 5 binar) — toate trec |
| **Clippy** | 0 warnings (`cargo clippy --all-targets -- -D warnings` in CI) |

### Implementat

- [x] Detectie Fast Scan + Slow Scan + Accept Scan
- [x] Parseri Gaia, CEF si Gaia-CEF (LEA blob in CEF Name)
- [x] Parser custom configurabil din `config.toml` (`kv` / `csv`) + subcomenzile `learn` si `test-parser` — vezi [Parser custom](#loguri-de-la-alte-firewall-uri--parser-custom)
- [x] Alertare SIEM (UDP CEF) si Email (SMTP async cu cache transport)
- [x] Sanitizare campuri CEF anti-injection
- [x] Rate Limiting UDP (Token Bucket)
- [x] Protectie memorie: MAX_HITS_PER_IP (FIFO) + MAX_TRACKED_IPS (LRU eviction)
- [x] Validare config cu raportare cumulata (16 constrangeri)
- [x] Whitelist IP-uri (IP + CIDR) — excluse complet din detectie
- [x] Hostname mapping static (`[network.hostnames]`) — afisare in CLI, SIEM (shost=/dhost=) si email
- [x] Subnet mapping static (`[network.subnets]`) — CIDR→locatie (etaj, cladire, zona) in CLI, SIEM (cs2/cs3) si email
- [x] Lateral Movement detection — comportament N destinatii unice, SigID 1004, severitate CEF 8
- [x] Distributed Scan detection — N surse unice catre aceeasi tinta, SigID 1005, severitate CEF 7
- [x] Beaconing C2 detection (#24) — flow periodic (CV pe intervale), SigID 1006, severitate CEF 9
- [x] Web Dashboard (#25) — server HTTP embedded cu graf D3.js force-directed, API JSON, auto-refresh 5s
- [x] Graceful shutdown SIGTERM + Hot reload SIGHUP
- [x] Persistenta la restart (#32) — starea detectorului si alertele din dashboard salvate la oprire si periodic — vezi [Persistenta la restart](#persistenta-la-restart)
- [x] Livrare durabila: spool pe disc, dead-letter pentru esecuri permanente, retry email doar catre destinatarii ramasi, golirea cozilor in spool la oprire
- [x] Teste: 162 passed (persistenta la restart, parser custom, statistici de parsare, learn/test-parser, parseri, detector, livrare/spool cu server SMTP fals, config strict, reload, web auth, whitelist si toate detectiile)

### Hardening operational

Versiunea curenta aplica limite si controale explicite pe toate fluxurile critice:

- `trusted_senders` este obligatoriu pe un listener non-loopback; configuratia
  inclusa accepta doar localhost si trebuie completata cu IP-urile firewall/relay.
  Pe un listener dual-stack (`::`), adresele IPv4-mapped (`::ffff:10.0.0.1`) sunt
  normalizate, deci intrarile IPv4 din lista se potrivesc;
- rate limiting-ul global si per sender este taxat per eveniment/linie, nu per
  datagrama, iar numarul de linii si lungimea unei linii sunt limitate;
- `max_tracked_flows`, `max_flows_per_source` si `max_tracked_ips` limiteaza
  cardinalitatea starii; la atingerea unei limite se evacueaza in lot ~1/8 din
  cele mai vechi intrari, ca un flood (sweep orizontal, IP-uri spoofed) sa coste
  O(1) amortizat per eveniment, nu O(n);
- SIEM si email au cozi independente; erorile si saturarea sunt salvate atomic
  in `alerting.spool_directory` si redate cu exponential backoff. Esecurile
  permanente ajung in dead-letter, iar la oprire cozile sunt golite in spool —
  vezi [Livrare alerte](#livrare-alerte--cozi-spool-si-dead-letter);
- listele CEF sunt esantionate, iar datagrama SIEM are o limita stricta de 60 KB;
- campurile TOML necunoscute sunt respinse, pentru ca typo-urile sa nu dezactiveze
  silentios o protectie;
- API-ul dashboard-ului necesita bearer token cand bind-ul nu este loopback si
  aplica limita de concurenta plus security headers; pentru acces remote, HTTP-ul
  trebuie publicat exclusiv printr-un reverse proxy TLS;
- toolchain-ul/MSRV este fixat la Rust 1.85 si verificat in CI pe Linux si Windows.

Setarile de listener, parser, cleanup, spool/queue/retry si securitate web necesita
restart. La `SIGHUP`, modificarile acestor campuri sunt raportate si ignorate; pragurile,
whitelist-ul, destinatarii si rate limiter-ul raman hot-reloadable.

Dupa ce campurile care necesita restart sunt fixate la valorile curente, config-ul
rezultat este **validat din nou**. Exemplu: un fisier care trece pe
`listen_address = "127.0.0.1"` cu `trusted_senders = []` este valid in sine, dar
procesul ramane pe adresa veche (ex: `0.0.0.0`), unde lista goala ar accepta
evenimente de la orice host — reload-ul este respins si config-ul vechi ramane activ.

Handler-ele SIGTERM/SIGHUP sunt inregistrate la pornire; daca inregistrarea esueaza,
procesul nu porneste (in loc sa ruleze fara semnale functionale).

### De implementat

- [x] Parser FortiGate (format Fortinet) — prin parser-ul custom
- [ ] Raport zilnic email cu clasificare subretele
- [x] Hot reload config la SIGHUP
- [x] Lateral Movement detection (#22)
- [x] Distributed Scan detection (#23)
- [x] Beaconing C2 detection (#24)

### Posibile implementari

#### Detectii noi
- [ ] Brute Force detection — accept scan repetate pe porturi critice (22, 3389, 445) de la acelasi IP (#39)
- [ ] Port Knock detection — secvente de porturi accesate in ordine specifica (#26)
- [ ] Exfiltration detection — volume mari de trafic outbound neobisnuit de la IP intern (#27)
- [ ] Supresie/deduplicare alerte — cooldown per IP per tip alerta, previne flood de emailuri (#28)

#### Parseri noi
- [x] Parser iptables/nftables — firewall Linux (#29) — prin parser-ul custom
- [ ] Parser Cisco ASA (#30)
- [ ] File watcher (tail -f echivalent) — citire din fisiere log locale, nu doar UDP (#31)

#### Operational / Rezilienta
- [x] Persistenta stare la restart — detectorul nu pierde contextul la repornire (#32)
- [ ] Dump statistici la SIGUSR1 — top atacatori si counteri la semnal, fara restart (#33)
- [ ] Blacklist locala de IP-uri (IOC offline) — fiser CSV/JSON cu IP-uri rele, alerta la primul pachet (#34)
- [ ] Threshold dinamic / baseline — prag adaptat la traficul normal al retelei (#35)

#### Raportare / Vizibilitate
- [x] Web Dashboard embedded cu graf D3.js force-directed (#25/#36)
- [ ] Export CSV/JSON per sesiune — analiza forensica offline dupa incident (#37)
- [ ] TLS pentru trimitere SIEM — traficul de alertare nu mai e plain UDP (#38)

---

## Arhitectura

```
                          +-------------------+
  Firewall (Gaia/CEF) -->| UDP :5555         |
  log-uri syslog         | LogParser (trait)  |
                          |   - GaiaParser    |
                          |   - CefParser     |
                          |   - GaiaCefParser |
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
3. Fiecare linie este parsata cu parser-ul activ (`gaia`, `cef` sau `gaia_cef`), selectat din `config.toml`
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

Comenzile de mai sus cer internet. Pentru serverele din reteaua izolata,
binarul se compileaza pe o masina conectata cu `deploy/build-rhel9.sh` (un binar
compilat pe Fedora nu porneste pe RHEL 9: `GLIBC_2.38 not found`) si se transfera
ca arhiva — vezi [Instalare ca serviciu](#instalare-ca-serviciu-rhel-9).

### Windows 10/11

- [Rust](https://rustup.rs/) (include cargo)
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) cu componenta "C++ build tools"

Pe Windows, oprirea gratioasa este disponibila prin Ctrl+C. `SIGHUP` si `SIGTERM`
sunt disponibile doar pe Unix/Linux.

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
| `network.parser` | `"gaia"`, `"cef"` sau `"gaia_cef"` |
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
| `network.hostnames` cheile | fiecare cheie trebuie sa fie un IP valid |
| `network.subnets` cheile | fiecare cheie trebuie sa fie un CIDR valid (ex: `10.10.1.0/24`) |

```toml
[network]
listen_address = "0.0.0.0"    # Interfata de ascultare
listen_port = 5555             # Port UDP pentru receptie log-uri
parser = "gaia"                # Parser activ: "gaia", "cef", "gaia_cef" sau "custom"
# debug = true                 # Mod debug: afiseaza fiecare pachet cu validare parsare

[network.hostnames]            # Mapping static IP → hostname (optional)
# "10.0.1.10" = "srv-dc01"    # Afisat in alerte CLI, SIEM (shost=/dhost=) si email
# "10.0.1.20" = "srv-mail"
# "10.0.2.50" = "ws-admin01"

[network.subnets]              # Mapping static subnet CIDR → locatie fizica (optional)
# "10.10.1.0/24" = "Etaj 1"   # Afisat in alerte CLI [Etaj 1], SIEM (cs2/cs3), email
# "10.10.2.0/24" = "Etaj 2"   # Longest prefix match: /24 are prioritate peste /16
# "10.10.0.0/16" = "Cladire Principala"

[detection]
alert_cooldown_secs = 300      # Cooldown intre alerte pentru acelasi IP
whitelist = [                  # IP-uri/CIDR excluse din detectie
    # "10.0.1.10",             # srv-dc01
    # "10.0.2.0/24",           # subnet management
]

[detection.fast_scan]
port_threshold = 15            # Alerta daca IP acceseaza >= N porturi unice...
time_window_secs = 10          # ...in acest interval (secunde)

[detection.slow_scan]
port_threshold = 30            # Alerta daca IP acceseaza >= N porturi unice...
time_window_mins = 5           # ...in acest interval (minute)

[detection.accept_scan]
port_threshold = 5             # Alerta daca IP acceseaza >= N porturi DESCHISE unice...
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
max_entry_age_secs = 600      # Sterge date mai vechi de N secunde (dar nu mai noi decat fereastra fiecarei detectii, ex: beaconing)
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

**Gaia-CEF** — Checkpoint LEA blob impachetat in CEF Name field (via ArcSight):
```
<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action="Drop" src="1.2.3.4" dst="5.6.7.8" service="443" proto="6"|5|
```

In acest format, ArcSight pune tot blob-ul LEA (perechi `key="value"`) in campul Name (index 5)
al CEF-ului, nu in extensii (index 7). Parser-ul `gaia_cef` extrage campurile din Name.

**Custom** — orice alt firewall care trimite linii `cheie=valoare` sau CSV (FortiGate,
iptables, Palo Alto...). Formatul se descrie in `[custom_parser]`; vezi
[Loguri de la alte firewall-uri](#loguri-de-la-alte-firewall-uri--parser-custom).

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

### Formatul Gaia-CEF (LEA blob in CEF Name)

Unele firewall-uri Checkpoint Gaia (versiune veche, LEA v5) trimit log-uri prin ArcSight,
dar ArcSight pune **tot blob-ul LEA** in campul Name (index 5), nu in extensii (index 7).
Extensiile raman goale sau minime.

```
<134>Feb 17 11:32:44 gw CEF:0|CheckPoint|FW-1|R77|100|action="Drop" src="1.2.3.4" dst="5.6.7.8" service="443" proto="6"|5|
```

Anatomia:

```
<134>            → prioritate syslog
Feb 17 11:32:44  → timestamp syslog
gw               → hostname
CEF:0            → versiunea CEF
CheckPoint       → vendor
FW-1             → produs
R77              → versiune produs
100              → signature ID
                 → Name (index 5) — AICI ESTE BLOB-UL LEA:
  action="Drop"     → actiunea firewall-ului
  src="1.2.3.4"     → IP sursa (atacatorul)
  dst="5.6.7.8"     → IP destinatie (tinta)
  service="443"     → portul destinatie
  proto="6"         → protocol IANA (6=tcp, 17=udp, 1=icmp)
5                → severitate
                 → extensii (index 7) — GOALE in acest format
```

Parsatorul `gaia_cef.rs` extrage campul Name (index 5), parseaza perechile `key="value"` cu
verificare boundary (nu sub-string match), si mapeaza numerele de protocol IANA la nume standard.

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
parser = "gaia"      # Scenariul A: firewall trimite GAIA direct la IDS-RS
parser = "cef"       # Scenariul B: ArcSight Forwarder trimite CEF la IDS-RS
parser = "gaia_cef"  # Scenariul C: ArcSight pune LEA blob in CEF Name (Gaia vechi, LEA v5)
```

In productie reala vei folosi cel mai probabil `parser = "cef"` daca ai deja
un ArcSight SmartConnector instalat, deoarece acesta normalizeaza totul la CEF.
Modul `"gaia"` este util cand conectezi firewall-ul **direct** la IDS-RS, fara intermediar.
Modul `"gaia_cef"` este pentru cazul specific in care ArcSight primeste log-uri LEA v5
de la Checkpoint vechi si le pune in campul Name al CEF-ului, nu in extensii.

---

## Loguri de la alte firewall-uri — Parser custom

Parserele `gaia`, `cef` si `gaia_cef` sunt facute pentru Check Point. Pentru orice
alt firewall care trimite linii **cheie=valoare** sau **CSV**, IDS-RS are parser-ul
`custom`: formatul se descrie in `config.toml`, fara modificari de cod.

Formatul **nu este ghicit la rulare**. Intr-un IDS, o linie interpretata gresit nu
da nicio eroare, doar rateaza atacuri — de aceea maparea este explicita, iar
programul ajuta doar la scrierea ei (`learn`) si la verificarea ei (`test-parser`).

### Pasii de configurare

1. **Colecteaza un sample** de cateva sute de linii, cat mai variat: conexiuni
   blocate, conexiuni permise si alte tipuri de log pe care le trimite firewall-ul.

2. **Genereaza o propunere:**
   ```bash
   ./target/release/ids-rs learn sample.log
   ```
   Comanda afiseaza campurile gasite (tipul dedus si exemple de valori), o
   sectiune `[custom_parser]` gata de copiat si cate linii din sample parseaza ea.
   Liniile `# VERIFICA:` marcheaza ce a fost ghicit, iar `# TODO:` ce lipseste.

3. **Copiaza sectiunea in `config.toml`** si seteaza `parser = "custom"` in `[network]`.
   Verifica fiecare camp si muta in `drop_values` / `accept_values` valorile din
   comentariul „Valori de actiune neclasificate”, daca au sens pentru voi.

4. **Verifica pe sample:**
   ```bash
   ./target/release/ids-rs test-parser config.toml sample.log
   ```
   ```
     Parsate:               23  (drop 20, accept 3)
     Actiune nemapata:       1
         "server-rst" ×1
     Ignorate:               1  (alt format, require_text lipsa, IP/port lipsa sau invalid)

   Exemple parsate:
     linia 1      drop   192.168.1.66 → 10.0.0.9:21223/tcp
   ```
   Repeta pasii 3–4 pana cand rezultatul corespunde asteptarilor.

5. **Porneste IDS-ul.** La fiecare 30 de secunde apare un rezumat al parsarii:
   ```
   [STAT] Parsare 30s: 1200 linii → 1150 parsate | 10 actiune nemapata | 40 ignorate
   ```
   Evenimentele cu actiune nemapata sunt raportate separat, cu un exemplu
   (`N evenimente ignorate: actiune nemapata (ex: "...")`). Daca intr-o fereastra
   nicio linie nu este parsata, apare un avertisment cu o linie de exemplu — semn ca
   formatul log-urilor s-a schimbat (ex: dupa un update de firmware). Aceleasi
   contoare, cumulate de la pornire, sunt in `GET /api/stats` pe dashboard.

### Referinta `[custom_parser]`

| Camp | Obligatoriu | Descriere |
|------|-------------|-----------|
| `format` | da | `"kv"` — perechi `cheie=valoare` separate prin spatii, valori optional intre ghilimele; `"csv"` — coloane separate de `delimiter` |
| `delimiter` | nu | Doar pentru `csv`. Implicit `","`; ex. `";"`, `"\t"`, `"\|"` |
| `require_text` | nu | Liniile care nu contin textul sunt ignorate (ex. `'type="traffic"'`, `",TRAFFIC,"`) |
| `fields.src_ip` | da | Cheia (kv) sau indexul coloanei de la 0 (csv) cu IP-ul sursa |
| `fields.dst_ip` | da | IP-ul destinatie — fara el nu se pot forma perechile pentru Fast/Slow/Accept Scan |
| `fields.dst_port` | da | Portul destinatie; liniile fara port valid (ex. ICMP) sunt ignorate |
| `fields.protocol` | nu | Nume (`TCP`) sau numar IANA (`6`); implicit `tcp` |
| `fields.action` + `drop_values` / `accept_values` | una din doua | Campul cu actiunea si valorile care inseamna drop / accept (fara diferenta majuscule/minuscule) |
| `action_from_text` | una din doua | Pentru log-uri fara camp de actiune: `{ "TEXT" = "drop" \| "accept" }`, cautat in linie; castiga textul cel mai lung |

Drop-urile alimenteaza Fast Scan si Slow Scan; accept-urile alimenteaza Accept Scan,
Lateral Movement, Distributed Scan si Beaconing. Valorile care nu apar in nicio
lista (ex. `reject` daca nu l-ati adaugat) nu ajung la detector.

Validarea la pornire raporteaza toate erorile odata: sectiune lipsa, ambele sau
niciuna dintre sursele de actiune, aceeasi valoare la drop si accept, coloana
numerica in format `kv` sau cheie text in format `csv`.

### Exemple gata facute

La finalul `config.toml` sunt trei exemple comentate, verificate automat de teste
pe sample-urile din `tester/`:

| Firewall | Format | Actiunea vine din | Sample |
|----------|--------|-------------------|--------|
| FortiGate | `kv`, `require_text = 'type="traffic"'` | `action` (`deny` / `accept`, `close`, `timeout`) | `tester/sample_fast_fortigate.log` |
| iptables | `kv` (`SRC=`, `DST=`, `DPT=`) | prefixul `--log-prefix` (`FW-DROP` / `FW-ACCEPT`) | `tester/sample_fast_iptables.log` |
| Palo Alto | `csv`, coloanele 7, 8, 25, 29, 30 | coloana 30 (`deny`, `drop`, `reset-*` / `allow`) | `tester/sample_fast_paloalto.log` |

Valorile de actiune din exemple urmeaza documentatia producatorilor — confirmati-le
pe log-urile voastre cu `test-parser`. Pentru iptables, prefixele trebuie sa fie cele
din regulile voastre, de exemplu:
```bash
iptables -A INPUT -j LOG --log-prefix "FW-DROP: "
```

Test complet cu tester-ul (dupa ce ati activat exemplul corespunzator):
```bash
python3 tester/tester.py fast-scan --format fortigate --ports 20 --delay 0.1
python3 tester/tester.py fast-scan --format iptables  --ports 20 --delay 0.1
python3 tester/tester.py fast-scan --format paloalto  --ports 20 --delay 0.1
```

### Limitari

- Un singur parser per instanta: un firewall cu alt format ruleaza intr-o instanta
  separata, cu propriul `config.toml` si port.
- Doar formate pe o singura linie, `kv` sau `csv` (nu JSON, nu XML, nu multi-linie).
- `[custom_parser]` si `network.parser` necesita restart; la `SIGHUP` modificarile
  lor sunt raportate si ignorate.
- `learn` analizeaza primele 10.000 de linii; la CSV generic alegerea coloanelor
  este cea mai nesigura — verificati-o pe tabelul de campuri afisat.

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
`main.rs` orchestreaza, `parser/` intelege formatele, `detector/` decide,
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

# Propune [custom_parser] dintr-un sample de log (nu porneste IDS-ul)
./target/release/ids-rs learn sample.log

# Verifica parser-ul configurat pe un sample (cod de iesire 1 daca nu parseaza nimic)
./target/release/ids-rs test-parser config.toml sample.log
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

## Instalare ca serviciu (RHEL 9)

IDS-RS ruleaza ca serviciu systemd sablon, `ids-rs@<nume>`: **o instanta per sursa
de log-uri** (ex: `ids-rs@checkpoint`, `ids-rs@fortigate`), fiecare cu config-ul,
portul si spool-ul ei.

Serverele sunt in retea izolata (fara internet), deci compilarea si impachetarea
se fac pe o **masina conectata**, iar pe server ajunge o singura arhiva:

```
masina conectata                         transfer            server RHEL 9 (air-gapped)
deploy/build-rhel9.sh  →  binar RHEL 9                       sha256sum -c
deploy/package.sh      →  ids-rs-…-rhel9.tar.gz  ───────►    tar xzf, sudo ./install.sh
```

| Fisier | Unde ruleaza | Rol |
|--------|--------------|-----|
| `deploy/build-rhel9.sh` | masina conectata | Compileaza binarul release intr-un container UBI 9 (podman) → `target/rhel9/release/ids-rs` |
| `deploy/package.sh` | masina conectata | Verifica glibc-ul cerut si creeaza `target/dist/ids-rs-<versiune>-<commit>-rhel9.tar.gz` + `.sha256` |
| `deploy/install.sh` | server, offline | Creeaza utilizatorul `ids-rs`, instaleaza binarul, unit-ul si `/etc/ids-rs/` |
| `deploy/systemd/ids-rs@.service` | server | Unit-ul sablon, cu hardening systemd |

Pe server binarul are nevoie doar de `glibc`, `openssl-libs`, `zlib` si `libgcc`, toate
din instalarea de baza RHEL 9; nu descarca nimic. Dashboard-ul web are D3.js inclus in binar.
Fluxul complet (arhiva → `install.sh` → serviciu → alerta → reload → stop) a fost
validat intr-un container RHEL 9.6 (UBI) fara retea; `systemd-analyze security`: 1.9 OK.

### 1. Compilare si impachetare (masina conectata)

Binarul trebuie compilat pentru glibc 2.34 (RHEL 9) — un binar compilat pe Fedora
nu porneste pe server. Cu podman:

```bash
deploy/build-rhel9.sh        # prima rulare descarca imaginea UBI 9, Rust 1.85 si crate-urile
deploy/package.sh            # → target/dist/ids-rs-0.1.0-<commit>-rhel9.tar.gz (+ .sha256)
```

Arhiva contine `ids-rs`, `install.sh`, `systemd/ids-rs@.service`, `example.toml`,
`README.md` si `SHA256SUMS`. Numele include commit-ul (cu `-dirty` daca exista
modificari necomise), ca sa stiti exact ce versiune ruleaza pe server.

### 2. Instalare pe server (offline, idempotent la upgrade)

Dupa transferul arhivei si al fisierului `.sha256` prin canalul aprobat:

```bash
sha256sum -c ids-rs-0.1.0-<commit>-rhel9.tar.gz.sha256
tar xzf ids-rs-0.1.0-<commit>-rhel9.tar.gz
cd ids-rs-0.1.0-<commit>-rhel9
sha256sum -c SHA256SUMS
sudo ./install.sh
```

Scriptul verifica intai ca binarul porneste pe sistem, apoi:
- creeaza utilizatorul de sistem `ids-rs` (fara shell, fara home);
- instaleaza `/usr/local/bin/ids-rs` si `/etc/systemd/system/ids-rs@.service`
  (cu `install` + `restorecon`, ca etichetele SELinux sa fie corecte);
- creeaza `/etc/ids-rs/` (`root:ids-rs`, `0750`) cu `example.toml`;
- nu suprascrie config-uri existente si nu porneste nicio instanta.

### 3. O instanta noua

```bash
sudo cp /etc/ids-rs/example.toml /etc/ids-rs/fortigate.toml
sudo chown root:ids-rs /etc/ids-rs/fortigate.toml
sudo chmod 0640 /etc/ids-rs/fortigate.toml      # contine parola SMTP / auth_token
sudoedit /etc/ids-rs/fortigate.toml
ids-rs test-parser /etc/ids-rs/fortigate.toml sample.log
sudo firewall-cmd --permanent --add-port=5556/udp && sudo firewall-cmd --reload
sudo systemctl enable --now ids-rs@fortigate
```

In config-ul fiecarei instante:
- `listen_port` si `web_dashboard.port` trebuie sa fie **unice** pe masina;
- `trusted_senders` = IP-urile firewall-urilor care trimit log-uri (obligatoriu
  cand `listen_address` nu este loopback);
- `spool_directory` ramane **relativ** (implicit `"spool"`): ajunge in
  `/var/lib/ids-rs/<nume>/spool`, singurul director in care serviciul poate scrie;
- la fel `persistence.path` (implicit `"state.json"` → `/var/lib/ids-rs/<nume>/state.json`).

Pentru a accepta log-uri doar de la firewall, in loc de `--add-port` se poate
folosi o regula cu sursa:
```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.1" port port="5556" protocol="udp" accept'
```

### Operare

```bash
systemctl status ids-rs@fortigate
journalctl -u ids-rs@fortigate -f          # alerte, rezumatul de parsare, avertismente
sudo systemctl reload ids-rs@fortigate     # SIGHUP: reincarca config-ul (praguri, whitelist...)
sudo systemctl restart ids-rs@fortigate    # necesar pentru parser, porturi, spool
```

`systemctl stop` trimite SIGTERM: cozile de alerte sunt golite in spool si
retrimise la pornirea urmatoare. La o oprire neasteptata, serviciul este repornit
dupa 5 secunde (`Restart=on-failure`).

Unit-ul ruleaza fara root, cu sistemul de fisiere read-only in afara
`/var/lib/ids-rs/<nume>` (`ProtectSystem=strict`), fara acces la `/home`, cu
filtru de apeluri de sistem si doar capabilitatea `CAP_NET_BIND_SERVICE`
(pentru porturi sub 1024, ex: syslog pe 514).

### Upgrade

Pe masina conectata: `deploy/build-rhel9.sh && deploy/package.sh`. Pe server,
dupa transfer si verificarea sumelor ca mai sus:

```bash
sudo ./install.sh                          # config-urile din /etc/ids-rs raman neatinse
sudo systemctl restart 'ids-rs@*'
```

---

## Web Dashboard

WebDashboard-ul IDS-RS oferă o vizualizare operațională, în timp real, a alertelor de securitate generate de detector. Scopul lui este să reducă timpul de analiză și să permită
trierea rapidă a incidentelor, fără a înlocui SIEM-ul.

Platforma afișează o hartă interactivă a rețelei (graph) cu noduri și conexiuni între surse și destinații, colorate pe tipuri de detecție (Fast, Slow, Accept, Lateral Movement,
Distributed, Beaconing C2). Operatorul poate face zoom, fit, freeze, pin/unpin noduri, izolare pe selecție și grupare pe subnet pentru înțelegerea rapidă a pattern-urilor de atac.

În partea de monitorizare, dashboard-ul include:

- statistici live (total alerte, atacatori unici, ținte unice),
- actualizare periodică automată,
- search după IP (omnisearch),
- filtre pe tip de alertă și severitate,
- vizualizări predefinite (critical, scans only, distributed only etc.).

Zona de alerte oferă un tabel cu:

- timestamp, tip alertă, sursă, destinație și detalii,
- clustering pentru evenimente repetitive,
- triage operațional (Ack / Dismiss / Escalate),
- sumar de status și opțiune de ascundere a alertelor dismissed,
- densitate configurabilă și panou colapsabil pentru a lăsa mai mult spațiu grafului.

Pentru investigații, dashboard-ul are:

- IP Dossier (context per IP: rol, tipuri de scan, timeline, peer-uri),
- etichete MITRE ATT&CK pentru contextualizare tactică,
- Investigation Workspace (IP-uri pinned + notițe, export JSON),
- Replay Mode pe fereastră de timp, cu control de viteză și slider temporal.

Pentru prezentare și raportare:

- export al grafului în PNG,
- mod fullscreen,
- suport dark/light theme,
- command palette și shortcut-uri de tastatură,
- notificări vizuale/audio pentru evenimente critice.

Tehnic, WebDashboard-ul este un server web embedded, read-only, care expune endpoint-uri API pentru alerte și graf, funcționează local/offline (inclusiv în medii izolate) și este
construit să aibă impact minim asupra fluxului principal de detecție.

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

Rezultat asteptat: `test result: ok. 157 passed` (biblioteca) si `test result: ok. 5 passed` (binar).

Pentru verificarea completa, ca in CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Testele acopera:
- Parser GAIA: drop valid, accept parsat (nu ignorat), broadcast fara src, ICMP fara service, format invalid
- Parser CEF: drop valid, accept parsat, syslog header, syslog priority header, non-CEF, campuri incomplete
- Parser Gaia-CEF: drop valid, accept valid, fara src, fara service, proto UDP/ICMP mapping, case-insensitive action, non-CEF, actiune irelevanta, dest_ip optional
- Parser custom: FortiGate / iptables / Palo Alto, `require_text`, actiuni nemapate numarate, prefix iptables cel mai specific, ghilimele si escape-uri, UTF-8; exemplele din `config.toml` ruleaza pe sample-urile din `tester/`
- `learn` / `test-parser`: detectie format, mapare dupa nume si continut, TOML generat recitit identic, escapare text din sample, raport parsate / nemapate / ignorate
- Config custom: sectiune obligatorie, sursa de actiune unica, drop/accept fara suprapuneri, coloane vs chei, fixat la SIGHUP
- Detector Fast Scan: alert, sub prag, cooldown, cleanup, IP-uri separate, max_hits_per_ip, max_tracked_ips LRU
- Detector Slow Scan: alert dedicat, cooldown, independenta fata de Fast Scan (`slow_test_config()`)
- Detector Accept Scan: alert accept, drop nu declanseaza accept scan, accept nu declanseaza fast scan, cooldown accept
- Detector Whitelist: IP individual blocheaza alerta, CIDR blocheaza subnet, IP ne-whitelistat genereaza alerta, CIDR boundary corect, Accept Scan blocat de whitelist
- Alerter: 7 teste sanitize_cef (anti-injection CEF), esantionare CEF sub 60 KB, IP-ul principal mereu in esantion, canale indisponibile, esec email partial (server SMTP fals)
- Livrare: spool durabil, intrari vechi (format anterior) citite, alerta pastrata cat canalul e indisponibil, dead-letter fara blocarea cozii, retry doar catre destinatarii ramasi, golirea cozilor la oprire cu SMTP blocat
- Config: campuri necunoscute respinse, `trusted_senders` obligatoriu pe listener expus, revalidare la reload, limite per sender implicite
- Detector capacitate: limite pe fluxuri si IP-uri, evictie in lot, sweep orizontal si flood cu IP-uri spoofed fara cost patratic
- Statistici de parsare: fiecare linie numarata intr-o singura categorie, diferente pe fereastra, exemplu trunchiat, raspunsul `/api/stats`
- Binar: adrese IPv4-mapped normalizate, canal de semnal inchis nu declanseaza oprirea, harta de rate limitere per expeditor limitata (evacuare inactivi, apoi resetare)

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
| `sample_fast_gaia_cef.log` | GAIA-CEF | 20 | 20 drop-uri LEA in CEF Name, porturi unice | Alerta Fast Scan |
| `sample_slow_gaia_cef.log` | GAIA-CEF | 35 | 35 drop-uri LEA in CEF Name, porturi unice | Alerta Slow Scan |
| `sample_normal_gaia_cef.log` | GAIA-CEF | 5 | 5 drop-uri LEA in CEF Name (sub prag) | Fara alerta |
| `sample2_gaia.log` | GAIA | 56 | Log-uri reale Checkpoint (accept + drop mixt) | Depinde de continut |
| `sample_fast_fortigate.log` | FortiGate (custom) | 25 | 20 deny + 3 accept + 1 log de sistem + 1 `server-rst` | Alerta Fast Scan; 1 actiune nemapata |
| `sample_fast_iptables.log` | iptables (custom) | 25 | 20 `FW-DROP` + 3 `FW-ACCEPT` + 1 linie kernel + 1 `FW-LOG` | Alerta Fast Scan; 1 actiune nemapata |
| `sample_fast_paloalto.log` | Palo Alto (custom) | 24 | 20 deny + 3 allow (TRAFFIC) + 1 log SYSTEM | Alerta Fast Scan |

Sample-urile custom necesita `parser = "custom"` si exemplul corespunzator din
`[custom_parser]` (comentat la finalul `config.toml`).

---

### Pas 2 — Fast Scan (trebuie sa declanseze alerta)

```bash
# GAIA (config.toml: parser = "gaia")
python3 tester/tester.py fast

# CEF (config.toml: parser = "cef")
python3 tester/tester.py fast --cef

# GAIA-CEF (config.toml: parser = "gaia_cef")
python3 tester/tester.py fast --gaia-cef
```

IDS-RS ar trebui sa afiseze o alerta `Fast Scan detectat!` in terminalul sau.

### Pas 3 — Slow Scan (trebuie sa declanseze alerta)

```bash
# GAIA
python3 tester/tester.py slow

# CEF
python3 tester/tester.py slow --cef

# GAIA-CEF
python3 tester/tester.py slow --gaia-cef
```

IDS-RS ar trebui sa afiseze o alerta `Slow Scan detectat!`.

### Pas 4 — Accept Scan (trebuie sa declanseze alerta)

```bash
# Genereaza accept-uri pe porturi unice — simuleaza enumerarea serviciilor deschise
python3 tester/tester.py accept-scan --format gaia --ports 10 --delay 0.05

# Format CEF
python3 tester/tester.py accept-scan --format cef --ports 10 --delay 0.05

# Format GAIA-CEF
python3 tester/tester.py accept-scan --format gaia_cef --ports 10 --delay 0.05
```

IDS-RS ar trebui sa afiseze o alerta `Accept Scan` cu badge **magenta** in terminal.
Diferenta fata de Fast Scan: evenimentele trimise au `action=accept`, nu `action=drop`.

### Pas 5 — Trafic normal (NU trebuie sa declanseze alerta)

```bash
# GAIA
python3 tester/tester.py normal

# CEF
python3 tester/tester.py normal --cef

# GAIA-CEF
python3 tester/tester.py normal --gaia-cef
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
python3 tester/tester.py fast-scan --format gaia_cef --ports 20 --delay 0.1
python3 tester/tester.py slow-scan --format gaia --ports 40
python3 tester/tester.py slow-scan --format cef --ports 40 --delay 3
python3 tester/tester.py accept-scan --format gaia --ports 10 --delay 0.1
python3 tester/tester.py accept-scan --format cef --ports 10 --delay 0.1
python3 tester/tester.py accept-scan --format gaia_cef --ports 10 --delay 0.1
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
│ tester.py fast --gaia-cef                │ Replay sample_fast_gaia_cef.log              │
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
| `--gaia-cef` | `false` | Format GAIA-CEF in loc de GAIA (preset-uri) |
| `--format` | `gaia` | Formatul log-urilor: `gaia`, `cef` sau `gaia_cef` (fast-scan/slow-scan) |
| `--source` | `192.168.11.7` | IP-ul sursa simulat (fast-scan/slow-scan) |
| `--ports` | `20` / `40` / `10` | Numar de porturi unice (fast-scan/slow-scan/accept-scan) |
| `--delay` | variabil | Delay intre batch-uri in secunde |
| `--batch` | `1` | Log-uri per pachet UDP |

### Schimbare parser in config.toml

Testele GAIA functioneaza cu `parser = "gaia"`, testele CEF cu `parser = "cef"`,
iar testele GAIA-CEF cu `parser = "gaia_cef"`.
Schimba in `config.toml` si reporneste IDS-RS:

```toml
[network]
parser = "cef"       # in loc de "gaia"
parser = "gaia_cef"  # pentru Checkpoint LEA blob in CEF Name
```

---

## Structura proiect

```
ids-rs/
├── Cargo.toml              # Dependente si metadata proiect
├── Cargo.lock              # Versiuni exacte blocate (generat automat)
├── config.toml             # Fisier de configurare
├── README.md               # Acest fisier
├── rust-toolchain.toml     # Toolchain fixat (Rust 1.85, MSRV)
├── deploy/
│   ├── build-rhel9.sh      # Compilare release pentru RHEL 9 (container UBI 9)
│   ├── package.sh          # Arhiva de livrare pentru reteaua izolata (+ SHA256SUMS)
│   ├── install.sh          # Instalare serviciu offline: utilizator, binar, unit, /etc/ids-rs
│   └── systemd/
│       └── ids-rs@.service # Unit systemd sablon, o instanta per sursa de log-uri
├── static/                 # dashboard.html + d3.v7.min.js (incluse in binar)
├── src/
│   ├── main.rs             # Entry point: UDP listener, orchestrare async
│   ├── config.rs           # Structuri de configurare (serde + toml)
│   ├── display.rs          # Output CLI colorat (ANSI): banner, alerte, stats
│   ├── detector/           # Motor detectie (API public: Detector, Alert, ScanType)
│   │   ├── mod.rs          # Detector: orchestrare, whitelist, praguri, LRU pe IP-uri, cleanup
│   │   ├── port_scan.rs    # Fast / Slow / Accept Scan (porturi unice per pereche)
│   │   ├── lateral.rs      # Lateral Movement
│   │   ├── distributed.rs  # Distributed Scan
│   │   ├── beaconing.rs    # Beaconing C2 (CV pe intervale)
│   │   ├── alert.rs        # Alert, ScanType
│   │   ├── baseline.rs     # Praguri dinamice EWMA
│   │   ├── capacity.rs     # Evictie in lot si retentie
│   │   ├── cooldown.rs     # Cooldown alerte
│   │   ├── snapshot.rs     # Starea salvata pe disc (varste in loc de Instant)
│   │   ├── whitelist.rs    # Whitelist IP / CIDR
│   │   └── tests.rs        # Testele detectorului
│   ├── alerter.rs          # Trimitere alerte: SIEM (UDP) + Email (SMTP async)
│   ├── delivery.rs         # Cozi de livrare, spool pe disc, dead-letter, retry
│   ├── web.rs              # Dashboard web embedded (axum): API alerte/graf/dosar IP
│   ├── parser_tools.rs     # Subcomenzile learn si test-parser
│   ├── persistence.rs      # Fisierul de stare: salvare atomica, restaurare la pornire
│   ├── lib.rs              # Exporta modulele pentru binar si teste
│   └── parser/
│       ├── mod.rs          # Trait LogParser, LogEvent, factory function
│       ├── gaia.rs         # Parser Checkpoint Gaia (format real syslog)
│       ├── cef.rs          # Parser CEF / ArcSight
│       ├── gaia_cef.rs     # Parser Gaia LEA blob in CEF Name (via ArcSight)
│       └── custom.rs       # Parser declarativ din [custom_parser] (kv / csv)
└── tester/
    ├── tester.py              # Script Python de testare (fast/slow/normal/replay/sample)
    ├── sample_fast_gaia.log   # 20 drop-uri GAIA (Fast Scan)
    ├── sample_fast_cef.log    # 20 drop-uri CEF  (Fast Scan)
    ├── sample_slow_gaia.log   # 35 drop-uri GAIA (Slow Scan)
    ├── sample_slow_cef.log    # 35 drop-uri CEF  (Slow Scan)
    ├── sample_normal_gaia.log # 5 drop-uri GAIA  (sub prag, trafic normal)
    ├── sample_normal_cef.log       # 5 drop-uri CEF   (sub prag, trafic normal)
    ├── sample_fast_gaia_cef.log   # 20 drop-uri GAIA-CEF (Fast Scan)
    ├── sample_slow_gaia_cef.log   # 35 drop-uri GAIA-CEF (Slow Scan)
    ├── sample_normal_gaia_cef.log # 5 drop-uri GAIA-CEF  (sub prag, trafic normal)
    ├── sample2_gaia.log           # 56 log-uri reale Checkpoint GAIA (accept + drop mixt)
    ├── sample_fast_fortigate.log  # FortiGate: Fast Scan + linii ignorate/nemapate (custom)
    ├── sample_fast_iptables.log   # iptables:  Fast Scan + linii ignorate/nemapate (custom)
    └── sample_fast_paloalto.log   # Palo Alto: Fast Scan + log SYSTEM ignorat (custom)
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
| `arc-swap`           | Swap atomic al config-ului la SIGHUP            |
| `axum` + `serde_json`| Server HTTP si API JSON pentru dashboard        |

---

## Concepte Rust acoperite

Codul este comentat extensiv in romana, explicand fiecare concept la prima utilizare.

| Concept                | Unde in cod                          |
|------------------------|--------------------------------------|
| Ownership si Borrowing | `parser/gaia.rs`, `detector/`        |
| Traits si impl         | `parser/mod.rs`, `parser/gaia.rs`    |
| Trait Objects (dyn)     | `parser/mod.rs`, `main.rs`           |
| Generics               | `config.rs` (`AsRef<Path>`)          |
| Enums si Pattern Match  | `detector/alert.rs` (`ScanType`, `match`) |
| Option si Result       | toate fisierele                      |
| Operatorul ?           | `config.rs`, `parser/gaia.rs`        |
| Arc (shared ownership)  | `main.rs`                           |
| Interior Mutability    | `detector/` (`DashMap`)              |
| Send + Sync            | `parser/mod.rs`, `detector/`         |
| Async / Await          | `main.rs`, `alerter.rs`             |
| tokio::spawn           | `main.rs` (cleanup task)            |
| tokio::select!         | `main.rs` (main loop)               |
| Move Closures          | `main.rs` (spawn)                   |
| Iteratori              | `detector/`, `display.rs`           |
| Derive Macros          | `config.rs`                          |
| Modules                | `parser/mod.rs`, `main.rs`          |
| Lifetime-uri           | `parser/gaia.rs` (`extract_field`)  |
| Unit Tests             | `parser/gaia.rs`, `parser/cef.rs`, `parser/gaia_cef.rs`, `detector/tests.rs` |

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

- [x] **#18 — Teste unitare Slow Scan** (`detector.rs`) — 3 teste dedicate.

- [x] **#19 — Parser Gaia-CEF** (`parser/gaia_cef.rs`) — Firewall-urile Checkpoint Gaia (LEA v5)
  trimit log-uri prin ArcSight. Parser-ul `gaia_cef` accepta 3 formate de intrare:
  (1) LEA blob in campul CEF Name (index 5), (2) LEA blob in extensia CEF `rawEvent=` sau `cs6=`
  (cu unescape `\=` → `=`), (3) LEA blob raw fara wrapper CEF. Detectie automata cu fallback
  prin `find_lea_blob()`. Extrage perechi `key="value"` cu verificare boundary (nu match substring
  ca `rule_action`), mapeaza numere protocol IANA (6→tcp, 17→udp, 1→icmp), filtreaza drop/accept.
  Integrat in factory (`mod.rs`), validare config (`config.rs`), tester (`tester.py` cu
  `--format gaia_cef` si `--gaia-cef`). 15 teste unitare (10 initiale + 5 rawEvent). Total la momentul implementarii: **48 passed**.

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

In `detector/`, dupa fiecare `push()` se apeleaza `keep_newest(&mut hits, cfg.max_hits_per_ip)`
(`detector/capacity.rs`):
```rust
pub(super) fn keep_newest<T>(hits: &mut Vec<T>, max: usize) {
    if hits.len() > max {
        let overflow = hits.len() - max;
        hits.drain(..overflow);   // sterge de la inceput (oldest first)
    }
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
  2. Selectam cele mai vechi max(1, max_tracked_ips / 8) IP-uri: aici A (t=1s)
  3. Stergem lotul din toate structurile (fluxuri, cooldown-uri, lateral,
     distributed, beacon, last_seen)
  4. Inseram D

Cu max_tracked_ips = 100.000, o evictie elibereaza 12.500 de locuri: urmatoarele
12.499 de IP-uri noi intra fara nicio parcurgere.

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
if is_new_ip && self.last_seen.len() >= cfg.max_tracked_ips {
    // Selectie partiala O(n) a celor mai vechi ~1/8 IP-uri (select_nth_unstable)
    let aged = self.last_seen.iter().map(|e| (*e.value(), *e.key())).collect();
    let count = eviction_count(self.last_seen.len(), cfg.max_tracked_ips);
    let victims: HashSet<IpAddr> = oldest_keys(aged, count).into_iter().collect();
    // O singura trecere prin fiecare tabela pentru tot lotul
    self.evict_sources(&victims);
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

*Nota: varianta curenta nu mai foloseste `min_by_key`, ci evictie in lot (vezi mai jos).*
Gasirea minimului parcurge **tot** DashMap-ul — O(n). Facuta la **fiecare** IP nou peste
limita, plus stergerea prin `retain` pe ~10 tabele, un flood cu IP-uri spoofed ajungea la
O(n) per pachet (30.000 de evenimente la limita de 5.000: ~17s). De aceea evictia
elibereaza un lot intreg o data, iar costul se amortizeaza.

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

Am ales scan O(n) + **evictie in lot**, fara dependente noi:
- O evictie elibereaza `max(1, limita / 8)` intrari, selectate cu `select_nth_unstable`
  (O(n), fara sortare completa); costul per IP nou devine O(1) amortizat
- Stergerea se face intr-o singura trecere per tabela pentru tot lotul; fluxurile
  de scan sunt gasite direct prin indexul per sursa (`source_flows`)
- Acelasi mecanism limiteaza `distributed_hits`, `beacon_hits` si fluxurile
  `(src, dst)` (`max_tracked_flows`, `max_flows_per_source`)
- Compromis: la atingerea limitei se uita deodata ~12% din cele mai vechi intrari,
  nu doar una

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
# Limita per expeditor (optional): un singur firewall nu poate consuma tot bugetul.
udp_per_sender_rate_limit = 2500
udp_per_sender_burst_size = 5000
```

| Parametru | Efect |
|-----------|-------|
| `udp_rate_limit = 0` | Rate limiting dezactivat (backward compatible) |
| `udp_rate_limit = 5000` | Maxim 5.000 pachete/secunda in medie |
| `udp_burst_size = 10000` | Permite burst de 10.000 pachete imediat |
| `udp_per_sender_rate_limit` | Rata per IP expeditor. Omis: 2.500, plafonat la `udp_rate_limit` cand acesta e activ |
| `udp_per_sender_burst_size` | Burst per IP expeditor. Omis: 5.000, plafonat la `udp_burst_size` cand limita globala e activa |

Un `udp_per_sender_rate_limit` setat **explicit** peste `udp_rate_limit` este respins la
validare. Valorile omise sunt plafonate automat, deci un config mai vechi cu
`udp_rate_limit = 1000` porneste fara modificari.

### Comportament

- **Fara rate limiting** (`udp_rate_limit = 0`): comportament identic cu versiunile anterioare.
- **Cu rate limiting activ**: la pornire se afiseaza rata si burst-ul configurat. Periodic (la 30s), daca au existat drop-uri, se afiseaza numarul de pachete dropate cu badge-ul `[ RATE ]`.
- **Validare config**: daca `udp_rate_limit > 0` si `udp_burst_size = 0`, configuratia este respinsa. Daca `udp_burst_size < udp_rate_limit`, se emite un warning (burst prea mic pentru a absorbi varfuri).

---

## Persistenta la restart

La un restart (upgrade, `systemctl restart`, crash) detectorul ar pierde tot
contextul: Slow Scan (fereastra de minute) si Beaconing (fereastra de o ora) ar
reincepe numaratoarea, iar cooldown-urile ar disparea — o scanare in desfasurare
ar trimite **din nou aceeasi alerta** catre SIEM si email.

```toml
[persistence]
enabled = true                # lipsa sectiunii = dezactivat (config-uri vechi)
path = "state.json"           # relativ la directorul de lucru
save_interval_secs = 300      # salvare periodica; un crash pierde cel mult acest interval
```

**Ce se salveaza:** hit-urile din ferestrele active ale tuturor detectiilor,
cooldown-urile, IP-urile urmarite, baseline-ul pragurilor dinamice si alertele
din dashboard (ultimele `web_dashboard.max_alerts`).

**Cand:** la oprire (SIGTERM / Ctrl+C, inainte de golirea cozilor de livrare)
si la fiecare `save_interval_secs`, pe un thread separat, fara a bloca procesarea.

**La pornire:** starea este restaurata inainte de primul eveniment:
```
[INFO] Stare restaurata din state.json: 42 IP-uri urmarite, 17 alerte (salvata acum 8s)
```
Momentele sunt salvate ca varste relative la salvare (nanosecunde) si refacute
tinand cont de timpul scurs; ce a iesit intre timp din ferestre nu mai conteaza.
Dupa un reboot recent, momentele mai vechi decat pornirea sistemului nu pot fi
reprezentate si sunt ignorate.

**Siguranta fisierului:**
- scriere atomica (`state.json.tmp` + rename) — un crash in timpul scrierii lasa
  intact fisierul anterior;
- permisiuni `0600` — fisierul contine IP-uri si alerte;
- format versionat; un fisier corupt sau incompatibil este mutat in
  `state.json.invalid` (pentru diagnostic) si IDS-ul porneste fara istoric.

Setarile `[persistence]` necesita restart (la `SIGHUP` sunt raportate si ignorate).

---

## Livrare alerte — Cozi, spool si dead-letter

Fiecare alerta este trimisa independent catre SIEM si catre email, prin cate o coada
in memorie (`alerting.queue_capacity`) si un worker dedicat. Un canal lent sau cazut
nu blocheaza detectia si nici celalalt canal.

### Spool-ul

```
spool/                      # alerting.spool_directory
├── siem/
│   ├── <timestamp>-<pid>-<seq>.json   # alerte in asteptare, livrate in ordine
│   └── dead/                          # esecuri permanente (nu se reincearca)
└── email/
    ├── <timestamp>-<pid>-<seq>.json
    └── dead/
```

O alerta ajunge in spool cand:
- coada din memorie este plina;
- livrarea esueaza tranzitoriu (SIEM inaccesibil, SMTP 4xx, timeout);
- canalul este indisponibil (dezactivat sau mailer-ul SMTP nu a putut fi construit) —
  alerta **nu** este considerata livrata si asteapta reactivarea canalului;
- procesul se opreste (SIGTERM / Ctrl+C) — vezi mai jos.

Workerul livreaza intai ce este in spool (cel mai vechi primul), cu exponential backoff
intre `retry_initial_secs` si `retry_max_secs`. Scrierile sunt atomice (fisier temporar +
`rename`), deci un crash nu lasa intrari partiale. Fisierele corupte sunt redenumite in
`.bad` si sarite.

### Dead-letter

O alerta care nu va putea fi livrata niciodata in forma actuala este mutata in
`<canal>/dead/`, ca sa nu blocheze restul cozii:
- mesajul CEF depaseste limita sigura de 60 KB (ex: hostname/locatie configurate foarte lungi);
- serverul SMTP respinge definitiv un destinatar (cod 5xx).

Alertele din `dead/` raman pe disc pentru inspectie. Dupa corectarea cauzei, pot fi
reinjectate manual prin mutarea fisierului inapoi in directorul canalului:

```bash
mv spool/email/dead/*.json spool/email/
```

### Email catre mai multi destinatari

Fiecare destinatar primeste un email separat. Daca unii esueaza:
- destinatarii care au primit deja alerta **nu** o mai primesc la retry;
- cei cu esec tranzitoriu raman in spool, doar ei fiind reincercati;
- cei respinsi definitiv ajung in `dead/`, cu lista lor de destinatari.

Intrarile din spool retin lista destinatarilor ramasi (`recipients`). Un destinatar
scos intre timp din config (SIGHUP) este sarit. Intrarile salvate de versiunile
anterioare (doar alerta, fara lista) sunt citite in continuare, ca destinate tuturor.

### Oprirea

La SIGTERM / Ctrl+C, workerii abandoneaza livrarile in curs si asteptarile de backoff,
salveaza in spool alerta in curs de trimitere si tot ce era in coada, apoi se opresc —
chiar daca SIEM-ul sau serverul SMTP nu raspund. La urmatoarea pornire, spool-ul este
livrat primul. O livrare de email intrerupta la jumatate poate fi retrimisa unor
destinatari care o primisera deja.

---

## Hostname Resolve — Mapping Static IP→Hostname

> **AFISARE CONTEXT** — Implementat in `src/config.rs`, `src/display.rs`, `src/alerter.rs`, `src/main.rs`.

### Ce problema rezolva

IDS-RS ruleaza intr-o **retea izolata fara internet**. Cand se detecteaza o scanare, alerta afiseaza
IP-uri numerice: `10.0.1.10 → 10.0.1.20`. Operatorul trebuie sa deschida un tabel separat
(spreadsheet, CMDB) ca sa identifice cine e sursa si cine e tinta. In incidente reale, fiecare secunda
conteaza — iar o eroare de identificare poate duce la blocarea serverului gresit.

Deoarece reteaua este izolata, **nu exista DNS extern** pe care IDS-ul sa il interogeze.
Reverse DNS (PTR records) ar presupune un server DNS intern configurat si disponibil —
ceea ce nu este garantat. Reverse DNS adauga si latenta la fiecare eveniment procesat.

### Solutia: Mapping static in `config.toml`

In loc de DNS, folosim un tabel de mapare IP→hostname configurat manual:

```toml
[network.hostnames]
"10.0.1.10" = "srv-dc01"       # Domain Controller
"10.0.1.20" = "srv-mail"       # Exchange Server
"10.0.2.50" = "ws-admin01"     # Workstation admin
"10.0.3.1"  = "fw-dmz"         # Firewall DMZ
```

Avantaje fata de DNS:
- **Zero latenta** — lookup in `HashMap` in memorie, O(1)
- **Zero dependinte** — nu necesita server DNS functional in retea
- **Deterministic** — hostname-ul nu se schimba in functie de starea DNS
- **Controlat** — adminul decide exact ce hostname apare in alerte

Dezavantaje:
- **Manual** — trebuie mentinut sincronizat cu CMDB/inventar
- **Incomplet** — IP-urile necunoscute apar fara hostname (dar asta e si informatie utila: un IP fara hostname = potential masina neautorizata)

### Fluxul de date

```
config.toml                     main.rs
[network.hostnames]    ──parse──>  HashMap<IpAddr, String>
"10.0.1.10" = "srv-dc01"                   │
"10.0.1.20" = "srv-mail"                   │
                                            ├─────> display.rs    (CLI output)
                                            │       format_ip() → "10.0.1.10 (srv-dc01)"
                                            │
                                            ├─────> alerter.rs    (SIEM CEF)
                                            │       shost=srv-dc01 dhost=srv-mail
                                            │
                                            └─────> alerter.rs    (Email HTML)
                                                    "10.0.1.10 (srv-dc01)" in tabel
```

### Unde apare hostname-ul

**1. Terminal (CLI) — eveniment firewall:**
```
[2026-03-16 12:00:00]  DROP  Src=10.0.1.10 (srv-dc01) DstPort=443 Proto=tcp Action=drop
```

**2. Terminal (CLI) — alerta:**
```
────────────────────────────────────────────────────────────────────
[2026-03-16 12:00:01] ▶▶▶  ALERT  [FAST SCAN] [IP: 10.0.1.10 (srv-dc01)] | 15 porturi unice detectate!
  Porturi: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080
────────────────────────────────────────────────────────────────────
```

**3. SIEM (CEF) — campurile `shost` si `dhost`:**
```
<38>Mar 16 12:00:01 ids-rs CEF:0|IDS-RS|Network Scanner Detector|1.0
  |1001|Fast Port Scan Detected|7
  |rt=1742122801000 src=10.0.1.10 shost=srv-dc01 dst=10.0.1.20 dhost=srv-mail
   cnt=15 act=alert msg=Fast Scan detectat: 15 porturi unice in 10 secunde
   cs1Label=ScannedPorts cs1=21,22,23,...
```

Campurile `shost` (Source Host Name) si `dhost` (Destination Host Name) sunt standard CEF.
ArcSight le mapeaza automat in Active Channel si dashboard-uri — operatorul vede direct
hostname-ul fara sa caute IP-ul in inventar.

**4. Email — tabelul de detalii:**

```
┌─────────────────┬──────────────────────────────┐
│ IP Sursa        │ 10.0.1.10 (srv-dc01)         │
│ IP Destinatie   │ 10.0.1.20 (srv-mail)         │
│ Porturi scanate │ 15                            │
│ Timestamp       │ 2026-03-16 12:00:01           │
└─────────────────┴──────────────────────────────┘
```

**5. Banner la pornire:**
```
║  Hostnames: 4 mapping-uri IP->hostname configurate                                                          ║
```

### Implementarea in Rust

#### Pasul 1: Configurare — `config.rs`

Adaugam un `HashMap<String, String>` in `NetworkConfig`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    // ... campuri existente ...

    /// Mapping static IP → hostname.
    /// Cheile sunt String-uri (limitare TOML — cheile de tabel sunt mereu String),
    /// parsate in IpAddr la startup in main.rs.
    #[serde(default)]
    pub hostnames: HashMap<String, String>,
}
```

**De ce `HashMap<String, String>` si nu `HashMap<IpAddr, String>`?**

TOML stocheaza cheile de tabel ca string-uri. Serde nu poate deserializa direct o cheie TOML
intr-un `IpAddr` fara un custom deserializer. Solutia simpla: stocam ca `String` → `String`
in config, si parsam in `IpAddr` → `String` o singura data la startup in `main.rs`.

Validarea se face in `validate()` — daca o cheie nu este un IP valid, eroarea este raportata:

```rust
for (ip_str, _hostname) in &self.network.hostnames {
    if ip_str.parse::<std::net::IpAddr>().is_err() {
        errors.push(format!(
            "network.hostnames: cheia \"{}\" nu este un IP valid", ip_str
        ));
    }
}
```

#### Pasul 2: Parsare la startup — `main.rs`

Convertim `HashMap<String, String>` → `HashMap<IpAddr, String>` o singura data:

```rust
let hostnames: HashMap<IpAddr, String> = config
    .network
    .hostnames
    .iter()
    .filter_map(|(ip_str, name)| {
        ip_str.parse::<IpAddr>().ok().map(|ip| (ip, name.clone()))
    })
    .collect();
```

Acest HashMap este apoi transmis prin referinta (`&hostnames`) la functiile display
si prin clonare la `Alerter::new()` (care il detine permanent).

**De ce `filter_map` si nu `map` + `unwrap`?**

`filter_map` sare silentios peste cheile invalide (nu face panic). In teorie,
`validate()` a verificat deja cheile, dar **defense-in-depth**: daca cumva o cheie
invalida trece de validare, nu vrem sa crape IDS-ul.

#### Pasul 3: Afisare in CLI — `display.rs`

Un helper privat formateaza IP-ul cu hostname:

```rust
/// Returneaza "IP (hostname)" daca hostname-ul exista, altfel doar "IP".
fn format_ip(ip: &IpAddr, hostnames: &HashMap<IpAddr, String>) -> String {
    match hostnames.get(ip) {
        Some(name) => format!("{} ({})", ip, name),
        None => ip.to_string(),
    }
}
```

`HashMap::get()` returneaza `Option<&String>`:
- `Some(name)` = IP-ul are hostname configurat → afisam ambele
- `None` = IP necunoscut → afisam doar IP-ul numeric

Functiile `log_firewall_event()` si `log_alert()` primesc `&HashMap<IpAddr, String>`
ca parametru si folosesc `format_ip()` in loc de `ip.to_string()`:

```rust
pub fn log_firewall_event(
    ip: &IpAddr,
    port: u16,
    protocol: &str,
    action: &str,
    hostnames: &HashMap<IpAddr, String>,   // NOU: mapping IP→hostname
) {
    // ...
    println!(
        "{} {} Src={} DstPort={} ...",
        ts.dimmed(),
        badge,
        format_ip(ip, hostnames).bright_blue(),   // "10.0.1.10 (srv-dc01)"
        // ...
    );
}
```

#### Pasul 4: SIEM CEF — `alerter.rs`

In mesajul CEF, adaugam campurile `shost` si `dhost` (standard ArcSight):

```rust
// Campul shost (Source Hostname) — prezent doar daca hostname-ul este configurat.
let shost_field = match self.hostnames.get(&alert.source_ip) {
    Some(name) => format!(" shost={}", sanitize_cef(name)),
    None => String::new(),   // String gol = campul nu apare in CEF
};
```

**Atentie la `sanitize_cef()`!** Hostname-urile sunt configurate de admin in `config.toml`,
deci in teorie sunt de incredere. Dar defense-in-depth: daca cineva pune un hostname
malitios (`"evil\nFake CEF:0|..."`), sanitizarea previne injectia. Aplicam aceeasi
protectie ca la celelalte campuri CEF — consistenta este mai importanta decat optimizarea.

Campurile sunt **conditionale** — apar doar daca hostname-ul exista:

```
src=10.0.1.10 shost=srv-dc01 dst=10.0.1.20 dhost=srv-mail   ← ambele hostname-uri configurate
src=10.0.1.10 dst=192.168.5.99                                ← niciun hostname configurat
src=10.0.1.10 shost=srv-dc01 dst=192.168.5.99                 ← doar sursa configurata
```

Aceasta abordare este compatibila cu ArcSight: campurile lipsa sunt ignorate, nu cauzeaza erori.

#### Pasul 5: Email HTML — `alerter.rs`

In template-ul HTML, hostname-urile sunt injectate langa IP prin placeholder-e:

```html
<tr><td>IP Sursa</td><td>__SRC_IP__ __SRC_HOST__</td></tr>
<tr><td>IP Destinatie</td><td>__DST_IP__ __DST_HOST__</td></tr>
```

Placeholder-ul `__SRC_HOST__` devine `(srv-dc01)` sau string gol (daca hostname necunoscut).

### Concepte Rust explicate

#### `HashMap<K, V>` — tabel hash din standard library

`HashMap` stocheaza perechi cheie→valoare cu acces O(1) amortizat.
In cazul nostru: `HashMap<IpAddr, String>` — cheia este un IP, valoarea este hostname-ul.

```rust
use std::collections::HashMap;

let mut hostnames = HashMap::new();
hostnames.insert("10.0.1.10".parse().unwrap(), "srv-dc01".to_string());

// Lookup: O(1) amortizat
match hostnames.get(&ip) {
    Some(name) => println!("{} ({})", ip, name),   // gasit
    None => println!("{}", ip),                     // negasit
}
```

`HashMap` nu este thread-safe — nu implementeaza `Sync`. Dar in cazul nostru:
- Creat o singura data la startup (nu se modifica dupa)
- Transmis prin `&HashMap` (referinta imutabila) catre display functions
- Clonat in Alerter (care il detine ca owner, dar nu il modifica)

Deci nu avem nevoie de `DashMap` sau `Arc<RwLock<...>>` — referinta imutabila
partajata este suficienta si zero-overhead.

#### `.iter().filter_map(...)` — transformare cu filtrare

```rust
let hostnames: HashMap<IpAddr, String> = config
    .network
    .hostnames                           // HashMap<String, String> din TOML
    .iter()                              // iterator peste (&String, &String)
    .filter_map(|(ip_str, name)| {       // transforma SI filtreaza
        ip_str.parse::<IpAddr>()         // Result<IpAddr, Error>
            .ok()                        // Result → Option (Err → None)
            .map(|ip| (ip, name.clone()))// Some(IpAddr) → Some((IpAddr, String))
    })
    .collect();                          // construieste HashMap-ul final
```

`filter_map` combina `.filter()` + `.map()` intr-un singur pas:
- Closure-ul returneaza `Option<T>`
- `Some(val)` → pastrat in rezultat
- `None` → eliminat (filtrat)

Alternativa cu `map` + `unwrap` ar fi panicked pe eroare de parsare.
`filter_map` + `.ok()` este pattern-ul idiomatic Rust pentru "incearca si ignora esecurile".

#### `#[serde(default)]` — campuri optionale in TOML

```rust
#[serde(default)]
pub hostnames: HashMap<String, String>,
```

`#[serde(default)]` inseamna: daca sectiunea `[network.hostnames]` lipseste complet
din `config.toml`, serde apeleaza `Default::default()` care pentru `HashMap` returneaza
un HashMap gol. Fara acest atribut, lipsa sectiunii ar cauza o eroare de deserializare.

Aceasta face feature-ul **retrocompatibil**: configuratiile vechi (fara `[network.hostnames]`)
continua sa functioneze exact ca inainte.

#### De ce `hostnames.clone()` la crearea Alerter-ului?

```rust
let alerter = Arc::new(Alerter::new(
    config.alerting.clone(),
    config.detection.clone(),
    hostnames.clone(),          // ← de ce clone?
)?);
```

`Alerter` **detine** (owns) hostname-urile. Main loop-ul tine o referinta separata
(`&hostnames`) pentru functiile display. Daca am pasa doar referinta la Alerter,
ar aparea lifetime issues: Alerter-ul este wrapped in `Arc` si poate supravietui
scope-ului original al HashMap-ului.

Costul clone-ului: O(n) la startup, o singura data. Pentru 100-500 hostname-uri
(retea cu 1000 IP-uri), < 0.01ms. Overhead neglijabil.

### Configurare

```toml
[network.hostnames]
"10.0.1.10" = "srv-dc01"       # Domain Controller — DNS, Kerberos, LDAP
"10.0.1.20" = "srv-mail"       # Exchange — SMTP, IMAP
"10.0.1.30" = "srv-backup"     # Backup server — Veeam
"10.0.2.50" = "ws-admin01"     # Workstation administrator
"10.0.3.1"  = "fw-dmz"         # Firewall DMZ interface
```

| Situatie | Comportament |
|----------|-------------|
| Sectiunea lipseste complet | Feature dezactivat, afisare doar IP-uri (retrocompatibil) |
| IP configurat gasit in eveniment | Afisare `IP (hostname)` in CLI, `shost=`/`dhost=` in CEF, hostname in email |
| IP neconfigurat in eveniment | Afisare doar `IP` (fara paranteze, fara hostname) |
| Cheie invalida (nu e IP valid) | Eroare la startup — raportata in validate() |

### Intrebari frecvente

**De ce nu reverse DNS in loc de mapping static?**

In retea izolata fara internet, reverse DNS (PTR records) presupune un server DNS intern
configurat cu toate inregistrarile. In practica, multe retele izolate au DNS partial
sau inexistent. Mapping-ul static este deterministic si nu depinde de nicio infrastructura.

**De ce nu DHCP lease table?**

DHCP lease files au format diferit per implementare (ISC, dnsmasq, Windows DHCP),
se schimba la fiecare reinnoire, si necesita acces la fisierul de lease al serverului
DHCP. Mapping-ul static este simplu si controlat de admin.

**Cum mentin hostnames actualizate?**

Ideal, prin automatizare: un script periodic care extrage inventarul din CMDB/AD
si genereaza sectiunea `[network.hostnames]` in `config.toml`. Cand va fi implementat
`#16 — Hot reload config la SIGHUP`, update-ul se aplica fara restart.

---

## Subnet Mapping — Mapping CIDR→Locatie

> **CONTEXT FIZIC** — Implementat in `src/config.rs`, `src/display.rs`, `src/alerter.rs`, `src/main.rs`.

### Ce problema rezolva

Hostname-urile identifica **ce masina** este implicata. Subnet mapping-ul identifica **unde se afla fizic**:
etaj, cladire, zona de retea. In reteaua noastra izolata, subnettele sunt alocate pe locatii fizice
(ex: 10.10.1.0/24 = Etaj 1, 10.10.2.0/24 = Etaj 2).

Cand o alerta spune `10.10.1.55 (ws-user42) [Etaj 1] → 10.10.3.20 (srv-files) [Etaj 3]`,
operatorul stie imediat ca un workstation de pe Etajul 1 scaneaza un server de pe Etajul 3 —
fara sa caute manual in schema retelei.

### Solutia: Mapping static in `config.toml`

```toml
[network.subnets]
"10.10.1.0/24" = "Etaj 1"
"10.10.2.0/24" = "Etaj 2"
"10.10.3.0/24" = "Etaj 3"
"10.10.0.0/24" = "Server Room"
"10.10.0.0/16" = "Cladire Principala"
```

**Longest prefix match**: daca un IP apartine mai multor subnete (ex: `10.10.1.55` e atat in
`/24 Etaj 1` cat si in `/16 Cladire Principala`), se aplica match-ul cel mai specific (`/24`).
Aceasta permite ierarhii: `/16` pentru cladire, `/24` pentru etaj.

### Unde apare locatia

**1. Terminal (CLI) — eveniment firewall:**
```
[2026-03-25 12:00:00]  DROP  Src=10.10.1.55 (ws-user42) [Etaj 1] DstPort=445 Proto=tcp Action=drop
```

**2. Terminal (CLI) — alerta:**
```
────────────────────────────────────────────────────────────────────
[2026-03-25 12:00:01] ▶▶▶  ALERT  [FAST SCAN] [IP: 10.10.1.55 (ws-user42) [Etaj 1]] | 15 porturi unice detectate!
────────────────────────────────────────────────────────────────────
```

**3. SIEM (CEF) — campurile `cs2` si `cs3`:**
```
<38>Mar 25 12:00:01 ids-rs CEF:0|IDS-RS|Network Scanner Detector|1.0
  |1001|Fast Port Scan Detected|7
  |rt=... src=10.10.1.55 shost=ws-user42 cs2Label=SourceLocation cs2=Etaj 1
   dst=10.10.3.20 dhost=srv-files cs3Label=DestLocation cs3=Etaj 3
   cnt=15 act=alert msg=... cs1Label=ScannedPorts cs1=21,22,...
```

**4. Email — tabelul de detalii:**
```
┌─────────────────┬────────────────────────────────────────┐
│ IP Sursa        │ 10.10.1.55 (ws-user42) [Etaj 1]       │
│ IP Destinatie   │ 10.10.3.20 (srv-files) [Etaj 3]       │
│ Porturi scanate │ 15                                      │
└─────────────────┴────────────────────────────────────────┘
```

**5. Banner la pornire:**
```
║  Subnets:   5 mapping-uri CIDR->locatie configurate                                                          ║
```

### Comportament

| Situatie | Comportament |
|----------|-------------|
| Sectiunea lipseste complet | Feature dezactivat, afisare doar IP (+hostname daca exista) — retrocompatibil |
| CIDR configurat gasit | Afisare `[locatie]` dupa IP/hostname in CLI, `cs2`/`cs3` in CEF, locatie in email |
| IP necuprins in niciun subnet | Fara locatie afisata |
| Cheie invalida (CIDR gresit) | Eroare la startup — raportata in validate() |
| Subnete imbricate | Se aplica longest prefix match (cel mai specific /prefix) |
| Hot reload SIGHUP | Subnet-urile sunt reincarcate din config.toml fara restart |

---

## TODO — Securitate si hardening

### Scazuta

- [ ] **Debug mode disk fill** — modul debug afiseaza fiecare pachet in stdout. In productie cu volum mare si stdout redirectat la fisier, poate umple disk-ul. *Mitigare: dezactivare automata dupa N minute sau limita de linii.*

---

## TODO — Functionalitati viitoare

### Impact ridicat

- [x] **#12 — Whitelist IP-uri** — `detection.whitelist` in `config.toml` cu IP-uri individuale si CIDR. IP-urile din whitelist sunt excluse complet din detectie (nu consuma memorie, nu genereaza alerte). Validare la pornire, afisare in banner. 5 teste unitare.

- [x] **#21 — Hostname resolve** — mapping static `[network.hostnames]` in `config.toml` (IP → hostname). Hostname-urile sunt afisate in: alerte CLI (`[IP: 10.0.1.10 (srv-dc01)]`), SIEM CEF (`shost=srv-dc01 dhost=srv-mail`), email (coloana IP Sursa/Destinatie). Validare cheilor IP la pornire. Util in reteaua izolata fara DNS.

- [x] **Subnet mapping** — mapping static `[network.subnets]` in `config.toml` (CIDR → locatie fizica). Afiseaza context fizic (etaj, cladire, zona) in: CLI (`[Etaj 1]`), SIEM CEF (`cs2Label=SourceLocation cs2=Etaj 1`), email (coloana IP cu locatie). Longest prefix match pentru subnete imbricate. Validare CIDR la pornire. Hot-reload SIGHUP.

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

- [x] **#25 — Web Dashboard (harta retea)** — server HTTP embedded in IDS-RS (task tokio separat),
  read-only, fara impact asupra detectiei. Arhitectura:
  - `GET /` → dashboard HTML cu graf D3.js force-directed
  - `GET /api/alerts` → JSON cu ultimele N alerte din memorie
  - `GET /api/graph` → noduri (IP-uri) + muchii (conexiuni) pentru graf
  - `GET /api/stats` → parser activ, uptime si contorii de parsare cumulati
    (`lines`, `parsed`, `unmapped`, `ignored`); protejat de token, ca restul `/api`
  - Noduri colorate: rosu = atacator, gri = tinta; dimensiune = numar alerte
  - Muchii colorate dupa tip: rosu = Fast Scan, galben = Slow Scan, magenta = Accept Scan
  - Hover pe nod: detalii IP (porturi scanate, timestamps, tip atac)
  - Auto-refresh la 5 secunde

  *Implementare: adauga `axum` + `serde_json` in `Cargo.toml`; sectiune*
  *`[web_dashboard]` in `config.toml` cu `enabled`, `port`, `bind`;*
  *`src/web.rs` cu server + endpoint-uri; buffer circular*
  *`Arc<Mutex<VecDeque<Alert>>>` partajat intre detectie si web server.*

### Impact mediu

- [ ] **#20 — Parser FortiGate (Fortinet)** — format propriu, diferit de Gaia si CEF. Adaugat ca optiune `parser = "fortigate"` in `config.toml`. Implementeaza `trait LogParser` in `src/parser/fortigate.rs`.


- [ ] **#23 — Distributed Scan** — N surse diferite → aceeasi tinta pe aceleasi porturi. Perspectiva inversata. SignatureID 1005.

- [ ] **#24 — Beaconing C2** — src→(dst, port) la intervale regulate (stddev mic). SignatureID 1006.



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
| — | Reload SIGHUP revalidat dupa fixarea campurilor care cer restart (nu mai poate goli `trusted_senders` pe un listener expus) | [Hardening operational](#hardening-operational) |
| — | Adrese IPv4-mapped normalizate pentru `trusted_senders` si rate limiting per sender | [Hardening operational](#hardening-operational) |
| — | Evictie in lot (fluxuri, IP-uri, distributed, beacon): fara cost O(n) per eveniment la flood | [Protectie DashMap](#protectie-dashmap--max_tracked_ips-si-lru-eviction) |

### Functionalitati

| # | Descriere |
|---|-----------|
| #1 | Mesaje SIEM citesc time_window din config (nu hardcodate) |
| #10 | Accept Scan — `accept_hits` separate, SigID 1003, magenta CLI |
| #12 | Whitelist IP-uri (IP + CIDR) — excluse complet din detectie |
| #17 | Cleanup task sleep-first (nu interval tick imediat) |
| #16 | SIGHUP config reload — reincarca `config.toml` fara restart, fara pierdere context (ArcSwap atomic) |
| #22 | Lateral Movement — 1 IP → N destinatii unice pe conexiuni acceptate (orice port), SignatureID 1004, CLI bright_red, severitate CEF 8 (Critical) |
| #23 | Distributed Scan — N surse → aceeasi tinta, perspectiva inversata, SignatureID 1005, CLI cyan, severitate CEF 7 (High) |
| #24 | Beaconing C2 — flow periodic (src, dst, dport) detectat prin Coefficient of Variation (CV) pe inter-arrival times. SignatureID 1006, CLI red, severitate CEF 9 (Critical). Praguri default: min_events=8, time_window=1h, cv_threshold=0.30 |
| — | Graceful shutdown SIGTERM — handler inregistrat la pornire (esecul opreste pornirea); la oprire, workerii de livrare salveaza in spool alertele nelivrate si cozile din memorie |
| #21 | Hostname resolve — mapping static `[network.hostnames]`, afisare in CLI/SIEM/email |
| — | Subnet mapping — `[network.subnets]` CIDR→locatie, afisare in CLI `[Etaj 1]`, SIEM (cs2/cs3), email. Longest prefix match, hot-reload SIGHUP, validare CIDR |
| — | `dest_ip` in LogEvent/Alert, `dst=` in CEF, porturi in `msg` |
| — | Livrare: dead-letter pentru esecuri permanente, retry email per destinatar, cozi golite in spool la oprire, canal indisponibil nu mai sterge alerte din spool |
| — | Parser Gaia-CEF accepta din nou inregistrari CEF trunchiate cu blob LEA in Name |
| — | IP-ul principal al alertei este mereu inclus in listele CEF esantionate |
| — | Limitele per sender omise sunt plafonate la limita globala (config-uri vechi raman valide) |

### Calitate cod

| # | Descriere |
|---|-----------|
| #2 | Cache SMTP transport (construit o data in `new()`) |
| #18 | Teste unitare Slow Scan (3 teste). **Total: 33 passed** |
