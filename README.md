# IDS-RS — Intrusion Detection System

Sistem de detectie a intruziunilor bazat pe analiza log-urilor de firewall, scris in Rust.
Detecteaza scanari de retea (Fast Scan si Slow Scan) si trimite alerte catre SIEM si email.

---

## Cuprins

- [Arhitectura](#arhitectura)
- [Cerinte sistem](#cerinte-sistem)
- [Compilare](#compilare)
- [Configurare](#configurare)
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

```toml
[network]
listen_address = "0.0.0.0"    # Interfata de ascultare
listen_port = 5555             # Port UDP pentru receptie log-uri
parser = "gaia"                # Parser activ: "gaia" sau "cef"

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

**CEF / ArcSight:**
```
CEF:0|CheckPoint|VPN-1 & FireWall-1|R81.20|100|Drop|5|src=192.168.11.7 dst=10.0.0.1 dpt=443 proto=TCP act=drop
```

---

## Rulare

```bash
# Cu config.toml din directorul curent
./target/release/ids-rs

# Cu cale explicita catre config
./target/release/ids-rs /etc/ids-rs/config.toml

# Cu debug logging activat (vede fiecare eveniment procesat)
RUST_LOG=debug ./target/release/ids-rs
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

Rezultat asteptat: `test result: ok. 15 passed`

Testele acopera:
- Parser GAIA: drop valid, accept ignorat, broadcast fara src, ICMP fara service, format invalid
- Parser CEF: drop valid, accept ignorat, non-CEF, campuri incomplete
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
2. Implementeaza `trait LogParser` (`parse` + `name`)
3. Adauga `pub mod noul_format;` in `src/parser/mod.rs`
4. Adauga o intrare in `match` din `create_parser()`
5. Seteaza `parser = "noul_format"` in `config.toml`

### Adaugare canal de alerta nou

1. Adauga sectiunea in `config.rs` si `config.toml`
2. Implementeaza metoda async in `alerter.rs`
3. Apeleaz-o din `send_alert()`
