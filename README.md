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

**Checkpoint Gaia (Raw)**
```
Sep 3 15:12:20 192.168.99.1 Checkpoint: drop 192.168.11.7 proto: tcp; service: 22; s_port: 1352
```

**CEF / ArcSight** (schelet, de completat la integrare)
```
CEF:0|CheckPoint|VPN-1|R81|100|Drop|5|src=192.168.11.7 dst=10.0.0.1 dpt=443 proto=TCP act=drop
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

Scriptul `tester.py` simuleaza log-uri de firewall trimise pe UDP.

```bash
python tester.py fast-scan --format gaia --ports 20 --delay 0.1

python tester.py slow-scan --format gaia --ports 40

python tester.py normal --format gaia --count 5

##########

python tester.py fast-scan --format cef --ports 25 --batch 5

python tester.py slow-scan --format cef --ports 35 --delay 8

python tester.py normal --format cef --count 3

##########

python tester.py replay --file /path/to/logs.txt

python tester.py replay --file /path/to/logs.txt --delay 0.05
```

### Parametri tester.py

| Parametru   | Default         | Descriere                                    |
|-------------|-----------------|----------------------------------------------|
| `--host`    | `127.0.0.1`    | Adresa IP a IDS-RS                           |
| `--port`    | `5555`          | Portul UDP al IDS-RS                         |
| `--ports`   | `20`            | Numar de porturi unice (fast-scan)           |
| `--delay`   | `0.1`           | Delay intre batch-uri in secunde (fast-scan) |
| `--source`  | `192.168.11.7`  | IP-ul sursa simulat (fast-scan)              |
| `--batch`   | `1`             | Log-uri per pachet UDP (fast-scan)           |

---

## Structura proiect

```
ids-rs/
├── Cargo.toml              # Dependente si metadata proiect
├── Cargo.lock              # Versiuni exacte blocate (generat automat)
├── config.toml             # Fisier de configurare
├── tester.py               # Script Python de testare
├── README.md               # Acest fisier
└── src/
    ├── main.rs             # Entry point: UDP listener, orchestrare async
    ├── config.rs           # Structuri de configurare (serde + toml)
    ├── display.rs          # Output CLI colorat (ANSI): banner, alerte, stats
    ├── detector.rs         # Motor detectie: DashMap, Fast/Slow Scan, cleanup
    ├── alerter.rs          # Trimitere alerte: SIEM (UDP) + Email (SMTP async)
    └── parser/
        ├── mod.rs          # Trait LogParser, LogEvent, factory function
        ├── gaia.rs         # Parser Checkpoint Gaia (format raw syslog)
        └── cef.rs          # Parser CEF / ArcSight (schelet functional)
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
| Lifetime-uri implicite  | `parser/gaia.rs`                    |
| Unit Tests             | `parser/gaia.rs`, `detector.rs`     |

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
