# Beaconing C2 Detection (#24) — Design

## Scop
Detectia traficului periodic de callback C2 intr-o retea interna izolata. Un host
compromis intern comunica cu un alt host intern (pivot / staging) la intervale
regulate. Aceasta sectiune extinde Detector-ul existent cu un al cincilea tip de
scan: `Beaconing`.

## Algoritm: Coefficient of Variation (CV)

Pe fiecare flow `(src_ip, dest_ip, dest_port)`:

1. La fiecare eveniment `accept` se inregistreaza timestamp-ul curent.
2. Se pastreaza doar timestamp-urile mai noi de `time_window_secs`.
3. Cand `len >= min_events`:
   - `delta[i] = ts[i+1] - ts[i]`
   - `mean = avg(delta)`; daca `mean ∉ [min_interval_secs, max_interval_secs]` → skip
   - `cv = stddev(delta) / mean`
   - Daca `cv <= cv_threshold` si flow nu e in cooldown → alerta.

## Config

```toml
[detection.beaconing]
enabled = false
min_events = 8
time_window_secs = 3600
cv_threshold = 0.30
min_interval_secs = 10
max_interval_secs = 3600

[detection.exceptions]
ignore_beaconing_ports = [123, 88, 389]     # NTP, Kerberos, LDAP heartbeat
authorized_beaconing_sources = []           # IP-uri cu polling/monitoring legitim
```

Validari `Config::validate`:
- `min_events >= 3`
- `time_window_secs > 0`
- `0 < cv_threshold <= 1`
- `min_interval_secs > 0 && max_interval_secs > min_interval_secs`

## State Detector

```rust
struct BeaconHit { seen_at: Instant }

beacon_hits: DashMap<(IpAddr, IpAddr, u16), Vec<BeaconHit>>
beacon_cooldowns: DashMap<(IpAddr, IpAddr, u16), Instant>
```

Limita memorie:
- `Vec<BeaconHit>` capped la `min_events * 4` per flow (drain oldest).
- Numar de chei capped la `max_tracked_ips` (LRU pe ultimul `seen_at`).

## Alert

Extindere `Alert`:
```rust
pub mean_interval_secs: Option<f64>,
pub cv: Option<f64>,
pub event_count: Option<usize>,
```

`ScanType::Beaconing` (Display "Beaconing C2"). SigID **1006**, severitate **9 (Critical)**.

Cooldown: refolosim `alert_cooldown_secs` global, pe cheia compozita `(src, dst, dport)`.

## Integrare

- `src/detector.rs`: ScanType variant, state nou, branch `--- 8. Beaconing ---` in
  `process_event`, cleanup periodic.
- `src/config.rs`: `BeaconingConfig`, extensie `DetectionExceptions`, validare.
- `src/display.rs`: format CLI cu mean/cv/count.
- `src/alerter.rs`: CEF SigID 1006 sev 9, `cs1=mean_interval cs2=cv cs3=event_count`;
  email subject + HTML row.
- `src/web.rs`: campurile noi serializate automat (sunt in `Alert`).
- `static/dashboard.html`: badge "Beaconing C2", coloana mean/cv vizibila pe rand.
- `config.toml`: sectiune `[detection.beaconing]` cu valori comentate.
- `README.md`: sectiune noua.
- `tester/tester.py`: scenariu `beaconing-c2` (10 calluri la 60s ± 5s pe acelasi flow).

## Teste

Unit (`src/detector.rs`):
- CV uniforma (intervale constante) → emite.
- CV mare (intervale random) → nu emite.
- `len < min_events` → nu emite.
- `mean < min_interval_secs` → nu emite.
- `mean > max_interval_secs` → nu emite.
- Port in `ignore_beaconing_ports` → nu inregistreaza.
- Sursa in `authorized_beaconing_sources` → nu inregistreaza.
- Cooldown previne dublarea.

Integration: 10 evenimente accept la 60s ± 5s → 1 alerta cu mean~60, cv<0.1.

## Edge cases

- `mean == 0` (timestamp identice burst) → skip (divide by zero).
- Single event in window → never reaches `min_events`.
- Action != "accept" → ignorat (beaconing-ul C2 implica conexiune reusita).

## Out of scope

- FFT / autocorelatie (varianta B din brainstorm) — amanata.
- Detectie pe traffic UDP (parser-ul curent emite `accept`/`drop` la nivel de flow).