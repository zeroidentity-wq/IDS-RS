# Jurnal de invataare — IDS-RS

Acest fisier urmareste progresul in invatarea Rust si programare prin proiectul IDS-RS.
Claude Code il citeste automat — contextul de invataare este portabil oriunde e clonat repo-ul.

---

## Profilul cursantului

- **Nivel programare:** Bazele unui limbaj (variabile, functii, bucle)
- **Nivel retelistica:** Concepte de baza (a auzit de IP, port, TCP/UDP)
- **Timp disponibil:** 4-7 ore/saptamana
- **Scop:** Intelegerea profunda, nu memorarea sintaxei. Vrea sa gandeasca ca un programator.
- **Limba preferata:** Romana

---

## Curriculum complet

```
FAZA 0  — Cum gandeste un programator
FAZA 1  — Cum comunica calculatoarele (retele, UDP, porturi, syslog)
FAZA 2  — Rust: tipuri, variabile, functii
FAZA 3  — Rust: Ownership (conceptul central, unic in Rust)
FAZA 4  — Rust: Structs, Enums, Pattern Matching
FAZA 5  — Rust: Traits (contracte si polimorfism)
FAZA 6  — Rust: Error handling (Option, Result, operatorul ?)
FAZA 7  — Proiect: Parserul (citesti si interpretezi text)
FAZA 8  — Proiect: Detectorul (algoritmi, structuri de date, sliding window)
FAZA 9  — Rust: Async si concurenta (tokio, Arc, DashMap)
FAZA 10 — Proiect: Alerter + main (pui totul cap la cap)
FAZA 11 — Rescrie IDS-RS de la zero (testul final)
```

---

## Progres

### FAZA 0 — Cum gandeste un programator
**Status:** Predata
**Predat in sesiunea:** 2026-02-19

**Concepte explicate:**
- Ce este un algoritm si cum gandesti in pasi
- Descompunerea problemelor (IDS-RS impartit in 5 probleme mici)
- Pseudocod — gandesti inainte sa scrii cod

**Exercitii date:**
- [ ] **0.1** — Scrie pseudocod: gaseste IP-ul cu cele mai multe porturi unice dintr-un fisier de log-uri
- [ ] **0.2** — Citeste `detector.rs:process_event` (linia 186) si raspunde: ce primeste, ce returneaza, ce verifica?

**Resurse:**
- [Think Like a Programmer (V. Anton Spraul)](https://nostarch.com/thinklikeaprogrammer) — primele 2 capitole
- [How to Design Programs](https://htdp.org/) — capitolul 1 (gratuit online)

---

### FAZA 1 — Cum comunica calculatoarele
**Status:** Predata
**Predat in sesiunea:** 2026-02-19

**Concepte explicate:**
- Adrese IP si porturi (analogia: casa + usa)
- UDP vs TCP (carte postala vs telefon)
- Ce este syslog si cum trimite firewall-ul log-uri
- Ce este un port scan si de ce e periculos
- Anatomia unui log Checkpoint Gaia

**Exercitii date:**
- [ ] **1.1** — `ss -tlnp` in terminal: ce porturi sunt deschise pe masina ta?
- [ ] **1.2** — Trimite un pachet UDP manual la IDS-RS cu `nc -u` si observa output-ul cu `debug = true`

**Resurse:**
- [Computer Networking: A Top-Down Approach](https://gaia.cs.umass.edu/kurose_ross/online_lectures.htm) — primele 2 capitole
- [Julia Evans — Networking zine](https://wizardzines.com/zines/networking/)
- [How DNS Works](https://howdns.works/)

---

### FAZA 2 — Rust: tipuri, variabile, functii
**Status:** Nepredata — urmeaza

**Obiectiv:** Sa intelegi cum Rust organizeaza datele si cum scrii functii de baza.

**Concepte de predat:**
1. **Variabile si mutabilitate** — `let` vs `let mut`, de ce imutabil e default
2. **Tipuri primitive** — `u8`, `u16`, `u32`, `u64`, `i32`, `f64`, `bool`
3. **String-uri** — `String` (owned, pe heap) vs `&str` (borrowed, slice)
4. **Functii** — parametri, valori de retur, `-> TipRetur`
5. **Control flow** — `if/else`, `loop`, `while`, `for ... in`
6. **Shadowing** — redeclararea cu `let` (diferit de `mut`)
7. **Type inference** — compilatorul deduce tipuri, dar uneori trebuie explicitat

**Unde apar in proiect:**
- `config.rs:59-65` — tipuri in struct: `String`, `u16`, `bool`
- `config.rs:80-92` — `u64`, `usize` — de ce tipuri diferite de integer
- `display.rs:359-361` — functia `timestamp()`: parametri zero, returneaza `String`
- `cef.rs:86-90` — `let mut` — variabile mutabile vs imutabile

**Exercitii:**
- [ ] **2.1** — Deschide `config.rs` si fa o lista cu TOATE tipurile de date folosite (String, u16, u64, bool, Vec<String>, usize). Pentru fiecare, scrie ce stocheaza si de ce e acel tip si nu altul.
- [ ] **2.2** — Scrie o functie `fn port_range(start: u16, end: u16) -> Vec<u16>` care returneaza un vector cu toate porturile din interval. Testeaza cu `cargo test`.
- [ ] **2.3** — Scrie o functie `fn is_private_ip(ip: &str) -> bool` care verifica daca un IP este privat (10.x.x.x, 172.16-31.x.x, 192.168.x.x). Foloseste `if/else` si `starts_with()`.
- [ ] **2.4** — Citeste `display.rs:54-128` (`print_banner`). Identifica: ce parametri primeste? Ce tipuri? Ce metode sunt apelate pe String-uri?

**Tema de pregatit (inainte de Faza 2):**
- Citeste [The Rust Book — Capitolul 1-3](https://doc.rust-lang.org/book/) (gratuit online)

**Resurse:**
- [The Rust Book — Ch. 3: Common Programming Concepts](https://doc.rust-lang.org/book/ch03-00-common-programming-concepts.html)
- [Rust By Example — Primitives](https://doc.rust-lang.org/rust-by-example/primitives.html)
- [Rustlings exercitii](https://github.com/rust-lang/rustlings) — sectiunile `variables`, `functions`, `if`, `primitive_types`

---

### FAZA 3 — Rust: Ownership
**Status:** Nepredata

**Obiectiv:** Sa intelegi ownership, borrowing si lifetime-uri — conceptul central care face Rust unic.

**Concepte de predat:**
1. **Stack vs Heap** — unde traiesc datele si de ce conteaza
2. **Regula ownership** — fiecare valoare are un singur proprietar
3. **Move semantics** — ce se intampla cand atribui `let b = a;`
4. **Borrowing imutabil** — `&T` (referinta shared, read-only)
5. **Borrowing mutabil** — `&mut T` (referinta exclusiva, read-write)
6. **Regula borrow checker** — ori N x `&T`, ori 1 x `&mut T`, niciodata ambele
7. **`.clone()` vs move** — cand si de ce clonezi explicit
8. **`.to_string()` si `.to_owned()`** — creare String owned din &str
9. **De ce Rust nu are garbage collector** — RAII si Drop

**Unde apar in proiect:**
- `parser/mod.rs:56-81` — de ce `String` (owned) in struct, nu `&str` (borrowed)
- `gaia.rs:80` — `fn extract_field<'a>(extensions: &'a str, key: &str) -> Option<&'a str>` — lifetime explicit
- `gaia.rs:123-176` — `&self` si `line: &str` — borrowing in practica
- `config.rs:155-172` — `.clone()` si `.to_string()` — creare de copii owned
- `detector.rs:186-188` — `&self` si `event: &LogEvent` — borrowing fara consum

**Exercitii:**
- [ ] **3.1** — Experiment in Rust Playground: scrie cod care face `let a = String::from("hello"); let b = a; println!("{}", a);` — observa eroarea. Explica DE CE nu merge. Apoi repara cu `.clone()`.
- [ ] **3.2** — Scrie o functie `fn longest_string(a: &str, b: &str) -> &str` care returneaza string-ul mai lung. Observa eroarea compilatorului despre lifetime-uri. Repara adaugand `<'a>`.
- [ ] **3.3** — Citeste `gaia.rs:80-93` (`extract_field`). Raspunde: de ce parametrul `extensions` are lifetime `'a` dar `key` nu? Ce legatura are lifetime-ul de iesire cu cel de intrare?
- [ ] **3.4** — Citeste comentariul din `parser/mod.rs:56-60`. Explica in cuvintele tale de ce LogEvent foloseste `String` si nu `&str` in campuri.
- [ ] **3.5** — In `main.rs:159-160`, de ce apelam `config.detection.clone()` cand cream Detector si Alerter? Ce s-ar intampla fara `.clone()`?

**Resurse:**
- [The Rust Book — Ch. 4: Understanding Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html) — **CEL MAI IMPORTANT CAPITOL**
- [Visualizing Rust Ownership](https://blog.logrocket.com/introducing-the-rust-borrow-checker/) — cu diagrame
- [Rust By Example — Ownership](https://doc.rust-lang.org/rust-by-example/scope.html)
- [Rustlings](https://github.com/rust-lang/rustlings) — sectiunile `move_semantics`, `lifetimes`
- Video: [Let's Get Rusty — Ownership Explained](https://www.youtube.com/watch?v=VFIOSWy93H0) (~15 min)

---

### FAZA 4 — Rust: Structs, Enums, Pattern Matching
**Status:** Nepredata

**Obiectiv:** Sa intelegi cum organizezi date (struct) si cum modelezi variante (enum) in Rust.

**Concepte de predat:**
1. **`struct`** — grupare de campuri cu nume (ca o "fisa" de date)
2. **`impl` blocuri** — metode atasate la struct (`Self`, `&self`, `&mut self`)
3. **`enum`** — tip cu variante (sum type / tagged union)
4. **`match`** — pattern matching exhaustiv (compilatorul te obliga sa tratezi toate cazurile)
5. **`if let`** — scurtatura pentru `match` cu o singura varianta
6. **`Option<T>`** — `Some(valoare)` sau `None` — inlocuieste `null`
7. **`#[derive(Debug, Clone)]`** — generare automata de implementari

**Unde apar in proiect:**
- `config.rs:50-56` — `AppConfig` struct cu 4 campuri (structuri imbricate)
- `parser/mod.rs:60-81` — `LogEvent` struct cu 6 campuri
- `detector.rs:62-66` — `ScanType` enum cu 2 variante (`Fast`, `Slow`)
- `detector.rs:76-83` — `impl Display for ScanType` cu `match`
- `detector.rs:90-99` — `Alert` struct
- `alerter.rs:110-129` — `match alert.scan_type` cu date diferite per varianta
- `gaia.rs:127-128` — `?` pe `Option` (propagare None)
- `display.rs:222-253` — `match` cu branch-uri extinse (formatare diferita per scan type)

**Exercitii:**
- [ ] **4.1** — Creeaza un `enum Protocol { Tcp, Udp, Icmp, Other(String) }` cu `impl Display`. Observa cum varianta `Other` poate contine date, spre deosebire de enum-urile din C/Java.
- [ ] **4.2** — Creeaza un struct `FirewallRule { id: u32, action: String, source: Option<IpAddr>, dest: Option<IpAddr> }` cu o metoda `fn describe(&self) -> String` care formateaza regula frumos. Trateaza `Option`-urile cu `match` sau `if let`.
- [ ] **4.3** — Citeste `detector.rs:62-83` (ScanType). Adauga o varianta imaginara `ScanType::Stealth` cu un camp `technique: String`. Actualizeaza `Display` si `match`-urile din `alerter.rs:110-129`. Observa cum compilatorul TE FORTEAZA sa tratezi noul caz peste tot. (exercitiu doar local, nu commit)
- [ ] **4.4** — Citeste `cef.rs:86-118`. Explica rolul fiecarui `Option<T>` — de ce `source_ip` este `Option<IpAddr>` initial, dar in struct-ul final `LogEvent` este `IpAddr` (non-optional)?
- [ ] **4.5** — Scrie o functie `fn classify_port(port: u16) -> &'static str` care returneaza "well-known" (0-1023), "registered" (1024-49151) sau "dynamic" (49152-65535) folosind `match` cu range patterns.

**Resurse:**
- [The Rust Book — Ch. 5: Using Structs](https://doc.rust-lang.org/book/ch05-00-structs.html)
- [The Rust Book — Ch. 6: Enums and Pattern Matching](https://doc.rust-lang.org/book/ch06-00-enums.html)
- [Rust By Example — Structs](https://doc.rust-lang.org/rust-by-example/custom_types/structs.html)
- [Rust By Example — Enums](https://doc.rust-lang.org/rust-by-example/custom_types/enum.html)
- [Rustlings](https://github.com/rust-lang/rustlings) — sectiunile `structs`, `enums`, `options`
- Video: [Let's Get Rusty — Enums](https://www.youtube.com/watch?v=DSZqIJhkNCM) (~12 min)

---

### FAZA 5 — Rust: Traits
**Status:** Nepredata

**Obiectiv:** Sa intelegi traits (contracte/interfete) si polimorfismul in Rust — cum faci cod extensibil fara mostenire.

**Concepte de predat:**
1. **Ce este un trait** — contract (set de metode pe care un tip TREBUIE sa le aiba)
2. **`impl Trait for Struct`** — cum "semnezi" contractul
3. **Default implementations** — metode cu implementare default in trait
4. **Trait objects: `Box<dyn Trait>`** — dynamic dispatch (rezolvare la runtime)
5. **Generics cu trait bounds: `<T: Trait>`** — static dispatch (rezolvare la compile-time)
6. **`Send + Sync`** — marker traits pentru thread safety
7. **Trait-uri standard: `Display`, `Debug`, `Clone`, `Default`**
8. **De ce Rust nu are mostenire** — composition over inheritance

**Unde apar in proiect:**
- `parser/mod.rs:97-106` — trait-ul `LogParser` cu 3 metode
- `parser/mod.rs:119-127` — factory function cu `Box<dyn LogParser>`
- `gaia.rs:102-185` — `impl LogParser for GaiaParser`
- `cef.rs:44-143` — `impl LogParser for CefParser`
- `detector.rs:76-83` — `impl Display for ScanType`
- `config.rs:155` — `fn load<P: AsRef<Path>>(path: P)` — generic cu trait bound
- `main.rs:143-144` — utilizarea trait object-ului: `parser.parse(line)`

**Exercitii:**
- [ ] **5.1** — Creeaza un trait `Summarizable` cu o metoda `fn summary(&self) -> String`. Implementeaza-l pentru `LogEvent` (din proiect) si pentru un struct nou `AlertSummary`. Apeleaza `.summary()` pe ambele printr-o functie `fn print_summary(item: &dyn Summarizable)`.
- [ ] **5.2** — Citeste `parser/mod.rs:97-127`. Raspunde: (a) de ce trait-ul cere `Send + Sync`? (b) de ce `create_parser` returneaza `Box<dyn LogParser>` si nu un tip concret? (c) ce s-ar intampla daca am vrea sa adaugam un al treilea parser (ex: JSON)?
- [ ] **5.3** — Citeste `config.rs:155` (`fn load<P: AsRef<Path>>`). Testeaza apeland `AppConfig::load("config.toml")` si `AppConfig::load(String::from("config.toml"))`. De ce ambele merg? Ce face `AsRef<Path>`?
- [ ] **5.4** — Imagineaza-ti ca vrei sa adaugi un parser pentru log-uri JSON. Scrie (doar pe hartie/pseudocod): (a) struct-ul `JsonParser`, (b) `impl LogParser for JsonParser`, (c) modificarea din `create_parser`. Cat de putin trebuie schimbat in restul codului?
- [ ] **5.5** — Explica diferenta dintre `fn process(parser: &dyn LogParser)` (dynamic dispatch) si `fn process<P: LogParser>(parser: &P)` (static dispatch). Care e mai rapid? Care e mai flexibil? Pe care o folosim in IDS-RS si de ce?

**Resurse:**
- [The Rust Book — Ch. 10.2: Traits](https://doc.rust-lang.org/book/ch10-02-traits.html)
- [The Rust Book — Ch. 17.2: Trait Objects](https://doc.rust-lang.org/book/ch17-02-trait-objects.html)
- [Rust By Example — Traits](https://doc.rust-lang.org/rust-by-example/trait.html)
- [Rustlings](https://github.com/rust-lang/rustlings) — sectiunea `traits`
- Video: [Jon Gjengset — Traits and Trait Objects](https://www.youtube.com/watch?v=grU-4u0Okto) (~25 min)
- Blog: [Rust Traits Explained (LogRocket)](https://blog.logrocket.com/rust-traits-a-deep-dive/)

---

### FAZA 6 — Rust: Error Handling
**Status:** Nepredata

**Obiectiv:** Sa intelegi cum Rust gestioneaza erorile FARA exceptii — cu `Result<T,E>`, `Option<T>` si operatorul `?`.

**Concepte de predat:**
1. **`Result<T, E>`** — `Ok(valoare)` sau `Err(eroare)` — fiecare functie care poate esua
2. **`Option<T>`** — `Some(valoare)` sau `None` — absenta valorii (nu null!)
3. **Operatorul `?`** — propagare automata a erorii catre apelant
4. **`unwrap()` si `expect()`** — extrage valoarea sau PANIC (doar in teste!)
5. **`.context()` si `.with_context()`** — adaugare mesaj la eroare (anyhow)
6. **`anyhow::bail!`** — macro de return cu eroare
7. **Strategii: "fail fast" vs "log and continue"**
8. **De ce Rust nu are exceptii** — erorile sunt valori, nu salturi de control

**Unde apar in proiect:**
- `config.rs:155-172` — `fn load()` cu `?` pe fiecare operatie
- `config.rs:182-331` — `fn validate()` cu colectare de erori in `Vec<String>` si `bail!`
- `gaia.rs:62-73` — `GaiaParser::new()` returneaza `Result<Self>`
- `gaia.rs:127-148` — `?` pe `Option` — propagare None
- `alerter.rs:74-86` — pattern "log and continue": eroare SIEM nu opreste email
- `cef.rs:117-119` — `source_ip?` si `dest_port?` — extragere din Option cu `?`
- `main.rs:115` — `AppConfig::load(&config_path)?` — propagare catre main

**Exercitii:**
- [ ] **6.1** — Scrie o functie `fn parse_port(input: &str) -> Result<u16, String>` care: (a) parseaza string-ul la u16, (b) verifica ca portul e > 0, (c) returneaza eroare descriptiva daca nu. Testeaza cu "443", "0", "abc", "99999".
- [ ] **6.2** — Scrie o functie `fn read_config_value(path: &str, key: &str) -> anyhow::Result<String>` care citeste un fisier, cauta o linie "key = value" si returneaza valoarea. Foloseste `?` si `.context()` pe fiecare pas.
- [ ] **6.3** — Citeste `config.rs:182-331` (`validate()`). Raspunde: de ce colectam TOATE erorile intr-un Vec in loc sa returnam la prima eroare gasita? Ce experienta ar avea utilizatorul in fiecare caz?
- [ ] **6.4** — Citeste `alerter.rs:74-86`. De ce folosim "log and continue" (afisam eroarea si continuam) in loc de `?` (propagam eroarea)? Ce s-ar intampla daca SIEM-ul e offline si am folosi `?`?
- [ ] **6.5** — Transforma acest cod cu `unwrap()` in cod safe:
  ```rust
  let ip: IpAddr = "192.168.1.1".parse().unwrap();
  let port: u16 = "443".parse().unwrap();
  let file = std::fs::read_to_string("config.toml").unwrap();
  ```
  Foloseste `?`, `match`, `if let` sau `.ok()` — fara niciun `unwrap()`.

**Resurse:**
- [The Rust Book — Ch. 9: Error Handling](https://doc.rust-lang.org/book/ch09-00-error-handling.html)
- [Rust By Example — Error Handling](https://doc.rust-lang.org/rust-by-example/error.html)
- [anyhow crate docs](https://docs.rs/anyhow/latest/anyhow/)
- [Rustlings](https://github.com/rust-lang/rustlings) — sectiunile `error_handling`, `options`
- Blog: [Rust Error Handling Best Practices](https://blog.burntsushi.net/rust-error-handling/)
- Video: [Let's Get Rusty — Error Handling](https://www.youtube.com/watch?v=wM6o70NAWUI) (~15 min)

---

### FAZA 7 — Proiect: Parserul
**Status:** Nepredata

**Obiectiv:** Sa intelegi cum se parseaza text structurat (log-uri firewall) — regex, string manipulation, si pattern-ul trait-based extensibil.

**Concepte de predat:**
1. **Ce inseamna "parsare"** — transformarea textului brut in date structurate
2. **Regex** — expresii regulate, compilare o singura data, grupuri de captura
3. **String slicing** — `&str`, `.split()`, `.find()`, `.strip_prefix()`
4. **Key-value extraction** — cum extragi date din formatul "key: value; key: value"
5. **Factory pattern** — `create_parser()` selecteaza implementarea la runtime
6. **Testare unitara** — `#[cfg(test)]`, `#[test]`, `assert!`, `assert_eq!`

**Unde apar in proiect:**
- `gaia.rs` — parser complet Gaia: regex header + key-value extraction
- `cef.rs` — parser complet CEF: split pipe + key=value
- `parser/mod.rs` — trait + factory function
- `gaia.rs:195-273` — teste unitare Gaia
- `cef.rs:146-207` — teste unitare CEF

**Exercitii:**
- [ ] **7.1** — Ia log-ul real din `gaia.rs:202-205` (test). Pe hartie, deseneaza procesul de parsare pas cu pas: (1) unde face match regex-ul, (2) ce e in zona de extensii, (3) cum extrage `src`, `service`, `proto`.
- [ ] **7.2** — Scrie un mini-parser (functie `fn parse_simple_log(line: &str) -> Option<(String, u16)>`) care extrage IP si port din formatul simplu: `"DROP src=1.2.3.4 dpt=443"`. Fara regex, doar cu `.find()`, `.split()`, `.strip_prefix()`.
- [ ] **7.3** — Scrie teste unitare pentru parser-ul tau de la 7.2: test cu input valid, test cu input invalid, test cu campuri lipsa. Ruleaza cu `cargo test`.
- [ ] **7.4** — Citeste `gaia.rs:68-70` (regex-ul). Decodifica pattern-ul: `r"(?i)Checkpoint:\s+\S+\s+\S+\s+(accept|drop|reject)\s+"`. Ce face fiecare parte? Testeaza pe [regex101.com](https://regex101.com/) cu un log real.
- [ ] **7.5** — Citeste `cef.rs:56-134`. Compara cu `gaia.rs:123-176`. Listeaza 3 diferente concrete intre cele 2 abordari de parsare (regex vs split). Care e mai flexibila? Care e mai rapida?
- [ ] **7.6** — **Proiect mini:** Scrie un `SyslogParser` (struct nou cu `impl LogParser`) care parseaza formatul: `"<PRI>Mon DD HH:MM:SS host program: message"`. Extrage prioritatea, timestamp-ul si mesajul. Nu trebuie integrat in IDS-RS — e exercitiu standalone.

**Resurse:**
- [The Rust Book — Ch. 8.2: Strings](https://doc.rust-lang.org/book/ch08-02-strings.html)
- [regex crate docs](https://docs.rs/regex/latest/regex/)
- [regex101.com](https://regex101.com/) — testeaza regex-uri interactiv (selecteaza "Rust" flavor)
- [Rust By Example — Testing](https://doc.rust-lang.org/rust-by-example/testing/unit_testing.html)
- [Rustlings](https://github.com/rust-lang/rustlings) — sectiunile `strings`, `tests`
- Video: [Regex in Rust — Lets Get Rusty](https://www.youtube.com/watch?v=O2R4VGjYqLY) (~10 min)

---

### FAZA 8 — Proiect: Detectorul
**Status:** Nepredata

**Obiectiv:** Sa intelegi algoritmul de detectie (sliding window), structurile de date HashMap/Vec, si cum functioneaza iteratorii in Rust.

**Concepte de predat:**
1. **`Vec<T>`** — array dinamic (creste/scade, alocat pe heap)
2. **`HashMap<K, V>`** — structura cheie/valoare (lookup O(1))
3. **Entry API** — `.entry(key).or_default()` — get-or-insert idiom
4. **Algoritmul sliding window** — pastreaza doar evenimentele din fereastra de timp
5. **Iteratori** — `.iter()`, `.filter()`, `.map()`, `.collect()` — zero-cost abstractions
6. **`sort_unstable()` + `dedup()`** — deduplicare eficienta
7. **Cooldown pattern** — prevenirea alertelor duplicate
8. **`Instant` vs `DateTime`** — timp monotonic vs wall-clock

**Unde apar in proiect:**
- `detector.rs:108-111` — struct `PortHit` (port + timestamp)
- `detector.rs:139-153` — struct `Detector` (DashMap-uri + config)
- `detector.rs:186-249` — `process_event()` — algoritmul principal
- `detector.rs:272-303` — `unique_ports_in_window()` — iterator chain
- `detector.rs:330-361` — `cleanup()` — curatare cu `.retain()`
- `detector.rs:370-467` — teste unitare

**Exercitii:**
- [ ] **8.1** — Pe hartie, simuleaza algoritmul: IP 10.0.0.1 trimite pachete pe porturile [22, 80, 22, 443, 8080] cu threshold=3 si window=10s. La al catelea pachet se declanseaza alerta? De ce?
- [ ] **8.2** — Scrie un program standalone care: (a) creeaza un `HashMap<String, Vec<u16>>`, (b) adauga porturi pentru 3 IP-uri diferite, (c) afiseaza cate porturi UNICE are fiecare IP. Foloseste `.entry().or_default()`.
- [ ] **8.3** — Rescrie `unique_ports_in_window` (detector.rs:272-303) in pseudocod. Apoi rescrie-l ca un `for` loop simplu (fara iteratori). Compara cele 2 versiuni — care e mai clara?
- [ ] **8.4** — Citeste `detector.rs:330-361` (`cleanup`). Raspunde: (a) de ce nu putem sterge din DashMap in timpul iteratiei? (b) ce face `.retain()`? (c) ce s-ar intampla daca NU am face cleanup periodic?
- [ ] **8.5** — Citeste testul `test_cooldown_prevents_duplicate_alert` (detector.rs:427-438). Scrie UN TEST NOU care verifica ca dupa expirarea cooldown-ului (5 secunde in test_config), o noua alerta ESTE generata. Hint: vei avea nevoie de `std::thread::sleep`.
- [ ] **8.6** — **Provocare:** Threshold-ul curent este "mai mare strict" (`ports.len() > threshold`). Daca schimbi in "mai mare sau egal" (`>=`), cate teste pica? De ce? Ce diferenta face in practica?

**Resurse:**
- [The Rust Book — Ch. 8: Common Collections](https://doc.rust-lang.org/book/ch08-00-common-collections.html) — Vec si HashMap
- [The Rust Book — Ch. 13: Iterators](https://doc.rust-lang.org/book/ch13-02-iterators.html)
- [Rust By Example — HashMap](https://doc.rust-lang.org/rust-by-example/std/hash.html)
- [Rustlings](https://github.com/rust-lang/rustlings) — sectiunile `vecs`, `hashmaps`, `iterators`
- Blog: [Rust Iterator Cheat Sheet](https://danielkeep.github.io/itercheat_baked.html)
- Video: [Rust Iterators](https://www.youtube.com/watch?v=4GcKrj4By8k) (~20 min, Jon Gjengset)

---

### FAZA 9 — Rust: Async si concurenta
**Status:** Nepredata

**Obiectiv:** Sa intelegi programarea asincrona (async/await), tokio runtime, si cum se partajeaza date intre task-uri concurente.

**Concepte de predat:**
1. **Thread vs async task** — de ce async e mai eficient (stack mic, user-space switch)
2. **`async fn` si `.await`** — functii care se suspenda fara a bloca thread-ul
3. **Future-uri** — "promisiune" ca o valoare va fi disponibila in viitor (lazy!)
4. **tokio runtime** — executorul care ruleaza futures (thread pool)
5. **`tokio::spawn`** — lanseaza un task async independent (background)
6. **`tokio::select!`** — asteapta pe mai multe futures, reactioneaza la primul
7. **`Arc<T>`** — Atomic Reference Counting — shared ownership intre thread-uri
8. **`DashMap`** — HashMap concurent cu sharding (interior mutability)
9. **`move` closures** — transferul ownership-ului in closures/tasks

**Unde apar in proiect:**
- `main.rs:77` — `#[tokio::main]` — macro care creeaza runtime-ul
- `main.rs:159-160` — `Arc::new()` si `Arc::clone()` — shared ownership
- `main.rs:182-204` — `tokio::spawn(async move { ... })` — background cleanup task
- `main.rs:258-352` — `tokio::select!` — UDP recv vs Ctrl+C
- `alerter.rs:74-86` — `async fn send_alert` — I/O asincron
- `alerter.rs:181-189` — `UdpSocket::bind().await` si `.send_to().await`
- `detector.rs:142-143` — `DashMap` — HashMap thread-safe fara lock explicit

**Exercitii:**
- [ ] **9.1** — Scrie un program tokio minimal care: (a) spawneaza 3 task-uri ce printeaza "Task N start", asteapta 1-3 secunde (`tokio::time::sleep`), apoi "Task N done", (b) asteapta toate sa se termine. Observa ordinea output-ului — e determinista?
- [ ] **9.2** — Scrie un program care foloseste `tokio::select!` cu 2 branch-uri: (a) `tokio::time::sleep(5s)` — "Timeout!", (b) citirea de pe stdin — "Ai scris: ...". Care se executa primul depinde de utilizator.
- [ ] **9.3** — Citeste `main.rs:182-204` (cleanup task). Raspunde: (a) de ce `Arc::clone(&detector)` INAINTE de `move`? (b) ce s-ar intampla daca NU am face clone si am muta direct `detector`? (c) de ce `async move` si nu doar `async`?
- [ ] **9.4** — Citeste `main.rs:258-352` (select loop). Raspunde: (a) ce face `biased;`? (b) de ce Ctrl+C e primul branch? (c) ce se intampla cu `recv_from` cand Ctrl+C e apasat?
- [ ] **9.5** — Experiment: creeaza un `Arc<DashMap<String, u32>>`, cloneaza-l in 3 task-uri spawn-ate, fiecare inserand 100 de valori. La final, verifica ca map-ul are 300 de intrari. Aceasta demonstreaza thread safety-ul DashMap.
- [ ] **9.6** — Citeste `alerter.rs:101-193`. De ce cream un socket UDP NOU la fiecare alerta (`UdpSocket::bind("0.0.0.0:0")`) in loc sa reutilizam unul? Care sunt avantajele si dezavantajele?

**Resurse:**
- [The Rust Book — Ch. 16: Fearless Concurrency](https://doc.rust-lang.org/book/ch16-00-concurrency.html)
- [Tokio Tutorial (oficial)](https://tokio.rs/tokio/tutorial) — parcurge primele 5 sectiuni
- [Async Rust Book](https://rust-lang.github.io/async-book/) — capitolele 1-3
- [DashMap docs](https://docs.rs/dashmap/latest/dashmap/)
- Video: [Crust of Rust: async/await](https://www.youtube.com/watch?v=ThjvMReOXYM) (~1.5h, Jon Gjengset) — excelent dar dens
- Video: [Let's Get Rusty — Async Rust](https://www.youtube.com/watch?v=K8LNPYNvT-U) (~15 min, mai accesibil)

---

### FAZA 10 — Proiect: Alerter + Main
**Status:** Nepredata

**Obiectiv:** Sa intelegi cum se conecteaza toate componentele: trimiterea de alerte (SIEM + email), orchestrarea din main, si pattern-urile de design folosite.

**Concepte de predat:**
1. **Format CEF** — Common Event Format pentru SIEM (structura campurilor)
2. **Syslog RFC 3164** — formatul header-ului syslog (priority, timestamp, hostname)
3. **UDP socket efemer** — `bind("0.0.0.0:0")` — OS alege portul
4. **SMTP async cu lettre** — trimitere email asincrona, credentiale, TLS
5. **Orchestrarea in main** — init, spawn, select loop, graceful shutdown
6. **Pattern "clone and own"** — clonare la initializare, ownership clar
7. **Modulele Rust** — `mod`, `pub`, `use`, `crate::`, vizibilitate

**Unde apar in proiect:**
- `alerter.rs:101-193` — constructia mesajului CEF + trimitere UDP
- `alerter.rs:209-295` — constructia email-ului + trimitere SMTP async
- `main.rs:51-55` — declararea modulelor (`mod config; mod parser;`)
- `main.rs:77-356` — intregul flow: config -> init -> spawn -> loop -> shutdown
- `display.rs` — modulul de afisare (separare de responsabilitati)

**Exercitii:**
- [ ] **10.1** — Citeste `alerter.rs:164-178` (format string CEF). Pe hartie, deseneaza structura mesajului CEF cu toate campurile. Compara cu exemplul din `alerter.rs:102-108`.
- [ ] **10.2** — Citeste `main.rs` de la linia 77 la 356. Fa o diagrama (pe hartie) cu ordinea operatiilor: (1) init tracing, (2) load config, ..., (7) select loop. Deseneaza sagetile de date: ce componenta primeste ce date?
- [ ] **10.3** — Citeste `display.rs:148-178` (log_info, log_warning, log_error). De ce toate functiile primesc `&str` si nu `String`? Ce s-ar schimba daca am folosi `String`?
- [ ] **10.4** — Scrie un program standalone care: (a) creeaza un socket UDP si trimite un mesaj CEF hardcodat catre `127.0.0.1:9514`, (b) intr-un alt terminal, asculta cu `nc -lu 9514`. Verifica ca mesajul ajunge corect.
- [ ] **10.5** — Citeste `main.rs:293-344` (procesarea log-urilor in loop). Traseaza flow-ul complet pentru UN singur pachet: (1) recv_from -> (2) from_utf8_lossy -> (3) lines() -> (4) parse() -> (5) process_event -> (6) send_alert. Ce se intampla la fiecare pas daca input-ul e invalid?
- [ ] **10.6** — **Proiect mini:** Scrie un `echo_server.rs` (program separat) care asculta pe UDP, primeste mesaje, le afiseaza si le trimite inapoi (echo). Foloseste `tokio::net::UdpSocket`, `select!` cu Ctrl+C. E versiunea simplificata a IDS-RS fara parsare/detectie.

**Resurse:**
- [CEF Format Guide (Micro Focus)](https://docs.microfocus.com/docs/CEF_Guide.pdf) — specificatia oficiala CEF
- [Syslog RFC 3164](https://datatracker.ietf.org/doc/html/rfc3164) — formatul syslog (skim headers/priority)
- [lettre crate docs](https://docs.rs/lettre/latest/lettre/) — biblioteca SMTP Rust
- [Tokio UdpSocket docs](https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html)
- [The Rust Book — Ch. 7: Packages and Modules](https://doc.rust-lang.org/book/ch07-00-managing-growing-projects-with-packages-crates-and-modules.html)
- Video: [Rust Modules Explained](https://www.youtube.com/watch?v=5RPXTFt5y3I) (~15 min)

---

### FAZA 11 — Rescrie IDS-RS de la zero
**Status:** Nepredata

**Obiectiv:** Demonstreaza ca intelegi TOTUL — rescrie IDS-RS fara sa te uiti la codul existent.

**Reguli:**
1. **Nu te uita la codul existent** — inchide repo-ul, lucreaza intr-un folder nou
2. **Porneste de la pseudocod** — scrie planul INAINTE de cod (Faza 0!)
3. **Construieste incremental** — un modul pe zi, nu totul dintr-o data
4. **Testeaza la fiecare pas** — `cargo test` dupa fiecare modul

**Etape recomandate:**
- [ ] **11.1** — Scrie pseudocodul complet pe hartie: ce module exista, ce face fiecare, cum comunica
- [ ] **11.2** — Creeaza proiectul: `cargo new ids-rs-v2`
- [ ] **11.3** — Implementeaza `config.rs` — struct-uri + load + validate
- [ ] **11.4** — Implementeaza `parser/mod.rs` + un parser (Gaia SAU CEF, la alegere)
- [ ] **11.5** — Implementeaza `detector.rs` — DashMap, process_event, cleanup
- [ ] **11.6** — Implementeaza `alerter.rs` — CEF message + UDP send
- [ ] **11.7** — Implementeaza `main.rs` — leaga totul, tokio select loop
- [ ] **11.8** — Adauga al doilea parser
- [ ] **11.9** — Adauga `display.rs` cu culori
- [ ] **11.10** — Adauga email alerting
- [ ] **11.11** — Compara cu originalul: ce ai facut diferit? Ce ai facut mai bine? Ce ai uitat?

**Criteriu de succes:**
- Aplicatia compileaza fara warnings
- Toate testele trec (`cargo test`)
- Poate primi log-uri UDP si detecta un Fast Scan
- Trimite alertă CEF catre un SIEM (testat cu `nc -lu`)
- Codul este comentat si explicat (ca si cum l-ar citi altcineva)

**Resurse pentru aceasta faza:**
- Doar cunostintele tale + docs.rs + The Rust Book
- Daca te blochezi > 30 minute pe un concept, poti reveni la faza relevanta din acest curriculum

---

## Resurse generale (valabile pe tot parcursul)

### Carti / Documentatie
| Resursa | Nivel | Descriere |
|---------|-------|-----------|
| [The Rust Programming Language (Book)](https://doc.rust-lang.org/book/) | Incepator | Cartea oficiala — GRATUITA, citeste capitolele cand apar in curriculum |
| [Rust By Example](https://doc.rust-lang.org/rust-by-example/) | Incepator | Exemple practice pentru fiecare concept |
| [Rustlings](https://github.com/rust-lang/rustlings) | Incepator | Exercitii interactive in terminal — complementeaza fiecare faza |
| [Programming Rust (O'Reilly)](https://www.oreilly.com/library/view/programming-rust-2nd/9781492052586/) | Intermediar | Cartea cea mai detaliata despre Rust |
| [Rust for Rustaceans (Jon Gjengset)](https://nostarch.com/rust-rustaceans) | Avansat | Dupa ce termini curriculum-ul, pentru deep-dive |

### Video / Canale YouTube
| Canal | Stil | Recomandat pentru |
|-------|------|-------------------|
| [Let's Get Rusty](https://www.youtube.com/@letsgetrusty) | Scurt, clar | Fiecare concept individual (10-20 min) |
| [Jon Gjengset](https://www.youtube.com/@jonhoo) | Deep-dive, live | Async, traits, iteratori (1-2h, dar excelente) |
| [No Boilerplate](https://www.youtube.com/@NoBoilerplate) | Motivational | De ce Rust e special, filozofia limbajului |
| [Rust in 100 Seconds (Fireship)](https://www.youtube.com/watch?v=5C_HPTJg5ek) | Ultra-scurt | Overview rapid (doar 100 secunde!) |

### Unelte
| Unealta | Link | Utilizare |
|---------|------|-----------|
| Rust Playground | [play.rust-lang.org](https://play.rust-lang.org/) | Testeaza cod Rust in browser (fara instalare) |
| regex101 | [regex101.com](https://regex101.com/) | Testeaza regex-uri cu explicatii vizuale |
| Compiler Explorer | [godbolt.org](https://godbolt.org/) | Vezi codul masina generat de Rust (avansat) |
| cargo clippy | `cargo clippy` in terminal | Lint — sugereaza cod mai idiom Rust |
| cargo fmt | `cargo fmt` in terminal | Formateaza codul automat |

---

## Instructiuni pentru Claude (la start de sesiune de invatare)

1. Citeste acest fisier pentru a intelege unde s-a ajuns.
2. Intreaba daca cursantul a rezolvat exercitiile din faza precedenta si discuta raspunsurile.
3. Continua cu prima faza marcata ca `Nepredata`.
4. La finalul fazei, marcheaza exercitiile ca date si actualizeaza statusul la `Predata`.
5. Respecta stilul mentor: explica intotdeauna de ce, nu doar ce.
6. Foloseste analogii din lumea reala (casa/usa pentru IP/port, etc.).
7. La exercitiile cu cod, guideaza cursantul pas cu pas — nu da solutia directa.
8. Dupa fiecare faza, recapituleaza cele 3 lucruri cele mai importante invatate.
