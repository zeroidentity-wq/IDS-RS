// =============================================================================
// main.rs - Punct de Intrare IDS-RS
// =============================================================================
//
// Acest fisier orchrestreaza toate componentele:
//   1. Incarca configurarea din config.toml
//   2. Initializeaza parser-ul, detectorul si alerter-ul
//   3. Porneste task-ul de cleanup periodic (async)
//   4. Asculta pe UDP si proceseaza fiecare log primit
//   5. Gestioneaza oprirea gratiosa (Ctrl+C)
//
// CONCEPTE RUST EXPLICATE:
//
// 1. #[tokio::main]
//    Aceasta macro transforma `async fn main()` intr-un main sincron
//    care porneste runtime-ul tokio. Fara ea, nu poti folosi `.await`
//    in main() deoarece Rust nu are un runtime async built-in.
//
//    Echivalent cu:
//    fn main() {
//        let rt = tokio::runtime::Runtime::new().unwrap();
//        rt.block_on(async { ... });
//    }
//
// 2. Arc<T> (Atomic Reference Counting)
//    Permite partajarea datelor intre task-uri async / thread-uri.
//    Fiecare .clone() incrementeaza un contor atomic (nu copiaza datele!).
//    Cand ultimul Arc este dropat, datele sunt dealocate.
//
//    Arc<Detector> = mai multe task-uri pot accesa acelasi Detector.
//    DashMap din Detector ofera interior mutability -> modificari safe
//    prin referinte shared (&).
//
// 3. tokio::select!
//    Macro care asteapta PE MAI MULTE futures SIMULTAN si executa
//    branch-ul care se completeaza primul. Similar cu `select()` din C
//    sau `Promise.race()` din JavaScript.
//
//    In codul nostru:
//    - Branch 1: recv_from() - asteapta pachete UDP
//    - Branch 2: ctrl_c() - asteapta semnalul de oprire
//    Primul care "castiga" isi executa blocul de cod.
//
// 4. MODULES (Declarare Moduli)
//    `mod config;` instruieste compilatorul sa caute `src/config.rs`
//    si sa il includa ca sub-modul al crate-ului.
//    `mod parser;` cauta `src/parser/mod.rs` (director cu mod.rs).
//
// =============================================================================

use arc_swap::ArcSwap;
use ids_rs::alerter::Alerter;
use ids_rs::config::{AppConfig, SubnetEntry};
use ids_rs::delivery;
use ids_rs::detector::Detector;
use ids_rs::{display, parser, web};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

// =============================================================================
// TokenBucket — Rate Limiter pentru receptie UDP
// =============================================================================
//
// CONCEPTE RUST EXPLICATE:
//
// Algoritmul Token Bucket:
//   - Bucket-ul contine un numar de "tokeni" (capacitate = burst size).
//   - La fiecare secunda, se adauga `refill_rate` tokeni (= rata configurata).
//   - Fiecare pachet consumat scoate 1 token din bucket.
//   - Daca bucket-ul e gol (tokens <= 0), pachetul este dropat.
//   - Bucket-ul nu poate depasi `max_tokens` (= burst size).
//
// Aceasta permite burst-uri scurte (ex: 10.000 pachete imediat) dar limiteaza
// rata medie la `refill_rate` pachete/secunda pe termen lung.
//
// NOTA RUST - f64 pentru tokeni:
// Folosim `f64` (nu u64) deoarece refill-ul se calculeaza proportional cu
// timpul scurs. Exemplu: daca au trecut 0.5 secunde si rata e 1000/s,
// adaugam 500.0 tokeni. Cu u64 am pierde precizia fractiunilor.
//
// =============================================================================

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokeni adaugati per secunda
    last_refill: Instant,
    dropped_count: u64, // contor pachete dropate (pentru afisare periodica)
}

impl TokenBucket {
    /// Creeaza un nou TokenBucket cu bucket-ul plin.
    ///
    /// `rate` = pachete acceptate per secunda (refill rate).
    /// `burst` = capacitate maxima bucket (permite varfuri scurte).
    fn new(rate: u64, burst: u64) -> Self {
        Self {
            tokens: burst as f64,
            max_tokens: burst as f64,
            refill_rate: rate as f64,
            last_refill: Instant::now(),
            dropped_count: 0,
        }
    }

    /// Incearca sa consume un token (= accepta un pachet).
    ///
    /// Recalculeaza tokenii pe baza timpului scurs de la ultimul refill,
    /// apoi consuma 1 token. Returneaza `false` daca bucket-ul e gol.
    ///
    /// NOTA RUST - `Instant::elapsed()`:
    /// Returneaza `Duration` de la momentul creat pana la acum (monotonic clock).
    /// `.as_secs_f64()` converteste la secunde cu precizie sub-secunda.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        // Refill: adaugam tokeni proportional cu timpul scurs.
        // `.min(self.max_tokens)` impiedica depasirea capacitatii burst.
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            self.dropped_count += 1;
            false
        }
    }

    /// Returneaza si reseteaza contorul de pachete dropate.
    ///
    /// Folosit pentru afisarea periodica a statisticilor de rate limiting.
    /// `std::mem::replace` schimba valoarea si returneaza cea veche — atomic
    /// din perspectiva ownership-ului (nu avem nevoie de Mutex deoarece
    /// TokenBucket nu este partajat intre thread-uri).
    fn take_dropped_count(&mut self) -> u64 {
        std::mem::replace(&mut self.dropped_count, 0)
    }
}

/// Punctul de intrare al aplicatiei.
///
/// NOTA RUST: `-> anyhow::Result<()>`
///
/// In Rust, main() poate returna un Result. Daca returneaza Err,
/// programul se termina cu exit code 1 si printeaza eroarea.
/// `()` = unit type (echivalentul void - nicio valoare de returnat).
/// `anyhow::Result<()>` = fie Ok(()) fie Err(eroare_cu_context).
///
/// Operatorul `?` din functie propaga erorile automat catre apelant.
/// In main(), eroarea este printata pe stderr si procesul se opreste.
///
/// IP-ul expeditorului unei datagrame, in forma canonica.
///
/// Un listener dual-stack (`::`) primeste datagramele IPv4 de la adrese
/// IPv4-mapped (`::ffff:10.0.0.1`). Fara normalizare, acestea nu s-ar potrivi
/// cu `trusted_senders = ["10.0.0.1"]` si fiecare sursa ar avea doua
/// rate limitere distincte.
fn sender_ip(addr: std::net::SocketAddr) -> IpAddr {
    addr.ip().to_canonical()
}

/// Asteapta urmatorul semnal livrat pe canal.
///
/// Daca task-ul care asculta semnalul s-a oprit (canal inchis), `recv()` ar
/// intoarce `None` imediat la fiecare iteratie: SIGTERM ar opri procesul
/// fara motiv, iar SIGHUP ar reincarca config-ul in bucla. Un canal inchis
/// inseamna "niciun semnal de acum inainte", deci ramanem in asteptare.
async fn next_signal(receiver: &mut tokio::sync::mpsc::UnboundedReceiver<()>) {
    if receiver.recv().await.is_none() {
        std::future::pending::<()>().await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // =========================================================================
    // 1. INITIALIZARE TRACING (debug logging)
    // =========================================================================
    //
    // Tracing este configurat pentru logging INTERN (debug/erori).
    // Output-ul vizual catre utilizator este gestionat de modulul `display`.
    //
    // `RUST_LOG` controleaza nivelul:
    //   RUST_LOG=debug cargo run    -> vede debug + info + warn + error
    //   RUST_LOG=ids_rs=trace       -> vede tot, inclusiv trace
    //   (fara RUST_LOG)             -> doar warn + error (default)
    //
    // NOTA RUST: `unwrap_or_else` cu closure:
    // `.unwrap_or_else(|_| ...)` - daca Err, executa closure-ul.
    // `|_|` = closure cu un parametru pe care il ignoram (eroarea).
    // Closure-ul este evaluat LAZY - doar daca Err.
    //
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ids_rs=warn".parse().unwrap()),
        )
        .with_target(false)
        .init();

    // =========================================================================
    // 2. INCARCARE CONFIGURARE
    // =========================================================================
    //
    // NOTA RUST: `std::env::args()` returneaza un iterator peste argumentele
    // liniei de comanda. `.nth(1)` returneaza al doilea argument (index 0 = exe).
    // `.unwrap_or_else` ofera o valoare default daca nu exista argument.
    //
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    let mut config = AppConfig::load(&config_path)?;

    // =========================================================================
    // 3. BANNER DE START
    // =========================================================================
    let mut debug_mode = config.network.debug;
    display::print_banner(&config);

    if debug_mode {
        display::log_warning("Mod DEBUG activ - toate pachetele vor fi afisate");
    }

    // =========================================================================
    // 4. INITIALIZARE COMPONENTE
    // =========================================================================
    //
    // NOTA RUST - TRAIT OBJECTS si DYNAMIC DISPATCH:
    //
    // `parser` are tipul `Box<dyn LogParser>`:
    //   - Box: alocat pe heap (necesar pentru trait objects)
    //   - dyn LogParser: dispatch dinamic - tipul concret e rezolvat la runtime
    //
    // La fiecare apel `parser.parse(line)`, Rust consulta vtable-ul
    // (tabel de pointeri la functii) pentru a gasi implementarea corecta.
    // Cost: un nivel de indirectie (pointer dereference) per apel.
    // Alternativa (static dispatch cu generics) ar elimina acest cost
    // dar nu ar permite selectia parser-ului din config la runtime.
    //
    let parser = parser::create_parser(&config.network.parser)?;
    display::log_info(&format!("Parser activ: {}", parser.name()));

    // NOTA RUST - Arc (Atomic Reference Counting):
    //
    // `Arc::new(detector)` wraps Detector intr-un smart pointer thread-safe.
    // `Arc::clone(&detector)` creeaza o NOUA referinta catre ACELEASI date
    // (NU cloneaza Detector-ul! Doar incrementeaza contorul atomic).
    //
    // De ce Arc si nu Rc?
    //   - Rc: single-threaded (contor non-atomic, mai rapid)
    //   - Arc: multi-threaded (contor atomic, necesar cu tokio multi-thread)
    //
    // tokio cu "full" features foloseste un thread pool, deci task-urile
    // pot rula pe thread-uri diferite -> TREBUIE Arc, nu Rc.
    //
    // Parsam mapping-ul IP→hostname din config.toml.
    // Cheia in TOML este String (IP), o convertim la IpAddr pentru lookup rapid.
    // Validarea cheilor se face in config.rs::validate().
    /// Parseaza mapping-ul IP→hostname din config.toml.
    /// Functie separata pentru reutilizare la reload SIGHUP (#16).
    fn parse_hostnames(config: &AppConfig) -> HashMap<IpAddr, String> {
        config
            .network
            .hostnames
            .iter()
            .filter_map(|(ip_str, name)| ip_str.parse::<IpAddr>().ok().map(|ip| (ip, name.clone())))
            .collect()
    }

    fn parse_trusted_senders(config: &AppConfig) -> HashSet<IpAddr> {
        config
            .network
            .trusted_senders
            .iter()
            .filter_map(|ip| ip.parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical())
            .collect()
    }

    let hostnames = Arc::new(ArcSwap::from_pointee(parse_hostnames(&config)));
    let subnets = Arc::new(ArcSwap::from_pointee(SubnetEntry::parse_subnets(
        &config.network.subnets,
    )));
    let mut trusted_senders = parse_trusted_senders(&config);

    let detector = Arc::new(Detector::new(config.detection.clone()));
    let alerter = Arc::new(Alerter::new(
        config.alerting.clone(),
        config.detection.clone(),
        parse_hostnames(&config),
        SubnetEntry::parse_subnets(&config.network.subnets),
    )?);

    let (delivery, delivery_workers) =
        delivery::DeliveryManager::start(&config.alerting, Arc::clone(&alerter))?;

    display::log_info("Detector initializat (DashMap thread-safe)");

    // =========================================================================
    // 4b. ALERT BUFFER + WEB DASHBOARD (#25)
    // =========================================================================
    //
    // Buffer circular de alerte partajat intre main loop (producator) si
    // web server (consumator read-only). Arc<Mutex<VecDeque>> — lock-ul
    // este tinut doar cateva microsecunde per push/read.
    //
    // Buffer-ul este creat INTOTDEAUNA (chiar daca dashboard-ul e dezactivat)
    // pentru a permite activarea via SIGHUP fara pierdere de alerte.
    //
    let alert_buffer: web::AlertBuffer = Arc::new(Mutex::new(VecDeque::new()));

    if config.web_dashboard.enabled {
        let web_alerts = Arc::clone(&alert_buffer);
        match web::start_web_server(&config.web_dashboard, web_alerts).await {
            Ok(_handle) => {}
            Err(e) => {
                display::log_warning(&format!("Web dashboard nu a pornit: {:#}", e));
            }
        }
    }

    // =========================================================================
    // 5. TASK CLEANUP PERIODIC (Background Async Task)
    // =========================================================================
    //
    // NOTA RUST - tokio::spawn si MOVE CLOSURES:
    //
    // `tokio::spawn(async move { ... })` lanseaza un task async independent.
    // Task-ul ruleaza concurent cu main loop-ul, pe thread pool-ul tokio.
    //
    // `move` in fata closure-ului TRANSFERA ownership-ul variabilelor
    // capturate IN closure. Fara `move`, closure-ul ar incerca sa
    // imprumute (&) variabilele - dar task-ul spawn-at poate supravietui
    // scope-ului curent, deci compilatorul cere ownership explicit.
    //
    // `Arc::clone()` INAINTE de `move` creeaza o referinta separata.
    // Dupa `move`, cleanup_detector este MUTAT in closure (owned de task).
    // `detector` original ramane valid (Arc separat) pentru main loop.
    //
    let cleanup_detector = Arc::clone(&detector);
    let cleanup_interval = config.cleanup.interval_secs;
    let max_age = config.cleanup.max_entry_age_secs;

    tokio::spawn(async move {
        // NOTA RUST: `tokio::time::interval()` face primul tick IMEDIAT la creare,
        // ceea ce ar rula un cleanup inutil la startup (cand memoria e goala).
        // Folosim `sleep` intr-un loop simplu: asteapta intai, curata dupa.
        // Pattern: sleep-first loop garanteaza ca primul cleanup are loc abia
        // dupa `cleanup_interval` secunde de la pornire.
        loop {
            tokio::time::sleep(Duration::from_secs(cleanup_interval)).await;

            let tracked_before = cleanup_detector.tracked_ips();
            cleanup_detector.cleanup(Duration::from_secs(max_age));
            let tracked_after = cleanup_detector.tracked_ips();

            let cleaned = tracked_before.saturating_sub(tracked_after);
            if tracked_after > 0 || cleaned > 0 {
                display::log_stats(tracked_after, cleaned);
            }
        }
    });

    // =========================================================================
    // 6. BIND SOCKET UDP
    // =========================================================================
    //
    // NOTA RUST - ASYNC BINDING:
    //
    // `UdpSocket::bind(addr).await?` este o operatie async care:
    //   1. Cere OS-ului sa creeze un socket UDP
    //   2. Il leaga (bind) de adresa/portul specificat
    //   3. Returneaza Result<UdpSocket, Error>
    //
    // `?` propaga eroarea daca bind esueaza (ex: port deja ocupat).
    // Eroarea include automat context din anyhow.
    //
    let bind_addr = format!(
        "{}:{}",
        config.network.listen_address, config.network.listen_port
    );
    let socket = UdpSocket::bind(&bind_addr).await?;
    display::log_info(&format!("Ascult pe UDP {}", bind_addr));
    display::log_info("Astept log-uri de la firewall... (Ctrl+C pentru oprire)");
    display::print_separator();

    // =========================================================================
    // 7. RATE LIMITER (Token Bucket, optional)
    // =========================================================================
    //
    // Daca `udp_rate_limit > 0`, cream un TokenBucket care limiteaza
    // numarul de pachete procesate per secunda. Daca `udp_rate_limit == 0`,
    // rate limiter-ul este dezactivat (backward compatible).
    //
    // NOTA RUST - Option<T>:
    // `Option<TokenBucket>` = fie `Some(bucket)` fie `None`.
    // Folosim `if let Some(ref mut limiter) = rate_limiter` in loop
    // pentru a accesa bucket-ul doar cand exista.
    //
    let mut rate_limiter: Option<TokenBucket> = if config.network.udp_rate_limit > 0 {
        display::log_info(&format!(
            "Rate limiting UDP activ: {} pachete/s, burst {}",
            config.network.udp_rate_limit, config.network.udp_burst_size
        ));
        Some(TokenBucket::new(
            config.network.udp_rate_limit,
            config.network.udp_burst_size,
        ))
    } else {
        None
    };
    let mut sender_rate_limiters: HashMap<IpAddr, TokenBucket> = HashMap::new();

    // Interval pentru afisarea periodica a statisticilor de rate limiting.
    // Folosim `tokio::time::interval` cu 30 secunde — suficient de rar
    // pentru a nu polua output-ul, dar suficient de des pentru vizibilitate.
    let mut rate_limit_tick = tokio::time::interval(Duration::from_secs(30));
    // Primul tick al `interval()` e imediat — il consumam ca sa nu afisam
    // statistici goale la startup.
    rate_limit_tick.tick().await;
    let mut framing_dropped: u64 = 0;

    // =========================================================================
    // 8. SIGNAL HANDLERS — SIGHUP (Hot Reload #16) si SIGTERM (Graceful Shutdown)
    // =========================================================================
    //
    // NOTA RUST — UNIX SIGNALS cu tokio:
    //
    // `tokio::signal::unix::signal(SignalKind::...)` creeaza un stream
    // async care produce un eveniment la fiecare semnal primit.
    // `.recv().await` suspenda executia pana la urmatorul semnal.
    //
    // SIGHUP (Signal Hangup) — conventia UNIX pentru reload config:
    //   kill -HUP <pid>    sau    systemctl reload ids-rs
    //
    // La primirea SIGHUP-ului:
    //   1. Re-citim config.toml (validate() inclus)
    //   2. Comparam listen_port/address/parser — daca difera, warning + skip
    //   3. Aplicam noile valori la detector, alerter, hostnames, rate limiter
    //   4. Starea de detectie (DashMap-urile) ramane INTACTA
    //
    // SIGTERM (Signal Terminate) — semnalul standard de oprire trimis de:
    //   kill <pid>    sau    systemctl stop ids-rs
    //
    // Fara handler explicit, OS-ul termina procesul imediat, potential
    // intrerupand o trimitere SMTP in curs. Cu handler, loop-ul se termina
    // la fel ca la Ctrl+C: alerta in curs de trimitere (.await activ) se
    // finalizeaza complet inainte de iesire — nu se pierde nicio alerta.
    //
    let (sighup_tx, mut sighup_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let (sigterm_tx, mut sigterm_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    // Inregistrarea handler-elor se face aici, cu `?`: daca esueaza, procesul
    // nu porneste, in loc sa ruleze fara SIGTERM/SIGHUP functionale.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut hangup = signal(SignalKind::hangup())
            .map_err(|e| anyhow::anyhow!("Nu pot inregistra handler-ul SIGHUP: {e}"))?;
        let mut terminate = signal(SignalKind::terminate())
            .map_err(|e| anyhow::anyhow!("Nu pot inregistra handler-ul SIGTERM: {e}"))?;
        tokio::spawn(async move {
            while hangup.recv().await.is_some() {
                let _ = sighup_tx.send(());
            }
        });
        tokio::spawn(async move {
            while terminate.recv().await.is_some() {
                let _ = sigterm_tx.send(());
            }
        });
    }
    // On non-Unix platforms the senders keep these branches pending while
    // Ctrl+C remains available as the portable shutdown mechanism.
    #[cfg(not(unix))]
    let (_sighup_guard, _sigterm_guard) = (sighup_tx, sigterm_tx);

    // =========================================================================
    // 9. MAIN LOOP - Receptie si Procesare Log-uri
    // =========================================================================
    //
    // NOTA RUST - BUFFER pe STACK:
    //
    // `[0u8; 65535]` aloca un array de 65535 bytes pe STACK (nu heap).
    // 65535 = dimensiunea maxima a unui pachet UDP.
    // Tipul: [u8; 65535] = array de bytes cu dimensiune fixa la compilare.
    //
    // `mut` deoarece `recv_from` va scrie in buffer (il modifica).
    //
    let mut buf = [0u8; 65535];

    loop {
        // NOTA RUST - tokio::select!:
        //
        // `select!` asteapta pe AMBELE branch-uri simultan:
        //   1. `socket.recv_from()` - asteapta un pachet UDP
        //   2. `tokio::signal::ctrl_c()` - asteapta Ctrl+C
        //
        // Cand unul se completeaza, celalalt este ANULAT (cancelled).
        // Anularea in Rust este SAFE - nu exista resurse nesalvate deoarece
        // Drop trait-ul curata automat (RAII).
        //
        // `biased;` = evalueaza branch-urile in ordine (nu random).
        // Primul match care e gata castiga. Folosim biased pentru
        // determinism - Ctrl+C are prioritate (evaluat primul).
        //
        tokio::select! {
            biased;

            // Branch: Oprire gratiosa la Ctrl+C (SIGINT).
            _ = tokio::signal::ctrl_c() => {
                println!();
                display::log_info("Oprire gratiosa... La revedere!");
                break;
            }

            // Branch: Oprire gratiosa la SIGTERM.
            //
            // SIGTERM este semnalul standard trimis de `kill <pid>` si
            // `systemctl stop ids-rs`. Fara acest handler, OS-ul ar termina
            // procesul imediat, intrerupand potential o trimitere SMTP activa.
            //
            // Cu `biased;`, acest branch este evaluat dupa Ctrl+C dar inainte
            // de SIGHUP si recv_from. Alerta curenta (daca send_alert este in
            // curs de .await) se finalizeaza complet — select! verifica
            // semnalele doar la urmatoarea iteratie a loop-ului.
            _ = next_signal(&mut sigterm_rx) => {
                display::log_info("SIGTERM primit — oprire gratiosa...");
                break;
            }

            // Branch: Hot reload config la SIGHUP (#16).
            _ = next_signal(&mut sighup_rx) => {
                display::log_reload("SIGHUP primit — reincarc config.toml...");
                match AppConfig::load(&config_path)
                    .and_then(|loaded| loaded.prepare_reload(&config))
                {
                    Ok((new_config, warnings)) => {
                        // Campurile care necesita restart au fost fixate la
                        // valorile curente, iar rezultatul a fost revalidat.
                        for warning in &warnings {
                            display::log_warning(&format!("SIGHUP: {warning}"));
                        }

                        // Aplicam noile valori la componentele reincarcabile.
                        debug_mode = new_config.network.debug;
                        let trusted_senders_changed =
                            new_config.network.trusted_senders != config.network.trusted_senders;
                        trusted_senders = parse_trusted_senders(&new_config);

                        // Detector: praguri, cooldown, whitelist.
                        detector.update_config(new_config.detection.clone());

                        // Alerter: SIEM, email, hostnames, subnets.
                        let new_hostnames = parse_hostnames(&new_config);
                        let new_subnets = SubnetEntry::parse_subnets(&new_config.network.subnets);
                        alerter.update_config(
                            new_config.alerting.clone(),
                            new_config.detection.clone(),
                            new_hostnames.clone(),
                            new_subnets.clone(),
                        );

                        // Hostnames si subnets partajate (folosite in main loop pentru display).
                        hostnames.store(Arc::new(new_hostnames));
                        subnets.store(Arc::new(new_subnets));

                        // Rate limiter: recream daca s-a schimbat.
                        if new_config.network.udp_rate_limit != config.network.udp_rate_limit
                            || new_config.network.udp_burst_size != config.network.udp_burst_size
                        {
                            rate_limiter = if new_config.network.udp_rate_limit > 0 {
                                display::log_reload(&format!(
                                    "Rate limiting UDP: {} pachete/s, burst {}",
                                    new_config.network.udp_rate_limit,
                                    new_config.network.udp_burst_size
                                ));
                                Some(TokenBucket::new(
                                    new_config.network.udp_rate_limit,
                                    new_config.network.udp_burst_size,
                                ))
                            } else {
                                display::log_reload("Rate limiting UDP dezactivat");
                                None
                            };
                        }
                        if trusted_senders_changed
                            || new_config.network.per_sender_limits()
                                != config.network.per_sender_limits()
                        {
                            sender_rate_limiters.clear();
                            display::log_reload(&format!(
                                "Rate limiting per sender: {} evenimente/s, burst {}",
                                new_config.network.per_sender_limits().0,
                                new_config.network.per_sender_limits().1
                            ));
                        }

                        // Salvam config-ul nou pentru comparatii viitoare la urmatorul SIGHUP.
                        config = new_config;

                        display::log_reload("Config reincarcat cu succes");
                    }
                    Err(e) => {
                        display::log_warning(&format!(
                            "SIGHUP: reload esuat, pastrez config-ul vechi: {:#}", e
                        ));
                    }
                }
            }

            // Branch: Afisare periodica statistici rate limiting (la fiecare 30s).
            _ = rate_limit_tick.tick() => {
                if let Some(ref mut limiter) = rate_limiter {
                    let dropped = limiter.take_dropped_count();
                    if dropped > 0 {
                        display::log_rate_limited(dropped);
                    }
                }
                if framing_dropped > 0 {
                    display::log_warning(&format!(
                        "{} evenimente UDP respinse de limitele de framing/sursa",
                        std::mem::take(&mut framing_dropped)
                    ));
                }
            }

            // Branch: Pachet UDP primit.
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        let sender = sender_ip(addr);
                        if !trusted_senders.is_empty() && !trusted_senders.contains(&sender) {
                            framing_dropped = framing_dropped.saturating_add(1);
                            continue;
                        }

                        // NOTA RUST - String::from_utf8_lossy:
                        //
                        // Converteste bytes in text UTF-8.
                        // "lossy" = caracterele invalide sunt inlocuite cu
                        // U+FFFD (replacement character) in loc sa returneze
                        // eroare. Sigur pentru log-uri care pot contine
                        // caractere non-UTF8.
                        //
                        // Returneaza Cow<str> (Copy on Write):
                        //   - Daca datele sunt UTF-8 valid: returneaza &str (zero-copy)
                        //   - Daca au caractere invalide: aloca un String nou
                        //
                        let data = String::from_utf8_lossy(&buf[..len]);

                        // GESTIONARE BUFFER COALESCING:
                        //
                        // Mai multe log-uri pot ajunge intr-un singur pachet UDP
                        // (lipite). Le separam pe newline-uri.
                        // `.lines()` returneaza un iterator care produce &str
                        // pentru fiecare linie, ignorand delimitatorii (\n, \r\n).
                        //
                        for (line_index, line) in data.lines().enumerate() {
                            if line_index >= config.network.max_lines_per_datagram {
                                framing_dropped = framing_dropped.saturating_add(1);
                                continue;
                            }
                            // `.trim()` returneaza un &str fara spatii la inceput/sfarsit.
                            // Nu aloca memorie noua - returneaza un sub-slice.
                            let line = line.trim();
                            if line.is_empty() {
                                continue;
                            }
                            if line.len() > config.network.max_line_length {
                                framing_dropped = framing_dropped.saturating_add(1);
                                continue;
                            }
                            // The token budget is charged per logical event, not per
                            // datagram, so newline coalescing cannot bypass the limit.
                            let (per_sender_rate, per_sender_burst) =
                                config.network.per_sender_limits();
                            if per_sender_rate > 0 {
                                let sender_limiter = sender_rate_limiters
                                    .entry(sender)
                                    .or_insert_with(|| {
                                        TokenBucket::new(
                                            per_sender_rate,
                                            per_sender_burst,
                                        )
                                    });
                                if !sender_limiter.try_consume() {
                                    framing_dropped = framing_dropped.saturating_add(1);
                                    continue;
                                }
                            }
                            if let Some(ref mut limiter) = rate_limiter {
                                if !limiter.try_consume() {
                                    continue;
                                }
                            }

                            // Debug: afiseaza linia raw primita.
                            if debug_mode {
                                display::log_debug_raw(line);
                            }

                            // Parsam linia cu parser-ul activ (dynamic dispatch).
                            if let Some(event) = parser.parse(line) {
                                // Debug: afiseaza campurile extrase.
                                if debug_mode {
                                    display::log_debug_parse_ok(&event);
                                }

                                // Afisam evenimentul in terminal cu badge dinamic
                                // (albastru = drop, verde = accept).
                                if config.network.log_events {
                                    display::log_firewall_event(
                                        &event.source_ip,
                                        event.dest_port,
                                        &event.protocol,
                                        event.action,
                                        &hostnames.load(),
                                        &subnets.load(),
                                    );
                                }

                                // Pastram log-ul original la nivel debug pentru audit/troubleshooting.
                                tracing::debug!(raw = %event.raw_log, "Log original");

                                // Procesam evenimentul in detector.
                                let alerts = detector.process_event(&event);

                                // Procesam alertele generate (daca exista).
                                for alert in alerts {
                                    // Afisam alerta in terminal (colorat, cu hostname-uri).
                                    display::log_alert(&alert, &hostnames.load(), &subnets.load());

                                    // Adaugam alerta in buffer-ul web dashboard (#25).
                                    // Lock tinut doar cateva microsecunde — eliberat inainte de .await.
                                    {
                                        let mut buf = alert_buffer.lock()
                                            .unwrap_or_else(|e: std::sync::PoisonError<_>| e.into_inner());
                                        buf.push_back(alert.clone());
                                        let max = config.web_dashboard.max_alerts;
                                        while buf.len() > max {
                                            buf.pop_front();
                                        }
                                    }

                                    // SIEM and email have independent bounded queues.
                                    // Saturation/failure is persisted to the durable spool.
                                    delivery.enqueue(&alert);
                                }
                            } else if debug_mode {
                                // Debug: afiseaza detalii despre esecul parsarii.
                                display::log_debug_parse_fail(
                                    line,
                                    parser.name(),
                                    parser.expected_format(),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // Erorile de receptie UDP sunt de obicei tranzitorii.
                        // Le logam ca warning si continuam - nu oprim procesul.
                        display::log_warning(&format!("Eroare receptie UDP: {}", e));
                    }
                }
            }
        }
    }

    // Workerii salveaza in spool alertele inca nelivrate si se opresc.
    delivery.shutdown();
    for worker in delivery_workers {
        if tokio::time::timeout(Duration::from_secs(10), worker)
            .await
            .is_err()
        {
            display::log_error(
                "Timeout la oprirea unui worker de livrare; alertele din coada sale pot fi pierdute",
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{next_signal, sender_ip};
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    #[test]
    fn ipv4_mapped_sender_matches_plain_ipv4() {
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:514".parse().unwrap();
        assert_eq!(sender_ip(mapped), "10.0.0.1".parse::<IpAddr>().unwrap());

        let native: SocketAddr = "[2001:db8::1]:514".parse().unwrap();
        assert_eq!(sender_ip(native), "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn closed_signal_channel_never_fires() {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<()>();
        drop(sender);
        let fired =
            tokio::time::timeout(Duration::from_millis(50), next_signal(&mut receiver)).await;
        assert!(fired.is_err());
    }

    #[tokio::test]
    async fn delivered_signal_fires() {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<()>();
        sender.send(()).unwrap();
        tokio::time::timeout(Duration::from_millis(50), next_signal(&mut receiver))
            .await
            .unwrap();
    }
}
