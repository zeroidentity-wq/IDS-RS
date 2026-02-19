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

mod alerter;
mod config;
mod detector;
mod display;
mod parser;

use alerter::Alerter;
use config::AppConfig;
use detector::Detector;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

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

    let config = AppConfig::load(&config_path)?;

    // =========================================================================
    // 3. BANNER DE START
    // =========================================================================
    let debug_mode = config.network.debug;
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
    let detector = Arc::new(Detector::new(config.detection.clone()));
    let alerter = Arc::new(Alerter::new(config.alerting.clone(), config.detection.clone()));

    display::log_info("Detector initializat (DashMap thread-safe)");

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
    // 7. MAIN LOOP - Receptie si Procesare Log-uri
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

            // Branch: Oprire gratiosa la Ctrl+C.
            _ = tokio::signal::ctrl_c() => {
                println!();
                display::log_info("Oprire gratiosa... La revedere!");
                break;
            }

            // Branch: Pachet UDP primit.
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, _addr)) => {
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
                        for line in data.lines() {
                            // `.trim()` returneaza un &str fara spatii la inceput/sfarsit.
                            // Nu aloca memorie noua - returneaza un sub-slice.
                            let line = line.trim();
                            if line.is_empty() {
                                continue;
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

                                // Afisam evenimentul de drop in terminal (albastru subtil).
                                display::log_drop_event(
                                    &event.source_ip,
                                    event.dest_port,
                                    &event.protocol,
                                    &event.action,
                                );

                                // Pastram log-ul original la nivel debug pentru audit/troubleshooting.
                                tracing::debug!(raw = %event.raw_log, "Log original");

                                // Procesam evenimentul in detector.
                                let alerts = detector.process_event(&event);

                                // Procesam alertele generate (daca exista).
                                for alert in alerts {
                                    // Afisam alerta in terminal (colorat).
                                    display::log_alert(&alert);

                                    // Trimitem alerta catre SIEM si email (async).
                                    alerter.send_alert(&alert).await;
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

    Ok(())
}
