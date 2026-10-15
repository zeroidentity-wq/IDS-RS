# IDS-RS — Detecție comportamentală din log-urile de firewall, cu alertare în ArcSight
## Cuprins

1. [Introducere](#1-pe-scurt)
2. [De ce un motor separat de ArcSight?](#2-de-ce-un-motor-separat-de-arcsight)
3. [Arhitectura și fluxul log-urilor](#3-arhitectura-și-fluxul-log-urilor)
4. [Formatele de log — anatomie](#4-formatele-de-log--anatomie)
5. [Călătoria unui eveniment, pas cu pas](#5-călătoria-unui-eveniment-pas-cu-pas)
6. [Logica de detecție](#6-logica-de-detecție)
7. [Ce furnizează IDS-RS](#7-ce-furnizează-ids-rs)
8. [Integrarea cu ArcSight](#8-integrarea-cu-arcsight)
9. [Instalare, rulare și configurare](#9-instalare-rulare-și-configurare)
10. [Limitări cunoscute](#10-limitări-cunoscute)
11. [Potențial de alertări viitoare în SIEM](#11-potențial-de-alertări-viitoare-în-siem)
12. [Întrebări frecvente](#12-întrebări-frecvente)

---

## 1. Introducere

**IDS-RS** este un serviciu (un singur binar, fără bază de date, fără dependențe externe la
rulare) care:

1. **primește** prin UDP log-urile de firewall Checkpoint (direct sau trimise mai departe de ArcSight);
2. **ține în memorie**, pe ferestre de timp glisante, cine cu cine vorbește, pe ce porturi și cu ce
   rezultat (Drop / Accept);
3. **detectează comportamente** pe care o singură linie de log nu le poate arăta: scanări de porturi,
   mișcare laterală, scanări distribuite și beaconing C2;
4. **trimite alerta** înapoi în **ArcSight ca eveniment CEF**, pe **email** (HTML) și într-un
   **dashboard web** local.

| Detecție | Ce înseamnă | Signature ID (CEF) | Severitate CEF | Activă implicit |
|---|---|---|---|---|
| **Fast Scan** | O sursă lovește multe porturi **blocate** pe aceeași țintă, foarte repede | `1001` | 7 (High) | da |
| **Slow Scan** | La fel, dar întins pe minute (scanare „stealth”) | `1002` | 6 (Medium) | da |
| **Accept Scan** | O sursă accesează multe porturi **permise** pe aceeași țintă (enumerare de servicii deschise) | `1003` | 5 (Medium) | da |
| **Lateral Movement** | O sursă se conectează cu succes la multe destinații diferite | `1004` | 8 (High) | nu |
| **Distributed Scan** | Multe surse diferite lovesc aceeași țintă | `1005` | 7 (High) | nu |
| **Beaconing C2** | Conexiuni acceptate, la intervale aproape constante, pe același flux src→dst:port | `1006` | 9 (Very High) | nu |

Detecțiile marcate „nu” se activează din `config.toml` (`enabled = true`). Sunt dezactivate
implicit pentru că au nevoie de un minim de tuning (whitelist, excepții) pe rețeaua reală.

---

## 2. De ce un motor separat de ArcSight?

Toate aceste detecții se pot face, teoretic, și cu reguli de corelare în ArcSight ESM.
În practică însă:

| Problemă în SIEM | Cum o rezolvă IDS-RS |
|---|---|
| Regulile de tip „N porturi **distincte** de la aceeași sursă în X secunde” sunt scumpe (aggregate pe câmpuri distincte, active lists mari). | Numărarea se face în memorie, pe structuri dedicate, la volumul de log-uri al firewall-ului. |
| Fiecare tip de detecție are nevoie de reguli diferite, cu agregări diferite (per sursă, per țintă, per flux). | Un singur motor, șase detecții, un singur format de ieșire. |
| Beaconing-ul (regularitatea intervalelor) este greu sau imposibil de exprimat într-o regulă de corelare clasică. | IDS-RS calculează direct media și coeficientul de variație al intervalelor. |
| Volumul mare de evenimente Drop/Accept încarcă ESM-ul. | ESM-ul primește **doar alertele**: câteva evenimente agregate, nu milioane de linii. |
| Alertele pe email din SIEM cer configurări suplimentare. | IDS-RS trimite direct email HTML, cu toate detaliile. |

Pe scurt: **IDS-RS face agregarea comportamentală, iar ArcSight face ce face cel mai bine**:
stocare, corelare de nivel înalt, case management, raportare.

---

## 3. Arhitectura și fluxul log-urilor

### 3.1 Diagrama arhitecturii

```
  Firewall / ArcSight
  (syslog pe UDP)
         │
         ▼
┌──────────────────────────────────────────┐
│ 1. RECEPȚIE  — UDP :5555                 │
│    trusted_senders, rate limit,          │
│    o datagramă → mai multe linii         │
└────────────────────┬─────────────────────┘
                     ▼
┌──────────────────────────────────────────┐
│ 2. PARSER  (unul, ales din config)       │
│    gaia  |  cef  |  gaia_cef             │
│    → src, dst, port, proto, acțiune      │
│    (doar Drop / Accept)                  │
└────────────────────┬─────────────────────┘
                     ▼
┌──────────────────────────────────────────┐
│ 3. DETECTOR  (stare în memorie)          │
│    Fast · Slow · Accept   per (src,dst)  │
│    Lateral Movement       per src        │
│    Distributed Scan       per dst        │
│    Beaconing C2           per src,dst,port│
│    + whitelist, excepții, cooldown       │
└────────────────────┬─────────────────────┘
                     │  alertă?
     ┌───────────────┼────────────────┬──────────────────┐
     ▼               ▼                ▼                  ▼
┌──────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Consolă  │  │ Dashboard web│  │ Coadă SIEM   │  │ Coadă Email  │
│ (colorat)│  │ (HTTP :8080) │  │ → ArcSight   │  │ → SMTP       │
└──────────┘  └──────────────┘  │   CEF/UDP 514│  │   HTML       │
                                └──────┬───────┘  └──────┬───────┘
                                       └── spool pe disc + retry + dead-letter ──┘

  În fundal: cleanup periodic — șterge din memorie datele ieșite din fereastra fiecărei
  detecții (dar nu mai devreme de max_entry_age_secs).
```

**Pe scurt, fluxul de date:**

1. Firewall-ul (direct sau prin ArcSight) trimite log-uri pe UDP, la portul configurat (implicit `5555`).
2. IDS-RS acceptă datagrame doar de la expeditorii din `trusted_senders`, aplică rate limiting și
   împarte fiecare datagramă pe linii.
3. Fiecare linie este citită de parserul activ, care extrage sursa, destinația, portul, protocolul
   și acțiunea. Liniile care nu sunt Drop sau Accept sunt ignorate.
4. Evenimentul intră în detector, care actualizează contoarele pentru toate detecțiile active.
5. Dacă un prag este depășit, se generează o alertă: apare în consolă și în dashboard și este pusă
   în cozile către ArcSight și email.
6. Dacă livrarea eșuează, alerta se salvează pe disc (spool) și se reîncearcă automat. Alertele
   care nu pot fi livrate niciodată ajung într-un director separat (dead-letter), ca să nu le
   blocheze pe celelalte.
7. Un task de cleanup șterge periodic datele vechi din memorie.

### 3.2 Scenariile de integrare

#### Scenariul A — Prin ArcSight, cu blob-ul LEA (parser `gaia_cef`) — recomandat

```
┌────────────┐  syslog   ┌──────────────────────┐  CEF / UDP 5555   ┌──────────────┐
│ Checkpoint │ ────────► │ ArcSight             │ ────────────────► │   IDS-RS     │
│  Gaia FW   │           │ SmartConnector /     │ (doar evenimente  │ parser =     │
└────────────┘           │ Logger (forwarding)  │  de firewall)     │ "gaia_cef"   │
                         └──────────────────────┘                   └──────┬───────┘
                                    ▲                                      │
                                    │  CEF / UDP 514 (alerte 1001–1006)    │
                                    └──────────────────────────────────────┘
```

ArcSight primește deja log-urile de la Checkpoint; adăugați o **destinație suplimentară**
(forwarding CEF Syslog/UDP) către IDS-RS. Parserul `gaia_cef` găsește blob-ul LEA original al
Checkpoint oriunde l-a pus ArcSight în mesajul CEF (vezi [4.3](#43-formatul-gaia-cef-blob-lea-în-cef--parser-gaia_cef)).

#### Scenariul B — Prin ArcSight, cu CEF normalizat (parser `cef`)

Același drum ca la A, dar connector-ul trimite evenimente CEF **normalizate**, cu câmpurile
standard `src`, `dst`, `dpt`, `act` în extensii. Folosiți acest parser dacă blob-ul LEA nu
ajunge în mesaj.

#### Scenariul C — Direct de la firewall (parser `gaia`)

```
┌────────────┐   syslog Gaia, UDP :5555   ┌──────────────┐
│ Checkpoint │ ─────────────────────────► │   IDS-RS     │ ──► ArcSight (alerte), Email
│  Gaia FW   │                            │ parser="gaia"│
└────────────┘                            └──────────────┘
```

Fără intermediar, deci fără latența introdusă de ArcSight (vezi [Limitări](#10-limitări-cunoscute)),
dar firewall-ul trebuie să trimită un flux de syslog suplimentar.

#### Cum alegeți

| Situație | Parser |
|---|---|
| ArcSight trimite mai departe evenimentele Checkpoint, iar blob-ul LEA (`action="Drop" src="…"`) apare în mesaj | `gaia_cef` |
| ArcSight trimite CEF normalizat, cu `src=… dst=… dpt=… act=…` | `cef` |
| Firewall-ul trimite direct către IDS-RS | `gaia` |
| Nu sunteți siguri | Porniți cu `network.debug = true` și vedeți ce parser reușește (vezi [9.5](#95-modul-debug--verificarea-parsării)) |

Un singur proces IDS-RS folosește **un singur parser**. Pentru surse în formate diferite se rulează
instanțe separate, pe porturi diferite.

> **Atenție la bucle:** filtrați forwarding-ul către IDS-RS astfel încât să plece **doar
> evenimentele de firewall** (de ex. `deviceVendor = Check Point`), nu și alertele IDS-RS
> care intră în același connector. IDS-RS ar ignora oricum propriile alerte (nu au `Drop`/`Accept`),
> dar ar consuma inutil din bugetul de rate limiting.

### 3.3 Ce ajunge efectiv pe portul 5555

O datagramă UDP poate conține **una sau mai multe linii** de log, separate prin newline
(connector-ele și relay-urile syslog grupează adesea mesajele):

```
Datagrama #1  →  <134>Oct 13 14:02:11 gw CEF:0|…|action="Drop" src="10.20.5.17" dst="10.0.0.1" service="21" proto="6"|5|

Datagrama #2  →  <134>Oct 13 14:02:11 gw CEF:0|…|action="Drop" src="10.20.5.17" dst="10.0.0.1" service="22" proto="6"|5|
                 <134>Oct 13 14:02:11 gw CEF:0|…|action="Accept" src="10.0.3.8" dst="10.0.1.10" service="443" proto="6"|5|
```

IDS-RS desparte datagrama pe linii și tratează fiecare linie independent. Limitele de protecție:
maximum `max_lines_per_datagram` linii (implicit 256), fiecare de maximum `max_line_length` octeți
(implicit 16 KB). Ce depășește limitele este numărat și raportat în consolă la fiecare 30 de secunde.

---

## 4. Formatele de log — anatomie

Indiferent de format, IDS-RS extrage **doar cinci câmpuri**:

| Câmp | `gaia` | `cef` | `gaia_cef` (LEA) | Obligatoriu |
|---|---|---|---|---|
| IP sursă | `src:` | `src=` | `src="…"` | da |
| IP destinație | `dst:` | `dst=` | `dst="…"` | practic da (fără el, linia nu contribuie la nicio detecție) |
| Port destinație | `service:` | `dpt=` | `service="…"` | da (fără port, de ex. ICMP, linia e ignorată) |
| Protocol | `proto:` | `proto=` | `proto="6/17/1"` | nu (informativ) |
| Acțiune | cuvântul după data Checkpoint | `act=` | `action="…"` | da |

- Contează **doar `Drop` și `Accept`** (fără diferență între litere mari și mici). `Reject`, `Log`,
  `Encrypt` etc. sunt ignorate.
- Sunt suportate IPv4 și IPv6.
- Restul câmpurilor (regulă, interfață, user etc.) nu sunt folosite, iar linia originală nu este
  retransmisă în alertă.

### 4.1 Formatul Checkpoint Gaia (syslog brut) — parser `gaia`

```
Sep  3 15:12:20 192.168.99.1 Checkpoint: 3Sep2007 15:12:08 drop 192.168.11.7 >eth8 rule: 113; src: 192.168.11.34; dst: 4.23.34.126; proto: tcp; service: 80; s_port: 2854;
```

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         UN RÂND DE LOG GAIA                             │
├───────────────────┬──────────────┬──────────────────────────────────────┤
│   HEADER SYSLOG   │              │         CORPUL CHECKPOINT            │
│  (adăugat de      │              │   (generat de firewall)              │
│   syslog daemon)  │              │                                      │
├───────────────────┤              ├──────────┬──────────┬────┬───────────┤
│ Sep  3 15:12:20   │ 192.168.99.1 │ 3Sep2007 │ 15:12:08 │drop│ src: …    │
│ (când a PRIMIT    │ (cine a      │ (când a  │          │    │ dst: …    │
│  serverul log-ul) │  trimis)     │  GENERAT │          │    │ service:  │
│                   │              │  fw-ul)  │          │    │ 80        │
└───────────────────┴──────────────┴──────────┴──────────┴────┴───────────┘
```

- **Cele două timestamp-uri diferă intenționat:** header-ul syslog (`15:12:20`) este momentul
  în care serverul de logging a *primit* mesajul; timestamp-ul Checkpoint (`15:12:08`) este momentul
  în care firewall-ul a *generat* evenimentul. Diferența reprezintă latența de rețea și buffering-ul.
  IDS-RS nu folosește niciunul dintre ele, ci momentul în care primește linia (vezi
  [Limitări](#10-limitări-cunoscute)).
- **`3Sep2007`** este formatul compact al Checkpoint: zi + lună abreviată + an, fără separatori.
- Acțiunea (`drop`) este cuvântul de după data și ora Checkpoint.
- Câmpurile de după acțiune sunt perechi `cheie: valoare;`:

| Câmp | Exemplu | Semnificație |
|---|---|---|
| `src` | `192.168.11.34` | IP-ul care a inițiat conexiunea |
| `dst` | `4.23.34.126` | IP-ul destinație |
| `proto` | `tcp` | protocolul |
| `service` | `80` | portul destinație (cel scanat) |
| `s_port` | `2854` | portul sursă (ales aleator de sistemul de operare; nefolosit) |

### 4.2 Formatul CEF (Common Event Format) — parser `cef`

CEF a fost creat de ArcSight pentru a standardiza log-urile de la producători diferiți
(Checkpoint, Cisco, Palo Alto etc.) într-un format unic. Structura este fixă, cu `|` ca separator:

```
<prefix syslog> CEF:Versiune|Vendor|Produs|VersiuneProdus|SignatureID|Nume|Severitate|Extensii
```

```
<134>Feb 17 11:32:44 gw-checkpoint CEF:0|CheckPoint|VPN-1 & FireWall-1|R81.20|100|Drop|5|src=192.168.11.34 dst=4.23.34.126 dpt=80 proto=TCP act=drop
```

```
<134>              → prioritate syslog (facility 16 = local0, severity 6 = info)
Feb 17 11:32:44    → timestamp syslog
gw-checkpoint      → hostname-ul dispozitivului
CEF:0              → versiunea formatului
CheckPoint         → vendor
VPN-1 & FireWall-1 → produs
R81.20             → versiunea produsului
100                → ID-ul evenimentului
Drop               → numele evenimentului
5                  → severitatea (0 = scăzută … 10 = critică)
extensii (cheie=valoare, separate prin spațiu):
  src=192.168.11.34   → IP sursă
  dst=4.23.34.126     → IP destinație
  dpt=80              → portul destinație
  proto=TCP           → protocolul
  act=drop            → acțiunea firewall-ului   ← IDS-RS decide pe baza acestui câmp
```

IDS-RS caută `CEF:` oriunde în linie (prefixul syslog poate lipsi sau varia), apoi citește
extensiile `src`, `dst`, `dpt`, `proto`, `act`.

### 4.3 Formatul Gaia-CEF (blob LEA în CEF) — parser `gaia_cef`

Unele integrări Checkpoint → ArcSight (în special cele vechi, LEA) nu mapează câmpurile în
extensiile CEF standard, ci păstrează **blob-ul LEA original** (perechi `cheie="valoare"`) într-un
singur câmp. Parserul `gaia_cef` îl caută, în ordine, în trei locuri:

| # | Unde este blob-ul | Exemplu |
|---|---|---|
| 1 | În câmpul **Name** (al 6-lea câmp din antetul CEF) | `CEF:0\|CheckPoint\|FW-1\|R77\|100\|action="Drop" src="1.2.3.4" dst="5.6.7.8" service="443" proto="6"\|5\|` |
| 2 | În extensia **`rawEvent=`** sau **`cs6=`** (cu `=` escapat ca `\=`) | `CEF:0\|…\|5\|rawEvent=action\="Drop" src\="1.2.3.4" …` |
| 3 | **Fără wrapper CEF** — linia este chiar blob-ul LEA | `time="…" action="Drop" src="1.2.3.4" dst="5.6.7.8" service="443" proto="6"` |

Anatomia variantei 1 (cea mai des întâlnită):

```
<134>            → prioritate syslog
Feb 17 11:32:44  → timestamp syslog
gw               → hostname
CEF:0            → versiunea CEF
CheckPoint       → vendor
FW-1             → produs
R77              → versiunea produsului
100              → signature ID
Name             → AICI ESTE BLOB-UL LEA:
  action="Drop"     → acțiunea firewall-ului
  src="1.2.3.4"     → IP sursă
  dst="5.6.7.8"     → IP destinație
  service="443"     → portul destinație
  proto="6"         → protocol IANA (6 = tcp, 17 = udp, 1 = icmp)
5                → severitate
extensii         → goale sau minime
```

Parserul verifică limitele cuvintelor la extragere: `rule_action="Drop"` **nu** este confundat
cu `action="Drop"`.

---

## 5. Călătoria unui eveniment, pas cu pas

Urmărim un caz concret, în scenariul recomandat (prin ArcSight, parser `gaia_cef`), de la
momentul în care firewall-ul blochează o conexiune până când alerta apare în ArcSight.

**Scenariul:** stația `10.20.5.17` (`ws-042`, Etaj 2) scanează serverul `10.0.0.1`
(`srv-db01`, Server Room) pe 15 porturi diferite în câteva secunde. Firewall-ul blochează fiecare
încercare.

### Etapa 1 — Firewall-ul generează log-ul, ArcSight îl trimite mai departe

Pentru fiecare încercare blocată, Checkpoint generează un eveniment. ArcSight îl primește, îl
stochează ca de obicei și îl trimite și către IDS-RS:

```
<134>Oct 13 14:02:11 gw CEF:0|CheckPoint|FW-1|R81|100|action="Drop" src="10.20.5.17" dst="10.0.0.1" service="21" proto="6"|5|
```

IDS-RS primește datagrama pe UDP 5555 și verifică, în ordine:

1. expeditorul (IP-ul connector-ului) este în `trusted_senders`? Dacă nu, datagrama e aruncată;
2. împarte datagrama pe linii și verifică limitele de număr și lungime;
3. aplică rate limiting-ul per expeditor și pe cel global.

### Etapa 2 — Parserul extrage ce ne interesează

Parserul `gaia_cef` găsește blob-ul LEA în câmpul Name și extrage:

| Câmp | Valoare |
|---|---|
| sursă | `10.20.5.17` |
| destinație | `10.0.0.1` |
| port destinație | `21` |
| protocol | `tcp` (din `proto="6"`) |
| acțiune | `drop` |

Dacă acțiunea ar fi fost `Reject` sau `Log`, linia ar fi fost ignorată aici.

### Etapa 3 — Detectorul numără și decide

Detectorul ține, pentru **perechea (10.20.5.17 → 10.0.0.1)**, o listă cu porturile blocate
și momentul în care a văzut fiecare port:

```
(10.20.5.17 → 10.0.0.1), Drop:
  :21 @ 14:02:11.0   :22 @ 14:02:11.3   :23 @ 14:02:11.5   :25 @ 14:02:11.9   …
```

La **fiecare** eveniment nou, verifică independent toate detecțiile active. Pentru acest eveniment
sunt relevante:

```
Fast Scan:  câte porturi DISTINCTE blocate în ultimele 10 secunde, pe această pereche?
            la al 15-lea port distinct (≥ 15)  →  ALERTĂ Fast Scan (1001)

Slow Scan:  câte porturi DISTINCTE blocate în ultimele 5 minute, pe această pereche?
            doar 15 (< 30)  →  nimic deocamdată; continuă să numere

Distributed Scan (dacă e activ): câte SURSE distincte au lovit 10.0.0.1 în ultimele 60 s?
            una singură  →  nimic
```

Evenimentele **Accept** sunt ținute separat de cele **Drop**, ca să nu se amestece: un Accept
contează pentru Accept Scan, Lateral Movement și Beaconing, nu pentru Fast/Slow Scan.

După alertă, perechea intră în **cooldown 5 minute** pentru Fast Scan: dacă scanarea continuă,
nu se generează sute de alerte identice. Dacă atacatorul ajunge la 30 de porturi distincte în
5 minute, se va genera separat și un **Slow Scan**.

### Etapa 4 — Alerta pleacă pe toate canalele

Alerta conține: tipul (Fast Scan), sursa, ținta, lista porturilor distincte și momentul. Apoi:

1. **apare în consolă**, colorat, cu hostname-ul și locația (dacă sunt configurate);
2. **intră în dashboard-ul web** (buffer cu ultimele `max_alerts` alerte);
3. **este pusă în coada SIEM și în coada de email**, care funcționează independent;
4. dacă livrarea eșuează (sau coada e plină), alerta se **salvează pe disc** (spool) și se
   reîncearcă automat, cu pauze din ce în ce mai mari (detalii în [7.2](#72-livrare-fiabilă-cozi--spool)).

### Etapa 5 — Mesajul CEF ajunge în ArcSight

IDS-RS construiește mesajul CEF și îl trimite pe UDP către connector-ul ArcSight (implicit
portul 514). Acesta este **exact** ce pleacă pe rețea:

```
<38>Oct 13 14:02:11 ids-rs CEF:0|IDS-RS|Network Scanner Detector|1.0|1001|Fast Port Scan Detected|7|rt=1792328531000 src=10.20.5.17 shost=ws-042 cs2Label=SourceLocation cs2=Etaj 2 dst=10.0.0.1 dhost=srv-db01 cs3Label=DestLocation cs3=Server Room cs4Label=PortSample cs4=21,22,23,25,80,110,135,139,143,443,445,993,995,3306,3389 cs5Label=DetectionWindowSecs cs5=10 cs6Label=ScannedPortList cs6=21,22,23,25,80,110,135,139,143,443,445,993,995,3306,3389 cnt=15 act=alert msg=Fast Scan detectat: 15 porturi unice in 10 secunde | scanned_ports: 21,22,23,… cs1Label=ScannedPortCount cs1=15
```

ArcSight îl parsează ca pe orice eveniment CEF. Explicația fiecărui câmp este în
[7.1](#71-evenimente-cef-către-arcsight).

### Rezumat vizual

```
Firewall            ArcSight                  IDS-RS                           ArcSight
────────            ────────                  ──────                           ────────
Drop tcp            primește log-ul,          recepție UDP :5555
10.20.5.17 →        îl stochează și     ───►  (trusted_senders, rate limit)
10.0.0.1:21         îl trimite mai departe    parser   → src, dst, port, acțiune
                                              detector → prag depășit? → alertă
                                              consolă + dashboard
                                              coadă SIEM  ─────────── CEF/UDP 514 ───► eveniment 1001
                                              coadă email ─────────── SMTP ──────────► inbox
```

---

## 6. Logica de detecție

### 6.1 Concepte comune

- **Fereastră glisantă:** la fiecare eveniment nou, IDS-RS se uită înapoi exact `time_window`
  secunde și numără **valori distincte** (porturi, destinații sau surse).
- **Timpul folosit este momentul primirii** log-ului de către IDS-RS, nu timestamp-ul din log.
  Vezi [Limitări](#10-limitări-cunoscute).
- **Cheia de agregare** diferă de la o detecție la alta (vezi tabelul de mai jos). Este important
  de știut pentru că determină **câte alerte** veți primi.
- **Cooldown** (`detection.alert_cooldown_secs`, implicit 300 s): după o alertă, aceeași cheie
  nu mai generează o alertă de același tip timp de 5 minute. O scanare care durează 30 de minute
  produce deci aproximativ 6 alerte, nu sute.
- **Whitelist** (`detection.whitelist`, IP-uri sau CIDR): **sursele** din whitelist sunt excluse
  din **toate** detecțiile.
- **Excepții** (`[detection.exceptions]`): excluderi țintite, doar pentru anumite detecții
  (vezi [Tuning](#tuning-anti-fals-pozitive)).

| Detecție | Acțiune | Cheie de agregare | Ce se numără | Prag implicit | Fereastră implicită |
|---|---|---|---|---|---|
| Fast Scan | Drop | (sursă, destinație) | porturi distincte | ≥ 15 | 10 s |
| Slow Scan | Drop | (sursă, destinație) | porturi distincte | ≥ 30 | 5 min |
| Accept Scan | Accept | (sursă, destinație) | porturi distincte | ≥ 5 | 30 s |
| Lateral Movement | Accept | sursă | destinații distincte | ≥ 5 | 60 s |
| Distributed Scan | Drop + Accept | destinație | surse distincte | ≥ 5 | 60 s |
| Beaconing C2 | Accept | (sursă, destinație, port) | regularitatea intervalelor | ≥ 8 conexiuni, CV ≤ 0.30 | 1 h |

### 6.2 Fast Scan (1001) și Slow Scan (1002)

**Ce caută:** o sursă care încearcă multe porturi diferite pe **aceeași** destinație, iar
firewall-ul le **blochează**. Este semnătura clasică `nmap -sS` sau a unui scanner de vulnerabilități.
Un exemplu complet este în [secțiunea 5](#5-călătoria-unui-eveniment-pas-cu-pas).

- **Slow Scan** folosește aceeași logică, cu un prag mai mare pe o fereastră mai lungă. Prinde
  scanările încetinite intenționat ca să treacă de pragurile clasice (`nmap -T1/-T2`).
- Ambele pot apărea pentru aceeași scanare: Fast la început, apoi Slow, când se acumulează
  porturile pe fereastra lungă.
- Contorizarea este **per pereche (sursă, destinație)**. O scanare a 50 de host-uri, fiecare
  pe ≥ 15 porturi, generează **50 de alerte Fast Scan** (câte una pe țintă). Sunt utile pentru
  agregare în ArcSight; vezi [regulile propuse](#83-idei-de-reguli-și-filtre-arcsight).

### 6.3 Accept Scan (1003)

**Ce caută:** o sursă care accesează **cu succes** multe porturi diferite pe aceeași țintă.
Înseamnă că regulile firewall-ului permit trafic larg către acea țintă, iar sursa enumeră
serviciile deschise.

- Pragul este mic (5 porturi în 30 s), pentru că traficul legitim rareori atinge atâtea porturi
  distincte pe același host într-un interval atât de scurt.
- Fals-pozitive tipice: servere de management sau monitorizare, agenți de backup, controlere
  de domeniu (multe servicii pe același host). Rezolvare: whitelist pentru sursă.

### 6.4 Lateral Movement (1004)

**Ce caută:** o sursă care deschide **conexiuni acceptate către multe destinații diferite**
(pe orice port) într-o fereastră scurtă. Este pattern-ul tipic al unui host compromis care
se propagă (SMB, RDP, WinRM, SSH).

```
10.20.5.17 → 10.0.1.10:445  Accept
10.20.5.17 → 10.0.1.11:445  Accept
10.20.5.17 → 10.0.1.12:3389 Accept
10.20.5.17 → 10.0.1.13:445  Accept
10.20.5.17 → 10.0.1.14:22   Accept   → 5 destinații distincte în 60 s
=> Lateral Movement (1004): src=10.20.5.17, lista celor 5 host-uri
```

- Agregarea este **per sursă**: o singură alertă, cu lista host-urilor contactate.
- Excepții dedicate: `authorized_scanners` (Nessus, OpenVAS etc.) și `ignore_lateral_ports`
  (porturi cu fan-out legitim mare: 135, 445, 5985 etc.).

### 6.5 Distributed Scan (1005)

**Ce caută:** perspectiva inversă, adică **mai multe surse diferite** care lovesc **aceeași
țintă** în aceeași fereastră. Este pattern-ul unui atac coordonat, al unui botnet sau al unui
scanner care își rotește IP-urile ca să evite pragurile per sursă.

- Agregarea este **per țintă**: o singură alertă, cu lista surselor și porturile vizate.
- Numără atât Drop, cât și Accept.
- Excepție dedicată: `ignore_distributed_target_ports` (porturi pe care o țintă primește
  legitim trafic de la mulți clienți: 53, 123, 80, 443 etc.).
- Câmpul `src` din alertă este **sursa care a depășit pragul** (ultima venită). Lista completă
  a surselor este în `cs6`.

### 6.6 Beaconing C2 (1006)

**Ce caută:** un flux `sursă → destinație:port` cu conexiuni acceptate la intervale
**aproape constante**, cum fac implanturile C2 (Cobalt Strike, Meterpreter, Sliver) care
„sună acasă” periodic.

Algoritm, pe fiecare flux:

1. se rețin momentele conexiunilor acceptate;
2. se calculează intervalele dintre ele, media lor și **coeficientul de variație**
   (CV = deviația standard / medie);
3. se emite alerta dacă:
   - există cel puțin `min_events` conexiuni (implicit 8);
   - intervalul mediu este între `min_interval_secs` și `max_interval_secs` (implicit 10 s – 1 h);
   - CV ≤ `cv_threshold` (implicit 0.30).

| CV | Interpretare |
|---|---|
| ~0.0 – 0.15 | Beacon „curat”, fără jitter (de ex. Cobalt Strike cu jitter 0%) |
| 0.15 – 0.30 | Beacon cu jitter moderat (pragul implicit) |
| 0.30 – 0.50 | Jitter mare; prinde mai mult, dar cu risc crescut de fals-pozitive |
| > 0.5 | Trafic uman, neregulat |

- Fals-pozitive tipice: NTP, Kerberos, LDAP, agenți de monitorizare (Zabbix, Nagios, SCCM).
  Se exclud prin `ignore_beaconing_ports` și `authorized_beaconing_sources`.
- În rețele izolate, un beacon între două host-uri interne este un indicator puternic de pivot
  sau compromitere, de aici severitatea 9.
- Istoricul fiecărui flux este păstrat pe toată fereastra de beaconing (implicit 1 h), chiar
  dacă `cleanup.max_entry_age_secs` este mai mic. Un beacon la 5 minute este deci detectat după
  ~35 de minute (a 8-a conexiune). Memoria rămâne mică: cel mult 32 de momente per flux.

### 6.7 Praguri dinamice (opțional)

Dacă activați `[detection.dynamic_threshold]`, pragurile pentru Fast, Slow și Accept Scan se
**adaptează la traficul observat**:

```
prag efectiv = medie + sensitivity_multiplier × deviație standard
```

Media și deviația sunt calculate EWMA din maximul de porturi distincte observat la fiecare ciclu
de cleanup. Pragul efectiv rămâne între `min_threshold_ratio` și `max_threshold_ratio` × pragul
static, iar până la acumularea a `min_samples` cicluri se folosește pragul static. Lateral,
Distributed și Beaconing rămân cu praguri fixe.

---

## 7. Ce furnizează IDS-RS

### 7.1 Evenimente CEF către ArcSight

Fiecare alertă este un singur mesaj syslog/CEF pe UDP (exemplu complet în
[Etapa 5](#etapa-5--mesajul-cef-ajunge-în-arcsight)). ArcSight îl citește în trei straturi.

**Stratul 1 — header syslog (RFC 3164)**

| Element | Valoare | Semnificație |
|---|---|---|
| Prioritate | `<38>` | facility 4 (security/auth) × 8 + severity 6 (info) |
| Timestamp | `Oct 13 14:02:11` | momentul alertei |
| Hostname | `ids-rs` | cine a trimis alerta (valoare fixă) |

**Stratul 2 — antetul CEF**

| Câmp CEF | Valoare | Câmp ArcSight |
|---|---|---|
| Device Vendor | `IDS-RS` | `deviceVendor` |
| Device Product | `Network Scanner Detector` | `deviceProduct` |
| Device Version | `1.0` | `deviceVersion` |
| Signature ID | `1001` … `1006` | `deviceEventClassId` (de folosit în reguli) |
| Name | vezi tabelul de mai jos | `name` |
| Severity | 5 … 9 | `deviceSeverity` (ArcSight o mapează pe Low/Medium/High/Very High) |

| SigID | Name | Severitate |
|---|---|---|
| 1001 | Fast Port Scan Detected | 7 |
| 1002 | Slow Port Scan Detected | 6 |
| 1003 | Accept Port Scan Detected | 5 |
| 1004 | Lateral Movement Detected | 8 |
| 1005 | Distributed Port Scan Detected | 7 |
| 1006 | Beaconing C2 Callback Detected | 9 |

**Stratul 3 — extensiile, comune tuturor alertelor**

| Cheie CEF | Câmp ArcSight | Conținut |
|---|---|---|
| `rt` | Device Receipt Time | momentul alertei, în ms epoch |
| `src` | Source Address | IP-ul sursei (atacatorul) |
| `dst` | Destination Address | ținta |
| `shost` / `dhost` | Source / Destination Host Name | doar dacă IP-ul are hostname în `[network.hostnames]` |
| `cs2` (`SourceLocation`) | Device Custom String 2 | locația sursei, dacă IP-ul se potrivește cu `[network.subnets]` |
| `cs3` (`DestLocation`) | Device Custom String 3 | locația destinației, la fel |
| `cnt` | Base Event Count | numărul relevant pentru detecție (porturi, host-uri, surse sau conexiuni) |
| `act` | Device Action | întotdeauna `alert` |
| `msg` | Message | descriere lizibilă și lista elementelor (vizibilă direct în Event List) |
| `cs1` | Device Custom String 1 | numărul, ca text (eticheta diferă pe tip; vezi mai jos) |

**Extensii specifice fiecărui tip**

| SigID | `cs1Label` | `cs4Label` | `cs5Label` | `cs6Label` | Altele |
|---|---|---|---|---|---|
| 1001 Fast | `ScannedPortCount` | `PortSample` (primele 20) | `DetectionWindowSecs` | `ScannedPortList` (max. 256) | — |
| 1002 Slow | `ScannedPortCount` | `PortSample` (primele 20) | `DetectionWindowMins` | `ScannedPortList` (max. 256) | — |
| 1003 Accept | `ScannedPortCount` | `PortSample` (primele 20) | `DetectionWindowSecs` | `ScannedPortList` (max. 256) | — |
| 1004 Lateral | `ContactedHostCount` | `ContactedHostSample` (primele 10) | `DetectionWindowSecs` | `ContactedHostList` (max. 128) | `dst` = ultima destinație contactată |
| 1005 Distributed | `AttackingSourceCount` | `TargetAddress` | `DetectionWindowSecs` | `AttackingSourceList` (max. 128) | `src` = sursa care a depășit pragul |
| 1006 Beaconing | `BeaconEventCount` | `MeanIntervalSecs` | `CV` | — | `dpt` = portul fluxului |

Note:

- Valorile ferestrelor (`cs5`) și textele din `msg` sunt citite din `config.toml`, deci reflectă
  automat pragurile pe care le configurați.
- Listele din `cs6` și `msg` sunt **trunchiate silențios** la limitele de mai sus. Numărul real
  este întotdeauna în `cnt` / `cs1`.
- Caracterele speciale sunt escapate conform standardului CEF: în extensii `\`, `=` și newline,
  în antet `\`, `|` și newline. Un hostname sau o valoare din log nu poate injecta câmpuri ori
  evenimente false. Spațiile rămân neescapate (sunt permise în valorile CEF), deci textele apar
  normal în ArcSight: `cs2=Etaj 2`, `msg=Fast Scan detectat: …`.
- Mesajul are o limită strictă de 60 KB pe datagramă. Listele trunchiate îl țin în practică
  mult sub această limită.

### 7.2 Livrare fiabilă (cozi + spool)

- SIEM-ul și email-ul au **cozi independente** (`alerting.queue_capacity`): dacă SMTP-ul e
  căzut, alertele către ArcSight pleacă în continuare.
- La eroare sau la saturarea cozii, alerta este **scrisă atomic pe disc** în
  `alerting.spool_directory` și reîncercată cu **backoff exponențial** (`retry_initial_secs`
  până la `retry_max_secs`), inclusiv după un restart.
- Dacă un canal este dezactivat sau serverul SMTP nu poate fi configurat, alertele din spool
  **rămân** acolo până la reactivare (nu sunt considerate livrate). Situația este raportată o
  singură dată în consolă.
- **Dead-letter:** o alertă care nu va putea fi livrată niciodată (mesaj CEF peste 60 KB,
  destinatar respins definitiv de SMTP cu cod 5xx) este mutată în `<spool>/<canal>/dead/` și nu
  mai blochează alertele din spatele ei. Fișierele rămân pentru inspecție; după corectarea cauzei
  pot fi reinjectate manual: `mv spool/email/dead/*.json spool/email/`.
- **La oprire** (Ctrl+C / `SIGTERM`), alertele din cozile din memorie și cea în curs de trimitere
  sunt salvate în spool și livrate la următoarea pornire, chiar dacă ArcSight sau SMTP-ul nu
  răspund în acel moment.
- Structura pe disc:

  ```
  spool/
  ├── siem/    *.json în așteptare (livrate în ordine)   dead/  eșecuri permanente
  └── email/   *.json în așteptare                        dead/  eșecuri permanente
  ```

- Atenție: livrarea către SIEM este UDP. „Trimis cu succes” înseamnă că pachetul a plecat,
  nu că ArcSight l-a confirmat.

### 7.3 Email

- Email HTML trimis prin SMTP (cu sau fără TLS sau autentificare), către lista din `alerting.email.to`.
- Fiecare destinatar primește un mesaj separat. Dacă unii eșuează, **doar ei** sunt reîncercați
  (cei care au primit deja alerta nu o primesc din nou); cei respinși definitiv ajung în dead-letter.
- Subiectul permite filtrarea ușoară în client:
  `🔴 [Fast Scan][SCANARE RETEA] IDS-RS 10.20.5.17 15 porturi`,
  `[MISCARE LATERALA]`, `[SCANARE COORDONATA]`, `[BEACON C2]`.
- Corpul conține: severitatea (CRITICĂ / RIDICATĂ / MEDIE / MEDIE-MICĂ), sursa și destinația
  cu hostname și locație, lista completă de porturi, host-uri sau surse și un footer configurabil.

### 7.4 Dashboard web (opțional)

Server HTTP local (implicit `http://127.0.0.1:8080`), read-only, care funcționează offline
(nu are dependențe CDN):

- **graf interactiv** sursă → destinație, colorat pe tip de detecție, cu grupare pe subnet;
- **tabel de alerte** cu filtre, căutare după IP și triage local (Ack / Dismiss / Escalate);
- **IP Dossier**: rolul IP-ului, tipurile de detecții, timeline, peer-uri;
- etichete **MITRE ATT&CK**: T1046 (Fast/Slow/Accept), T1595.001 (Distributed),
  T1021 (Lateral), T1071 (Beaconing);
- replay pe o fereastră de timp și export PNG sau JSON.

API JSON, util pentru scripturile voastre:

| Endpoint | Conținut |
|---|---|
| `GET /api/alerts` (opțional `?ip=…`) | ultimele `max_alerts` alerte (implicit 1000) |
| `GET /api/graph` | noduri și muchii pentru graf, plus statistici |
| `GET /api/ip/{ip}` | dosarul unui IP |
| `GET /health` | `{"status":"ok"}`, pentru monitorizare |

Dacă dashboard-ul ascultă pe o interfață non-loopback, API-ul cere header-ul
`Authorization: Bearer <auth_token>` (minimum 16 caractere). Pentru acces remote se recomandă
un reverse proxy cu TLS în față. Buffer-ul de alerte este doar în memorie și se golește la restart.

---

## 8. Integrarea cu ArcSight

### 8.1 Trimiterea log-urilor de firewall către IDS-RS

1. În SmartConnector-ul sau Logger-ul care primește log-urile Checkpoint, adăugați o
   **destinație CEF Syslog (UDP)** către `IP-IDS-RS:5555`.
2. Puneți un **filtru** pe destinație: doar evenimentele de firewall (de ex.
   `deviceVendor = "Check Point"`), cu acțiune Drop sau Accept, dacă e posibil. Reduce volumul și
   evită bucla cu propriile alerte.
3. Adăugați IP-ul connector-ului în `network.trusted_senders`.
4. Porniți IDS-RS cu `network.debug = true` câteva minute și verificați parsarea
   (vezi [9.5](#95-modul-debug--verificarea-parsării)).

### 8.2 Primirea alertelor în ArcSight

- Configurați `[alerting.siem]` cu `host` și `port` ale unui SmartConnector **Syslog Daemon**
  (CEF este recunoscut automat).
- Toate alertele se identifică prin: `deviceVendor = "IDS-RS"` și
  `deviceProduct = "Network Scanner Detector"`.
- Recomandăm o categorizare sau un mapping pe `deviceEventClassId` (`1001`–`1006`) și
  redenumirea câmpurilor custom după etichetele `csNLabel`.

### 8.3 Idei de reguli și filtre ArcSight

| Idee | Logică | De ce |
|---|---|---|
| **Canal dedicat IDS-RS** | Filtru `deviceVendor = IDS-RS` | Vizibilitate imediată pentru analiști. |
| **Escaladare pe lanț** (kill chain) | Aceeași `sourceAddress` produce `1001`/`1002` și apoi `1003` sau `1004` în ≤ 30 min | Recunoaștere urmată de acces reușit sau propagare: incident real, nu zgomot. |
| **Scan → Beacon** | `destinationAddress` dintr-un `1003` apare ulterior ca `sourceAddress` într-un `1006` | Ținta scanată a devenit sursă de beaconing: posibilă compromitere. |
| **Agregare scanare orizontală** | Mai multe `1001` de la aceeași sursă către destinații diferite în X minute → un singur caz | Compensează agregarea per pereche (sursă, destinație), vezi 6.2. |
| **Active List „surse IDS-RS”** | Orice alertă adaugă `sourceAddress` într-o listă cu TTL de 24 h | Corelare cu alte surse: VPN, AD, proxy, EDR. |
| **Beaconing = incident direct** | `1006` → caz automat, prioritate maximă | Fals-pozitivele reale se elimină din config (excepții), nu din SIEM. |
| **Distributed pe servere critice** | `1005` cu `destinationAddress` într-o listă de assets critice | Atac coordonat asupra unui server important. |
| **Monitorizarea IDS-RS** | Nicio alertă `IDS-RS` în N zile și/sau `/health` indisponibil | Detectează oprirea serviciului (vezi și limitările). |

### 8.4 Cum arată în Active Channel

```
Time             Name                           Source        Destination   Base Event Count  Priority   Message
Oct 13 14:02:11  Fast Port Scan Detected        10.20.5.17    10.0.0.1      15                High       Fast Scan detectat: 15 porturi unice in 10 secunde | scanned_ports: 21,22,…
Oct 13 14:05:40  Lateral Movement Detected      10.20.5.17    10.0.1.14     5                 High       Lateral Movement detectat: 5 destinatii unice in 60 secunde | contacted_hosts: …
Oct 13 15:10:02  Beaconing C2 Callback Detected 10.0.1.14     10.0.9.9      8                 Very High  Beaconing C2 detectat: 8 calluri pe portul 443, interval mediu 60.2s, CV 0.041
```

La deschiderea evenimentului apar și câmpurile custom (de ex. `ScannedPortList` cu toate porturile
vizate de atacator).

---

## 9. Instalare, rulare și configurare

### 9.1 Cerințe de sistem

**RHEL 9.x / Fedora**

```bash
# Compilator Rust (versiunea exactă, 1.85, este aleasă automat din rust-toolchain.toml)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Dependențe de sistem (pentru SMTP cu TLS / OpenSSL)
sudo dnf install -y gcc openssl-devel pkg-config
```

**Windows 10/11**
Pe Windows, oprirea se face cu Ctrl+C; `SIGHUP` (reîncărcare) și `SIGTERM` există doar pe Linux.

**Verificare:**

```bash
cargo --version
rustc --version
python3 --version   # Python 3.10+, doar pentru tester
```

### 9.2 Compilare

```bash
cargo build --release      # varianta de producție → target/release/ids-rs
cargo test                 # testele unitare
cargo build                # varianta de dezvoltare (rapidă, neoptimizată) → target/debug/ids-rs
```

Rezultatul este un singur binar, care se poate copia pe un server fără acces la internet,
împreună cu `config.toml`.

### 9.3 Rulare

```bash
./target/release/ids-rs                          # citește ./config.toml
./target/release/ids-rs /etc/ids-rs/config.toml  # cale explicită
RUST_LOG=ids_rs=debug ./target/release/ids-rs    # log-uri interne detaliate
```

- **Oprire curată:** Ctrl+C sau `SIGTERM`. Alertele nelivrate din cozi sunt salvate în spool și
  trimise la următoarea pornire.
- **Reîncărcare configurație fără restart:** `kill -HUP <pid>`.
  - *Se aplică imediat:* praguri, ferestre, whitelist, excepții, hostname-uri, subrețele,
    destinatari email, destinația SIEM, rate limiting, `trusted_senders`, debug.
  - *Necesită restart* (modificarea este semnalată și ignorată): adresa și portul de ascultare,
    parserul, setările de cleanup, coada, retry-ul și spool-ul, precum și bind-ul, port-ul,
    token-ul și concurența dashboard-ului.
  - Dacă noua configurație are erori, se păstrează cea veche și se afișează un avertisment.
  - Configurația este validată **după** ce se ignoră câmpurile care cer restart. De exemplu, un
    fișier care trece pe `listen_address = "127.0.0.1"` cu `trusted_senders = []` este respins
    dacă procesul ascultă în continuare pe `0.0.0.0`, unde lista goală ar accepta log-uri de la
    oricine.

**Exemplu de output la pornire și la o alertă** (prescurtat):

```
╔══════════════════════════════════════════════════════════════╗
║        IDS-RS  ::  INTRUSION DETECTION SYSTEM  v0.1.0        ║
║                  Network Port Scan Detector                  ║
╠══════════════════════════════════════════════════════════════╣
║  Parser: GAIA_CEF       Listen: UDP/5555                     ║
║  SIEM:   127.0.0.1:514  Email:  ON                           ║
║  Web:    http://127.0.0.1:8080                               ║
║  Adapt:  OFF (praguri statice)                               ║
║  Fast:  >=15 ports/10s       Slow: >=30 ports/5min           ║
╚══════════════════════════════════════════════════════════════╝

[2026-10-13 14:00:00]  INFO  Parser activ: Checkpoint Gaia LEA (ArcSight)
[2026-10-13 14:00:00]  INFO  Detector initializat (DashMap thread-safe)
[2026-10-13 14:00:00]  INFO  Web dashboard activ: http://127.0.0.1:8080
[2026-10-13 14:00:00]  INFO  Ascult pe UDP 0.0.0.0:5555
[2026-10-13 14:00:00]  INFO  Astept log-uri de la firewall... (Ctrl+C pentru oprire)
────────────────────────────────────────────────────────────────
[2026-10-13 14:00:00]  INFO  Rate limiting UDP activ: 10000 pachete/s, burst 20000

────────────────────────────────────────────────────────────────
[2026-10-13 14:02:11] ▶▶▶  ALERT  [FAST SCAN] [IP: 10.20.5.17 (ws-042) [Etaj 2]] | 15 porturi unice detectate!
  Porturi: 21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389
────────────────────────────────────────────────────────────────
[2026-10-13 14:02:11]  SENT  Alert 'Fast Scan' transmis -> 127.0.0.1:514
[2026-10-13 14:03:00]  STAT  3 IP-uri urmarite | Cleanup: 0 sterse
```

Liniile `RATE` (evenimente aruncate de rate limiting) și `WARN` apar doar când e cazul.

### 9.4 Fișierul `config.toml`

Toate setările sunt în `config.toml`; nicio valoare nu este scrisă direct în cod.

| Secțiune | Ce configurați |
|---|---|
| `[network]` | port și adresă UDP, parser, `trusted_senders`, rate limit, debug |
| `[network.hostnames]` | IP → nume (`"10.0.1.10" = "srv-dc01"`); apare în `shost`/`dhost`, email, consolă |
| `[network.subnets]` | CIDR → locație (`"10.10.1.0/24" = "Etaj 1"`); potrivire pe cel mai specific prefix; apare în `cs2`/`cs3` |
| `[detection]` | cooldown, limite de memorie, whitelist |
| `[detection.exceptions]` | excepții per detecție (vezi mai jos) |
| `[detection.fast_scan]`, `slow_scan`, `accept_scan` | prag și fereastră |
| `[detection.lateral_movement]`, `distributed_scan`, `beaconing` | `enabled`, prag și fereastră |
| `[detection.dynamic_threshold]` | praguri adaptive (vezi 6.7) |
| `[alerting]` | coadă, retry, director de spool |
| `[alerting.siem]` | `enabled`, `host`, `port` ArcSight |
| `[alerting.email]` | server SMTP, TLS, autentificare, expeditor, destinatari, footer |
| `[cleanup]` | cât de des și după cât timp se șterge starea veche din memorie |
| `[web_dashboard]` | `enabled`, `bind`, `port`, `auth_token`, `max_alerts` |

Fragment minimal pentru scenariul recomandat:

```toml
[network]
listen_address = "0.0.0.0"
listen_port = 5555
parser = "gaia_cef"
trusted_senders = ["10.1.1.50"]        # IP-ul connector-ului ArcSight

[network.hostnames]
"10.0.0.1" = "srv-db01"

[network.subnets]
"10.20.5.0/24" = "Etaj 2"
"10.0.0.0/24"  = "Server Room"

[detection]
alert_cooldown_secs = 300
whitelist = ["10.0.1.20"]              # de ex. serverul de backup

[detection.fast_scan]
port_threshold = 15
time_window_secs = 10

[alerting.siem]
enabled = true
host = "10.1.1.50"                     # connector-ul Syslog Daemon
port = 514

[alerting.email]
enabled = true
smtp_server = "smtp.intern.local"
smtp_port = 25
smtp_tls = false
from = "ids-rs@intern.local"
to = ["soc@intern.local"]
```

Fișierul `config.toml` din proiect conține toate opțiunile, comentate.

#### Validarea la pornire

Configurația este **verificată complet la pornire** (aproximativ 60 de verificări). Dacă ceva
nu este în regulă, IDS-RS **nu pornește** și afișează **toate problemele deodată**:

```
Error: config.toml contine 3 erori de configurare:
  1. network.trusted_senders trebuie configurat cand listen_address nu este loopback
  2. detection.slow_scan.time_window_mins (1 min = 60s) trebuie sa fie mai mare decat detection.fast_scan.time_window_secs (300s)
  3. cleanup.max_entry_age_secs (30) este mai mic decat fereastra Slow Scan (1 min = 60s): datele necesare detectiei Slow Scan vor fi sterse prematur
```

Și **câmpurile necunoscute** (de ex. o greșeală de scriere: `port_treshold`) opresc pornirea.
O protecție nu poate fi dezactivată din greșeală printr-un typo.

Regulile cele mai importante în practică:

| Regulă | De ce |
|---|---|
| `trusted_senders` este obligatoriu dacă `listen_address` nu este loopback | nimeni din rețea nu poate injecta log-uri false |
| `parser` ∈ `gaia`, `cef`, `gaia_cef` | — |
| Fereastra Slow Scan > fereastra Fast Scan | altfel cele două detecții se suprapun |
| `cleanup.max_entry_age_secs` ≥ fereastra Slow Scan | altfel datele sunt șterse înainte de a fi evaluate |
| Pragurile și ferestrele > 0; `alert_cooldown_secs` ≥ 1 | un prag 0 ar alerta la fiecare pachet |
| `udp_burst_size` ≥ `udp_rate_limit`; limita per expeditor (dacă e setată explicit) ≤ limita globală | rate limiting coerent. Dacă `udp_per_sender_*` lipsesc, se folosesc 2500/5000, plafonate automat la limita globală |
| Beaconing: `min_events` ≥ 3, `cv_threshold` în (0, 1], `max_interval_secs` > `min_interval_secs` | statistică relevantă |
| Email activ: server, expeditor și cel puțin un destinatar valid | — |
| Whitelist, excepții, hostname-uri, subrețele: IP-uri sau CIDR valide | — |
| Dashboard pe interfață non-loopback: `auth_token` de minimum 16 caractere | API-ul nu rămâne expus fără autentificare |

> Ferestrele Lateral Movement, Distributed Scan și Beaconing nu trebuie acoperite de
> `cleanup.max_entry_age_secs`: cleanup-ul păstrează automat datele fiecărei detecții cel puțin
> cât fereastra ei.

#### Tuning anti fals-pozitive

Ordinea recomandată:

1. **Hostname-uri și subrețele** completate, ca alertele să fie lizibile din prima.
2. **Rulați 1–2 săptămâni doar cu Fast, Slow și Accept Scan** și observați ce surse alertează
   legitim.
3. Puneți în **whitelist** sursele care nu trebuie să alerteze niciodată (de ex. serverul de
   backup).
4. Folosiți **excepțiile** când o sursă sau un port este legitim doar pentru un anumit tip de
   comportament:

   | Excepție | Exclude din | Exemple |
   |---|---|---|
   | `authorized_scanners` | Lateral Movement | Nessus, OpenVAS |
   | `ignore_lateral_ports` | Lateral Movement | 135, 445, 5985, 5986 |
   | `ignore_distributed_target_ports` | Distributed Scan | 53, 123, 80, 443 |
   | `ignore_beaconing_ports` | Beaconing | 123, 88, 389, 636 |
   | `authorized_beaconing_sources` | Beaconing | Zabbix, Nagios, SCCM |

5. Activați apoi Lateral, Distributed și Beaconing, una câte una.

### 9.5 Modul debug — verificarea parsării

Ca să vedeți exact ce ajunge pe port și dacă parsarea reușește, setați în `config.toml`:

```toml
[network]
debug = true
```

Pentru fiecare linie primită apar: linia brută (`RAW`), rezultatul (`OK` sau `FAIL`) și, la
eșec, formatul pe care îl aștepta parserul:

```
[2026-10-13 14:02:11]  RAW   <134>Oct 13 14:02:11 gw CEF:0|CheckPoint|FW-1|R81|100|action="Drop" src="10.20.5.17" dst="10.0.0.1" service="21" proto="6"|5|
[2026-10-13 14:02:11]   OK    src=10.20.5.17 dpt=21 proto=tcp action=drop

[2026-10-13 14:02:12]  RAW   <134>Oct 13 14:02:12 gw CEF:0|CheckPoint|FW-1|R81|100|Drop|5|src=10.20.5.17 dst=10.0.0.1 dpt=22 act=drop
[2026-10-13 14:02:12]  FAIL  Parsare esuata! (parser: Checkpoint Gaia LEA (ArcSight))
                              Primit:   "<134>Oct 13 14:02:12 gw CEF:0|CheckPoint|FW-1|R81|100|Drop|5|src=10.20.5.17 dst=10.0.0.1 dpt=22 act=drop"
                              Asteptat: "action="Drop" src="IP" dst="IP" service="PORT" proto="6" (raw LEA, CEF Name, sau CEF rawEvent=)"
```

Al doilea exemplu este un CEF normalizat trimis către parserul `gaia_cef`. Mesajul `FAIL`
indică faptul că trebuie folosit parserul `cef`.

Modul debug afișează **fiecare** linie, deci folosiți-l doar pentru diagnostic, nu în producție.
Caracterele de control din liniile primite (de ex. secvențe ANSI) sunt afișate escapat
(`\u{1b}`), ca să nu poată modifica terminalul.
Dezactivarea se poate face fără restart (`kill -HUP`).

### 9.6 Testare fără firewall real

Directorul `tester/` conține un generator de trafic și un server SMTP fals:

```bash
python3 tester/smtp_server.py                   # SMTP local pe portul 1025 (afișează email-urile)
python3 tester/tester.py fast --gaia-cef        # replay din fișierele sample
python3 tester/tester.py fast-scan              # Fast Scan generat dinamic
python3 tester/tester.py slow-scan
python3 tester/tester.py accept-scan
python3 tester/tester.py lateral-movement
python3 tester/tester.py distributed-scan
python3 tester/tester.py beaconing-c2
python3 tester/tester.py normal                 # trafic normal: NU trebuie să alerteze
python3 tester/tester.py replay <fișier.log>    # log-uri reale exportate
```

Opțiunile globale `--host` și `--port` indică instanța IDS-RS țintă. Rulați
`python3 tester/tester.py <comandă> --help` pentru toate opțiunile.

---

## 10. Limitări cunoscute

| Limitare | Impact | Recomandare |
|---|---|---|
| **Timpul se măsoară la primire, nu din timestamp-ul log-ului.** | Dacă ArcSight trimite log-urile în loturi sau cu întârziere, evenimentele „se înghesuie” sau „se rarefiază”. Fast Scan poate apărea fals sau poate lipsi, iar intervalele de Beaconing sunt distorsionate. Un replay de log-uri istorice nu reproduce timing-ul real. | Forwarding în timp real, fără batching; ideal, varianta directă `gaia`. |
| **Doar Drop și Accept.** | `Reject` și alte acțiuni sunt ignorate. | Dacă politica voastră folosește Reject, trebuie extins parserul. |
| **Linii fără port sau destinație sunt ignorate.** | ICMP (ping sweep) nu este detectat. | — |
| **Scanare orizontală pe un singur port blocat.** | O sursă care încearcă `:445` pe 200 de host-uri, toate cu Drop, nu declanșează Fast/Slow (1 port per pereche) și nici Lateral (care numără doar Accept). | Regulă de corelare în ArcSight pe log-urile brute, până la o detecție dedicată (vezi secțiunea 11). |
| **Fast/Slow/Accept sunt per pereche (sursă, destinație).** | O scanare pe multe ținte produce multe alerte. | Agregare în ArcSight (vezi 8.3). |
| **Starea de detecție este doar în memorie.** | La restart se pierde contextul (o scanare lentă în curs „începe de la zero”) și istoricul dashboard-ului. Alertele nelivrate nu se pierd (sunt în spool). | Restart planificat, în afara orelor de vârf. |
| **Whitelist-ul se aplică doar sursei.** | Un IP din whitelist poate apărea în continuare ca **destinație** în alerte. | Intenționat; pentru destinații folosiți excepțiile pe porturi. |
| **Dead-letter-ul nu se reîncearcă automat.** | Alertele mutate în `<spool>/<canal>/dead/` nu ajung în SIEM sau pe email până nu sunt reinjectate. | Urmăriți mesajele „esuata definitiv” din consolă; după corectare, mutați fișierele înapoi în directorul canalului. |
| **Livrare SIEM prin UDP, fără TLS.** | Fără confirmare de primire; trafic în clar. | Rețea de management dedicată. TLS este pe roadmap. |
| **Un parser per instanță.** | Formate mixte necesită mai multe instanțe. | Porturi diferite, câte un `config.toml` per instanță. |
| **Lista din `cs6` / `msg` este trunchiată silențios** (256 de porturi, 128 de IP-uri). | Lista nu e completă la scanări foarte mari. | Numărul real este în `cnt` / `cs1`. |
| **Fără serviciu systemd livrat.** | Repornirea automată trebuie configurată manual. | Unit file propriu, cu `Restart=on-failure`. |

---

## 11. Potențial de alertări viitoare în SIEM

### 11.1 Detecții noi, pe aceleași log-uri de firewall

| Idee | Ce ar detecta | Valoare pentru SIEM |
|---|---|---|
| **Horizontal Sweep** | O sursă, același port, multe destinații **blocate** | Acoperă golul descris în limitări (căutare de SMB/RDP/SSH deschis). |
| **Brute Force pe porturi critice** | Conexiuni repetate de la aceeași sursă pe 22, 3389, 445 | Complementar cu log-urile de autentificare din AD sau Linux. |
| **Port Knocking** | Secvențe de porturi accesate într-o ordine fixă | Backdoor-uri ascunse în spatele firewall-ului. |
| **Blacklist IOC offline** | Orice trafic către sau de la IP-uri dintr-un fișier CSV/JSON local | Feed-uri threat intel în rețele fără internet, cu alertă la primul pachet. |
| **Exfiltrare** | Volum neobișnuit de trafic outbound de la un host intern | Necesită parsarea câmpurilor de bytes din log (azi neextrase). |
| **Detecție „primă dată”** | O sursă internă care contactează pentru prima dată o destinație sau un port | Baseline per host, foarte util în rețele stabile sau izolate. |

### 11.2 Surse și formate noi

- Parser **FortiGate**, **Cisco ASA**, **iptables/nftables**: aceleași detecții pe alte firewall-uri.
- **Citire din fișiere** (echivalent `tail -f`), nu doar UDP: replay forensic sau surse fără syslog.

### 11.3 Îmbunătățiri ale ieșirii către SIEM

- **Timestamp din log** în locul momentului primirii; rezolvă cea mai importantă limitare.
- **TLS / TCP** pentru livrarea către ArcSight, cu confirmare.
- **Câmpuri numerice** (`cn1`…`cn3`) pentru contoare, CV și interval, ca să puteți folosi
  comparații numerice direct în regulile ArcSight.
- **ID de corelare** comun pentru alertele aceleiași campanii (de ex. scan → lateral → beacon de
  la aceeași sursă).
- **Raport zilnic** pe email: top surse, top ținte, statistici de funcționare.
- **Statistici periodice** (JSON sau eveniment CEF de „heartbeat”) pentru monitorizarea IDS-RS
  din SIEM sau Zabbix.
- **Persistența stării** la restart.

Dacă aveți nevoie de una dintre acestea sau de alt tip de detecție, spuneți-ne. Arhitectura
permite adăugarea unei detecții sau a unui parser nou fără modificarea restului fluxului.

---

## 12. Întrebări frecvente

**Înlocuiește IDS-RS regulile de corelare din ArcSight?**
Nu. Le completează: face agregarea grea pe log-urile brute și trimite în ArcSight evenimente
deja „cu sens”, pe care regulile voastre le pot corela mai departe.

**Cât de multe alerte o să primim?**
Depinde de rețea. Cooldown-ul (5 minute per cheie) limitează repetările. Începeți doar cu
Fast, Slow și Accept, plus whitelist, apoi activați restul.

**Ce resurse consumă?**
Puține: un singur proces, starea doar în memorie, cu limite stricte de memorie (`max_tracked_ips`,
`max_tracked_flows`, `max_hits_per_ip`). Când limitele sunt atinse, intrările cele mai vechi sunt
eliminate primele.

**Pot să-l testez fără să ating producția?**
Da: rulați-l local cu `tester/tester.py` și `tester/smtp_server.py`, cu SIEM-ul îndreptat
spre un connector de test.

**Ce se întâmplă dacă ArcSight sau serverul de email nu răspund?**
Alertele se scriu în spool pe disc și se reîncearcă automat, inclusiv după restart. Cele care
nu pot fi livrate niciodată (de ex. un destinatar respins definitiv) sunt mutate în `dead/`,
fără să le blocheze pe celelalte.

**Cum verific că log-urile ajung și sunt înțelese?**
Cu modul debug (vezi [9.5](#95-modul-debug--verificarea-parsării)).
