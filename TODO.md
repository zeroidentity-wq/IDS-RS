# TODO — IDS-RS

Ce a ramas de implementat, in ordinea recomandata. Starea la 2026-10-15.

## Prioritare

- [ ] **Brute Force detection (#39)** — conexiuni repetate pe porturi critice
  (22, 3389, 445, ...) de la acelasi IP. Logurile de firewall vad doar conexiunile,
  nu autentificarile esuate, deci detectia este pe frecventa. Modul nou in
  `src/detector/`, alaturi de celelalte detectii.
- [ ] **Blacklist locala de IP-uri / IOC offline (#34)** — fisier CSV/JSON cu IP-uri
  cunoscute ca rele, alerta la primul pachet. Potrivit pentru reteaua izolata;
  lista se actualizeaza prin acelasi canal de transfer ca arhiva de livrare.
- [ ] **Raport zilnic pe email** — sumar al alertelor zilei, clasificat pe subretele
  (`[network.subnets]`). Poate folosi alertele pastrate de persistenta.

## Depind de logurile celuilalt departament

De lamurit intai: ce format au logurile (un sample), daca pot trimite syslog UDP.

- [ ] **Format JSON in parser-ul custom** — pentru surse care scriu JSON
  (ex: Suricata `eve.json`, firewall-uri cloud).
- [ ] **Citire din fisiere locale, `tail -f` (#31)** — daca nu pot trimite syslog UDP.
- [ ] **Mai multe parsere intr-o instanta** — parser ales dupa IP-ul expeditorului;
  doar daca se doreste o instanta centrala in loc de una per departament.

## Utile, fara graba

- [ ] **Parser Cisco ASA (#30)** — formatul ASA nu este `cheie=valoare`
  (`Deny tcp src outside:1.2.3.4/5555 dst inside:...`). Varianta propusa: un format
  `regex` (grupuri numite) in parser-ul custom, care acopera si alte formate.
  Doar daca exista un utilizator real de ASA.
- [ ] **Dump statistici la SIGUSR1 (#33)** — top atacatori si contoare; se suprapune
  partial cu `/api/stats` si cu rezumatul de parsare la 30 s.
- [ ] **Export CSV/JSON per sesiune (#37)** — pentru analiza dupa incident; poate fi
  un endpoint in dashboard.

## Mari sau de nisa

- [ ] **Exfiltration detection (#27)** — volume mari de trafic outbound; necesita
  numarul de bytes din loguri, pe care parserele nu il extrag inca.
- [ ] **Port Knock detection (#26)** — secvente de porturi in ordine; scenariu rar
  intr-o retea interna.
- [ ] **TLS pentru trimiterea catre SIEM (#38)** — relevant doar daca traficul spre
  ArcSight trece prin segmente nesigure.

## Curatenie repo

- [ ] `utils/docx_packages/` — wheel-uri Python urmarite in git.
- [ ] `utils/Prezentare/` si `utils/prezentare/` — directoare care difera doar prin
  majuscule (probleme pe Windows/macOS); fisierele `PREZENTARE_*` sunt duplicate.
- [ ] `LEARNING_RUST.md` — trimiterile la linii din vechiul `detector.rs` sunt
  depasite (detectorul este acum in `src/detector/`).
