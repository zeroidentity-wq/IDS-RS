# IDS-RS WebDashboard

## Prezentare completa (non-tehnica)

---

## 0. Mesajul cheie (30 sec)

WebDashboard-ul IDS-RS este o harta live a alertelor de securitate din retea.

In loc sa citesti mii de log-uri sau sa cauti manual in liste, vezi imediat:
- cine ataca (Atacatori)
- cine este vizat (Tinte)
- ce tip de comportament s-a detectat (scanare, miscare laterala, beaconing)
- care este gravitatea (severitate)

Este punctul forte pentru prezentare si operare, pentru ca transforma date tehnice in imagine clara, actionabila.

---

## 1. Problema pe care o rezolva (1 minut)

In majoritatea organizatiilor, semnalele de securitate apar sub forma de:
- log-uri brute (text)
- evenimente SIEM (liste)
- rapoarte (post-factum)

Pentru cine nu lucreaza zilnic cu aceste sisteme, este greu sa raspunzi rapid la intrebari simple:
- "Ce se intampla acum in retea?"
- "E un incident real sau zgomot?"
- "Pe cine afecteaza?"
- "E un atacator unic sau mai multi?"

WebDashboard-ul raspunde exact la aceste intrebari, vizual si imediat.

---

## 2. Ce este WebDashboard-ul (1 minut)

WebDashboard-ul este o pagina web livrata de IDS-RS care afiseaza alertele generate de program.

Important (pentru incredere si siguranta):
- este read-only: nu modifica reteaua, nu "blocheaza" automat, nu schimba reguli
- nu necesita internet: functioneaza si in retele izolate
- foloseste doar alertele deja generate de IDS-RS, nu necesita agenti pe statii

Pe scurt: IDS-RS detecteaza, WebDashboard-ul arata.

---

## 3. Cum arata (imagine mentala)

Dashboard-ul este gandit ca o consola SOC:

1. Header (sus)
- titlu: IDS-RS Network Dashboard
- indicator Live (ultima actualizare)
- trei valori mari:
  - Alerte (cate alerte sunt in bufferul curent)
  - Atacatori (cate surse distincte)
  - Tinte (cate destinatii distincte)
- un grafic mic (sparkline) cu "alerte/minut" pe ultimele 60 de minute

2. Bara de filtre
- filtre rapide pe severitate: Critical / High / Medium
- filtre pe tip: Fast Scan, Slow Scan, Accept Scan, Lateral Movement, Distributed Scan, Beaconing C2
- heatmap 24h: o banda vizuala pe ore cu severitatea maxima detectata

3. Zona principala: harta (graf)
- noduri = IP-uri (calculatoare / servere)
- muchii = legaturi intre sursa si tinta (cine catre cine)
- culori = tipul alertei

4. Tabel (jos)
- lista alertelor recente, in ordine (cele mai noi sus)
- fiecare alerta are tip, timp, sursa, tinta, si actiuni de triage (marcare)

5. Panouri de investigatie
- IP dossier: cand dai click pe un IP, se deschide un panou cu "dosarul" lui
- Investigation workspace: poti "pina" IP-uri si sa scrii notite (se salveaza in browser)

---

## 4. Ce inseamna conceptele (glosar simplu)

- Alerta: un semnal ca IDS-RS a detectat un comportament suspect.
- Atacator: sursa care genereaza traficul suspect (ex: un IP care scaneaza).
- Tinta: destinatia vizata (ex: un server scanat).
- Severitate: cat de urgent este. Gandeste-te la "prioritate de reactie".

Tipurile de alerte, traduse pe romaneste:
- Fast Scan: "scaneaza rapid multe porturi" (cauta intrari)
- Slow Scan: "scaneaza incet, ca sa nu fie vazut"
- Accept Scan: "testeaza porturi care raspund (servicii deschise)"
- Lateral Movement: "un host se plimba prin reteaua interna, contactand multe masini"
- Distributed Scan: "mai multe surse ataca aceeasi tinta (atac coordonat)"
- Beaconing C2: "un host face apeluri regulate, periodic, ca un 'telefon acasa'"

---

## 5. Cum se foloseste (workflow de 2 minute)

### 5.1. Pasul 1: te uiti la 'starea de ansamblu'

In header vezi:
- cate alerte au aparut
- cati atacatori distincti
- cate tinte distincte

Daca Atacatori si Tinte cresc brusc, ai un semn ca se intampla ceva activ.

### 5.2. Pasul 2: filtrezi la esential

De obicei, incepi cu:
- Critical (Beaconing C2 si Lateral Movement)

De ce:
- aceste tipuri sugereaza risc real (posibil host compromis), nu doar scanning generic.

### 5.3. Pasul 3: intri pe un IP (IP dossier)

Click pe un IP important.

In IP dossier vezi:
- daca apare ca atacator, tinta sau ambele
- cate alerte a generat
- cu cine "vorbeste" cel mai des (peer-i)
- ce porturi apar in alerte
- o cronologie (timeline) a evenimentelor

### 5.4. Pasul 4: marchezi si notezi

Foloseste triage:
- acknowledge (vazut / in lucru)
- escalate (urgent)
- dismiss (zgomot / fals pozitiv)

Poti salva IP-uri in workspace si sa notezi decizii (ex: "server backup, trafic normal").

---

## 6. Cum ajung alertele in dashboard (explicatie non-tehnica)

IDS-RS sta in reteaua ta si primeste log-uri de la firewall.

Cand detecteaza un tipar, produce o alerta.

WebDashboard-ul afiseaza ultimele alerte intr-o lista si intr-o harta.
Se actualizeaza automat la fiecare cateva secunde, astfel incat sa vezi aproape in timp real ce se intampla.

---

## 7. De ce e util in prezentare (beneficii clare)

1. Ofera vizibilitate imediata:
   in 10 secunde, oricine intelege "cine ataca pe cine".

2. Reduce dependenta de interpretare tehnica:
   nu trebuie sa citesti log-uri.

3. Ajuta la prioritizare:
   Critical vs High vs Medium.

4. Ajuta la investigatie rapida:
   IP dossier arata istoricul si relatiile.

5. Functioneaza in retele restrictive:
   fara internet, fara servicii externe.

6. Sigur operational:
   read-only, nu modifica infrastructura.

---

## 8. Scenariu de demo (5 minute, pas cu pas)

### Pregatire (inainte de prezentare)

1. Pornesti IDS-RS.
2. Deschizi dashboard-ul in browser: `http://127.0.0.1:8080`
3. Optional: pornesti SIEM local de test (daca e cazul).

### Demo live

1. Arata dashboard-ul gol:
   - "aici ar aparea alertele, live"

2. Ruleaza un val de alerte (script tester):
   - "acum simulez atacuri diferite"

3. In dashboard:
   - vezi cum cresc Alerte/Atacatori/Tinte
   - apar noduri si muchii in graf

4. Filtreaza pe Critical:
   - arata cum ramane "esenta"

5. Click pe un IP:
   - arata IP dossier
   - arata timeline si peers

6. Pune un IP in workspace:
   - arata ca poti tine o lista de investigatie

7. Optional:
   - fullscreen pe graf
   - export PNG pentru raport (o imagine cu "incident view")

---

## 9. Intrebari frecvente (non-tehnice)

1. "Inlocuieste SIEM-ul?"
Nu. SIEM-ul ramane sistemul oficial de colectare/correlare. Dashboard-ul e pentru vizibilitate rapida si prezentare, in special pentru oameni non-tehnici.

2. "Este sigur?"
Da, pentru ca e read-only. Afiseaza doar alertele, nu executa actiuni asupra retelei.

3. "Ce inseamna ca nu are nevoie de internet?"
Pagina si libraria grafica sunt servite local de IDS-RS. Nu depinde de CDN-uri sau servicii externe.

4. "Ce se intampla daca sunt prea multe alerte?"
Dashboard-ul pastreaza un numar limitat de alerte recente (buffer). Scopul lui este vizibilitatea in timp real, nu arhivarea pe termen lung (asta ramane rolul SIEM-ului).

---

## 10. Concluzie (30 sec)

WebDashboard-ul este partea care transforma IDS-RS intr-un produs usor de inteles.

Este:
- vizual
- live
- actionabil
- sigur (read-only)
- potrivit pentru prezentare si pentru triage rapid

---

## Anexa (optional, 1 slide pentru tehnici)

Pentru audienta tehnica, pe scurt:
- Pagina este servita direct din IDS-RS (server HTTP embedded).
- Browserul cere periodic date (JSON) si redeseneaza graful + tabelul.
- Totul functioneaza offline (fara internet).

