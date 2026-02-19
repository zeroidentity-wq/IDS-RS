# CLAUDE.md — Instrucțiuni pentru Claude Code (IDS-RS)

> **La fiecare sesiune:** citește `LEARNING_RUST.md` pentru contextul de învățare
> și progresul curent. Dacă utilizatorul vrea să continue învățarea, urmează
> instrucțiunile din acel fișier.


## Profilul utilizatorului

Utilizatorul este **începător în Rust, programare și rețelistică**.
Scopul principal al proiectului este **învățarea**, nu doar livrarea de cod funcțional.

---

## Comunicare

- Răspunde **în română** întotdeauna.
- Termenii tehnici Rust/rețele se lasă în engleză (`ownership`, `trait`, `async`,
  `socket`, etc.) — aceasta este terminologia pe care utilizatorul o va găsi în
  documentație și online.
- **Explică întotdeauna de ce**, nu doar ce. Înainte de orice implementare,
  explică conceptul și motivul deciziei de design.
- Când introduci un concept Rust sau de rețelistică nou, **explică-l complet**
  la prima utilizare — nu presupune cunoștințe anterioare.
- Dacă există mai multe abordări, prezintă opțiunile cu pro/contra înainte
  de a implementa.

---

## Cod

- Comentează codul nou în română, explicând **intenția** — nu doar ce face
  linia, ci de ce este necesară.
- Adaugă blocuri `// NOTA RUST:` pentru concepte noi, consistent cu stilul
  existent în proiect.
- Fără `unwrap()` în cod de producție — doar în teste.

---

## Workflow (respectat la fiecare implementare)

1. Citește fișierele relevante înainte de orice modificare.
2. Explică planul înainte să scrii cod.
3. Rulează `cargo build` și `cargo test` după implementare — toate testele trebuie să treacă.
4. Actualizează `README.md` (Changelog + orice secțiune afectată).
5. Marchează task-ul ca `completed` în lista de TODO.
6. Propune un mesaj de commit scurt — **utilizatorul face commit-ul manual**.

---

## Ce să NU faci

- Nu adăuga cod fără explicație, chiar dacă pare trivial.
- Nu face refactoring sau „îmbunătățiri" nesolicitate.
- Nu omite actualizarea README și a task-urilor după implementare.
- Nu face commit automat.
