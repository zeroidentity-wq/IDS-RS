// =============================================================================
// detector/capacity.rs - Limite de memorie: evictie in lot si retentie
// =============================================================================
//
// Toate tabelele detectorului sunt limitate: un flood (IP-uri spoofed, sweep
// orizontal) nu trebuie sa poata creste memoria fara limita. Helper-ele de
// aici sunt comune tuturor detectiilor.
//
// =============================================================================

use dashmap::DashMap;
use std::hash::Hash;
use std::time::Instant;

/// Cate intrari elibereaza o evictie cand o limita este atinsa.
///
/// Gasirea celor mai vechi intrari cere o parcurgere O(n). Eliberand un lot
/// de ~1/8 din limita, parcurgerea se amortizeaza la O(1) per cheie noua, in
/// loc de O(n) la fiecare cheie noua (ex: flood cu IP-uri sursa spoofed).
fn eviction_batch(limit: usize) -> usize {
    (limit / 8).max(1)
}

/// Cate intrari trebuie eliberate ca sa incapa una noua: cel putin surplusul
/// fata de limita, rotunjit in sus la un lot intreg.
pub(super) fn eviction_count(len: usize, limit: usize) -> usize {
    (len + 1).saturating_sub(limit).max(eviction_batch(limit))
}

/// Cheile celor mai vechi `count` intrari, dupa `age` (mai mic = mai vechi).
/// Selectie partiala O(n), fara sortare completa.
pub(super) fn oldest_keys<K, A: Ord>(mut aged: Vec<(A, K)>, count: usize) -> Vec<K> {
    let count = count.min(aged.len());
    if count == 0 {
        return Vec::new();
    }
    if count < aged.len() {
        aged.select_nth_unstable_by(count - 1, |left, right| left.0.cmp(&right.0));
    }
    aged.truncate(count);
    aged.into_iter().map(|(_, key)| key).collect()
}

/// Face loc pentru o cheie noua intr-o tabela de hit-uri limitata la `limit`
/// chei: daca tabela e plina, elimina in lot cheile cu cel mai vechi ultim
/// hit si le returneaza (ca apelantul sa stearga si starea asociata, ex:
/// cooldown-uri).
///
/// LRU criteriu: ultima intrare din vectorul de hit-uri. Vectorul fiind
/// populat append-only, `.last()` da cel mai recent `seen_at` in O(1).
pub(super) fn make_room<K, V>(
    map: &DashMap<K, Vec<V>>,
    key: &K,
    limit: usize,
    seen_at: impl Fn(&V) -> Instant,
) -> Vec<K>
where
    K: Eq + Hash + Clone,
{
    if map.contains_key(key) || map.len() < limit {
        return Vec::new();
    }
    let aged = map
        .iter()
        .map(|entry| (entry.value().last().map(&seen_at), entry.key().clone()))
        .collect();
    let victims = oldest_keys(aged, eviction_count(map.len(), limit));
    for victim in &victims {
        map.remove(victim);
    }
    victims
}

/// Pastreaza doar ultimele `max` intrari (cele mai recente).
///
/// `.drain(..N)` sterge primele N elemente (cele mai vechi, oldest-first).
pub(super) fn keep_newest<T>(hits: &mut Vec<T>, max: usize) {
    if hits.len() > max {
        let overflow = hits.len() - max;
        hits.drain(..overflow);
    }
}

/// Sterge hit-urile pentru care `keep` e fals si cheile ramase fara hit-uri.
/// Returneaza cheile sterse.
///
/// NOTA RUST: Nu putem sterge din DashMap in timpul iteratiei (ar invalida
/// iteratorul). De aceea colectam cheile goale si le stergem separat, cu
/// `remove_if` - o cheie umpluta intre timp de alt task ramane.
pub(super) fn prune<K, V>(map: &DashMap<K, Vec<V>>, keep: impl Fn(&V) -> bool) -> Vec<K>
where
    K: Eq + Hash + Clone,
{
    let mut empty = Vec::new();
    for mut entry in map.iter_mut() {
        entry.value_mut().retain(&keep);
        if entry.value().is_empty() {
            empty.push(entry.key().clone());
        }
    }
    empty.retain(|key| map.remove_if(key, |_, hits| hits.is_empty()).is_some());
    empty
}
