// =============================================================================
// detector/cooldown.rs - Cooldown-ul alertelor (anti-spam)
// =============================================================================
//
// Dupa o alerta, aceeasi cheie (pereche src/dst, sursa, tinta sau flow) nu
// mai genereaza alta alerta de acelasi tip pana nu expira cooldown-ul.
//
// =============================================================================

use dashmap::DashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Momentul ultimei alerte per cheie.
///
/// NOTA RUST: generic peste cheie (`K`) - acelasi tip serveste cheile
/// `IpAddr`, `(IpAddr, IpAddr)` si `(IpAddr, IpAddr, u16)` ale detectiilor.
pub(super) struct Cooldowns<K>(DashMap<K, Instant>);

impl<K: Eq + Hash> Cooldowns<K> {
    pub(super) fn new() -> Self {
        Self(DashMap::new())
    }

    /// Cheia a generat o alerta acum mai putin de `cooldown`.
    pub(super) fn is_active(&self, key: &K, cooldown: Duration) -> bool {
        self.0
            .get(key)
            .is_some_and(|last| Instant::now().saturating_duration_since(*last) < cooldown)
    }

    pub(super) fn start(&self, key: K, now: Instant) {
        self.0.insert(key, now);
    }

    pub(super) fn remove(&self, key: &K) {
        self.0.remove(key);
    }

    pub(super) fn retain_keys(&self, keep: impl Fn(&K) -> bool) {
        self.0.retain(|key, _| keep(key));
    }

    /// Cheile si momentele ultimei alerte (pentru snapshot).
    pub(super) fn entries(&self) -> Vec<(K, Instant)>
    where
        K: Clone,
    {
        self.0
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect()
    }

    /// Sterge cooldown-urile expirate.
    pub(super) fn prune(&self, now: Instant, cooldown: Duration) {
        self.0
            .retain(|_, last| now.saturating_duration_since(*last) <= cooldown);
    }
}
