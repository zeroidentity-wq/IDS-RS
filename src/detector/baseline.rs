// =============================================================================
// detector/baseline.rs - EWMA Baseline, praguri dinamice (#35)
// =============================================================================
//
// EWMA (Exponentially Weighted Moving Average) urmareste media si varianta
// numarului maxim de porturi unice per IP per fereastra de timp.
//
// La fiecare ciclu de cleanup (~60s), esantionam starea curenta:
//   - Pentru fiecare IP urmarit, numaram porturile unice in fereastra Fast/Slow/Accept.
//   - Luam maximul per scan type (cel mai "zgomotos" IP legitim din retea).
//   - Actualizam EWMA cu acest maxim.
//
// Formula EWMA:
//   mean    = mean + alpha * (value - mean)
//   variance = (1 - alpha) * (variance + alpha * delta^2)
//
// Pragul efectiv: mean + multiplier * stddev, clamped in [static*min_ratio, static*max_ratio].
// Cost memorie: 24 bytes per scan type (3 x f64).
//
// =============================================================================

use crate::config::DynamicThresholdConfig;
use serde::{Deserialize, Serialize};

/// Starea EWMA pentru un singur tip de scan.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(super) struct BaselineEwma {
    mean: f64,
    variance: f64,
    samples: u64,
}

impl BaselineEwma {
    pub(super) fn new() -> Self {
        Self {
            mean: 0.0,
            variance: 0.0,
            samples: 0,
        }
    }

    /// Actualizeaza EWMA cu o observatie noua.
    pub(super) fn update(&mut self, value: f64, alpha: f64) {
        self.samples += 1;
        if self.samples == 1 {
            self.mean = value;
            self.variance = 0.0;
            return;
        }
        let delta = value - self.mean;
        self.mean += alpha * delta;
        self.variance = (1.0 - alpha) * (self.variance + alpha * delta * delta);
    }

    fn stddev(&self) -> f64 {
        self.variance.sqrt()
    }
}

/// Stare baseline pentru toate tipurile de scan cu praguri dinamice.
/// Salvata ca atare in snapshot (#32): fara ea, pragurile dinamice ar
/// reveni la cele statice pana la `min_samples` cicluri dupa restart.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(super) struct BaselineState {
    pub(super) fast_scan: BaselineEwma,
    pub(super) slow_scan: BaselineEwma,
    pub(super) accept_scan: BaselineEwma,
}

impl BaselineState {
    pub(super) fn new() -> Self {
        Self {
            fast_scan: BaselineEwma::new(),
            slow_scan: BaselineEwma::new(),
            accept_scan: BaselineEwma::new(),
        }
    }
}

/// Calculeaza pragul efectiv pentru un tip de scan, tinand cont de baseline dinamic.
///
/// Daca pragurile dinamice sunt dezactivate sau nu s-au colectat destule esantioane,
/// returneaza pragul static din config.
pub(super) fn effective_threshold_value(
    static_threshold: usize,
    baseline: &BaselineEwma,
    dt: &DynamicThresholdConfig,
) -> usize {
    if !dt.enabled || baseline.samples < dt.min_samples {
        return static_threshold;
    }
    let dynamic = baseline.mean + dt.sensitivity_multiplier * baseline.stddev();
    let floor = (static_threshold as f64 * dt.min_threshold_ratio).ceil() as usize;
    let ceiling = (static_threshold as f64 * dt.max_threshold_ratio).floor() as usize;
    // Rotunjirea poate inversa limitele cand intervalul [min, max] nu contine
    // niciun intreg (ex: prag 3, ratii 0.5..0.6 -> floor 2, ceiling 1);
    // `clamp` ar intra in panica si ar opri tot procesul.
    let floor = floor.max(1);
    let ceiling = ceiling.max(floor);
    (dynamic.ceil() as usize).clamp(floor, ceiling)
}

pub(super) type BaselineSnapshot = BaselineState;
