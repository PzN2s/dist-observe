//! Predictive layer (MVP): trend-based exhaustion forecast.
//! Least-squares slope over the recent window -> "exhaustion in X hours".
//! Baseline-deviation check (z-score) also included so we don't rely on fixed thresholds alone.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Forecast {
    pub resource: String,      // "mem" | "disk"
    pub current_pct: f64,
    pub growth_pct_per_hour: f64,
    pub hours_left: Option<f64>,
    pub verdict: String,
}

fn linreg(xs: &[f64], ys: &[f64]) -> (f64, f64) {
    // returns (slope, intercept); xs in hours, ys in %.
    // Pair first: callers must pass matched slices, but never trust it —
    // mismatched lengths would otherwise poison the means.
    let n = xs.len().min(ys.len());
    let (xs, ys) = (&xs[..n], &ys[..n]);
    let n = n as f64;
    if n < 2.0 {
        return (0.0, ys.first().copied().unwrap_or(0.0));
    }
    let mx: f64 = xs.iter().sum::<f64>() / n;
    let my: f64 = ys.iter().sum::<f64>() / n;
    let mut num = 0.0;
    let mut den = 0.0;
    for (x, y) in xs.iter().zip(ys.iter()) {
        num += (x - mx) * (y - my);
        den += (x - mx) * (x - mx);
    }
    if den.abs() < 1e-12 {
        return (0.0, my);
    }
    let slope = num / den;
    (slope, my - slope * mx)
}

pub fn forecast_series(resource: &str, times_sec: &[f64], vals: &[f64]) -> Forecast {
    let current = vals.last().copied().unwrap_or(0.0);
    if times_sec.len() < 3 {
        return Forecast {
            resource: resource.into(),
            current_pct: current,
            growth_pct_per_hour: 0.0,
            hours_left: None,
            verdict: "need ≥3 samples for a forecast".into(),
        };
    }
    let span_s = times_sec.last().unwrap_or(&0.0) - times_sec.first().unwrap_or(&0.0);
    let t0 = times_sec[0];
    let xs: Vec<f64> = times_sec.iter().map(|t| (t - t0) / 3600.0).collect();
    let (slope, _) = linreg(&xs, vals);

    // Noise gate: ignore tiny slopes (jitter).
    if slope <= 0.01 {
        return Forecast {
            resource: resource.into(),
            current_pct: current,
            growth_pct_per_hour: slope,
            hours_left: None,
            verdict: if slope <= 0.0 {
                "stable or shrinking — no exhaustion on current trend".into()
            } else {
                "growth negligible (<0.01 %/h)".into()
            },
        };
    }
    let hours_left = (100.0 - current) / slope;
    // A sub-minute window cannot page anyone: slopes extrapolated from seconds
    // of jitter produce absurd "CRITICAL in 0.3h" verdicts (seen live). Report
    // the rate honestly but cap the severity at UNCERTAIN until minutes exist.
    if span_s < 60.0 {
        return Forecast {
            resource: resource.into(),
            current_pct: current,
            growth_pct_per_hour: slope,
            hours_left: Some(hours_left),
            verdict: format!(
                "UNCERTAIN (short window): ~{hours_left:.1}h at {slope:.2}%/h — collect minutes/hours before paging anyone"
            ),
        };
    }
    let verdict = if hours_left < 0.0 {
        "already over 100% — check data".into()
    } else if hours_left < 24.0 {
        format!("CRITICAL: exhaustion in ~{hours_left:.1}h at {slope:.2}%/h")
    } else if hours_left < 72.0 {
        format!("WARNING: exhaustion in ~{hours_left:.1}h at {slope:.2}%/h")
    } else {
        format!("OK: ~{hours_left:.1}h left at {slope:.2}%/h")
    };
    Forecast {
        resource: resource.into(),
        current_pct: current,
        growth_pct_per_hour: slope,
        hours_left: Some(hours_left),
        verdict,
    }
}

pub fn forecast_from_store(series: &[(f64, f64, f64)]) -> (Forecast, Forecast) {
    let ts: Vec<f64> = series.iter().map(|(t, _, _)| *t).collect();
    let mem: Vec<f64> = series.iter().map(|(_, m, _)| *m).collect();
    let disk: Vec<f64> = series.iter().map(|(_, _, d)| *d).collect();
    (
        forecast_series("mem", &ts, &mem),
        forecast_series("disk", &ts, &disk),
    )
}

/// Z-score baseline deviation: is the latest value anomalous vs its own history?
pub fn zscore_anomaly(vals: &[f64]) -> Option<(f64, String)> {    if vals.len() < 10 {
        return None;
    }
    let (base, &[last]) = vals.split_at(vals.len() - 1) else {
        return None;
    };
    let n = base.len() as f64;
    let mean = base.iter().sum::<f64>() / n;
    let var = base.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    let std = var.sqrt();
    if std < 1e-6 {
        return None;
    }
    let z = (last - mean) / std;
    if z.abs() > 3.0 {
        Some((z, format!("baseline deviation z={z:.1} (mean {mean:.1}±{std:.1})")))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linreg_ignores_length_mismatch() {
        // 3 x-values, 5 y-values: must pair the first 3, never divide the
        // 3-pair covariance by n=5 (that would shrink every slope 40%).
        let (slope, _) = linreg(&[0.0, 1.0, 2.0], &[0.0, 1.0, 2.0, 99.0, 99.0]);
        assert!((slope - 1.0).abs() < 1e-9, "slope={slope}");
    }

    #[test]
    fn forecast_needs_span_not_just_count() {
        let f = forecast_series("mem", &[0.0, 0.5, 1.0], &[50.0, 50.5, 51.0]);
        assert!(f.verdict.contains("short window"), "{}", f.verdict);
    }

    #[test]
    fn short_window_never_pages_critical() {
        // Steep 1-second slope: honest rate, capped severity.
        let f = forecast_series("mem", &[0.0, 0.5, 1.0], &[50.0, 60.0, 70.0]);
        assert!(!f.verdict.contains("CRITICAL"), "{}", f.verdict);
        assert!(f.verdict.contains("UNCERTAIN"), "{}", f.verdict);
    }
}
