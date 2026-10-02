//! Tenant isolation via cgroup v2 + PSI (Pressure Stall Information).
//! System-wide counters (pswpin/out, RetransSegs) see the WHOLE host — a
//! neighbor's storm looks exactly like ours. PSI fixes attribution: every
//! cgroup reports its OWN stall times. Compare tenant stalls vs host stalls
//! at the same unified timestamp:
//!   tenant stalled too → OURS (we are the pressure)
//!   host stalled, tenant clean → NEIGHBOR noise (not us — filter it)
//! Signal used is `total=` (monotonic microseconds stalled) → per-interval
//! stall fraction at full 1s resolution (avg10/60/300 windows are too slow).
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PsiWindow {
    pub some10: f64,
    pub some60: f64,
    pub some300: f64,
    pub total: u64, // microseconds stalled, monotonic
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PsiSample {
    pub cgroup: String,
    pub sys_cpu: PsiWindow,
    pub sys_mem_some: PsiWindow,
    pub sys_mem_full: PsiWindow,
    pub sys_io_some: PsiWindow,
    pub ten_cpu: PsiWindow,
    pub ten_mem_some: PsiWindow,
    pub ten_mem_full: PsiWindow,
    pub ten_io_some: PsiWindow,
}

fn parse_window(text: &str, prefix: &str) -> PsiWindow {
    let mut w = PsiWindow::default();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with(prefix) {
            continue;
        }
        for tok in line.split_whitespace().skip(1) {
            if let Some((k, v)) = tok.split_once('=') {
                match k {
                    "avg10" => w.some10 = v.parse().unwrap_or(0.0),
                    "avg60" => w.some60 = v.parse().unwrap_or(0.0),
                    "avg300" => w.some300 = v.parse().unwrap_or(0.0),
                    "total" => w.total = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        break; // first matching line only (some vs full selected by prefix)
    }
    w
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn self_cgroup() -> String {
    // v2 single line: "0::/user.slice/..."; v1: "N:subsys:/path" lines.
    let t = read("/proc/self/cgroup");
    for line in t.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 && (parts[0] == "0" || parts[1].is_empty()) {
            return parts[2].to_string();
        }
    }
    // v1 fallback: memory controller path
    for line in t.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 && parts[1].contains("memory") {
            return parts[2].to_string();
        }
    }
    String::new()
}

pub fn sample() -> PsiSample {
    let cg = self_cgroup();
    let base = if cg.is_empty() {
        String::new()
    } else {
        format!("/sys/fs/cgroup{cg}")
    };
    let sys_cpu = read("/proc/pressure/cpu");
    let sys_mem = read("/proc/pressure/memory");
    let sys_io = read("/proc/pressure/io");
    let (tc, tm, ti) = if base.is_empty() {
        (String::new(), String::new(), String::new())
    } else {
        (
            read(&format!("{base}/cpu.pressure")),
            read(&format!("{base}/memory.pressure")),
            read(&format!("{base}/io.pressure")),
        )
    };
    PsiSample {
        cgroup: if cg.is_empty() { "(unknown)".into() } else { cg },
        sys_cpu: parse_window(&sys_cpu, "some"),
        sys_mem_some: parse_window(&sys_mem, "some"),
        sys_mem_full: parse_window_full(&sys_mem),
        sys_io_some: parse_window(&sys_io, "some"),
        ten_cpu: parse_window(&tc, "some"),
        ten_mem_some: parse_window(&tm, "some"),
        ten_mem_full: parse_window_full(&tm),
        ten_io_some: parse_window(&ti, "some"),
    }
}

/// The `full` line (everyone stalled) rather than `some` (someone stalled).
fn parse_window_full(text: &str) -> PsiWindow {
    let mut w = PsiWindow::default();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("full") {
            continue;
        }
        for tok in line.split_whitespace().skip(1) {
            if let Some((k, v)) = tok.split_once('=') {
                match k {
                    "avg10" => w.some10 = v.parse().unwrap_or(0.0),
                    "avg60" => w.some60 = v.parse().unwrap_or(0.0),
                    "avg300" => w.some300 = v.parse().unwrap_or(0.0),
                    "total" => w.total = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        break;
    }
    w
}

/// Stall fraction (0.0-1.0+) of wall time spent stalled between two samples.
pub fn stall_frac(cur_total: u64, prev_total: u64, dt_s: f64) -> f64 {
    if dt_s <= 0.0 {
        return 0.0;
    }
    (cur_total.saturating_sub(prev_total) as f64 / 1e6) / dt_s
}

#[derive(Debug, Clone, PartialEq)]
pub enum TenantVerdict {
    Ours,
    Neighbor,
    Unclear,
}

/// Pure attribution rule on mem-stall fractions (tenant vs host, same window).
/// Thresholds: <1% = clean, ≥3% = stalled (hysteresis gap stays Unclear).
pub fn attribute(ten_stall: f64, sys_stall: f64) -> TenantVerdict {
    if ten_stall >= 0.03 {
        TenantVerdict::Ours
    } else if ten_stall < 0.01 && sys_stall >= 0.03 {
        TenantVerdict::Neighbor
    } else {
        TenantVerdict::Unclear
    }
}

pub fn render(sample: &PsiSample, prev: Option<&PsiSample>, dt_s: f64) -> String {
    let mut o = String::new();
    o.push_str(&format!("tenant cgroup: {}\n", sample.cgroup));
    o.push_str("  resource   host-stall%   tenant-stall%   verdict\n");    let rows = [
        ("cpu", stall_frac(sample.sys_cpu.total, prev.map(|p| p.sys_cpu.total).unwrap_or(0), dt_s), stall_frac(sample.ten_cpu.total, prev.map(|p| p.ten_cpu.total).unwrap_or(0), dt_s)),
        ("mem-some", stall_frac(sample.sys_mem_some.total, prev.map(|p| p.sys_mem_some.total).unwrap_or(0), dt_s), stall_frac(sample.ten_mem_some.total, prev.map(|p| p.ten_mem_some.total).unwrap_or(0), dt_s)),
        ("mem-full", stall_frac(sample.sys_mem_full.total, prev.map(|p| p.sys_mem_full.total).unwrap_or(0), dt_s), stall_frac(sample.ten_mem_full.total, prev.map(|p| p.ten_mem_full.total).unwrap_or(0), dt_s)),
        ("io-some", stall_frac(sample.sys_io_some.total, prev.map(|p| p.sys_io_some.total).unwrap_or(0), dt_s), stall_frac(sample.ten_io_some.total, prev.map(|p| p.ten_io_some.total).unwrap_or(0), dt_s)),
    ];
    for (name, sys, ten) in rows {
        let v = match attribute(ten, sys) {
            TenantVerdict::Ours => "OURS",
            TenantVerdict::Neighbor => "NEIGHBOR",
            TenantVerdict::Unclear => "—",
        };
        o.push_str(&format!(
            "  {name:9} {sys:>10.1}% {ten:>12.1}%   {v}\n",
            sys = sys * 100.0,
            ten = ten * 100.0
        ));
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEM: &str = "some avg10=12.50 avg60=3.00 avg300=0.50 total=4405590\nfull avg10=4.00 avg60=1.00 avg300=0.10 total=3417108\n";
    const CPU: &str = "some avg10=0.11 avg60=0.18 avg300=0.09 total=91498774\n";

    #[test]
    fn parses_some_and_full_lines() {
        let s = parse_window(MEM, "some");
        assert!((s.some10 - 12.5).abs() < 1e-9);
        assert_eq!(s.total, 4405590);
        let f = parse_window_full(MEM);
        assert!((f.some10 - 4.0).abs() < 1e-9);
        assert_eq!(f.total, 3417108);
    }

    #[test]
    fn cpu_has_no_full_line() {
        let f = parse_window_full(CPU);
        assert_eq!(f.total, 0); // absent → zero, never garbage
    }

    #[test]
    fn stall_frac_math() {
        assert!((stall_frac(2_000_000, 1_000_000, 1.0) - 1.0).abs() < 1e-9);
        assert_eq!(stall_frac(100, 900, 1.0), 0.0); // reset → saturate, never negative
        assert_eq!(stall_frac(5, 0, 0.0), 0.0);
    }

    #[test]
    fn attribution_rules() {
        assert_eq!(attribute(0.10, 0.12), TenantVerdict::Ours); // tenant stalled too
        assert_eq!(attribute(0.002, 0.08), TenantVerdict::Neighbor); // host storms, tenant clean
        assert_eq!(attribute(0.0, 0.0), TenantVerdict::Unclear); // all quiet
        assert_eq!(attribute(0.015, 0.10), TenantVerdict::Unclear); // hysteresis gap
        assert_eq!(attribute(0.002, 0.01), TenantVerdict::Unclear); // host ripple, not a storm
    }
}
