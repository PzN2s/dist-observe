//! Burst-resolution tenant attribution via major page faults.
//! Lesson learned live: PSI `total=` at 1s resolution cannot see sub-second
//! swap-in micro-bursts (a 9k-pages/s storm moved host mem-stall by <0.5%).
//! Major faults can: one majflt ≈ one blocking disk read, and swap-in IS disk
//! read. Summing majflt over every thread in OUR cgroup vs the host-wide
//! `pgmajfault` counter attributes each burst at full sample resolution:
//!   host majors spiking, tenant majors flat → NEIGHBOR (not us)
//!   tenant majors tracking host → OURS
//! PSI stays as the sustained-pressure signal; faults cover micro-bursts.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantSample {
    pub cgroup: String,
    pub tids: u64,        // threads accounted in this sample
    pub minflt: u64,      // tenant-cgroup cumulative minor faults
    pub majflt: u64,      // tenant-cgroup cumulative major faults
    pub sys_minflt: u64,  // host-wide pgfault
    pub sys_majflt: u64,  // host-wide pgmajfault
}

fn vmstat(key: &str) -> u64 {
    let Ok(t) = std::fs::read_to_string("/proc/vmstat") else {
        return 0;
    };
    for line in t.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some(key) {
            return it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        }
    }
    0
}

fn self_cgroup() -> String {
    let Ok(t) = std::fs::read_to_string("/proc/self/cgroup") else {
        return String::new();
    };
    for line in t.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 && (parts[0] == "0" || parts[1].is_empty()) {
            return parts[2].to_string();
        }
    }
    String::new()
}

/// (minflt, majflt) of one thread; None if unreadable (exited).
fn thread_faults(tid: &str) -> Option<(u64, u64)> {
    let t = std::fs::read_to_string(format!("/proc/{tid}/stat")).ok()?;
    // comm may contain spaces/parens: fields start after the LAST ')'.
    let after = t.rfind(')')?; // index of ')' — careful: rfind returns byte index
    let rest = &t[after + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After comm: state(3) ppid(4) ... minflt is field 10 → index 7 here.
    if f.len() < 11 {
        return None;
    }
    Some((f[7].parse().ok()?, f[9].parse().ok()?))
}

pub fn sample() -> TenantSample {
    let cg = self_cgroup();
    let (mut tids, mut minflt, mut majflt) = (0u64, 0u64, 0u64);
    if !cg.is_empty() {
        if let Ok(procs) = std::fs::read_to_string(format!("/sys/fs/cgroup{cg}/cgroup.procs")) {
            for tid in procs.split_whitespace().take(5000) {
                if let Some((mi, ma)) = thread_faults(tid) {
                    tids += 1;
                    minflt += mi;
                    majflt += ma;
                }
            }
        }
    }
    TenantSample {
        cgroup: if cg.is_empty() { "(unknown)".into() } else { cg },
        tids,
        minflt,
        majflt,
        sys_minflt: vmstat("pgfault"),
        sys_majflt: vmstat("pgmajfault"),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FaultVerdict {
    Ours,
    Neighbor,
    Unclear,
}

/// Counter rate with wrap/reset saturation (never negative).
pub fn rate(cur: u64, prev: u64, dt_s: f64) -> f64 {
    if dt_s <= 0.0 {
        return 0.0;
    }
    (cur.saturating_sub(prev) as f64) / dt_s
}

/// Pure rule on major-fault rates (faults/s, same window).
/// Called only when a host-level spike already fired — the question is just
/// "did WE fault?". Tenant ≈0 while host storms → NEIGHBOR.
pub fn attribute(ten_rate: f64, sys_rate: f64) -> FaultVerdict {
    if sys_rate < 50.0 {
        return FaultVerdict::Unclear; // no host storm to attribute
    }
    if ten_rate >= 0.3 * sys_rate || ten_rate > 100.0 {
        FaultVerdict::Ours
    } else if ten_rate < 5.0 && ten_rate < 0.1 * sys_rate {
        FaultVerdict::Neighbor
    } else {
        FaultVerdict::Unclear
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbor_when_tenant_flat() {
        assert_eq!(attribute(0.0, 2000.0), FaultVerdict::Neighbor);
        assert_eq!(attribute(4.0, 500.0), FaultVerdict::Neighbor);
    }

    #[test]
    fn ours_when_tracking() {
        assert_eq!(attribute(800.0, 2000.0), FaultVerdict::Ours); // 40% share
        assert_eq!(attribute(150.0, 200.0), FaultVerdict::Ours); // over abs floor
    }

    #[test]
    fn unclear_without_host_storm() {
        assert_eq!(attribute(0.0, 10.0), FaultVerdict::Unclear);
        assert_eq!(attribute(30.0, 200.0), FaultVerdict::Unclear); // grey zone
    }

    #[test]
    fn thread_stat_parsing() {
        // comm with spaces and parens — fields must still align.
        // after comm: state ppid pgrp session tty tpgid flags MINFLT cminflt MAJFLT
        let fake = "12345 (my proc (x)) R 1 2 3 4 5 6 100 8 200 0 0";
        let t = fake.rfind(')').unwrap();
        let f: Vec<&str> = fake[t + 1..].split_whitespace().collect();
        assert_eq!(f[7], "100"); // minflt
        assert_eq!(f[9], "200"); // majflt
    }
}
