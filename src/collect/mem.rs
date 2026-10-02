//! RAM collector: heap + non-heap (mmap/shm/mlock) so Rust↔Python↔C++
//! FFI leaks that hide from heap-only profilers are still visible here.
//!
//! Swap ground truth: /proc/meminfo (SwapTotal/SwapFree) is authoritative on
//! Linux. sysinfo is kept only as fallback. Paging activity (pswpin/pswpout
//! from /proc/vmstat, cumulative) distinguishes a STEADY old baseline from
//! ACTIVE thrashing — a flat swap % alone cannot.
use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemSample {
    pub total_kb: u64,
    pub available_kb: u64,
    pub used_kb: u64,
    pub used_pct: f64,
    pub free_kb: u64,
    pub buffers_kb: u64,
    pub cached_kb: u64,
    pub shmem_kb: u64,    // shared memory (/dev/shm, IPC) — classic FFI leak spot
    pub mlocked_kb: u64,  // GPU-pinned / mlock'd — invisible to heap profilers
    pub swap_total_kb: u64, // from /proc/meminfo (ground truth)
    #[serde(default)]
    pub swap_free_kb: u64,  // from /proc/meminfo (ground truth)
    pub swap_used_kb: u64,
    pub swap_used_pct: f64,
    /// Cumulative pages swapped in/out since boot (/proc/vmstat pswpin/pswpout).
    /// Rate = Δ/Δt distinguishes STEADY baseline from ACTIVE thrashing.
    /// #[serde(default)]: added after v1 — old rows read as zero, never dropped.
    #[serde(default)]
    pub swap_in_pages: u64,
    #[serde(default)]
    pub swap_out_pages: u64,
}

fn meminfo_field(key: &str) -> u64 {
    let Ok(t) = std::fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    for line in t.lines() {
        if line.starts_with(key) {
            // "MemTotal:        7913184 kB"
            let v = line
                .split_whitespace()
                .nth(1)
                .and_then(|x| x.parse::<u64>().ok())
                .unwrap_or(0);
            return v;
        }
    }
    0
}

fn vmstat_field(key: &str) -> u64 {
    let Ok(t) = std::fs::read_to_string("/proc/vmstat") else {
        return 0;
    };
    for line in t.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some(key) {
            return it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        }
    }
    0
}

pub fn sample(sys: &mut System) -> MemSample {
    sys.refresh_memory();
    // sysinfo 0.30 reports bytes — normalize to KB for the snapshot schema.
    let total_kb = sys.total_memory() / 1024;
    let avail_sys_kb = sys.available_memory() / 1024;
    let available_kb = if avail_sys_kb > 0 {
        avail_sys_kb
    } else {
        meminfo_field("MemAvailable:")
    };
    let used_kb = total_kb.saturating_sub(available_kb);
    let used_pct = if total_kb > 0 {
        used_kb as f64 * 100.0 / total_kb as f64
    } else {
        0.0
    };
    // Ground truth from /proc/meminfo; fallback to sysinfo if /proc unreadable.
    let mut swap_total_kb = meminfo_field("SwapTotal:");
    let mut swap_free_kb = meminfo_field("SwapFree:");
    if swap_total_kb == 0 {
        swap_total_kb = sys.total_swap() / 1024;
        swap_free_kb = sys.free_swap() / 1024;
    }
    let swap_used_kb = swap_total_kb.saturating_sub(swap_free_kb);
    MemSample {
        total_kb,
        available_kb,
        used_kb,
        used_pct,
        free_kb: sys.free_memory() / 1024,
        buffers_kb: meminfo_field("Buffers:"),
        cached_kb: meminfo_field("Cached:"),
        shmem_kb: meminfo_field("Shmem:"),
        mlocked_kb: meminfo_field("Mlocked:"),
        swap_total_kb,
        swap_free_kb,
        swap_used_kb,
        swap_used_pct: if swap_total_kb > 0 {
            swap_used_kb as f64 * 100.0 / swap_total_kb as f64
        } else {
            0.0
        },
        swap_in_pages: vmstat_field("pswpin"),
        swap_out_pages: vmstat_field("pswpout"),
    }
}

/// Swap-out paging rate (pages/s) between two samples. ~0 + flat swap % =
/// STEADY old baseline; sustained >0 = ACTIVE thrashing.
pub fn swap_out_rate(prev: &MemSample, cur: &MemSample, dt_s: f64) -> f64 {
    if dt_s <= 0.0 {
        return 0.0;
    }
    (cur.swap_out_pages.saturating_sub(prev.swap_out_pages) as f64) / dt_s
}

pub fn swap_in_rate(prev: &MemSample, cur: &MemSample, dt_s: f64) -> f64 {
    if dt_s <= 0.0 {
        return 0.0;
    }
    (cur.swap_in_pages.saturating_sub(prev.swap_in_pages) as f64) / dt_s
}
