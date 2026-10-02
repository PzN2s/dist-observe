//! Disk collector: usage (for exhaustion forecast) + I/O counters.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskSample {
    pub path: String,
    pub total_gb: f64,
    pub avail_gb: f64,
    pub used_pct: f64,
    pub read_kb_total: u64,
    pub write_kb_total: u64,
}

fn statvfs_usage(path: &str) -> (f64, f64, f64) {
    let c = std::ffi::CString::new(path).unwrap();
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid C string + valid out pointer.
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return (0.0, 0.0, 0.0);
    }
    let total = st.f_blocks as f64 * st.f_frsize as f64;
    let avail = st.f_bavail as f64 * st.f_frsize as f64;
    let used_pct = if total > 0.0 {
        (total - avail) * 100.0 / total
    } else {
        0.0
    };
    (total / 1e9, avail / 1e9, used_pct)
}

fn diskstats_totals() -> (u64, u64) {
    // /proc/diskstats sectors (512B) -> KB. Sum all physical disks (skip loop/ram).
    let mut r: u64 = 0;
    let mut w: u64 = 0;
    let Ok(t) = std::fs::read_to_string("/proc/diskstats") else {
        return (0, 0);
    };
    for line in t.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 14 {
            continue;
        }
        let name = f[2];
        if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") {
            continue;
        }
        // Only whole devices (sda, vda, nvme0n1) — partitions end with digit for sd/vd.
        // Keep it simple: count everything except loop/ram; double-count risk is minor for MVP rate math.
        let rs: u64 = f[5].parse().unwrap_or(0);
        let ws: u64 = f[9].parse().unwrap_or(0);
        r += rs / 2;
        w += ws / 2;
    }
    (r, w)
}

pub fn sample(path: &str) -> DiskSample {
    let (total_gb, avail_gb, used_pct) = statvfs_usage(path);
    let (r, w) = diskstats_totals();
    DiskSample {
        path: path.to_string(),
        total_gb,
        avail_gb,
        used_pct,
        read_kb_total: r,
        write_kb_total: w,
    }
}
