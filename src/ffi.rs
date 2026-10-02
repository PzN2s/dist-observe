//! FFI memory tracking: where RSS *really* lives, per process.
//! A heap profiler (tracemalloc, heapy, DHAT) sees only managed allocations.
//! Memory malloc'd/mmap'd across an FFI boundary (C extension, ctypes, Rust
//! cdylib, CUDA pinned buffers) bypasses it entirely — yet it all shows up in
//! /proc/PID/smaps. We parse smaps per mapping and attribute every kilobyte to
//! exactly one category, so a leak reads as:
//!   "anon-mmap +45MB while heap flat → native/FFI leak, heap profilers blind"
//! instead of "RSS grew, good luck".
//!
//! Python-arena heuristic: CPython obmalloc owns 256 KiB arenas (anon, rw,
//! exactly 262144 bytes). Counting them separates "Python objects" from raw
//! native mmaps without attaching to the interpreter.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessMem {
    pub pid: u32,
    pub comm: String,
    pub rss_kb: u64,
    pub pss_kb: u64,
    pub heap_kb: u64,   // brk [heap] — what sbrk/malloc-small uses
    pub stack_kb: u64,
    pub anon_kb: u64,   // anonymous mmaps — malloc-large, FFI buffers, Rust Vecs spilled here
    pub file_kb: u64,   // file-backed (libraries, binaries, data files)
    pub shm_kb: u64,    // /dev/shm, SYSV, memfd — IPC incl. FFI zero-copy rings
    pub gpu_kb: u64,    // /dev/nvidia* device mappings visible in smaps
    pub guard_kb: u64,   // '---p' reservations, not real memory
    pub other_kb: u64,   // vdso/vvar and friends
    pub arena_count: u32,
    pub arena_kb: u64, // subset of anon_kb: likely CPython arenas
    pub top_libs: Vec<(String, u64)>, // path → rss_kb, top 5
}

impl ProcessMem {
    /// RSS living OUTSIDE the brk heap: the FFI/native blind spot.
    pub fn ffi_gap_kb(&self) -> u64 {
        self.rss_kb.saturating_sub(self.heap_kb)
    }
}

pub struct Mapping {
    pub perms: String,
    pub size_kb: u64,
    pub rss_kb: u64,
    pub pss_kb: u64,
    pub pathname: String,
}

fn field_kb(stripped: &str) -> u64 {
    // stripped = text AFTER "Label:" → ["44", "kB"]
    stripped.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// Parse raw /proc/PID/smaps text into mappings.
pub fn parse_smaps(text: &str) -> Vec<Mapping> {
    let mut out = Vec::new();
    let mut cur: Option<Mapping> = None;
    for line in text.lines() {
        // header: "00400000-0040b000 r--p 00000000 00:28 123 /usr/bin/foo" (path optional)
        let mut parts = line.split_whitespace();
        let is_hdr = match (parts.next(), parts.next()) {
            (Some(addr), Some(perms)) => {
                addr.contains('-')
                    && perms.len() == 4
                    && perms.chars().all(|c| "rwxps-".contains(c))
                    && {
                        let halves: Vec<&str> = addr.split('-').collect();
                        halves.len() == 2
                            && halves.iter().all(|h| {
                                !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit())
                            })
                    }
            }
            _ => false,
        };
        if is_hdr {
            if let Some(m) = cur.take() {
                out.push(m);
            }
            let mut parts = line.split_whitespace();
            parts.next();
            let perms = parts.next().unwrap_or("").to_string();
            let rest: Vec<&str> = parts.collect();
            // after perms: offset dev inode [path...] — path is the 4th+ token if present
            let pathname = if rest.len() >= 4 { rest[3..].join(" ") } else { String::new() };
            cur = Some(Mapping { perms, size_kb: 0, rss_kb: 0, pss_kb: 0, pathname });
            continue;
        }
        if let Some(m) = cur.as_mut() {
            if let Some(v) = line.strip_prefix("Size:") {
                m.size_kb = field_kb(v);
            } else if let Some(v) = line.strip_prefix("Rss:") {
                m.rss_kb = field_kb(v);
            } else if let Some(v) = line.strip_prefix("Pss:") {
                m.pss_kb = field_kb(v);
            }
        }
    }
    if let Some(m) = cur.take() {
        out.push(m);
    }
    out
}

const ARENA_BYTES: u64 = 262_144; // CPython obmalloc arena = 256 KiB

pub fn attribute(pid: u32, comm: String, maps: &[Mapping]) -> ProcessMem {
    let mut pm = ProcessMem { pid, comm, ..Default::default() };
    let mut libs: HashMap<String, u64> = HashMap::new();
    for m in maps {
        pm.rss_kb += m.rss_kb;
        pm.pss_kb += m.pss_kb;
        if m.perms.starts_with("---") {
            pm.guard_kb += m.size_kb;
            continue;
        }
        let p = m.pathname.as_str();
        if p == "[heap]" {
            pm.heap_kb += m.rss_kb;
        } else if p == "[stack]" || p.starts_with("[stack:") {
            pm.stack_kb += m.rss_kb;
        } else if p.starts_with("[anon") {
            pm.anon_kb += m.rss_kb;
            if m.perms.starts_with("rw") && m.size_kb * 1024 == ARENA_BYTES {
                pm.arena_count += 1;
                pm.arena_kb += m.rss_kb;
            }
        } else if p.starts_with("/dev/shm/") || p.starts_with("SYSV") || p.starts_with("/SYSV") || p.starts_with("/memfd:") || p.starts_with("memfd:") {
            pm.shm_kb += m.rss_kb;
        } else if p.starts_with("/dev/nvidia") {
            pm.gpu_kb += m.rss_kb;
        } else if p.starts_with('/') {
            pm.file_kb += m.rss_kb;
            if p.contains(".so") {
                *libs.entry(p.to_string()).or_insert(0) += m.rss_kb;
            }
        } else if p.is_empty() {
            pm.anon_kb += m.rss_kb;
            if m.perms.starts_with("rw") && m.size_kb * 1024 == ARENA_BYTES {
                pm.arena_count += 1;
                pm.arena_kb += m.rss_kb;
            }
        } else {
            pm.other_kb += m.rss_kb; // vdso, vvar, vsyscall…
        }
    }
    let mut libs: Vec<(String, u64)> = libs.into_iter().collect();
    libs.sort_by_key(|a| std::cmp::Reverse(a.1));
    libs.truncate(5);
    pm.top_libs = libs;
    pm
}

fn read_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into())
}

fn fast_rss_kb(pid: u32) -> Option<u64> {
    let t = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in t.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            return v.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

pub fn sample_pid(pid: u32) -> Option<ProcessMem> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/smaps")).ok()?;
    let maps = parse_smaps(&text);
    Some(attribute(pid, read_comm(pid), &maps))
}

/// Top-N processes by RSS with full smaps attribution (skips unreadable ones).
/// Over-samples 4× because smaps needs same-UID/CAP_SYS_PTRACE while status
/// is world-readable — the biggest RSS holders are often another user's.
pub fn top_n(n: usize) -> (Vec<ProcessMem>, usize) {
    let mut cands: Vec<(u32, u64)> = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return (vec![], 0);
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if let Ok(pid) = name.parse::<u32>() {
            if let Some(rss) = fast_rss_kb(pid) {
                cands.push((pid, rss));
            }
        }
    }
    cands.sort_by_key(|a| std::cmp::Reverse(a.1));
    let mut skipped = 0usize;
    let mut out = Vec::new();
    for (pid, _) in cands.into_iter().take(n * 4 + 4) {
        match sample_pid(pid) {
            Some(p) => {
                out.push(p);
                if out.len() >= n {
                    break;
                }
            }
            None => skipped += 1,
        }
    }
    (out, skipped)
}

/// Least-squares slope (KB per hour) of a (t_seconds, value) series.
fn slope_per_hour(ts: &[f64], vals: &[f64]) -> f64 {
    let n = ts.len() as f64;
    if n < 2.0 {
        return 0.0;
    }
    let mx = ts.iter().sum::<f64>() / n;
    let my = vals.iter().sum::<f64>() / n;
    let (mut num, mut den) = (0.0, 0.0);
    for (x, y) in ts.iter().zip(vals.iter()) {
        num += (x - mx) * (y - my);
        den += (x - mx) * (x - mx);
    }
    if den.abs() < 1e-12 {
        return 0.0;
    }
    num / den * 3600.0
}

pub struct TrendVerdict {
    pub text: String,
}

/// Which category is actually leaking? Growth ranking, not vibes.
pub fn leak_verdict(history: &[ProcessMem]) -> TrendVerdict {
    if history.len() < 3 {
        return TrendVerdict { text: "need ≥3 samples".into() };
    }
    let ts: Vec<f64> = (0..history.len()).map(|i| i as f64).collect();
    let series = [
        ("heap (brk)", history.iter().map(|p| p.heap_kb as f64).collect::<Vec<_>>()),
        ("anon-mmap", history.iter().map(|p| p.anon_kb as f64).collect::<Vec<_>>()),
        ("file", history.iter().map(|p| p.file_kb as f64).collect::<Vec<_>>()),
        ("shm", history.iter().map(|p| p.shm_kb as f64).collect::<Vec<_>>()),
        ("gpu-map", history.iter().map(|p| p.gpu_kb as f64).collect::<Vec<_>>()),
    ];
    // NOTE: rss-total is deliberately NOT ranked — it is the sum of the above
    // and would always trivially "lead". It is reported as context only.
    let rss_growth = history.last().map(|p| p.rss_kb as f64).unwrap_or(0.0)
        - history.first().map(|p| p.rss_kb as f64).unwrap_or(0.0);
    let mut growth: Vec<(&str, f64, f64)> = series
        .iter()
        .map(|(name, vals)| {
            let g = vals.last().unwrap_or(&0.0) - vals.first().unwrap_or(&0.0);
            (*name, g, slope_per_hour(&ts, vals))
        })
        .collect();
    growth.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut o = String::new();
    for (name, g, rate) in &growth {
        o.push_str(&format!("  {name:10} {g:+8.0} KB total ({rate:+.0} KB/h)\n"));
    }
    o.push_str(&format!("  rss-total  {rss_growth:+8.0} KB (context only, not ranked)\n"));
    let (top_name, top_g, _) = growth[0];
    const NOISE_KB: f64 = 1024.0; // <1MB over the window = noise
    let verdict = if top_g < NOISE_KB {
        "no leak signature: all categories flat (<1MB growth)".to_string()
    } else if top_name == "anon-mmap" {        let heap_g = growth.iter().find(|(n, _, _)| *n == "heap (brk)").map(|x| x.1).unwrap_or(0.0);
        if heap_g < NOISE_KB {
            format!(
                "native/FFI LEAK: anon-mmap +{top_g:.0} KB while heap flat — \
                 malloc/mmap without free, or unreleased FFI buffers. \
                 Heap profilers (tracemalloc/heapy) are BLIND here; check native code / ctypes / cdylib paths"
            )
        } else {
            format!("mixed growth: anon-mmap +{top_g:.0} KB leads but heap also grows — check both")
        }
    } else if top_name == "heap (brk)" {
        format!("managed-heap growth +{top_g:.0} KB — visible to language profilers (tracemalloc/heapy/DHAT)")
    } else if top_name == "shm" {
        format!("shared-memory growth +{top_g:.0} KB — IPC/zero-copy rings or leaked shm segments (check /dev/shm, ipcs)")
    } else if top_name == "file" {
        format!("file-backed growth +{top_g:.0} KB — libraries or mmapped data files")
    } else {
        format!("{top_name} leads with +{top_g:.0} KB")
    };
    TrendVerdict { text: format!("{o}  → {verdict}") }
}

pub fn render_top(rows: &[ProcessMem], skipped: usize) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "{:>7} {:<16} {:>9} {:>9} {:>8} {:>8} {:>8} {:>7} {:>6}  {}\n",
        "PID", "COMM", "RSS", "PSS", "HEAP", "ANON", "FILE", "SHM", "ARENA", "TOP-LIB"
    ));
    for p in rows {
        let lib = p.top_libs.first().map(|(l, k)| format!("{} {}MB", short_lib(l), k / 1024)).unwrap_or_default();
        o.push_str(&format!(
            "{:>7} {:<16} {:>8}M {:>8}M {:>7}M {:>7}M {:>7}M {:>6}M {:>5}×  {}\n",
            p.pid,
            trunc(&p.comm, 16),
            p.rss_kb / 1024,
            p.pss_kb / 1024,
            p.heap_kb / 1024,
            p.anon_kb / 1024,
            p.file_kb / 1024,
            p.shm_kb / 1024,
            p.arena_count,
            lib
        ));
    }
    o.push_str("(RSS−heap = FFI/native blind spot · ARENA× = likely CPython 256K arenas)\n");
    if skipped > 0 {
        o.push_str(&format!("(skipped {skipped} unreadable PIDs — smaps needs same-UID or root)\n"));
    }
    o
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { s[..n].to_string() }
}

fn short_lib(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
00400000-0040b000 r--p 00000000 00:28 123 /usr/bin/python3
Size:                44 kB
Rss:                 40 kB
Pss:                 40 kB
00e5b000-00e7c000 rw-p 00000000 00:00 0 [heap]
Size:               132 kB
Rss:                100 kB
Pss:                100 kB
7f000000-7f040000 rw-p 00000000 00:00 0
Size:               256 kB
Rss:                200 kB
Pss:                200 kB
7f040000-7f080000 rw-p 00000000 00:00 0
Size:               256 kB
Rss:                256 kB
Pss:                256 kB
7f080000-7f180000 rw-p 00000000 00:00 0
Size:              1024 kB
Rss:                512 kB
Pss:                512 kB
7f180000-7f280000 r--p 00000000 00:28 456 /usr/lib/libfoo.so
Size:              1024 kB
Rss:                300 kB
Pss:                100 kB
7f280000-7f290000 rw-p 00000000 00:00 0 /dev/shm/ring
Size:                64 kB
Rss:                 64 kB
Pss:                 32 kB
7fff0000-7fff8000 rw-p 00000000 00:00 0 [stack]
Size:                32 kB
Rss:                 16 kB
Pss:                 16 kB
ffffffffff600000-ffffffffff601000 ---p 00000000 00:00 0 [vsyscall]
Size:                 4 kB
Rss:                  0 kB
Pss:                  0 kB
";

    #[test]
    fn parses_all_mappings() {
        let m = parse_smaps(SAMPLE);
        assert_eq!(m.len(), 9, "got {} mappings", m.len());
        assert_eq!(m[0].pathname, "/usr/bin/python3");
        assert_eq!(m[2].pathname, "");
        assert_eq!(m[2].size_kb, 256);
    }

    #[test]
    fn attributes_categories() {
        let m = parse_smaps(SAMPLE);
        let p = attribute(1234, "python3".into(), &m);
        assert_eq!(p.heap_kb, 100);
        assert_eq!(p.stack_kb, 16);
        assert_eq!(p.shm_kb, 64);
        assert_eq!(p.file_kb, 40 + 300);
        assert_eq!(p.arena_count, 2, "two 256K anon arenas");
        assert_eq!(p.arena_kb, 200 + 256);
        // anon = 200+256 arenas + 512 big mmap (guard excluded, vsyscall excluded)
        assert_eq!(p.anon_kb, 200 + 256 + 512);
        assert_eq!(p.guard_kb, 4);
        assert_eq!(p.other_kb, 0);
        assert_eq!(p.top_libs, vec![("/usr/lib/libfoo.so".to_string(), 300)]);
        assert_eq!(p.rss_kb, 40 + 100 + 200 + 256 + 512 + 300 + 64 + 16);
        assert_eq!(p.ffi_gap_kb(), p.rss_kb - 100);
    }

    #[test]
    fn verdict_native_leak_heap_flat() {
        let mk = |heap: u64, anon: u64| ProcessMem {
            pid: 1, comm: "x".into(), rss_kb: heap + anon, heap_kb: heap, anon_kb: anon,
            ..Default::default()
        };
        let hist: Vec<ProcessMem> = (0..5).map(|i| mk(100, 1000 + i * 9000)).collect();
        let v = leak_verdict(&hist);
        assert!(v.text.contains("FFI LEAK"), "got: {}", v.text);
    }

    #[test]
    fn verdict_flat_is_quiet() {
        let mk = || ProcessMem { pid: 1, comm: "x".into(), rss_kb: 5000, heap_kb: 100, anon_kb: 4000, ..Default::default() };
        let hist = vec![mk(), mk(), mk(), mk()];
        assert!(leak_verdict(&hist).text.contains("no leak signature"));
    }

    #[test]
    fn verdict_managed_heap() {
        let mk = |heap: u64| ProcessMem { pid: 1, comm: "x".into(), rss_kb: heap + 4000, heap_kb: heap, anon_kb: 4000, ..Default::default() };
        let hist: Vec<ProcessMem> = (0..4).map(|i| mk(100 + i * 5000)).collect();
        assert!(leak_verdict(&hist).text.contains("managed-heap"), "got: {}", leak_verdict(&hist).text);
    }

    #[test]
    fn verdict_rss_total_never_wins_ranking() {
        // Soak regression: anon +213616, file +312, heap 0 → rss-total (+213928)
        // trivially exceeds anon. The verdict must still blame anon-mmap.
        let mk = |i: u64| ProcessMem {
            pid: 1, comm: "x".into(),
            rss_kb: 8000 + i * 53482, heap_kb: 100,
            anon_kb: 4000 + i * 53404, file_kb: 500 + i * 78,
            ..Default::default()
        };
        let hist: Vec<ProcessMem> = (0..4).map(mk).collect();
        let v = leak_verdict(&hist);
        assert!(v.text.contains("FFI LEAK"), "got: {}", v.text);
        assert!(!v.text.starts_with("  → rss-total"), "rss-total must not win: {}", v.text);
    }
}
