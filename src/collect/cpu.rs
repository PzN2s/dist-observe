//! CPU collector: per-core usage, NUMA topology, context switches, page faults.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumaNode {
    pub id: u32,
    pub cpus: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuSample {
    pub total_pct: f32,
    pub per_core_pct: Vec<f32>,
    pub per_core_freq_mhz: Vec<u64>,
    pub load_avg_1: f64,
    pub load_avg_5: f64,
    pub load_avg_15: f64,
    pub ctx_switches_total: u64,
    pub processes_running: u32,
    pub page_faults_minor: u64,
    pub page_faults_major: u64,
    pub numa_nodes: Vec<NumaNode>,
}

fn read_u64_from(path: &str, key: &str) -> Option<u64> {
    let t = std::fs::read_to_string(path).ok()?;
    for line in t.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some(key) {
            return it.next()?.parse().ok();
        }
    }
    None
}

fn numa_topology() -> Vec<NumaNode> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/devices/system/node") else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.starts_with("node") {
            continue;
        }
        let id: u32 = match name[4..].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let cpulist =
            std::fs::read_to_string(e.path().join("cpulist")).unwrap_or_default();
        let cpus = parse_cpulist(&cpulist);
        out.push(NumaNode { id, cpus });
    }
    out.sort_by_key(|n| n.id);
    out
}

fn parse_cpulist(s: &str) -> Vec<u32> {
    let mut cpus = Vec::new();
    for part in s.trim().split(',') {
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) {
                cpus.extend(a..=b);
            }
        } else if let Ok(v) = part.parse::<u32>() {
            cpus.push(v);
        }
    }
    cpus
}

pub fn sample(sys: &mut System) -> CpuSample {
    sys.refresh_cpu();
    let cpus = sys.cpus();
    let per_core_pct = cpus.iter().map(|c| c.cpu_usage()).collect::<Vec<_>>();
    let per_core_freq_mhz = cpus.iter().map(|c| c.frequency()).collect::<Vec<_>>();
    let total_pct = if per_core_pct.is_empty() {
        0.0
    } else {
        per_core_pct.iter().sum::<f32>() / per_core_pct.len() as f32
    };
    let load = System::load_average();

    // /proc/stat: "ctxt <n>" + "procs_running <n>"
    let mut ctx = 0u64;
    let mut running = 0u32;
    if let Ok(stat) = std::fs::read_to_string("/proc/stat") {
        for line in stat.lines() {
            if let Some(v) = line.strip_prefix("ctxt ") {
                ctx = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("procs_running ") {
                running = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
            }
        }
    }
    let minor = read_u64_from("/proc/vmstat", "pgfault").unwrap_or(0);
    let major = read_u64_from("/proc/vmstat", "pgmajfault").unwrap_or(0);

    CpuSample {
        total_pct,
        per_core_pct,
        per_core_freq_mhz,
        load_avg_1: load.one,
        load_avg_5: load.five,
        load_avg_15: load.fifteen,
        ctx_switches_total: ctx,
        processes_running: running,
        page_faults_minor: minor,
        page_faults_major: major,
        numa_nodes: numa_topology(),
    }
}

/// NUMA imbalance detector: max node avg vs min node avg (needs per-core + topology).
pub fn numa_imbalance(sample: &CpuSample) -> Option<f32> {
    if sample.numa_nodes.is_empty() || sample.per_core_pct.is_empty() {
        return None;
    }
    let mut avgs = Vec::new();
    for n in &sample.numa_nodes {
        let vals: Vec<f32> = n
            .cpus
            .iter()
            .filter_map(|c| sample.per_core_pct.get(*c as usize).copied())
            .collect();
        if !vals.is_empty() {
            avgs.push(vals.iter().sum::<f32>() / vals.len() as f32);
        }
    }
    if avgs.len() < 2 {
        return None;
    }
    let (mut mn, mut mx) = (f32::MAX, f32::MIN);
    for v in avgs {
        mn = mn.min(v);
        mx = mx.max(v);
    }
    Some(mx - mn)
}

#[allow(dead_code)]
pub fn _map_example() -> HashMap<String, String> {
    HashMap::new()
}
