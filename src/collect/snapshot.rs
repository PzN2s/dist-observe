//! One complete snapshot: every layer stamped with the SAME unified timestamp.
//! This is the differentiator — no per-tool clock skew.
use crate::collect::{cpu::CpuSample, disk::DiskSample, gpu::GpuSample, mem::MemSample, net::NetSample, psi::PsiSample, tenant::TenantSample};
use crate::clock::UnifiedTimestamp;
use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedSnapshot {
    pub ts: UnifiedTimestamp,
    pub hostname: String,
    pub cpu: CpuSample,
    pub mem: MemSample,
    pub disk: DiskSample,
    pub gpus: Vec<GpuSample>,
    // #[serde(default)]: snapshots recorded by older binaries lack these —
    // replay/show must read them as zeroed, never drop the row.
    #[serde(default)]
    pub net: NetSample,
    #[serde(default)]
    pub psi: PsiSample,
    #[serde(default)]
    pub tenant: TenantSample,
}

pub fn take(sys: &mut System, disk_path: &str) -> UnifiedSnapshot {
    // ONE timestamp for all layers in this tick.
    let ts = UnifiedTimestamp::now();
    let cpu = crate::collect::cpu::sample(sys);
    let mem = crate::collect::mem::sample(sys);
    let disk = crate::collect::disk::sample(disk_path);
    let gpus = crate::collect::gpu::sample_all();
    let net = crate::collect::net::sample();
    let psi = crate::collect::psi::sample();
    let tenant = crate::collect::tenant::sample();
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".into());
    UnifiedSnapshot {
        ts,
        hostname,
        cpu,
        mem,
        disk,
        gpus,
        net,
        psi,
        tenant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v1-era JSON (no net/psi/tenant, no swap_free/in/out_pages) must still
    /// parse after upgrades — replay/show on old DBs, never silent drops.
    #[test]
    fn old_schema_rows_still_parse() {
        let old = r#"{"ts":{"wall_ns":1700000000000000000,"mono_ns":1,"wall_iso":"t"},
            "hostname":"h","cpu":{"total_pct":10.0,"per_core_pct":[],"per_core_freq_mhz":[],
            "load_avg_1":0.0,"load_avg_5":0.0,"load_avg_15":0.0,"ctx_switches_total":0,
            "processes_running":0,"page_faults_minor":0,"page_faults_major":0,"numa_nodes":[]},
            "mem":{"total_kb":100,"available_kb":50,"used_kb":50,"used_pct":50.0,"free_kb":50,
            "buffers_kb":0,"cached_kb":0,"shmem_kb":0,"mlocked_kb":0,"swap_total_kb":0,
            "swap_used_kb":0,"swap_used_pct":0.0},
            "disk":{"path":"/","total_gb":10.0,"avail_gb":9.0,"used_pct":10.0,
            "read_kb_total":0,"write_kb_total":0},"gpus":[]}"#;
        let s: UnifiedSnapshot = serde_json::from_str(old).expect("old rows must parse");
        assert_eq!(s.mem.swap_in_pages, 0);
        assert!(s.net.conns.is_empty());
        assert_eq!(s.hostname, "h");
    }
}
