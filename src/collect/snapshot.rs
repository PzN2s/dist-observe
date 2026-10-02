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
    pub net: NetSample,
    pub psi: PsiSample,
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
