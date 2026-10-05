//! GPU collector via NVML. Graceful fallback when no NVIDIA GPU/driver exists
//! (CI machines, AMD-only hosts): returns `available=false` instead of crashing.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GpuSample {
    pub index: u32,
    pub name: String,
    pub available: bool,
    pub util_pct: u32,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    pub mem_used_pct: f64,
    pub temp_c: u32,
    pub clock_mhz: u32,
    pub power_w: f64,
}

pub fn sample_all() -> Vec<GpuSample> {
    match sample_nvml() {
        Ok(v) => v,
        Err(e) => vec![GpuSample {
            index: 0,
            name: format!("no-gpu ({e})"),
            available: false,
            util_pct: 0,
            mem_used_mb: 0,
            mem_total_mb: 0,
            mem_used_pct: 0.0,
            temp_c: 0,
            clock_mhz: 0,
            power_w: 0.0,
        }],
    }
}

fn sample_one(nvml: &nvml_wrapper::Nvml, i: u32) -> anyhow::Result<GpuSample> {
    use nvml_wrapper::enum_wrappers::device::{Clock, TemperatureSensor};
    // Every fallible call degrades to a zero/placeholder INDEPENDENTLY:
    // old drivers, missing sensors, and permission-denied /dev nodes
    // (non-video-group users) yield partial data, never an error, never a panic.
    let dev = nvml.device_by_index(i)?;
    let name = dev.name().unwrap_or_else(|_| format!("gpu{i}"));
    let util = dev.utilization_rates().ok();
    let mem = dev.memory_info().ok();
    let temp = dev.temperature(TemperatureSensor::Gpu).unwrap_or(0);
    let clock = dev.clock_info(Clock::Graphics).unwrap_or(0);
    let power = dev.power_usage().map(|mw| mw as f64 / 1000.0).unwrap_or(0.0);
    let (used_mb, total_mb) = match mem {
        Some(m) => (m.used / 1024 / 1024, m.total / 1024 / 1024),
        None => (0, 0),
    };
    Ok(GpuSample {
        index: i,
        name,
        available: true,
        util_pct: util.map(|u| u.gpu).unwrap_or(0),
        mem_used_mb: used_mb,
        mem_total_mb: total_mb,
        mem_used_pct: if total_mb > 0 {
            used_mb as f64 * 100.0 / total_mb as f64
        } else {
            0.0
        },
        temp_c: temp,
        clock_mhz: clock,
        power_w: power,
    })
}


fn sample_nvml() -> anyhow::Result<Vec<GpuSample>> {
    // One NVML handle per thread for life; failures retry next tick (late driver install works).
    thread_local! {
        static NVML: std::cell::RefCell<Option<nvml_wrapper::Nvml>> =
            const { std::cell::RefCell::new(None) };
    }
    let mut out = Vec::new();
    NVML.with(|cell| -> anyhow::Result<()> {
        if cell.borrow().is_none() {
            *cell.borrow_mut() = Some(nvml_wrapper::Nvml::init()?);
        }
        let nvml = cell.borrow();
        let nvml = nvml.as_ref().unwrap();
        let n = nvml.device_count()?;
        for i in 0..n {
            // Per-device isolation: ONE flaky GPU (hotplug, MIG reconfig,
            // transient NVML hiccup) must never blind the healthy ones.
            match sample_one(nvml, i) {
                Ok(g) => out.push(g),
                Err(e) => out.push(GpuSample {
                    index: i,
                    name: format!("gpu{i} unreadable ({e})"),
                    available: false,
                    ..Default::default()
                }),
            }
        }
        Ok(())
    })?;
    if out.is_empty() {
        // Driver alive, zero devices: same shape as no-driver, never empty.
        out.push(GpuSample {
            index: 0,
            name: "no-gpu (driver loaded, zero devices)".into(),
            available: false,
            ..Default::default()
        });
    }
    Ok(out)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_hardware_never_panics_and_keeps_shape() {
        // On THIS box (no NVIDIA): exactly one unavailable marker, all
        // numeric fields zeroed, downstream code can blindly iterate.
        let v = sample_all();
        assert!(!v.is_empty());
        for g in &v {
            assert!(!g.available);
            assert_eq!(g.util_pct, 0);
            assert_eq!(g.mem_used_pct, 0.0);
        }
    }

    #[test]
    fn repeated_calls_share_one_handle_without_panic() {
        // Exercises the thread-local cache path (init ONCE, reuse after).
        let a = sample_all();
        let b = sample_all();
        assert_eq!(a.len(), b.len());
    }
}