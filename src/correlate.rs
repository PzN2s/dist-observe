//! Anomaly correlator: ring buffer keyed by unified timestamp.
//! Steady highs stay silent (cooldown + delta gates); only new events fire.

use crate::collect::snapshot::UnifiedSnapshot;
use std::collections::{HashMap, VecDeque};

/// Minimum re-alert interval per anomaly type (seconds) + minimum value delta
/// that counts as "material change" and re-fires immediately.
/// Spike detector tuning: fire when current rate >= max(FLOOR, FACTOR × median).
const SPIKE_HIST_N: usize = 10;
const SPIKE_MIN_BASELINE: usize = 4;
const SPIKE_FACTOR: f64 = 5.0;
const SPIKE_FLOOR: f64 = 300.0; // pages/s — below this is noise, never a spike

fn delta_for(key: &str) -> f64 {
    match key {
        "cpu" => 5.0,    // pct points
        "mem" => 2.0,
        "swap" => 2.0,
        "disk" => 1.0,
        "numa" => 10.0,
        // paging-rate keys: absolute deltas are meaningless for rates;
        // they re-fire on fresh spikes (force) or cooldown expiry only.
        "pgin" | "pgout" | "retrans" | "tcploss" | "nstorm" => f64::INFINITY,
        k if k.starts_with("temp") => 2.0, // °C
        k if k.starts_with("vram") => 3.0,
        _ => 1.0,
    }
}

fn median_of(hist: &VecDeque<f64>) -> f64 {
    if hist.is_empty() {
        return 0.0;
    }
    let mut v: Vec<f64> = hist.iter().copied().collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

fn rate_spike_tuned(
    hist: &VecDeque<f64>,
    cur: f64,
    factor: f64,
    floor: f64,
) -> Option<(f64, f64)> {
    if hist.len() < SPIKE_MIN_BASELINE {
        return None; // not enough baseline yet — refuse to judge
    }
    let med = median_of(hist);
    let threshold = (factor * med).max(floor);
    if cur >= threshold {
        Some((med, threshold))
    } else {
        None
    }
}

/// Neighbor-storm digest: extreme sustained host noise escalates once (capacity incident).
const NSTORM_WINDOW_NS: u64 = 600_000_000_000; // trailing 10 minutes
const NSTORM_TH: usize = 20; // fire at this many neighbor detections…
const NSTORM_REARM: usize = 10; // …and re-arm only once it calms below this
fn spike_floor(key: &str) -> f64 {
    match key {
        "pgin" | "pgout" => 300.0,   // pages/s
        "retrans" => 50.0,            // segs/s — wifi baseline is ~0-5/s
        "tcploss" => 10.0,            // loss events/s — any cluster matters
        _ => SPIKE_FLOOR,
    }
}

struct Reason {
    key: String,
    msg: String,
    value: f64,
    /// A new event even if `value` barely moved (e.g. quiet → thrashing transition).
    force: bool,
}

pub struct Correlator {
    buf: VecDeque<UnifiedSnapshot>,
    capacity: usize,
    pub window_ms: i64,
    cooldown_s: f64,
    /// key -> (last emitted mono_ns, last emitted value)
    last_emit: HashMap<String, (u64, f64)>,
    suppressed: HashMap<String, u64>,
    /// Previous swap-out rate; quiet→active transitions are new events.
    last_swap_out_rate: f64,
    /// Per-signal rate baselines for the median spike detector
    /// (pgin/pgout/retrans/tcploss…).
    sig_hists: HashMap<String, VecDeque<f64>>,
    /// Edge-triggered spikes: only quiet→spiking transitions force-fire.
    sig_active: HashMap<String, bool>,
    /// Timestamps (mono_ns) of neighbor-labeled spike DETECTIONS (fired or
    /// suppressed — evidence accumulates either way) + digest edge state.
    nstorm_times: VecDeque<u64>,
    nstorm_active: bool,
}

#[derive(Debug)]
pub struct Anomaly {
    pub at_iso: String,
    pub reasons: Vec<String>,
    /// e.g. "swap ×3 (Δ0.1% < 2.0%, cooldown 30s)" — why silence is not missing data.
    pub suppressed: Vec<String>,
    pub snapshot: UnifiedSnapshot,
}

/// Display-only triage for `--only-actionable`: show an anomaly iff at least
/// one reason is fresh (not a cooldown reminder) and not filed as neighbor
/// noise. STORAGE IS UNTOUCHED — snapshots and full logs are always written;
/// this gates `println` only, so any filtered event stays investigable.
pub fn is_actionable(reasons: &[String]) -> bool {
    reasons.iter().any(|r| {
        !r.contains("NEIGHBOR noise") && !r.contains("(after ×")
    })
}

impl Correlator {
    pub fn with_cooldown(capacity: usize, window_ms: i64, cooldown_s: f64) -> Self {
        Self {
            buf: VecDeque::with_capacity(capacity),
            capacity,
            window_ms,
            cooldown_s,
            last_emit: HashMap::new(),
            suppressed: HashMap::new(),
            last_swap_out_rate: 0.0,
            sig_hists: HashMap::new(),
            sig_active: HashMap::new(),
            nstorm_times: VecDeque::new(),
            nstorm_active: false,
        }
    }

    fn hist_push(hist: &mut VecDeque<f64>, v: f64) {
        hist.push_back(v);
        if hist.len() > SPIKE_HIST_N {
            hist.pop_front();
        }
    }

    /// Spike-check `cur` for signal `key` against its own baseline, then record
    /// it. Returns (spike, was_already_active). History never contains `cur`
    /// at decision time. `spike && !was_active` = rising edge → force-fire.
    fn sig_check(&mut self, key: &str, cur: f64) -> (Option<(f64, f64)>, bool) {
        let hist = self
            .sig_hists
            .entry(key.to_string())
            .or_default();
        let spike = rate_spike_tuned(hist, cur, SPIKE_FACTOR, spike_floor(key));
        let was_active = self.sig_active.get(key).copied().unwrap_or(false);
        Self::hist_push(hist, cur);
        self.sig_active.insert(key.to_string(), spike.is_some());
        (spike, was_active)
    }

    pub fn push(&mut self, s: UnifiedSnapshot) -> Option<Anomaly> {
        let prev = self.buf.back().cloned();
        // Current rates (paging + TCP). Swap-out also drives the
        // quiet→active transition rule below.
        let (cur_in, cur_out, cur_retrans, cur_loss) = match prev.as_ref() {
            Some(p) => {
                let dt =
                    (s.ts.mono_ns.saturating_sub(p.ts.mono_ns) as f64) / 1e9;
                let nr = crate::collect::net::rate;
                (
                    crate::collect::mem::swap_in_rate(&p.mem, &s.mem, dt),
                    crate::collect::mem::swap_out_rate(&p.mem, &s.mem, dt),
                    nr(s.net.retrans_segs, p.net.retrans_segs, dt),
                    nr(
                        s.net.loss_events(),
                        p.net.loss_events(),
                        dt,
                    ),
                )
            }
            None => (0.0, 0.0, 0.0, 0.0),
        };
        let mut reasons = detect(&s, prev.as_ref());
        // Quiet → thrashing transition is a NEW event even if swap % barely moved.
        let rate_transition = self.last_swap_out_rate < ACTIVE_PAGING_RATE
            && cur_out >= ACTIVE_PAGING_RATE;
        self.last_swap_out_rate = cur_out;
        if rate_transition {
            for r in reasons.iter_mut().filter(|r| r.key == "swap") {
                r.force = true;
            }
        }
        // ACTIVITY spikes vs own median baselines — independent of levels.
        // Tenant suffix answers "whose storm is it?" from PSI at the same tick.
        let tloc = tenant_suffix(&s, prev.as_ref());
        if s.mem.swap_total_kb > 0 {
            let (pgin_spike, pgin_was) = self.sig_check("pgin", cur_in);
        if let Some((med, thr)) = pgin_spike {
                reasons.push(Reason {
                    key: "pgin".into(),
                    msg: format!(
                        "paging spike: pswpin {cur_in:.0}/s (median {med:.0}/s, thr {thr:.0}/s){tloc}"
                    ),
                    value: cur_in,
                    force: !pgin_was,
                });
            }
            let (pgout_spike, pgout_was) = self.sig_check("pgout", cur_out);
        if let Some((med, thr)) = pgout_spike {
                reasons.push(Reason {
                    key: "pgout".into(),
                    msg: format!(
                        "paging spike: pswpout {cur_out:.0}/s (median {med:.0}/s, thr {thr:.0}/s){tloc}"
                    ),
                    value: cur_out,
                    force: !pgout_was,
                });
            }
        }
        // TCP stack activity: retransmit / loss-event spikes + the verdict that
        // separates "real network problem" from "local pressure in disguise".
        let (retr_spike, retr_was) = self.sig_check("retrans", cur_retrans);
        if let Some((med, thr)) = retr_spike {
            reasons.push(Reason {
                key: "retrans".into(),
                msg: format!(
                    "TCP retransmit spike: {cur_retrans:.0} segs/s (median {med:.0}/s, thr {thr:.0}/s) — {}",
                    net_verdict(&s, prev.as_ref())
                ),
                value: cur_retrans,
                force: !retr_was,
            });
        }
        let (loss_spike, loss_was) = self.sig_check("tcploss", cur_loss);
        if let Some((med, thr)) = loss_spike {
            reasons.push(Reason {
                key: "tcploss".into(),
                msg: format!(
                        "TCP loss-event spike: {cur_loss:.0}/s timeouts+fastretrans (median {med:.0}/s, thr {thr:.0}/s) — {}",
                    net_verdict(&s, prev.as_ref())
                ),
                value: cur_loss,
                force: !loss_was,
            });
        }
        // Storm digest counts active (not just spiking) samples: medians adapt
        // within ~5 ticks, but sustained extremes are still evidence.
        let now_mono = s.ts.mono_ns;
        let extreme = cur_in >= spike_floor("pgin")
            || cur_out >= spike_floor("pgout")
            || cur_retrans >= spike_floor("retrans")
            || cur_loss >= spike_floor("tcploss");
        if extreme && tenant_suffix(&s, prev.as_ref()).contains("NEIGHBOR noise") {
            self.nstorm_times.push_back(now_mono);
        }
        while self
            .nstorm_times
            .front()
            .map(|t| now_mono.saturating_sub(*t) > NSTORM_WINDOW_NS)
            .unwrap_or(false)
        {
            self.nstorm_times.pop_front();
        }
        if self.nstorm_times.len() >= NSTORM_TH && !self.nstorm_active {
            self.nstorm_active = true;
            reasons.push(Reason {
                key: "nstorm".into(),
                msg: format!(
                    "neighbor storm: {} host-level spikes in 10min, tenant clean throughout — \
                     escalate (migrate/throttle/complain), not a local bug. \
                     Raw stream was filtered from view; full log retained",
                    self.nstorm_times.len()
                ),
                value: self.nstorm_times.len() as f64,
                force: true,
            });
        } else if self.nstorm_times.len() < NSTORM_REARM {
            self.nstorm_active = false;
        }
        self.buf.push_back(s.clone());
        if self.buf.len() > self.capacity {
            self.buf.pop_front();
        }
        if reasons.is_empty() {
            return None;
        }
        // Gather neighbors within ±window using monotonic clock (immune to NTP jumps).
        let center = s.ts.mono_ns as i64;
        let win_ns = self.window_ms * 1_000_000;
        let _near: Vec<&UnifiedSnapshot> = self
            .buf
            .iter()
            .filter(|o| ((o.ts.mono_ns as i64) - center).abs() <= win_ns)
            .collect();

        // Delta + cooldown gate per reason key.
        let mut fire = Vec::new();
        let mut still_suppressed = Vec::new();
        for r in reasons {
            let delta_need = delta_for(&r.key);
            let should_fire = match self.last_emit.get(&r.key) {
                None => true, // first sighting always fires
                Some((last_ns, last_val)) => {
                    let dt_s =
                        (s.ts.mono_ns.saturating_sub(*last_ns) as f64) / 1e9;
                    let moved = (r.value - *last_val).abs() >= delta_need;
                    r.force || moved || dt_s >= self.cooldown_s
                }
            };
            if should_fire {
                self.last_emit
                    .insert(r.key.clone(), (s.ts.mono_ns, r.value));
                // reset suppression counter on fire; report how many were held back
                let held = self.suppressed.remove(&r.key).unwrap_or(0);
                let msg = if held > 0 {
                    format!("{} (after ×{} suppressed)", r.msg, held)
                } else {
                    r.msg
                };
                fire.push(msg);
            } else {
                let n = self.suppressed.entry(r.key.clone()).or_insert(0);
                *n += 1;
                let (last_ns, last_val) = self.last_emit[&r.key];
                let dt_s =
                    (s.ts.mono_ns.saturating_sub(last_ns) as f64) / 1e9;
                still_suppressed.push(format!(
                    "{} ×{} (Δ{:.1} < {:.1}, {:.0}s/{}s cooldown)",
                    r.key,
                    *n,
                    (r.value - last_val).abs(),
                    delta_need,
                    dt_s,
                    self.cooldown_s as i64
                ));
            }
        }
        if fire.is_empty() {
            return None; // all repeats suppressed — steady state, stay silent
        }
        Some(Anomaly {
            at_iso: s.ts.wall_iso.clone(),
            reasons: fire,
            suppressed: still_suppressed,
            snapshot: s,
        })
    }
}

/// Sustained paging above this = ACTIVE thrashing (pages/s).
const ACTIVE_PAGING_RATE: f64 = 500.0;

/// Whose storm is it: PSI stalls plus fault rates, same timestamp. Only added when decisive.
fn tenant_suffix(s: &UnifiedSnapshot, prev: Option<&UnifiedSnapshot>) -> String {
    let Some(p) = prev else {
        return String::new();
    };
    let dt = (s.ts.mono_ns.saturating_sub(p.ts.mono_ns) as f64) / 1e9;
    use crate::collect::{psi, tenant};
    let psi_ten = psi::stall_frac(
        s.psi.ten_mem_some.total,
        p.psi.ten_mem_some.total,
        dt,
    );
    let psi_sys = psi::stall_frac(
        s.psi.sys_mem_some.total,
        p.psi.sys_mem_some.total,
        dt,
    );
    let flt_ten = tenant::rate(s.tenant.majflt, p.tenant.majflt, dt);
    let flt_sys = tenant::rate(s.tenant.sys_majflt, p.tenant.sys_majflt, dt);
    let psi_v = psi::attribute(psi_ten, psi_sys);
    let flt_v = tenant::attribute(flt_ten, flt_sys);
    let ours = psi_v == psi::TenantVerdict::Ours || flt_v == tenant::FaultVerdict::Ours;
    let neigh = psi_v == psi::TenantVerdict::Neighbor
        || flt_v == tenant::FaultVerdict::Neighbor;
    if ours {
        format!(
            " — tenant active (mem-stall {ten:.1}% vs host {sys:.1}%, majflt {ft:.0}/s vs host {fs:.0}/s) → OURS",
            ten = psi_ten * 100.0,
            sys = psi_sys * 100.0,
            ft = flt_ten,
            fs = flt_sys
        )
    } else if neigh {
        format!(
            " — tenant clean (mem-stall {ten:.1}% vs host {sys:.1}%, majflt {ft:.0}/s vs host {fs:.0}/s) → NEIGHBOR noise",
            ten = psi_ten * 100.0,
            sys = psi_sys * 100.0,
            ft = flt_ten,
            fs = flt_sys
        )
    } else {
        String::new()
    }
}
fn net_verdict(s: &UnifiedSnapshot, prev: Option<&UnifiedSnapshot>) -> String {
    let mut local = Vec::new();
    if s.cpu.total_pct > 80.0 {
        local.push(format!("CPU {:.0}% saturated", s.cpu.total_pct));
    }
    if let Some(p) = prev {
        let dt = (s.ts.mono_ns.saturating_sub(p.ts.mono_ns) as f64) / 1e9;
        let out = crate::collect::mem::swap_out_rate(&p.mem, &s.mem, dt);
        if out >= ACTIVE_PAGING_RATE {
            local.push(format!("swap-out ACTIVE ({out:.0}/s)"));
        }
    }
    if s.mem.used_pct > 90.0 {
        local.push(format!("RAM {:.0}%", s.mem.used_pct));
    }
    if local.is_empty() {
        "no local pressure (CPU calm, no active paging) → NETWORK-SIDE".into()
    } else {
        format!("local pressure present ({}) → may MASQUERADE as network issue", local.join(", "))
    }
}

fn detect(s: &UnifiedSnapshot, prev: Option<&UnifiedSnapshot>) -> Vec<Reason> {
    let mut r = Vec::new();
    if s.cpu.total_pct > 90.0 {
        r.push(Reason {
            key: "cpu".into(),
            msg: format!("CPU {:.1}% > 90%", s.cpu.total_pct),
            value: s.cpu.total_pct as f64,
            force: false,
        });
    }
    if s.mem.used_pct > 90.0 {
        r.push(Reason {
            key: "mem".into(),
            msg: format!("RAM {:.1}% > 90%", s.mem.used_pct),
            value: s.mem.used_pct,
            force: false,
        });
    }
    if s.mem.swap_used_pct > 50.0 && s.mem.swap_total_kb > 0 {
        // STEADY vs ACTIVE: flat swap % with ~0 paging = old baseline, not new damage.
        let (rate_out, rate_in) = match prev {
            Some(p) => {
                let dt_s = (s.ts.mono_ns.saturating_sub(p.ts.mono_ns) as f64) / 1e9;
                (
                    crate::collect::mem::swap_out_rate(&p.mem, &s.mem, dt_s),
                    crate::collect::mem::swap_in_rate(&p.mem, &s.mem, dt_s),
                )
            }
            None => (0.0, 0.0),
        };
        let state = if rate_out < 1.0 && rate_in < 1.0 {
            "STEADY baseline (no active paging)"
        } else {
            "ACTIVE thrashing"
        };
        r.push(Reason {
            key: "swap".into(),
            msg: format!(
                "swap {:.1}% {} (pswpout {:.0}/s, pswpin {:.0}/s){}",
                s.mem.swap_used_pct, state, rate_out, rate_in,
                tenant_suffix(s, prev)
            ),
            value: s.mem.swap_used_pct,
            force: false,
        });
    }
    if let Some(imb) = crate::collect::cpu::numa_imbalance(&s.cpu) {
        if imb > 40.0 {
            r.push(Reason {
                key: "numa".into(),
                msg: format!("NUMA imbalance {imb:.1}% across nodes"),
                value: imb as f64,
                force: false,
            });
        }
    }
    for g in &s.gpus {
        if !g.available {
            continue;
        }
        if g.temp_c >= 83 {
            r.push(Reason {
                key: format!("temp{}", g.index),
                msg: format!("{} temp {}°C (thermal throttle zone)", g.name, g.temp_c),
                value: g.temp_c as f64,
                force: false,
            });
        }
        if g.mem_used_pct > 90.0 {
            r.push(Reason {
                key: format!("vram{}", g.index),
                msg: format!("{} VRAM {:.1}%", g.name, g.mem_used_pct),
                value: g.mem_used_pct,
                force: false,
            });
        }
    }
    if s.disk.used_pct > 90.0 {
        r.push(Reason {
            key: "disk".into(),
            msg: format!("disk {} {:.1}% full", s.disk.path, s.disk.used_pct),
            value: s.disk.used_pct,
            force: false,
        });
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hist(vals: &[f64]) -> VecDeque<f64> {
        vals.iter().copied().collect()
    }

    #[test]
    fn user_case_in_spike_fires() {
        // pswpin baseline ~5-17/s, sudden 909/s — the reported miss.
        let h = hist(&[5.0, 12.0, 17.0, 8.0, 10.0]);
        let (med, thr) = rate_spike_tuned(&h, 909.0, SPIKE_FACTOR, SPIKE_FLOOR).expect("must be a spike");
        assert!(med < 20.0 && thr <= 909.0);
    }

    #[test]
    fn small_noise_does_not_fire() {
        let h = hist(&[1.0, 2.0, 3.0, 2.0, 1.0]);
        assert!(rate_spike_tuned(&h, 30.0, SPIKE_FACTOR, SPIKE_FLOOR).is_none()); // 15× median but below floor
    }

    #[test]
    fn sustained_high_adapts_and_stops_firing() {
        let h = hist(&[800.0, 820.0, 790.0, 810.0, 805.0]);
        assert!(rate_spike_tuned(&h, 850.0, SPIKE_FACTOR, SPIKE_FLOOR).is_none());
    }

    #[test]
    fn needs_minimum_baseline() {
        let h = hist(&[5.0, 6.0]);
        assert!(rate_spike_tuned(&h, 5000.0, SPIKE_FACTOR, SPIKE_FLOOR).is_none());
    }

    #[test]
    fn zero_baseline_still_catches_big_jump() {
        let h = hist(&[0.0, 0.0, 0.0, 0.0]);
        assert!(rate_spike_tuned(&h, 500.0, SPIKE_FACTOR, SPIKE_FLOOR).is_some());
        assert!(rate_spike_tuned(&h, 100.0, SPIKE_FACTOR, SPIKE_FLOOR).is_none());
    }

    // End-to-end through Correlator::push with fabricated counters:
    // flat swap % + flat rates, then a pswpin jump identical to the user report.
    fn snap(
        mono_s: u64,
        swap_in: u64,
        swap_out: u64,
        retrans: u64,
    ) -> UnifiedSnapshot {
        use crate::collect::{cpu, disk, gpu, mem, net};
        use crate::clock::UnifiedTimestamp;
        UnifiedSnapshot {
            ts: UnifiedTimestamp {
                wall_ns: 1_700_000_000_000_000_000 + mono_s * 1_000_000_000,
                mono_ns: mono_s * 1_000_000_000,
                wall_iso: format!("t{mono_s}"),
            },
            hostname: "test".into(),
            cpu: cpu::CpuSample {
                total_pct: 10.0,
                per_core_pct: vec![10.0],
                per_core_freq_mhz: vec![3000],
                load_avg_1: 1.0,
                load_avg_5: 1.0,
                load_avg_15: 1.0,
                ctx_switches_total: 0,
                processes_running: 1,
                page_faults_minor: 0,
                page_faults_major: 0,
                numa_nodes: vec![],
            },
            mem: mem::MemSample {
                total_kb: 1000,
                available_kb: 500,
                used_kb: 500,
                used_pct: 50.0,
                free_kb: 500,
                buffers_kb: 0,
                cached_kb: 0,
                shmem_kb: 0,
                mlocked_kb: 0,
                swap_total_kb: 1000,
                swap_free_kb: 400,
                swap_used_kb: 600,
                swap_used_pct: 60.0, // flat across all samples
                swap_in_pages: swap_in,
                swap_out_pages: swap_out,
            },
            disk: disk::DiskSample {
                path: "/".into(),
                total_gb: 10.0,
                avail_gb: 9.0,
                used_pct: 10.0,
                read_kb_total: 0,
                write_kb_total: 0,
            },
            gpus: vec![gpu::GpuSample {
                index: 0,
                name: "none".into(),
                available: false,
                util_pct: 0,
                mem_used_mb: 0,
                mem_total_mb: 0,
                mem_used_pct: 0.0,
                temp_c: 0,
                clock_mhz: 0,
                power_w: 0.0,
            }],
            net: net::NetSample { retrans_segs: retrans, ..Default::default() },
            psi: Default::default(),
            tenant: Default::default(),
        }
    }

    #[test]
    fn push_fires_on_swap_in_spike_with_flat_swap_pct() {
        let mut c = Correlator::with_cooldown(100, 500, 3600.0); // huge cooldown: only spikes can re-fire
        // 6 baseline samples: ~10 pswpin/s, swap % pinned at 60.0.
        let mut pin = 0u64;
        let mut anomalies = 0;
        for t in 0..6u64 {
            pin += 10;
            if c.push(snap(t, pin, 0, 0)).is_some() {
                anomalies += 1;
            }
        }
        assert_eq!(anomalies, 1, "only the first-sighting swap LEVEL fires");
        // Spike sample: +909 pages in 1s, swap % still exactly 60.0.
        let a = c
            .push(snap(6, pin + 909, 0, 0))
            .expect("spike must fire a new anomaly");
        assert!(
            a.reasons.iter().any(|m| m.contains("pswpin 909/s")),
            "unexpected reasons: {:?}",
            a.reasons
        );
    }

    #[test]
    fn push_fires_on_retrans_spike_with_calm_cpu() {
        // Flat CPU 10%, flat swap, flat retrans (~2/s)… then a retrans storm.
        // Must fire as NETWORK-SIDE, not local pressure.
        let mut c = Correlator::with_cooldown(100, 500, 3600.0);
        let mut r = 0u64;
        let mut anomalies = 0;
        for t in 0..6u64 {
            r += 2;
            if c.push(snap(t, 0, 0, r)).is_some() {
                anomalies += 1;
            }
        }
        assert_eq!(anomalies, 1, "only the first-sighting swap LEVEL fires");
        let a = c
            .push(snap(6, 0, 0, r + 850))
            .expect("retrans storm must fire");
        assert!(
            a.reasons.iter().any(|m| m.contains("retransmit spike") && m.contains("NETWORK-SIDE")),
            "unexpected reasons: {:?}",
            a.reasons
        );
    }

    #[test]
    fn sustained_storm_alerts_once_per_cooldown() {        // Same storm magnitude 4 samples in a row, cooldown 1h:
        // edge-triggering must fire the FIRST, suppress the rest.
        let mut c = Correlator::with_cooldown(100, 500, 3600.0);
        let mut r = 0u64;
        for t in 0..6u64 {
            r += 2;
            let _ = c.push(snap(t, 0, 0, r));
        }
        let mut fired = 0;
        for t in 6..10u64 {
            r += 5000;
            if c.push(snap(t, 0, 0, r)).is_some() {
                fired += 1;
            }
        }
        assert_eq!(fired, 1, "sustained storm must not re-fire inside cooldown");
    }

    #[test]
    fn retrans_spike_under_cpu_pressure_masquerades() {
        // Same storm, but CPU saturated → verdict must say MASQUERADE.
        let mut c = Correlator::with_cooldown(100, 500, 3600.0);
        let mut r = 0u64;
        for t in 0..6u64 {
            r += 2;
            let mut s = snap(t, 0, 0, r);
            s.cpu.total_pct = 95.0; // saturated from the start
            let _ = c.push(s);
        }
        let mut s = snap(6, 0, 0, r + 850);
        s.cpu.total_pct = 95.0;
        let a = c.push(s).expect("storm must fire");
        assert!(
            a.reasons.iter().any(|m| m.contains("MASQUERADE")),
            "unexpected reasons: {:?}",
            a.reasons
        );
    }

    #[test]
    fn paging_spike_labeled_neighbor_when_tenant_clean() {
        // Host storms (pswpin 2000/s, host mem stall 6%) while THIS tenant's
        // PSI totals never move → the spike must carry the NEIGHBOR label.
        let mut c = Correlator::with_cooldown(100, 500, 3600.0);
        for t in 0..6u64 {
            let _ = c.push(snap(t, t * 10, 0, 0)); // ~10/s baseline, PSI flat
        }
        let mut s = snap(6, 50 + 2000, 0, 0);
        s.psi.ten_mem_some.total = 0; // tenant never stalls
        s.psi.sys_mem_some.total = 60_000; // host stalled 6% of this 1s window
        let a = c.push(s).expect("storm must fire");
        assert!(
            a.reasons.iter().any(|m| m.contains("NEIGHBOR noise")),
            "unexpected reasons: {:?}",
            a.reasons
        );
    }

    #[test]
    fn paging_spike_labeled_neighbor_via_majflt_microburst() {
        // PSI sees nothing (1s dilution) but host majors storm while tenant
        // majors stay flat → NEIGHBOR via the fault path.
        let mut c = Correlator::with_cooldown(100, 500, 3600.0);
        for t in 0..6u64 {
            let _ = c.push(snap(t, t * 10, 0, 0));
        }
        let mut s = snap(6, 50 + 2000, 0, 0);
        s.tenant.majflt = 0; // tenant faulted never
        s.tenant.sys_majflt = 3000; // host: 3000 majors in 1s
        let a = c.push(s).expect("storm must fire");
        assert!(
            a.reasons.iter().any(|m| m.contains("NEIGHBOR noise")),
            "unexpected reasons: {:?}",
            a.reasons
        );
    }

    #[test]
    fn paging_spike_labeled_ours_when_tenant_stalls() {
        let mut c = Correlator::with_cooldown(100, 500, 3600.0);
        for t in 0..6u64 {
            let _ = c.push(snap(t, t * 10, 0, 0));
        }
        let mut s = snap(6, 50 + 2000, 0, 0);
        s.psi.ten_mem_some.total = 80_000; // tenant stalled 8% too
        s.psi.sys_mem_some.total = 90_000;
        let a = c.push(s).expect("storm must fire");
        assert!(
            a.reasons.iter().any(|m| m.contains("→ OURS")),
            "unexpected reasons: {:?}",
            a.reasons
        );
    }

    #[test]
    fn actionable_filter_rules() {
        // OURS fresh → show. NEIGHBOR → hide. Reminder → hide. Fresh LEVEL → show.
        assert!(is_actionable(&["CPU 95.0% > 90%".to_string()]));
        assert!(is_actionable(&["paging spike: pswpout 5/s → OURS".to_string()]));
        assert!(!is_actionable(&["paging spike: pswpin 9/s → NEIGHBOR noise".to_string()]));
        assert!(!is_actionable(&["swap 61.0% STEADY (after ×29 suppressed)".to_string()]));
        assert!(is_actionable(&[
            "paging spike: pswpin 9/s → NEIGHBOR noise".to_string(),
            "CPU 91.0% > 90%".to_string(),
        ]));
        assert!(!is_actionable(&[]));
    }

    /// Storm sample: pswpin jumps AND the host keeps stalling (+60ms of stall
    /// per 1s sample = 6% sustained) while this tenant's totals never move.
    /// Totals are cumulative: pinning them would fake a stall that instantly
    /// decays to zero rate, so the caller threads `sys_tot` through.
    fn neighbor_storm_sample(
        c: &mut Correlator,
        t: u64,
        pin: u64,
        sys_tot: u64,
    ) -> Option<Anomaly> {
        let mut s = snap(t, pin, 0, 0);
        s.psi.ten_mem_some.total = 0;
        s.psi.sys_mem_some.total = sys_tot;
        c.push(s)
    }

    #[test]
    fn neighbor_storm_digest_fires_once_then_rearms() {
        let mut c = Correlator::with_cooldown(100, 500, 3600.0);
        for t in 0..6u64 {
            let _ = c.push(snap(t, t * 10, 0, 0));
        }
        // 22 consecutive neighbor detections → digest at #20, edge-held after.
        let mut digests = 0;
        let mut pin = 60u64;
        let mut sys_tot = 0u64;
        for t in 6..28u64 {
            pin += 2000;
            sys_tot += 60_000;
            if let Some(a) = neighbor_storm_sample(&mut c, t, pin, sys_tot) {
                if a.reasons.iter().any(|m| m.contains("neighbor storm")) {
                    digests += 1;
                }
            }
        }
        assert_eq!(digests, 1, "digest must fire exactly once per storm episode");
        // 610 quiet seconds slide the 10-min window → re-arms.
        for t in 28..638u64 {
            let _ = c.push(snap(t, t * 10, 0, 0));
        }
        let mut digests2 = 0;
        for t in 638..660u64 {
            pin += 2000;
            sys_tot += 60_000;
            if let Some(a) = neighbor_storm_sample(&mut c, t, pin, sys_tot) {
                if a.reasons.iter().any(|m| m.contains("neighbor storm")) {
                    digests2 += 1;
                }
            }
        }
        assert_eq!(digests2, 1, "digest must re-fire for a NEW episode after calm");
    }
}
