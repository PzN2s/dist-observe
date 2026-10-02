//! Non-determinism detector: same input, different workers → different bits?
//! Every worker run records input/output hashes PLUS the unified-timestamp
//! correlation snapshot (CPU/GPU/swap) taken at that exact moment.
//!
//! Decision rule (no hand-waving):
//! - Same reduction order but different outputs → SUSPECTED RACE (strong).
//! - Different orders: compare the observed |a−b| against the deterministic
//!   worst-case summation error bound (Wilkinson: (n−1)·ε·Σ|x|).
//!   Within bound → BENIGN FP variance (order + heterogeneous clocks explain it).
//!   Beyond bound → SUSPECTED RACE, even with different orders.
//! - GPU clock/temp deltas are supporting evidence, never the verdict alone —
//!   and the verdict works with zero GPU telemetry (order metadata + bound).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const F64_EPS: f64 = 2.220446049250313e-16; // 2^-52

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRun {
    pub input_id: String,
    pub worker: String,
    pub input_hash: String,
    pub output_hash: String,
    pub output_f64: f64,
    pub order_desc: String,
    pub order_seed: u64,
    pub input_len: usize,
    pub input_abs_sum: f64,
    pub wall_ns: u64,
    pub mono_ns: u64,
    pub wall_iso: String,
    pub snapshot_json: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Identical,
    Insufficient,
    BenignFp,
    SuspectedRace,
}

#[derive(Debug, Clone)]
pub struct Classification {
    pub input_id: String,
    pub verdict: Verdict,
    pub runs: usize,
    pub max_abs_diff: f64,
    pub rel_diff: f64,
    pub error_bound: f64,
    pub evidence: Vec<String>,
    pub env_lines: Vec<String>,
}

pub fn sha_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn hash_floats(vals: &[f64]) -> String {
    let mut h = Sha256::new();
    for v in vals {
        h.update(v.to_le_bytes());
    }
    format!("{:x}", h.finalize())
}

/// Worst-case error of ANY sequential summation order (Wilkinson-style).
/// If two orders disagree by more than this, order alone cannot explain it.
pub fn order_error_bound(n: usize, abs_sum: f64) -> f64 {
    if n < 2 {
        return 0.0;
    }
    (n - 1) as f64 * F64_EPS * abs_sum
}

fn order_key(r: &WorkerRun) -> String {
    format!("{}#{}", r.order_desc, r.order_seed)
}

pub fn classify(input_id: &str, runs: &[WorkerRun]) -> Classification {
    let mut c = Classification {
        input_id: input_id.into(),
        verdict: Verdict::Insufficient,
        runs: runs.len(),
        max_abs_diff: 0.0,
        rel_diff: 0.0,
        error_bound: 0.0,
        evidence: vec![],
        env_lines: env_lines(runs),
    };
    if runs.len() < 2 {
        c.evidence.push("need ≥2 runs for the same input".into());
        return c;
    }
    let outs: Vec<f64> = runs.iter().map(|r| r.output_f64).collect();
    let mut max_abs = 0.0f64;
    for (i, a) in outs.iter().enumerate() {
        for b in &outs[i + 1..] {
            max_abs = max_abs.max((a - b).abs());
        }
    }
    let scale = outs.iter().map(|v| v.abs()).fold(0.0f64, f64::max).max(1.0);
    c.max_abs_diff = max_abs;
    c.rel_diff = max_abs / scale;

    let first = &runs[0];
    let bound = order_error_bound(first.input_len, first.input_abs_sum);
    c.error_bound = bound;

    let same_input = runs.iter().all(|r| r.input_hash == first.input_hash);
    c.evidence.push(format!(
        "input hash {} across workers",
        if same_input { "identical" } else { "DIFFERS (not the same input!)" }
    ));
    if !same_input {
        c.verdict = Verdict::SuspectedRace;
        c.evidence.push("workers did not even agree on the input".into());
        return c;
    }

    let orders: std::collections::HashSet<String> = runs.iter().map(order_key).collect();
    let distinct_outputs: std::collections::HashSet<String> =
        runs.iter().map(|r| r.output_hash.clone()).collect();
    if distinct_outputs.len() == 1 {
        c.verdict = Verdict::Identical;
        c.evidence.push("bit-identical outputs on all workers".into());
        return c;
    }

    c.evidence.push(format!(
        "orders: {} | outputs differ by {:.6} (rel {:.3e}) | order-only bound {:.6}",
        orders.iter().cloned().collect::<Vec<_>>().join(", "),
        max_abs,
        c.rel_diff,
        bound
    ));
    if orders.len() == 1 {
        c.verdict = Verdict::SuspectedRace;
        c.evidence.push(
            "SAME reduction order, different bits — order cannot explain this; \
             points at a real race (lost update / unsynchronized aggregation) \
             or divergent code paths"
                .into(),
        );
        return c;
    }
    if max_abs <= bound {
        c.verdict = Verdict::BenignFp;
        c.evidence.push(format!(
            "within the deterministic summation error bound ({max_abs:.6} ≤ {bound:.6}): \
             order-dependent FP rounding fully explains the diff"
        ));
        c.evidence.push(
            "pattern matches 'differs across workers, vanishes on single-worker \
             rerun' → aggregation/order effect, not input corruption"
                .into(),
        );
    } else {
        c.verdict = Verdict::SuspectedRace;
        let k = if bound > 0.0 { max_abs / bound } else { f64::INFINITY };
        c.evidence.push(format!(
            "EXCEEDS worst-case order-only bound by ×{k:.1} — no summation order \
             can produce this gap; suspected race or dropped/duplicated shard"
        ));
    }
    c
}

/// Per-run environment at its own unified timestamp (the correlation half).
fn env_lines(runs: &[WorkerRun]) -> Vec<String> {
    let mut out = Vec::new();
    let mut gpu_seen = false;
    for r in runs {
        match serde_json::from_str::<crate::collect::snapshot::UnifiedSnapshot>(
            &r.snapshot_json,
        ) {
            Ok(s) => {
                let gpu = s
                    .gpus
                    .iter()
                    .filter(|g| g.available)
                    .map(|g| format!("G{} {}MHz {}°C", g.index, g.clock_mhz, g.temp_c))
                    .collect::<Vec<_>>()
                    .join(" ");
                if !gpu.is_empty() {
                    gpu_seen = true;
                }
                out.push(format!(
                    "  {} @ {} cpu {:4.1}% swap {:4.1}% gpu[{}]",
                    r.worker,
                    r.wall_iso,
                    s.cpu.total_pct,
                    s.mem.swap_used_pct,
                    if gpu.is_empty() { "n/a".into() } else { gpu }
                ));
            }
            Err(_) => out.push(format!("  {} @ {} (snapshot unparsable)", r.worker, r.wall_iso)),
        }
    }
    if !runs.is_empty() {
        let dt_ms = (runs.last().unwrap().mono_ns.saturating_sub(runs.first().unwrap().mono_ns)) as f64 / 1e6;
        out.push(format!("  runs spanned {dt_ms:.0}ms wall-to-wall"));
    }
    if !gpu_seen && !runs.is_empty() {
        out.push(
            "  no GPU telemetry on any run — verdict rests on order metadata + error bound alone"
                .into(),
        );
    }
    out
}

pub fn render(c: &Classification) -> String {
    let tag = match c.verdict {
        Verdict::Identical => "✔ IDENTICAL",
        Verdict::Insufficient => "? INSUFFICIENT DATA",
        Verdict::BenignFp => "≈ BENIGN FP VARIANCE",
        Verdict::SuspectedRace => "⚠ SUSPECTED RACE",
    };
    let mut o = String::new();
    o.push_str(&format!(
        "{tag} input={} runs={} maxΔ={:.6} rel={:.3e} bound={:.6}\n",
        c.input_id, c.runs, c.max_abs_diff, c.rel_diff, c.error_bound
    ));
    for e in &c.evidence {
        o.push_str(&format!("  • {e}\n"));
    }
    o.push_str("  env @ each run's unified timestamp:\n");
    for l in &c.env_lines {
        o.push_str(&format!("{l}\n"));
    }
    o
}

/// Synthetic scenario: sum [1e16] + 1000×[1.0] on 2 workers.
/// Forward fold absorbs every 1.0 (result 1e16); reverse fold keeps them
/// (result 1e16+1000) — a pure order artifact. With --inject-race, worker-b
/// additionally drops the 1e16 shard (lost-update race): gap ≈1e16 ≫ bound.
pub fn demo(db: &str, inject_race: bool, input_id: &str) -> anyhow::Result<()> {
    let big = 1e16f64;
    let ones = vec![1.0f64; 1000];
    let mut values = vec![big];
    values.extend_from_slice(&ones);
    let input_hash = hash_floats(&values);
    let abs_sum: f64 = values.iter().map(|v| v.abs()).sum();

    let mut sys = sysinfo::System::new_all();
    sys.refresh_cpu_usage();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    let mut store = crate::store::Store::open(db)?;

    // worker-a order depends on mode (see race note below).
    let a_desc = if inject_race { "reverse-fold" } else { "forward-fold" };
    let mut runs = vec![];
    for (worker, order, seed, drop_shard0) in [
        ("worker-a", a_desc, 11u64, false),
        ("worker-b", "reverse-fold", if inject_race { 11 } else { 22 }, inject_race),
    ] {
        let mut seq: Vec<f64> = if order == "reverse-fold" {
            values.iter().rev().copied().collect()
        } else {
            values.clone()
        };
        if drop_shard0 {
            seq.retain(|v| *v != big); // the "lost update": huge shard never aggregated
        }
        let sum: f64 = seq.iter().sum();
        let snap = crate::collect::snapshot::take(&mut sys, "/");
        let run = WorkerRun {
            input_id: input_id.into(),
            worker: worker.into(),
            input_hash: input_hash.clone(),
            output_hash: sha_hex(&sum.to_le_bytes()),
            output_f64: sum,
            order_desc: order.into(),
            order_seed: seed,
            input_len: values.len(),
            input_abs_sum: abs_sum,
            wall_ns: snap.ts.wall_ns,
            mono_ns: snap.ts.mono_ns,
            wall_iso: snap.ts.wall_iso.clone(),
            snapshot_json: serde_json::to_string(&snap)?,
        };
        println!("{worker} [{order}#{seed}] sum={sum:.1} hash={:.12} @ {}",
            run.output_hash, run.wall_iso);
        store.insert_run(&run)?;
        runs.push(run);
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    if inject_race {
        println!("(disclosed fault: worker-b dropped the 1e16 shard — a lost-update race)");
    }
    let c = classify(input_id, &runs);
    println!("\n{}", render(&c));
    println!("stored 2 runs in {db} — re-check anytime with: nondet-check --db {db} --input {input_id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(worker: &str, out: f64, desc: &str, seed: u64, n: usize, abs: f64) -> WorkerRun {
        WorkerRun {
            input_id: "t".into(),
            worker: worker.into(),
            input_hash: "same".into(),
            output_hash: sha_hex(&out.to_le_bytes()),
            output_f64: out,
            order_desc: desc.into(),
            order_seed: seed,
            input_len: n,
            input_abs_sum: abs,
            wall_ns: 1,
            mono_ns: 1,
            wall_iso: "t".into(),
            snapshot_json: "{}".into(), // unparsable on purpose → env path must not crash
        }
    }

    #[test]
    fn benign_order_variance_within_bound() {
        // 1e16 vs 1e16+1000, bound ≈ 2220 → benign.
        let rs = vec![
            run("a", 1e16, "forward-fold", 11, 1001, 1e16 + 1000.0),
            run("b", 1e16 + 1000.0, "reverse-fold", 22, 1001, 1e16 + 1000.0),
        ];
        let c = classify("t", &rs);
        assert_eq!(c.verdict, Verdict::BenignFp, "{c:?}");
    }

    #[test]
    fn same_order_different_bits_is_race() {
        let rs = vec![
            run("a", 1.5, "kahan", 7, 10, 100.0),
            run("b", 1.5000000001, "kahan", 7, 10, 100.0),
        ];
        let c = classify("t", &rs);
        assert_eq!(c.verdict, Verdict::SuspectedRace, "{c:?}");
    }

    #[test]
    fn different_orders_beyond_bound_is_race() {
        let rs = vec![
            run("a", 1e16, "forward-fold", 11, 1001, 1e16 + 1000.0),
            run("b", 1000.0, "reverse-fold", 22, 1001, 1e16 + 1000.0), // lost shard
        ];
        let c = classify("t", &rs);
        assert_eq!(c.verdict, Verdict::SuspectedRace, "{c:?}");
        assert!(c.max_abs_diff > c.error_bound);
    }

    #[test]
    fn identical_outputs() {
        let rs = vec![
            run("a", 42.0, "forward-fold", 11, 5, 100.0),
            run("b", 42.0, "forward-fold", 11, 5, 100.0),
        ];
        assert_eq!(classify("t", &rs).verdict, Verdict::Identical);
    }

    #[test]
    fn bound_math() {
        assert_eq!(order_error_bound(1, 1e16), 0.0);
        let b = order_error_bound(1001, 1e16 + 1000.0);
        assert!(b > 1000.0 && b < 10000.0, "bound={b}");
    }
}
