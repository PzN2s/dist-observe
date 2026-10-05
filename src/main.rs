mod agent;
mod central;
mod clock;
mod collect;
mod correlate;
mod doctor;
mod ffi;
mod net;
mod tls;
mod nondet;
mod predict;
mod report;
mod store;

use anyhow::Result;
use clap::{Parser, Subcommand};
use sysinfo::System;

#[derive(Parser)]
#[command(name = "dist-observe", about = "Distributed Systems Observability & Correlator — MVP")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Record samples to SQLite (and print). The foundation for correlation.
    Record {
        #[arg(long, default_value = "1.0")] interval: f64,
        #[arg(long, default_value = "0")] count: usize, // 0 = infinite
        #[arg(long, default_value = "observe.db")] db: String,
        #[arg(long, default_value = "/")] disk: String,
        #[arg(long, default_value = "500")] window_ms: i64,
        /// Min seconds before re-printing the same anomaly type (delta can fire sooner).
        #[arg(long, default_value = "30.0")] anomaly_cooldown: f64,
        /// Display only: OURS + fresh unlabeled anomalies (storage untouched).
        #[arg(long)] only_actionable: bool,
    },
    /// Live watch: pretty one-line status + anomaly snapshots (same as record, human output).
    Watch {
        #[arg(long, default_value = "1.0")] interval: f64,
        #[arg(long, default_value = "0")] count: usize,
        #[arg(long, default_value = "observe.db")] db: String,
        #[arg(long, default_value = "/")] disk: String,
        #[arg(long, default_value = "30.0")] anomaly_cooldown: f64,
        /// Display only: OURS + fresh unlabeled anomalies (storage untouched).
        #[arg(long)] only_actionable: bool,
    },
    /// Predictive alert: exhaustion forecast from recorded trend.
    Predict {
        #[arg(long, default_value = "observe.db")] db: String,
        #[arg(long, default_value = "300")] samples: usize,
    },
    /// Print last N snapshots as JSON.
    Show {
        #[arg(long, default_value = "observe.db")] db: String,
        #[arg(long, default_value = "5")] limit: usize,
    },
    /// Agent: collect locally, push every sample to a central collector.
    Agent {
        #[arg(long, default_value = "127.0.0.1:18080")] collector: String,
        #[arg(long)] node_id: Option<String>,
        #[arg(long, default_value = "1.0")] interval: f64,
        #[arg(long, default_value = "0")] count: usize,
        #[arg(long, default_value = "/")] disk: String,
        /// Optional local spillover copy (same schema, node-tagged).
        #[arg(long)] local_db: Option<String>,
        /// mTLS files (required unless --insecure).
        #[arg(long)] tls_ca: Option<String>,
        #[arg(long)] tls_cert: Option<String>,
        #[arg(long)] tls_key: Option<String>,
        /// Plaintext HTTP. Lab use only — the agent refuses without EITHER
        /// full --tls-* files OR this flag.
        #[arg(long)] insecure: bool,
        /// Display only: OURS + fresh unlabeled anomalies (storage untouched).
        #[arg(long)] only_actionable: bool,
    },
    /// Collector: receive from agents, cross-correlate within ±window_ms.
    Collector {
        #[arg(long, default_value = "127.0.0.1:18080")] bind: String,
        #[arg(long, default_value = "central.db")] db: String,
        #[arg(long, default_value = "500")] window_ms: i64,
        #[arg(long, default_value = "30.0")] anomaly_cooldown: f64,
        #[arg(long)] tls_ca: Option<String>,
        #[arg(long)] tls_cert: Option<String>,
        #[arg(long)] tls_key: Option<String>,
        #[arg(long)] audit_log: Option<String>,
        #[arg(long)] insecure: bool,
    },
    /// Check this machine's clock-sync fitness for cross-node correlation.
    Doctor {
        #[arg(long, default_value = "500")] window_ms: i64,
    },
    /// Synthetic non-determinism demo: 2 workers sum identical floats in
    /// different orders (pure FP artifact) — or with --inject-race, a lost shard.
    NondetDemo {
        #[arg(long, default_value = "nondet.db")] db: String,
        #[arg(long, default_value = "demo-sum")] input: String,
        #[arg(long)] inject_race: bool,
    },
    /// Re-classify stored worker runs for one input (benign FP vs race).
    NondetCheck {
        #[arg(long, default_value = "nondet.db")] db: String,
        #[arg(long)] input: String,
    },
    /// One-shot ranked table: where each process's RSS really lives
    /// (heap vs anon-mmap vs file vs shm vs python-arenas vs top .so).
    FfiTop {
        #[arg(long, default_value = "8")] top: usize,
    },
    /// Track one PID's categories over time → leak verdict
    /// (native/FFI leak vs managed-heap growth).
    FfiTrack {
        #[arg(long)] pid: u32,
        #[arg(long, default_value = "1.0")] interval: f64,
        #[arg(long, default_value = "30")] count: usize,
    },
    /// Tenant vs host pressure stalls (cgroup PSI): whose storm is it?
    Psi,
    /// Replay stored snapshots through a fresh correlator (offline analysis:
    /// same code path as live, e.g. proving the storm digest on recorded data).
    Replay {
        #[arg(long, default_value = "observe.db")] db: String,
        #[arg(long, default_value = "30.0")] anomaly_cooldown: f64,
        /// Display only: same --only-actionable triage as live.
        #[arg(long)] only_actionable: bool,
    },
    /// Generate CA + server + client certificates for mTLS (run once).
    Keygen {
        #[arg(long, default_value = "certs")] dir: String,
        /// Extra server SANs (DNS names or IPs beyond localhost/127.0.0.1).
        #[arg(long)] server_san: Vec<String>,
        /// Client (agent) identities to mint, e.g. --client node-a --client node-b.
        #[arg(long)] client: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Record { interval, count, db, disk, window_ms, anomaly_cooldown, only_actionable } => {
            record(RecordOpts { db, disk, interval, count, window_ms, anomaly_cooldown, pretty: false, only_actionable })
        }
        Cmd::Watch { interval, count, db, disk, anomaly_cooldown, only_actionable } => {
            record(RecordOpts { db, disk, interval, count, window_ms: 500, anomaly_cooldown, pretty: true, only_actionable })
        }
        Cmd::Predict { db, samples } => predict_cmd(&db, samples),
        Cmd::Show { db, limit } => show_cmd(&db, limit),
        Cmd::Agent { collector, node_id, interval, count, disk, local_db, tls_ca, tls_cert, tls_key, insecure, only_actionable } => {
            let tls = tls_client(tls_ca, tls_cert, tls_key, insecure)?;
            agent::run(agent::Opts { collector, node_id, interval, count, disk, local_db, tls, only_actionable })
        }
        Cmd::Collector { bind, db, window_ms, anomaly_cooldown, tls_ca, tls_cert, tls_key, audit_log, insecure } => {
            let mode = tls_server(tls_ca, tls_cert, tls_key, audit_log, insecure)?;
            central::serve(&bind, &db, window_ms, anomaly_cooldown, mode)
        }
        Cmd::Doctor { window_ms } => doctor::run(window_ms),
        Cmd::Keygen { dir, server_san, client } => {
            let clients = if client.is_empty() { vec!["agent".to_string()] } else { client };
            tls::keygen(&dir, &server_san, &clients)
        }
        Cmd::NondetDemo { db, input, inject_race } => nondet::demo(&db, inject_race, &input),
        Cmd::NondetCheck { db, input } => {
            let mut st = store::Store::open(&db)?;
            let runs = st.runs_for_input(&input)?;
            if runs.is_empty() {
                println!("no runs for input '{input}' in {db}");
                return Ok(());
            }
            println!("{}", nondet::render(&nondet::classify(&input, &runs)));
            Ok(())
        }
        Cmd::FfiTop { top } => {
            let (rows, skipped) = ffi::top_n(top);
            println!("{}", ffi::render_top(&rows, skipped));
            Ok(())
        }
        Cmd::FfiTrack { pid, interval, count } => ffi_track(pid, interval, count),
        Cmd::Replay { db, anomaly_cooldown, only_actionable } => {
            let mut st = store::Store::open(&db)?;
            let snaps = st.all_snapshots()?;
            if snaps.is_empty() {
                println!("no snapshots in {db}");
                return Ok(());
            }
            let mut corr = correlate::Correlator::with_cooldown(600, 500, anomaly_cooldown);
            let mut fired = 0usize;
            for s in snaps {
                if let Some(a) = corr.push(s) {
                    // Storage already happened at record time; replay only prints.
                    if !only_actionable || correlate::is_actionable(&a.reasons) {
                        println!("{}", report::render(&a));
                        fired += 1;
                    }
                }
            }
            println!("replay done (anomalies shown: {fired})");
            Ok(())
        }
        Cmd::Psi => {
            let a = collect::psi::sample();
            let fa = collect::tenant::sample();
            std::thread::sleep(std::time::Duration::from_secs(1));
            let b = collect::psi::sample();
            let fb = collect::tenant::sample();
            print!("{}", collect::psi::render(&b, Some(&a), 1.0));
            let tr = collect::tenant::rate(fb.majflt, fa.majflt, 1.0);
            let sr = collect::tenant::rate(fb.sys_majflt, fa.sys_majflt, 1.0);
            let v = match collect::tenant::attribute(tr, sr) {
                collect::tenant::FaultVerdict::Ours => "OURS",
                collect::tenant::FaultVerdict::Neighbor => "NEIGHBOR",
                collect::tenant::FaultVerdict::Unclear => "—",
            };
            println!(
                "tenant majflt: {:.0}/s ({} tids) vs host {:.0}/s → {v} [burst-resolution]",
                tr, fb.tids, sr
            );
            Ok(())
        }
    }
}

/// Clamp sample intervals: ≤0 busy-loops, negative panics Duration.
/// Floor at 100ms with a loud warning instead of trusting CLI input.
fn sane_interval(v: f64, who: &str) -> f64 {
    if v.is_finite() && v >= 0.1 {
        return v;
    }
    eprintln!("WARNING: {who} interval {v}s invalid — clamped to 0.1s");
    0.1
}

fn ffi_track(pid: u32, interval: f64, count: usize) -> Result<()> {
    let interval = sane_interval(interval, "ffi-track");
    println!("tracking PID {pid} every {interval}s × {count} (smaps categories)…");
    let mut hist = Vec::new();
    for i in 0..count {
        match ffi::sample_pid(pid) {
            Some(p) => {
                println!(
                    "[{i}] rss {:6}M heap {:5}M anon {:6}M file {:5}M shm {:4}M arenas {:3}× gap {:6}M",
                    p.rss_kb / 1024,
                    p.heap_kb / 1024,
                    p.anon_kb / 1024,
                    p.file_kb / 1024,
                    p.shm_kb / 1024,
                    p.arena_count,
                    p.ffi_gap_kb() / 1024
                );
                hist.push(p);
            }
            None => println!("[{i}] PID {pid} unreadable (exited or permission denied)"),
        }
        if i + 1 < count {
            std::thread::sleep(std::time::Duration::from_secs_f64(interval));
        }
    }
    println!("\n{}", ffi::leak_verdict(&hist).text);
    Ok(())
}

fn tls_client(
    ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    insecure: bool,
) -> Result<Option<std::sync::Arc<rustls::ClientConfig>>> {
    match (ca, cert, key, insecure) {
        (Some(ca), Some(cert), Some(key), _) => {
            Ok(Some(tls::client_config(&tls::TlsFiles { ca, cert, key })?))
        }
        (None, None, None, true) => {
            eprintln!("WARNING: agent→collector in PLAINTEXT (--insecure). Lab use only.");
            Ok(None)
        }
        _ => anyhow::bail!(
            "TLS needs --tls-ca + --tls-cert + --tls-key together, or --insecure for lab use"
        ),
    }
}

fn tls_server(
    ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    audit_log: Option<String>,
    insecure: bool,
) -> Result<central::TlsMode> {
    match (ca, cert, key, insecure) {
        (Some(ca), Some(cert), Some(key), _) => Ok(central::TlsMode::Tls {
            cfg: tls::server_config(&tls::TlsFiles { ca, cert, key })?,
            audit: audit_log,
        }),
        (None, None, None, true) => Ok(central::TlsMode::Insecure),
        _ => anyhow::bail!(
            "TLS needs --tls-ca + --tls-cert + --tls-key together, or --insecure for lab use"
        ),
    }
}

/// record()/watch() knobs in one struct (clippy::too_many_arguments).
struct RecordOpts {
    db: String,
    disk: String,
    interval: f64,
    count: usize,
    window_ms: i64,
    anomaly_cooldown: f64,
    pretty: bool,
    only_actionable: bool,
}

fn record(o: RecordOpts) -> Result<()> {
    let RecordOpts { db, disk, interval, count, window_ms, anomaly_cooldown, pretty, only_actionable } = o;
    let interval = sane_interval(interval, "record");
    let mut sys = System::new_all();
    // Warmup: sysinfo CPU usage needs two reads ≥ MINIMUM_CPU_UPDATE_INTERVAL
    // apart — otherwise the first sample is always 0.0% (cold-start artifact).
    sys.refresh_cpu_usage();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    let mut st = store::Store::open(&db)?;
    let mut corr = correlate::Correlator::with_cooldown(600, window_ms, anomaly_cooldown);
    println!("recording → {db} every {interval}s (unified ns timestamp, window ±{window_ms}ms). Ctrl-C to stop.");
    let mut i = 0usize;
    let mut prev: Option<collect::snapshot::UnifiedSnapshot> = None;
    loop {
        let snap = collect::snapshot::take(&mut sys, &disk);
        if pretty {
            println!("{}", report::status_line(prev.as_ref(), &snap));
        } else {
            println!("{}", serde_json::to_string(&snap)?);
        }
        if let Some(a) = corr.push(snap.clone()) {
            // Display-only filter: storage above is untouched, full log retained.
            if !only_actionable || correlate::is_actionable(&a.reasons) {
                println!("{}", report::render(&a));
            }
        }
        st.insert(&snap.hostname.clone(), &snap).unwrap_or_else(|e| {
            // Storage must never abort a recording run (disk full, transient
            // lock): the sample already went to stdout, keep going.
            eprintln!("store insert failed (sample kept on stdout): {e}");
        });
        prev = Some(snap);
        i += 1;
        if count != 0 && i >= count {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs_f64(interval));
    }
    println!("done: {i} samples → {db}");
    Ok(())
}

fn predict_cmd(db: &str, samples: usize) -> Result<()> {
    let mut st = store::Store::open(db)?;
    let n = st.count()?;
    if n < 3 {
        println!("only {n} samples in {db} — record more first (need ≥3).");
        return Ok(());
    }
    let series = st.recent_series(samples)?;
    let (mem, disk) = predict::forecast_from_store(&series);
    println!("forecast from {} samples in {db}:", series.len());
    println!("  MEM : {:5.1}% | {:+.3}%/h | {}", mem.current_pct, mem.growth_pct_per_hour, mem.verdict);
    println!("  DISK: {:5.1}% | {:+.3}%/h | {}", disk.current_pct, disk.growth_pct_per_hour, disk.verdict);
    // Baseline deviation on mem series
    let mem_vals: Vec<f64> = series.iter().map(|(_, m, _)| *m).collect();
    if let Some((z, msg)) = predict::zscore_anomaly(&mem_vals) {
        println!("  BASELINE: mem anomaly z={z:.1} — {msg}");
    }
    Ok(())
}

fn show_cmd(db: &str, limit: usize) -> Result<()> {
    use rusqlite::{params, Connection};
    let conn = Connection::open(db)?;
    let mut stmt = conn.prepare("SELECT json FROM snapshots ORDER BY wall_ns DESC LIMIT ?1")?;
    let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
    for r in rows.flatten() {
        println!("{r}");
    }
    Ok(())
}
