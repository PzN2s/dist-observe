//! Agent: collects locally with the unified timestamp and pushes every
//! sample to the central collector over HTTP. Local dedup still applies for
//! console output; the collector makes the final cross-node decision.

use anyhow::Result;

/// All agent knobs in one struct (keeps the arg list reviewable).
pub struct Opts {
    pub collector: String,
    pub node_id: Option<String>,
    pub interval: f64,
    pub count: usize,
    pub disk: String,
    pub local_db: Option<String>,
    pub tls: Option<std::sync::Arc<rustls::ClientConfig>>,
    pub only_actionable: bool,
}

pub fn run(o: Opts) -> Result<()> {
    let addr = crate::net::normalize_addr(&o.collector);
    let node = o.node_id.unwrap_or_else(|| {
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "agent".into())
    });
    let interval = o.interval;
    let count = o.count;
    let disk = o.disk.as_str();
    let tls = o.tls;
    let only_actionable = o.only_actionable;
    let mut sys = sysinfo::System::new_all();
    sys.refresh_cpu_usage();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    let mut local: Option<crate::store::Store> = match &o.local_db {
        Some(p) => Some(crate::store::Store::open(p)?),
        None => None,
    };
    println!("agent {node} → collector {addr} every {interval}s{}. Ctrl-C to stop.",
        if tls.is_some() { " [mTLS]" } else { " [INSECURE]" });
    let mut sent = 0usize;
    let mut dropped = 0usize;
    let mut offsets: Vec<f64> = Vec::new();
    let mut i = 0usize;
    // ONE connection (and one TLS handshake) for the whole run; transparent
    // reconnect if the server ever closes it (it caps at 200 reqs/conn).
    let mut conn = match crate::net::Conn::connect(&addr, &tls) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("initial connect failed: {e}");
            return Err(e);
        }
    };
    let mut reconnects = 0u32;
    let mut takes: Vec<f64> = Vec::new();
    loop {
        let t0 = std::time::Instant::now();
        let snap = crate::collect::snapshot::take(&mut sys, disk);
        takes.push(t0.elapsed().as_secs_f64() * 1000.0);
        println!("{}", crate::report::status_line(None, &snap));
        let body = serde_json::json!({"node": node, "snapshot": snap}).to_string();
        let mut push = conn.post(&addr, "/ingest", &body);
        if push.is_err() {
            // Single transparent retry on a fresh connection.
            match crate::net::Conn::connect(&addr, &tls) {
                Ok(c) => {
                    conn = c;
                    reconnects += 1;
                    push = conn.post(&addr, "/ingest", &body);
                }
                Err(e) => push = Err(e),
            }
        }
        match push {
            Ok((200, resp)) => {
                sent += 1;
                // Collector returns any cross-node anomaly inline, pre-triaged.
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
                    // Display-only filter: the collector stored everything.
                    let show = !only_actionable
                        || v.get("actionable").and_then(|a| a.as_bool()).unwrap_or(true);
                    if show {
                        if let Some(rep) = v.get("anomaly").and_then(|a| a.as_str()) {
                            println!("{rep}");
                        }
                    }
                    // Link skew: receive_wall − sample_wall per sample.
                    if let Some(off) = v.get("offset_ms").and_then(|o| o.as_f64()) {
                        offsets.push(off);
                        if off.abs() > 50.0 {
                            println!("link: offset {off:+.1}ms (over half budget!)");
                        }
                    }
                }
            }
            Ok((code, resp)) => {
                dropped += 1;
                eprintln!("collector HTTP {code}: {resp}");
            }
            Err(e) => {
                dropped += 1;
                eprintln!("push failed (sample kept locally in RAM, not lost from disk if --local-db): {e}");
            }
        }
        if let Some(st) = local.as_mut() {
            if let Err(e) = st.insert(&node, &snap) {
                eprintln!("local db: {e}");
            }
        }
        i += 1;
        if count != 0 && i >= count {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs_f64(interval));
    }
    println!("agent done: sent={sent} dropped={dropped} reconnects={reconnects}");
    if !offsets.is_empty() {
        let mut s = offsets.clone();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let med = s[s.len() / 2];
        let p95 = s[((s.len() as f64 * 0.95) as usize).min(s.len() - 1)];
        println!("link skew: n={} median {med:+.1}ms p95 {p95:+.1}ms (budget ±100ms)", s.len());
        // Pipeline decomposition: offset = local collect + clock/network.
        // take() runs AFTER the stamp, so subtract it for the true sync number.
        let mut adj: Vec<f64> = offsets.iter().zip(takes.iter()).map(|(o, t)| o - t).collect();
        adj.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let amed = adj[adj.len() / 2];
        let ap95 = adj[((adj.len() as f64 * 0.95) as usize).min(adj.len() - 1)];
        let mut tt = takes.clone();
        tt.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        println!("pipeline: collect p50 {:.1}ms | clock+network skew p50 {amed:+.1}ms p95 {ap95:+.1}ms", tt[tt.len() / 2]);
    }
    Ok(())
}
