//! Central collector: receives snapshots from agents, tracks per-node clock
//! skew, persists to SQLite, and joins anomalies ACROSS nodes within the same
//! ±window_ms wall-clock window (not just within one node).
//!
//! Clock-sync contract: cross-node correlation is only valid if the skew
//! between nodes is small vs the window. Rule: |skew| budget = window/5
//! (±500 ms window → ±100 ms budget). The collector measures the apparent
//! offset of every push (receive_wall − sample_wall ≈ clock_diff + one-way
//! network delay) and reports median/p95 per node on `GET /nodes`. Anything
//! over budget is flagged — fix NTP (chrony) instead of trusting the join.

use crate::collect::snapshot::UnifiedSnapshot;
use crate::correlate::Correlator;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Allowed |skew| = window/5. A 500 ms window tolerates 100 ms skew.
pub fn skew_budget_ms(window_ms: i64) -> i64 {
    (window_ms / 5).max(10)
}

#[derive(Debug, Deserialize)]
pub struct IngestBody {
    pub node: String,
    pub snapshot: UnifiedSnapshot,
}

/// Input validation BEFORE storage: a rogue/compromised agent must not be
/// able to poison the DB or break correlation math with insane values.
/// (serde_json already rejects NaN/inf and the 1MB body cap bounds parsing.)
fn validate_snapshot(s: &UnifiedSnapshot) -> anyhow::Result<()> {
    use anyhow::bail;
    let pct = |v: f64, name: &str| -> anyhow::Result<()> {
        if !(0.0..=100.0).contains(&v) {
            bail!("{name} out of range: {v}");
        }
        Ok(())
    };
    pct(s.cpu.total_pct as f64, "cpu.total_pct")?;
    if s.cpu.per_core_pct.len() > 4096 {
        bail!("per_core_pct too long: {}", s.cpu.per_core_pct.len());
    }
    for v in &s.cpu.per_core_pct {
        pct(*v as f64, "cpu.per_core")?;
    }
    pct(s.mem.used_pct, "mem.used_pct")?;
    pct(s.mem.swap_used_pct, "mem.swap_used_pct")?;
    pct(s.disk.used_pct, "disk.used_pct")?;
    for g in &s.gpus {
        pct(g.mem_used_pct, "gpu.mem_used_pct")?;
        if g.util_pct > 100 {
            bail!("gpu.util out of range: {}", g.util_pct);
        }
    }
    // Sanity magnitudes (16 PiB ceiling — catches garbage, allows any real box).
    const BIG: u64 = 1 << 54;
    if s.mem.total_kb > BIG || s.mem.swap_total_kb > BIG {
        bail!("memory magnitude insane");
    }
    if s.net.conns.len() > 64 {
        bail!("net.conns too many: {}", s.net.conns.len());
    }
    if s.hostname.len() > 256 {
        bail!("hostname too long");
    }
    // Clock sanity: >24h off means broken clock or replayed blob (skew
    // budget enforcement itself lives in /nodes + the cross-node join).
    let now = crate::clock::UnifiedTimestamp::now().wall_ns as i64;
    if ((s.ts.wall_ns as i64) - now).abs() > 86_400_000_000_000 {
        bail!("wall_ns more than 24h from collector time");
    }
    Ok(())
}

struct NodeState {
    corr: Correlator,
    buf: VecDeque<UnifiedSnapshot>,
    /// Recent apparent offsets (recv_wall_ns − sample_wall_ns), nanoseconds.
    offsets_ns: VecDeque<i64>,
    samples: u64,
    cgroup: String,
    tids: u64,
    anomalies: u64,
}

pub struct Central {
    store: crate::store::Store,
    nodes: HashMap<String, NodeState>,
    window_ms: i64,
    cooldown_s: f64,
    /// Sliding-window rate limiter: peer IP → recent request Instants.
    /// 120/min/IP: comfortable for 1Hz agents, fatal for floods/bugs.
    hits: HashMap<String, VecDeque<std::time::Instant>>,
    audit: Option<String>,
    webhook_url: Option<String>,
}

const RATE_PER_MIN: usize = 120;

#[derive(Debug, Serialize)]
pub struct NodeSkew {
    pub node: String,
    pub samples: u64,
    pub offset_median_ms: f64,
    pub offset_p95_ms: f64,
    pub skew_ok: bool,
    pub cgroup: String,
    pub tids: u64,
}

pub struct IngestOut {
    pub offset_ms: f64,
    pub cross_report: Option<String>,
    /// Machine-readable triage for agents running --only-actionable.
    pub actionable: bool,
    pub reasons: Vec<String>,
}

fn percentile(sorted: &mut [i64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted.sort_unstable();
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)] as f64 / 1e6
}

fn median(v: &mut [i64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2] as f64 / 1e6
    } else {
        (v[n / 2 - 1] + v[n / 2]) as f64 / 2e6
    }
}

impl Central {
    pub fn open(
        db: &str,
        window_ms: i64,
        cooldown_s: f64,
        audit: Option<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            store: crate::store::Store::open(db)?,
            nodes: HashMap::new(),
            window_ms,
            cooldown_s,
            hits: HashMap::new(),
            audit,
            webhook_url: None,
        })
    }

    pub fn set_webhook(&mut self, url: Option<String>) {
        self.webhook_url = url;
    }

    /// True if this peer IP may proceed (sliding 60s window).
    pub fn check_rate(&mut self, peer: &str) -> bool {
        let now = std::time::Instant::now();
        // Bound the table itself: drop peers idle a full window once it grows
        // past 1k entries, so distinct-IP churn can't grow it without bound.
        if self.hits.len() > 1024 {
            self.hits.retain(|_, q: &mut VecDeque<std::time::Instant>| {
                q.back().map(|t| now.duration_since(*t).as_secs() < 60).unwrap_or(false)
            });
        }
        let q = self.hits.entry(peer.to_string()).or_default();
        while q.front().map(|t| now.duration_since(*t).as_secs() >= 60).unwrap_or(false) {
            q.pop_front();
        }
        if q.len() >= RATE_PER_MIN {
            return false;
        }
        q.push_back(now);
        true
    }

    pub fn node_names(&self) -> Vec<String> {
        let mut n: Vec<String> = self.nodes.keys().cloned().collect();
        n.sort();
        n
    }

    pub fn skew_report(&self) -> Vec<NodeSkew> {
        let budget = skew_budget_ms(self.window_ms) as f64;
        let mut out = Vec::new();
        for (name, st) in &self.nodes {
            let mut v: Vec<i64> = st.offsets_ns.iter().copied().collect();
            let med = median(&mut v);
            let mut v2 = v.clone();
            let p95 = percentile(&mut v2, 95.0);
            out.push(NodeSkew {
                node: name.clone(),
                samples: st.samples,
                offset_median_ms: med,
                offset_p95_ms: p95,
                skew_ok: med.abs() <= budget,
                cgroup: st.cgroup.clone(),
                tids: st.tids,
            });
        }
        out.sort_by(|a, b| a.node.cmp(&b.node));
        out
    }

    /// Ingest one agent snapshot. Returns measured offset + optional
    /// cross-node anomaly report.
    pub fn ingest(
        &mut self,
        node: &str,
        snap: UnifiedSnapshot,
    ) -> anyhow::Result<IngestOut> {
        let recv_wall = crate::clock::UnifiedTimestamp::now().wall_ns as i64;
        let offset_ns = recv_wall - snap.ts.wall_ns as i64;
        self.store.insert(node, &snap)?;

        let st = self.nodes.entry(node.to_string()).or_insert_with(|| NodeState {
            corr: Correlator::with_cooldown(600, self.window_ms, self.cooldown_s),
            buf: VecDeque::with_capacity(600),
            offsets_ns: VecDeque::with_capacity(120),
            samples: 0,
            cgroup: String::new(),
            tids: 0,
            anomalies: 0,
        });
        st.samples += 1;
        st.cgroup = snap.psi.cgroup.clone();
        st.tids = snap.tenant.tids;
        st.offsets_ns.push_back(offset_ns);
        if st.offsets_ns.len() > 120 {
            st.offsets_ns.pop_front();
        }
        st.buf.push_back(snap.clone());
        if st.buf.len() > 600 {
            st.buf.pop_front();
        }

        // Local (per-node) anomaly first — dedup/throttle preserved per node.
        let local = st.corr.push(snap.clone());
        let (cross_report, actionable, reasons) = match local {
            None => (None, true, vec![]),
            Some(a) => {
                let flag = crate::correlate::is_actionable(&a.reasons);
                (Some(self.render_cross(node, &a)), flag, a.reasons.clone())
            }
        };
        if cross_report.is_some() {
            // bump per-node anomaly counter (best effort: re-fetch state)
            if let Some(st2) = self.nodes.get_mut(node) {
                st2.anomalies += 1;
            }
        }
        Ok(IngestOut {
            offset_ms: offset_ns as f64 / 1e6,
            cross_report,
            actionable,
            reasons,
        })
    }

    /// Prometheus exposition of the latest sample per node + anomaly counters.
    pub fn metrics(&self) -> String {
        let mut o = String::new();
        o.push_str("# HELP dist_observe_up 1 if the node recently reported\n");
        o.push_str("# TYPE dist_observe_up gauge\n");
        o.push_str("# HELP dist_observe_anomalies_total cross-node anomalies per node\n");
        o.push_str("# TYPE dist_observe_anomalies_total counter\n");
        let now_ns = crate::clock::UnifiedTimestamp::now().wall_ns as i64;
        for (name, st) in &self.nodes {
            let up = st
                .buf
                .back()
                .map(|s| ((now_ns - s.ts.wall_ns as i64) < 30_000_000_000) as u8)
                .unwrap_or(0);
            o.push_str(&format!("dist_observe_up{{node=\"{name}\"}} {up}\n"));
            o.push_str(&format!(
                "dist_observe_anomalies_total{{node=\"{name}\"}} {}\n",
                st.anomalies
            ));
            if let Some(s) = st.buf.back() {
                o.push_str(&format!(
                    "dist_cpu_pct{{node=\"{name}\"}} {:.2}\ndist_mem_pct{{node=\"{name}\"}} {:.2}\ndist_swap_pct{{node=\"{name}\"}} {:.2}\n",
                    s.cpu.total_pct, s.mem.used_pct, s.mem.swap_used_pct
                ));
                o.push_str(&format!(
                    "dist_clock_offset_ms{{node=\"{name}\"}} {:.2}\n",
                    st.offsets_ns.back().copied().unwrap_or(0) as f64 / 1e6
                ));
            }
        }
        o
    }

    /// Join the triggering snapshot with the nearest same-window snapshot
    /// from every OTHER node (matched on wall_ns — the cross-node join key).
    fn render_cross(
        &self,
        trigger_node: &str,
        a: &crate::correlate::Anomaly,
    ) -> String {
        let center = a.snapshot.ts.wall_ns as i64;
        let win_ns = self.window_ms * 1_000_000;
        let budget = skew_budget_ms(self.window_ms);
        let mut o = String::new();
        o.push_str(&format!(
            "⚠ CROSS-NODE ANOMALY @ {} trigger={} — {}\n",
            a.at_iso,
            trigger_node,
            a.reasons.join(" | ")
        ));
        // Trigger node line.
        o.push_str(&format!("  {}\n", peer_line(trigger_node, 0, &a.snapshot)));
        // Peer nodes: nearest snapshot inside the window.
        let mut names = self.node_names();
        names.retain(|n| n != trigger_node);
        for n in &names {
            let st = &self.nodes[n];
            let best = st
                .buf
                .iter()
                .min_by_key(|s| ((s.ts.wall_ns as i64) - center).abs());
            match best {
                Some(s) => {
                    let d_ns = s.ts.wall_ns as i64 - center;
                    if d_ns.abs() <= win_ns {
                        o.push_str(&format!(
                            "  {}\n",
                            peer_line(n, d_ns / 1_000_000, s)
                        ));
                    } else {
                        o.push_str(&format!(
                            "  [{n} — no sample within ±{}ms (nearest {:+.0}ms) — clock or agent gap?]\n",
                            self.window_ms,
                            d_ns as f64 / 1e6
                        ));
                    }
                }
                None => o.push_str(&format!("  [{n} — no samples yet]\n")),
            }
        }
        // Skew footer: is this join trustworthy?
        let mut skews = Vec::new();
        for sk in self.skew_report() {
            let mark = if sk.skew_ok { "✓" } else { "✗ OVER BUDGET" };
            skews.push(format!(
                "{} {:+.1}ms {}",
                sk.node, sk.offset_median_ms, mark
            ));
        }
        o.push_str(&format!(
            "  skew budget ±{}ms: {}\n",
            budget,
            skews.join(" | ")
        ));
        if !a.suppressed.is_empty() {
            o.push_str(&format!("  (suppressed: {})\n", a.suppressed.join(" ; ")));
        }
        o
    }
}

fn peer_line(node: &str, delta_ms: i64, s: &UnifiedSnapshot) -> String {
    let gpu = if s.gpus.iter().any(|g| g.available) {
        s.gpus
            .iter()
            .filter(|g| g.available)
            .map(|g| format!("G{}:{}%", g.index, g.util_pct))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        "gpu:n/a".into()
    };
    format!(
        "[{node} {delta_ms:+}ms] cpu {:4.1}% mem {:4.1}% swap {:4.1}% {gpu}",
        s.cpu.total_pct, s.mem.used_pct, s.mem.swap_used_pct,
    )
}

/// Transport mode: mTLS by default; plaintext only with explicit --insecure.
pub enum TlsMode {
    Tls {
        cfg: Arc<rustls::ServerConfig>,
        audit: Option<String>,
    },
    Insecure,
}

fn audit(msg: &str, audit_file: &Option<String>) {    use chrono::Utc;
    let line = format!("{} {msg}", Utc::now().to_rfc3339());
    eprintln!("AUDIT {line}");
    if let Some(path) = audit_file {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn audit_of(central: &Arc<Mutex<Central>>) -> Option<String> {
    central.lock().unwrap().audit.clone()
}

fn webhook_url_of(central: &Arc<Mutex<Central>>) -> Option<String> {
    central.lock().unwrap().webhook_url.clone()
}

/// Blocking serve loop: thread-per-connection, shared Central behind a Mutex.
pub fn serve(
    bind: &str,
    db: &str,
    window_ms: i64,
    cooldown_s: f64,
    tls: TlsMode,
    webhook_url: Option<String>,
) -> anyhow::Result<()> {
    let audit_file = match &tls {
        TlsMode::Tls { audit, .. } => audit.clone(),
        TlsMode::Insecure => None,
    };
    let central = Arc::new(Mutex::new(Central::open(
        db,
        window_ms,
        cooldown_s,
        audit_file,
    )?));
    central.lock().unwrap().set_webhook(webhook_url);
    let listener = crate::net::listen(bind)?;
    match &tls {
        TlsMode::Tls { .. } => println!(
            "collector on {bind} (db={db}, window ±{window_ms}ms, skew budget ±{}ms) [mTLS REQUIRED]",
            skew_budget_ms(window_ms)
        ),
        TlsMode::Insecure => println!(
            "collector on {bind} (db={db}) [!!! INSECURE PLAINTEXT — lab use only !!!]"
        ),
    }
    let tls = Arc::new(tls);
    // Hard cap on concurrent connection threads: TLS handshakes cost CPU even
    // when they end in rejection, so an unbounded thread-per-connection server
    // is handshake-floodable. Excess connections are dropped + audited.
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    const MAX_CONNS: usize = 64;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or("?".into());
        if live.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= MAX_CONNS {
            live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            audit(&format!("conn-cap peer={peer}"), &match &*tls {
                TlsMode::Tls { audit, .. } => audit.clone(),
                TlsMode::Insecure => None,
            });
            continue;
        }
        let central = Arc::clone(&central);
        let tls = Arc::clone(&tls);
        let live = Arc::clone(&live);
        std::thread::spawn(move || {
            struct Guard(Arc<std::sync::atomic::AtomicUsize>);
            impl Drop for Guard {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let _guard = Guard(live);
            match &*tls {
            TlsMode::Tls { cfg, audit: audit_file } => {
                let mut conn = match rustls::ServerConnection::new(Arc::clone(cfg)) {
                    Ok(c) => c,
                    Err(e) => {
                        audit(&format!("tls-init-fail peer={peer} err={e}"), audit_file);
                        return;
                    }
                };
                let mut sock = stream;
                let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                let mut tls_stream = rustls::Stream::new(&mut conn, &mut sock);
                // One handshake, then up to 200 requests on this connection.
                // Only a FIRST-request failure is a reject (no app byte trusted).
                // Later EOF/timeout = client went away after clean service: quiet.
                let mut served = 0u32;
                for _ in 0..200 {
                    match handle_tls(&mut tls_stream, &central, &peer) {
                        Ok(true) => served += 1,
                        Ok(false) => break, // client asked to close
                        Err(e) => {
                            if served == 0 {
                                audit(&format!("tls-reject peer={peer} err={e}"), audit_file);
                            }
                            break;
                        }
                    }
                }
                // Clean TLS shutdown so clients don't see truncation errors.
                tls_stream.conn.send_close_notify();
                let _ = std::io::Write::flush(&mut tls_stream);
            }
            TlsMode::Insecure => {
                let mut sock = stream;
                let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                for _ in 0..200 {
                    match handle(&mut sock, &central, &peer) {
                        Ok(true) => {}
                        _ => break,
                    }
                }
            }
            }
        });
    }
    Ok(())
}

fn handle_tls(
    stream: &mut rustls::Stream<rustls::ServerConnection, std::net::TcpStream>,
    central: &Arc<Mutex<Central>>,
    peer: &str,
) -> anyhow::Result<bool> {
    handle_generic(stream, central, peer)
}

fn handle(
    stream: &mut std::net::TcpStream,
    central: &Arc<Mutex<Central>>,
    peer: &str,
) -> anyhow::Result<bool> {
    handle_generic(&mut *stream, central, peer)
}

fn handle_generic(
    s: &mut (impl std::io::Read + std::io::Write),
    central: &Arc<Mutex<Central>>,
    peer: &str,
) -> anyhow::Result<bool> {
    let req = crate::net::read_request(s)?;
    // Honor one-shot clients (curl, health checks); agents use keep-alive.
    let ka = req
        .headers
        .get("connection")
        .map(|v| v.trim().eq_ignore_ascii_case("keep-alive"))
        .unwrap_or(true);
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/ingest") => {
            // Rate limit first (cheap), before any parsing/storage work.
            if !central.lock().unwrap().check_rate(peer) {
                audit(&format!("rate-limit peer={peer}"), &audit_of(central));
                let resp = serde_json::json!({"ok": false, "error": "rate limited (120/min)"});
                crate::net::respond_json_conn(&mut *s, 429, &resp.to_string(), ka)?;
                return Ok(false);
            }
            if req.body.len() > 1_048_576 {
                audit(&format!("oversize-body peer={peer} bytes={}", req.body.len()), &audit_of(central));
                let resp = serde_json::json!({"ok": false, "error": "body > 1MB"});
                crate::net::respond_json_conn(&mut *s, 400, &resp.to_string(), ka)?;
                return Ok(false);
            }
            let body: Result<IngestBody, _> = serde_json::from_slice(&req.body);
            match body {
                Ok(b) => {
                    let node = sanitize_node(&b.node);
                    if let Err(e) = validate_snapshot(&b.snapshot) {
                        audit(&format!("bad-snapshot peer={peer} node={node} err={e}"), &audit_of(central));
                        let resp = serde_json::json!({"ok": false, "error": format!("invalid snapshot: {e}")});
                        crate::net::respond_json_conn(&mut *s, 400, &resp.to_string(), ka)?;
                        return Ok(false);
                    }
                    match central.lock().unwrap().ingest(&node, b.snapshot) {
                        Ok(out) => {
                            let resp = serde_json::json!({
                                "ok": true,
                                "offset_ms": out.offset_ms,
                                "anomaly": out.cross_report,
                                "actionable": out.actionable,
                                "reasons": out.reasons,
                            });
                            crate::net::respond_json_conn(&mut *s, 200, &resp.to_string(), ka)?;
                            if let Some(rep) = out.cross_report {
                                println!("{rep}");
                                // Centralized alerting: every cross-node anomaly,
                                // best-effort. (Set it here OR on agents, not both.)
                                crate::notify::fire(
                                    &webhook_url_of(central),
                                    crate::notify::payload("collector", &node, "", &out.reasons),
                                );
                            }
                        }
                        Err(e) => {
                            let resp = serde_json::json!({"ok": false, "error": e.to_string()});
                            crate::net::respond_json_conn(&mut *s, 500, &resp.to_string(), ka)?;
                        }
                    }
                }
                Err(e) => {
                    let resp = serde_json::json!({"ok": false, "error": format!("bad json: {e}")});
                    crate::net::respond_json_conn(&mut *s, 400, &resp.to_string(), ka)?;
                }
            }
        }
        ("GET", "/health") => {
            let c = central.lock().unwrap();
            let resp = serde_json::json!({"ok": true, "nodes": c.node_names()});
            crate::net::respond_json_conn(&mut *s, 200, &resp.to_string(), ka)?;
        }
        ("GET", "/nodes") => {
            let c = central.lock().unwrap();
            let rep = c.skew_report();
            let budget = skew_budget_ms(c.window_ms);
            let resp = serde_json::json!({"skew_budget_ms": budget, "nodes": rep});
            crate::net::respond_json_conn(&mut *s, 200, &resp.to_string(), ka)?;
        }
        ("GET", "/metrics") => {
            // Prometheus exposition (text/plain). Suggest scrape_interval ≥15s.
            let body = central.lock().unwrap().metrics();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
                body.len(),
                if ka { "keep-alive" } else { "close" }
            );
            s.write_all(head.as_bytes())?;
            s.write_all(body.as_bytes())?;
            s.flush()?;
        }
        _ => {
            let resp = serde_json::json!({"ok": false, "error": "use POST /ingest or GET /nodes|/health"});
            crate::net::respond_json_conn(&mut *s, 404, &resp.to_string(), ka)?;
        }
    }
    Ok(ka)
}

fn sanitize_node(n: &str) -> String {
    let clean: String = n
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(64)
        .collect();
    if clean.is_empty() {
        "anon".into()
    } else {
        clean
    }
}
