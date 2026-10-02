//! Network stack telemetry for throughput correlation.
//! Question answered: "throughput dropped — real network problem (retransmit
//! spike, collapsing cwnd) or local pressure (CPU/swap) MASQUERADING as one?"
//! Sources (all std-only, no pcap, no root):
//! - per-iface byte/packet/drop counters → throughput B/s (non-lo + lo split)
//! - /proc/net/snmp Tcp: InSegs/OutSegs/RetransSegs (cumulative)
//! - /proc/net/netstat TcpExt: Timeouts/FastRetrans/SlowStartRetrans/SackRecovery
//! - `ss -tin` (best effort): per-connection cwnd/rtt/retrans — the actual
//!   congestion-window collapse signal, top retransmitters only.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SsConn {
    pub local: String,
    pub peer: String,
    pub cwnd: u32,
    pub rtt_ms: f64,
    pub retrans_total: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetSample {
    // non-loopback totals (the throughput that matters)
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
    // loopback, tracked separately (tests, local IPC storms)
    pub lo_rx_bytes: u64,
    pub lo_tx_bytes: u64,
    // TCP stack cumulative counters
    pub in_segs: u64,
    pub out_segs: u64,
    pub retrans_segs: u64,
    pub timeouts: u64,
    pub fast_retrans: u64,
    pub slowstart_retrans: u64,
    pub sack_recovery: u64,
    pub conns: Vec<SsConn>,
}

impl NetSample {
    /// Loss-ish events that all mean "congestion control did something drastic".
    pub fn loss_events(&self) -> u64 {
        self.timeouts + self.fast_retrans + self.slowstart_retrans + self.sack_recovery
    }
}

fn read_u64(path: &str) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Parse paired header/value lines ("Tcp: A B C" / "Tcp: 1 2 3") into a map.
fn kv_pairs(text: &str, section: &str) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    let lines: Vec<&str> = text.lines().collect();
    for w in lines.windows(2) {
        let (h, v) = (w[0], w[1]);
        let mut ht = h.split_whitespace();
        let mut vt = v.split_whitespace();
        if ht.next() != Some(section) || vt.next() != Some(section) {
            continue;
        }
        let keys: Vec<&str> = ht.collect();
        let vals: Vec<&str> = vt.collect();
        for (k, val) in keys.iter().zip(vals.iter()) {
            map.insert(k.to_string(), val.parse().unwrap_or(0));
        }
    }
    map
}

fn snmp_tcp() -> HashMap<String, u64> {
    std::fs::read_to_string("/proc/net/snmp")
        .map(|t| kv_pairs(&t, "Tcp:"))
        .unwrap_or_default()
}

fn netstat_tcpext() -> HashMap<String, u64> {
    std::fs::read_to_string("/proc/net/netstat")
        .map(|t| kv_pairs(&t, "TcpExt:"))
        .unwrap_or_default()
}

fn get(m: &HashMap<String, u64>, k: &str) -> u64 {
    m.get(k).copied().unwrap_or(0)
}

/// Parse `ss -tin` text: connection header + indented tcp_info detail line.
pub fn parse_ss(text: &str) -> Vec<SsConn> {
    let mut out = Vec::new();
    let mut local = String::new();
    let mut peer = String::new();
    for line in text.lines() {
        if line.starts_with(char::is_whitespace) || line.starts_with('\t') {
            // detail line: "... cwnd:10 ... rtt:153.6/87.5 ... retrans:0/7 ..."
            let toks: Vec<&str> = line.split_whitespace().collect();
            let mut cwnd = 0u32;
            let mut rtt = 0.0f64;
            let mut retrans = 0u64;
            for t in toks {
                if let Some(v) = t.strip_prefix("cwnd:") {
                    cwnd = v.parse().unwrap_or(0);
                } else if let Some(v) = t.strip_prefix("rtt:") {
                    rtt = v.split('/').next().and_then(|x| x.parse().ok()).unwrap_or(0.0);
                } else if let Some(v) = t.strip_prefix("retrans:") {
                    retrans = v.split('/').nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
                }
            }
            if retrans > 0 {
                out.push(SsConn { local: local.clone(), peer: peer.clone(), cwnd, rtt_ms: rtt, retrans_total: retrans });
            }
        } else {
            // header: "ESTAB 0 0 local peer" (5 fields; title line is mixed-case, skip it)
            let f: Vec<&str> = line.split_whitespace().collect();
            let is_state = !f.is_empty()
                && f[0].chars().all(|c| c.is_ascii_uppercase() || c == '-');
            if is_state && f.len() >= 5 {
                local = f[3].to_string();
                peer = f[4].to_string();
            } else {
                local.clear();
                peer.clear();
            }
        }
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.retrans_total));
    out.truncate(5);
    out
}

fn ss_conns() -> Vec<SsConn> {
    // `ss` dumps netlink: fast normally, but a wedged stack (exactly when you
    // need telemetry most) must never stall the whole 1s sample. coreutils
    // `timeout` bounds it with zero leaked threads (a spawn+abandon thread
    // would leak one thread per wedged sample). Missing `timeout` binary →
    // empty conns, everything else still sampled.
    let out = std::process::Command::new("timeout")
        .args(["1", "ss", "-tin"])
        .output();
    let Ok(out) = out else {
        return vec![];
    };
    if !out.status.success() {
        return vec![];
    }
    parse_ss(&String::from_utf8_lossy(&out.stdout))
}

pub fn sample() -> NetSample {
    let mut rx = 0u64;
    let (mut tx, mut rxp, mut txp, mut rxd, mut txd) = (0, 0, 0, 0, 0);
    let (mut lo_rx, mut lo_tx) = (0, 0);
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let base = format!("/sys/class/net/{name}/statistics");
            let r: u64 = read_u64(&format!("{base}/rx_bytes"));
            let t: u64 = read_u64(&format!("{base}/tx_bytes"));
            if name == "lo" {
                lo_rx += r;
                lo_tx += t;
            } else {
                rx += r;
                tx += t;
                rxp += read_u64(&format!("{base}/rx_packets"));
                txp += read_u64(&format!("{base}/tx_packets"));
                rxd += read_u64(&format!("{base}/rx_dropped"));
                txd += read_u64(&format!("{base}/tx_dropped"));
            }
        }
    }
    let tcp = snmp_tcp();
    let ext = netstat_tcpext();
    NetSample {
        rx_bytes: rx,
        tx_bytes: tx,
        rx_packets: rxp,
        tx_packets: txp,
        rx_drops: rxd,
        tx_drops: txd,
        lo_rx_bytes: lo_rx,
        lo_tx_bytes: lo_tx,
        in_segs: get(&tcp, "InSegs"),
        out_segs: get(&tcp, "OutSegs"),
        retrans_segs: get(&tcp, "RetransSegs"),
        timeouts: get(&ext, "TCPTimeouts"),
        fast_retrans: get(&ext, "TCPFastRetrans"),
        slowstart_retrans: get(&ext, "TCPSlowStartRetrans"),
        sack_recovery: get(&ext, "TCPSackRecovery"),
        conns: ss_conns(),
    }
}

/// Bytes/s between two samples (saturating: counters can wrap/reset).
pub fn rate(cur: u64, prev: u64, dt_s: f64) -> f64 {
    if dt_s <= 0.0 {
        return 0.0;
    }
    (cur.saturating_sub(prev) as f64) / dt_s
}

pub fn human_bps(bps: f64) -> String {
    if bps >= 1e9 {
        format!("{:.2}GB/s", bps / 1e9)
    } else if bps >= 1e6 {
        format!("{:.2}MB/s", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.0}KB/s", bps / 1e3)
    } else {
        format!("{bps:.0}B/s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNMP: &str = "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts\nTcp: 1 200 120000 -1 10 5 0 1 3 1000 900 25 0 4\n";
    const NETSTAT: &str = "TcpExt: SyncookiesFailed TCPTimeouts TCPFastRetrans TCPSlowStartRetrans TCPSackRecovery\nTcpExt: 0 7 3 1 2\n";

    #[test]
    fn parses_snmp_tcp_by_name() {
        let m = kv_pairs(SNMP, "Tcp:");
        assert_eq!(m["InSegs"], 1000);
        assert_eq!(m["RetransSegs"], 25);
        assert_eq!(m["OutSegs"], 900);
    }

    #[test]
    fn parses_tcpext_loss_keys() {
        let m = kv_pairs(NETSTAT, "TcpExt:");
        assert_eq!(m["TCPTimeouts"], 7);
        assert_eq!(m["TCPFastRetrans"], 3);
        assert_eq!(loss_of(&m), 7 + 3 + 1 + 2);
    }

    fn loss_of(m: &HashMap<String, u64>) -> u64 {
        m.get("TCPTimeouts").copied().unwrap_or(0)
            + m.get("TCPFastRetrans").copied().unwrap_or(0)
            + m.get("TCPSlowStartRetrans").copied().unwrap_or(0)
            + m.get("TCPSackRecovery").copied().unwrap_or(0)
    }

    const SS: &str = "State Recv-Q Send-Q Local Address:Port Peer Address:Port\nESTAB 0 0 10.0.0.2:5000 10.0.0.3:443\n\t cubic wscale:8,10 rto:300 rtt:50.0/10.0 cwnd:10 retrans:0/9 delivery_rate 1bps\nESTAB 0 0 10.0.0.2:5001 10.0.0.4:443\n\t cubic rtt:20.0/5.0 cwnd:12 retrans:0/0\n";

    #[test]
    fn parses_ss_retransmitters_only() {
        let c = parse_ss(SS);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].retrans_total, 9);
        assert_eq!(c[0].cwnd, 10);
        assert_eq!(c[0].local, "10.0.0.2:5000");
        assert_eq!(c[0].peer, "10.0.0.3:443");
        assert!((c[0].rtt_ms - 50.0).abs() < 1e-9);
    }

    #[test]
    fn rate_saturates_on_reset() {
        assert_eq!(rate(100, 900, 1.0), 0.0); // counter wrapped → 0, never negative
        assert_eq!(rate(1000, 900, 1.0), 100.0);
        assert_eq!(rate(5, 0, 0.0), 0.0);
    }
}
