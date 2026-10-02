//! Human-readable anomaly reports: explanation, not just numbers.
use crate::correlate::Anomaly;

pub fn render(a: &Anomaly) -> String {
    let s = &a.snapshot;
    let mut o = String::new();
    o.push_str(&format!(
        "⚠ ANOMALY @ {} ({}) — {}\n",
        a.at_iso,
        s.hostname,
        a.reasons.join(" | ")
    ));
    o.push_str(&format!(
        "  CPU {:5.1}% (load {:.2}) | ctx_switches {} | procs_running {}\n",
        s.cpu.total_pct, s.cpu.load_avg_1, s.cpu.ctx_switches_total, s.cpu.processes_running
    ));
    o.push_str(&format!(
        "  RAM {:5.1}% used ({} / {} MB) | shm {} MB | mlock {} kB | swap {:4.1}% (in/out {} / {} pages)\n",
        s.mem.used_pct,
        s.mem.used_kb / 1024,
        s.mem.total_kb / 1024,
        s.mem.shmem_kb / 1024,
        s.mem.mlocked_kb,
        s.mem.swap_used_pct,
        s.mem.swap_in_pages,
        s.mem.swap_out_pages,
    ));
    o.push_str(&format!(
        "  DISK {} {:4.1}% ({:.1} GB free) | io r/w {} / {} MB\n",
        s.disk.path,
        s.disk.used_pct,
        s.disk.avail_gb,
        s.disk.read_kb_total / 1024,
        s.disk.write_kb_total / 1024,
    ));
    for g in &s.gpus {
        if !g.available {
            o.push_str(&format!("  GPU: {}\n", g.name));
        } else {
            o.push_str(&format!(
                "  GPU-{} {} util {}% vram {}/{}MB ({:.0}%) {}°C {}MHz {:.0}W\n",
                g.index,
                g.name,
                g.util_pct,
                g.mem_used_mb,
                g.mem_total_mb,
                g.mem_used_pct,
                g.temp_c,
                g.clock_mhz,
                g.power_w
            ));
        }
    }
    o.push_str(&format!(
        "  unified ts wall_ns={} mono_ns={}\n",
        s.ts.wall_ns, s.ts.mono_ns
    ));
    if !a.suppressed.is_empty() {
        o.push_str(&format!("  (suppressed steady repeats: {})\n", a.suppressed.join(" ; ")));
    }
    o
}

/// One-line status for `watch` mode. Shows live deltas + paging rate so a
/// flat swap % is distinguishable from active movement *during* recording.
pub fn status_line(
    prev: Option<&crate::collect::snapshot::UnifiedSnapshot>,
    s: &crate::collect::snapshot::UnifiedSnapshot,
) -> String {
    let gpu = if s.gpus.iter().any(|g| g.available) {
        s.gpus
            .iter()
            .filter(|g| g.available)
            .map(|g| format!("G{}:{}%{}C", g.index, g.util_pct, g.temp_c))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        "GPU:n/a".into()
    };
    let (swap_extra, mem_extra, net_extra) = match prev {
        Some(p) => {
            let dt_s =
                (s.ts.mono_ns.saturating_sub(p.ts.mono_ns) as f64) / 1e9;
            let out = crate::collect::mem::swap_out_rate(&p.mem, &s.mem, dt_s);
            let inn = crate::collect::mem::swap_in_rate(&p.mem, &s.mem, dt_s);
            let dswap = s.mem.swap_used_pct - p.mem.swap_used_pct;
            let dmem = s.mem.used_pct - p.mem.used_pct;
            let rx = crate::collect::net::rate(s.net.rx_bytes, p.net.rx_bytes, dt_s);
            let tx = crate::collect::net::rate(s.net.tx_bytes, p.net.tx_bytes, dt_s);
            let rr = crate::collect::net::rate(s.net.retrans_segs, p.net.retrans_segs, dt_s);
            (
                format!("({:+.1}pp, out {out:.0}/s in {inn:.0}/s)", dswap),
                format!("({:+.1}pp)", dmem),
                format!(
                    "(↓{} ↑{} retr {rr:.0}/s)",
                    crate::collect::net::human_bps(rx),
                    crate::collect::net::human_bps(tx)
                ),
            )
        }
        None => (String::new(), String::new(), String::new()),
    };
    format!(
        "{} cpu {:4.1}% mem {:4.1}%{} swap {:4.1}%{} disk {:4.1}% net{} {} numa_nodes={}",
        s.ts.wall_iso,
        s.cpu.total_pct,
        s.mem.used_pct,
        mem_extra,
        s.mem.swap_used_pct,
        swap_extra,
        s.disk.used_pct,
        net_extra,
        gpu,
        s.cpu.numa_nodes.len(),
    )
}
