//! doctor: verify this machine's clock-sync fitness for cross-node correlation.
//! Prints: NTP/Chrony state, measured offset, and the skew budget for the window.

use anyhow::Result;

pub fn run(window_ms: i64) -> Result<()> {
    let budget = crate::central::skew_budget_ms(window_ms);
    println!("clock-sync doctor (window ±{window_ms}ms → skew budget ±{budget}ms)");
    println!();

    // 1. chrony, if present: authoritative system offset.
    let mut have_source = false;
    if let Ok(out) = std::process::Command::new("chronyc").arg("tracking").output() {
        if out.status.success() {
            have_source = true;
            let txt = String::from_utf8_lossy(&out.stdout);
            for line in txt.lines() {
                if line.contains("System time") || line.contains("Leap status") {
                    println!("  chrony: {}", line.trim());
                }
            }
            // Parse "System time     : 0.000123456 seconds slow of NTP time"
            for line in txt.lines() {
                if line.contains("System time") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        if let Ok(sec) = parts[2].parse::<f64>() {
                            let ms = sec * 1000.0;
                            println!("  measured NTP offset: {ms:+.2}ms {}", verdict(ms, budget as f64));
                        }
                    }
                }
            }
        }
    }
    // 2. systemd-timesyncd fallback.
    if !have_source {
        if let Ok(out) = std::process::Command::new("timedatectl").arg("show-timesync").output() {
            if out.status.success() {
                let txt = String::from_utf8_lossy(&out.stdout);
                println!("  timesyncd: {}", txt.lines().next().unwrap_or("").trim());
            }
        }
    }
    if !have_source {
        println!("  no chrony/timesyncd data — install chrony for production multi-node use.");
    }
    println!();
    println!("  rule: keep |skew| ≤ window/5 (±{budget}ms here). The collector enforces");
    println!("  this live on GET /nodes: nodes over budget are flagged ✗ and their");
    println!("  cross-node joins must NOT be trusted until NTP is fixed.");
    println!();
    println!("  verify live: curl http://<collector>/nodes  → offset_median_ms per node.");
    Ok(())
}

fn verdict(ms: f64, budget: f64) -> &'static str {
    if ms.abs() <= budget {
        "✓ within budget"
    } else {
        "✗ OVER BUDGET — fix NTP before trusting cross-node correlation"
    }
}
