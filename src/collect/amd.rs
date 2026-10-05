//! AMD GPU telemetry via `rocm-smi` (best effort, same philosophy as `ss`).
//! Only attempted when NVML yielded nothing: NVIDIA first, AMD fallback,
//! graceful absence otherwise. Output parsing is deliberately tolerant —
//! `rocm-smi` table layouts drift across versions, so we scan for stable
//! `Key: value Unit` tokens instead of column positions. Anything unparsable
//! yields an empty vec (caller falls back to the unavailable marker).
//! Untestable without AMD hardware here: covered by synthetic-text unit tests.
use crate::collect::gpu::GpuSample;

fn num_after(line: &str, key: &str) -> Option<f64> {
    let i = line.find(key)?;
    line[i + key.len()..]
        .split_whitespace()
        .next()?
        .trim_end_matches(|c: char| !c.is_ascii_digit() && c != '.')
        .parse()
        .ok()
}

/// One card block: rocm-smi separates cards with `===...` or `GPU[<i>]` headers.
pub fn parse_rocm(text: &str) -> Vec<GpuSample> {
    #[derive(Default)]
    struct Acc {
        name: Option<String>,
        temp_c: u32,
        util: u32,
        used_mb: u64,
        total_mb: u64,
        clock_mhz: u32,
        power_w: f64,
        seen: bool,
    }
    impl Acc {
        fn note(&mut self) {
            self.seen = true;
        }
    }
    fn detail(a: &mut Acc, line: &str) {
        let low = line.to_lowercase();
        if low.contains("card series") || low.contains("card model") {
            if let Some(v) = line.split_once(':').map(|x| x.1) {
                a.name = Some(v.trim().to_string());
                a.note();
            }
        } else if low.contains("temperature") || low.contains("temp ") || low.starts_with("temp:") {
            if let Some(v) = num_after(line, ":").or_else(|| num_after(&low, "temp")) {
                a.temp_c = v as u32;
                a.note();
            }
        } else if low.contains("gpu use") || low.contains("gpu%") || low.contains("utilization") {
            if let Some(v) = num_after(line, ":").or_else(|| num_after(&low, "use")) {
                a.util = v.min(100.0) as u32;
                a.note();
            }
        } else if (low.contains("vram") && low.contains("used")) || low.contains("memory used") {
            // NB: check USED before TOTAL — "Total Used Memory" contains both words.
            if let Some(v) = num_after(line, ":") {
                a.used_mb = v as u64;
                a.note();
            }
        } else if (low.contains("vram") && low.contains("total")) || low.contains("memory total") {
            if let Some(v) = num_after(line, ":") {
                a.total_mb = v as u64;
            }
        } else if low.contains("sclk") || low.contains("gfx") || low.contains("gpu clock") {
            // rocm-smi clocks print as MHz already (sometimes "800Mhz").
            if let Some(v) = num_after(line, ":") {
                a.clock_mhz = v as u32;
            }
        } else if low.contains("power") && (low.contains("watt") || low.contains("(w)") || low.contains(" w")) {
            if let Some(v) = num_after(line, ":") {
                a.power_w = v;
            }
        }
    }
    let mut cards: Vec<Acc> = Vec::new();
    let mut cur: Option<usize> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("===") {
            cur = None; // decorative banner, not a card
            continue;
        }
        // "GPU[2] : ..." switches card context AND may carry a reading.
        if let Some(rest) = line.strip_prefix("GPU[") {
            if let Some((idx_s, tail)) = rest.split_once(']') {
                if let Ok(idx) = idx_s.parse::<usize>() {
                    while cards.len() <= idx {
                        cards.push(Acc::default());
                    }
                    cur = Some(idx);
                    // Remainder after "]" is often ": <detail>" — parse it.
                    let tail = tail.trim_start_matches([':', ' ']);
                    if !tail.is_empty() {
                        detail(&mut cards[idx], tail);
                    }
                    continue;
                }
            }
        }
        if let Some(i) = cur {
            detail(&mut cards[i], line);
        }
    }
    cards
        .into_iter()
        .enumerate()
        .filter(|(_, a)| a.seen)
        .map(|(i, a)| {
            let pct = if a.total_mb > 0 {
                a.used_mb as f64 * 100.0 / a.total_mb as f64
            } else {
                0.0
            };
            GpuSample {
                index: i as u32,
                name: a.name.unwrap_or_else(|| format!("amd-gpu{i}")),
                available: true,
                util_pct: a.util,
                mem_used_mb: a.used_mb,
                mem_total_mb: a.total_mb,
                mem_used_pct: pct,
                temp_c: a.temp_c,
                clock_mhz: a.clock_mhz,
                power_w: a.power_w,
                backend: "rocm".into(),
            }
        })
        .collect()
}

/// Best-effort sample; empty vec when the binary is absent or output unreadable.
pub fn sample_all() -> Vec<GpuSample> {
    sample_with("rocm-smi")
}

fn sample_with(bin: &str) -> Vec<GpuSample> {
    let out = std::process::Command::new("timeout")
        .args(["2", bin, "-a"])
        .output();
    let Ok(out) = out else { return vec![] };
    if !out.status.success() {
        return vec![];
    }
    parse_rocm(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
================================= ROCm System Management Interface ==========\n\
GPU[0] : Card Series: Navi 31 [Radeon RX 7900 XTX]\n\
GPU[0] : Temperature (Sensor #0): 61.0 C\n\
GPU[0] : GPU use (%): 73 %\n\
GPU[0] : VRAM Total Memory (MB): 24576\n\
GPU[0] : VRAM Total Used Memory (MB): 8192\n\
GPU[0] : sclk clock level: 2100Mhz\n\
GPU[0] : Average Graphics Package Power (W): 187.0\n\
GPU[1] : Card Series: Navi 31 [Radeon RX 7900 XTX]\n\
GPU[1] : Temperature (Sensor #0): 44.0 C\n\
GPU[1] : GPU use (%): 5 %\n\
";

    #[test]
    fn parses_two_cards_tolerantly() {
        let v = parse_rocm(SAMPLE);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].backend, "rocm");
        assert!(v[0].name.contains("7900"));
        assert_eq!(v[0].temp_c, 61);
        assert_eq!(v[0].util_pct, 73);
        assert_eq!(v[0].mem_total_mb, 24576);
        assert_eq!(v[0].mem_used_mb, 8192);
        assert!((v[0].mem_used_pct - 33.33).abs() < 0.1);
        assert_eq!(v[0].clock_mhz, 2100);
        assert!((v[0].power_w - 187.0).abs() < 1e-9);
        assert_eq!(v[1].temp_c, 44);
    }

    #[test]
    fn garbage_yields_nothing_not_panic() {
        assert!(parse_rocm("").is_empty());
        assert!(parse_rocm("hello\nworld\n").is_empty());
    }

    #[test]
    fn absent_binary_yields_empty() {
        // No PATH mutation (tests run in parallel): a bogus binary name must
        // degrade to empty, never fail.
        assert!(sample_with("definitely-not-a-gpu-tool-xyz").is_empty());
    }
}
