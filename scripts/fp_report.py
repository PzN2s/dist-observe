"""Soak FP analysis: bucket watch-log anomalies per 2-min window.

Usage: python3 scripts/fp_report.py /tmp/soak.log
Counts ANOMALY headers + per-type reason hits, prints rate/min per bucket and
flags buckets that would page (any CRITICAL-ish reason) vs noise.
"""
import re, sys
from collections import Counter

BUCKET = 120  # seconds

def main(path):
    total = Counter()
    buckets: dict[int, Counter] = {}
    starts = []
    first_ts = None
    # watch status lines carry RFC3339 timestamps: 2026-..T..Z
    ts_re = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
    cur_sec = 0
    for line in open(path, errors="replace"):
        m = ts_re.match(line)
        if m:
            # bucket by elapsed whole minutes is complex without dates; use line order:
            # 1 status line ~= 1s (interval=1). Track sample index instead.
            cur_sec += 1
        if "ANOMALY @" in line:
            b = cur_sec // BUCKET
            buckets.setdefault(b, Counter())["ANOMALY"] += 1
            total["ANOMALY"] += 1
            for key in ["swap", "paging spike", "retransmit spike", "loss-event",
                        "CPU", "RAM", "NUMA", "VRAM", "temp", "disk", "thrashing"]:
                if key in line:
                    buckets[b][key] += 1
                    total[key] += 1
    n = cur_sec
    print(f"samples≈{n} ({n//60}min), total anomalies={total['ANOMALY']}")
    print(f"{'bucket':>8} {'ANOM':>5}  breakdown")
    for b in sorted(buckets):
        c = buckets[b]
        det = ", ".join(f"{k}×{v}" for k, v in sorted(c.items()) if k != "ANOMALY") or "-"
        print(f"{b*2:>3}-{(b+1)*2:>3}min {c['ANOMALY']:>5}  {det}")
    if total["ANOMALY"]:
        print(f"\noverall FP-ish rate: {total['ANOMALY']/max(n,1)*60:.2f} anomalies/min of wall time")
    print("\nnote: 'anomaly' here = fired alert; true/false judged against the",
          "scenario timeline (baseline should be ~0, incident should be >0).")

if __name__ == "__main__":
    main(sys.argv[1])
