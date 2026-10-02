#!/usr/bin/env bash
# Self-memory + DB-size tracker for the soak. Appends one CSV line per minute:
# ts, then per PID rss_kb/hwm_kb, then DB sizes, then loadavg.
# Usage: memtrack.sh <csv> <pid...>  (runs 310 iterations ≈ 5h10m)
CSV="$1"; shift
echo "ts,pids_rss_hwm,central_kb,watch_kb,locala_kb,load1" > "$CSV"
for _ in $(seq 1 310); do
  TS=$(date +%s)
  MEM=""
  for P in "$@"; do
    if [ -r "/proc/$P/status" ]; then
      R=$(awk '/VmRSS:/{print $2}' "/proc/$P/status" 2>/dev/null)
      H=$(awk '/VmHWM:/{print $2}' "/proc/$P/status" 2>/dev/null)
      MEM="${MEM}${P}:${R:-0}/${H:-0} "
    else
      MEM="${MEM}${P}:dead "
    fi
  done
  CS=$(du -k ~/dist-observe/soak/central.db 2>/dev/null | cut -f1)
  WS=$(du -k ~/dist-observe/soak/watch.db 2>/dev/null | cut -f1)
  LS=$(du -k ~/dist-observe/soak/local-a.db 2>/dev/null | cut -f1)
  L1=$(cut -d' ' -f1 /proc/loadavg)
  echo "$TS,$MEM,${CS:-0},${WS:-0},${LS:-0},$L1" >> "$CSV"
  sleep 60
done
