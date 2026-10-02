#!/usr/bin/env bash
# One-glance soak status: aliveness, sample counts, anomalies so far, DB sizes.
SOAK=~/dist-observe/soak
for n in load collector agent-a agent-b watch ffitrack nondet memtrack; do
  if [ -f "$SOAK/$n.pid" ]; then
    P=$(cat "$SOAK/$n.pid")
    if kill -0 "$P" 2>/dev/null; then ST="alive"; else ST="dead"; fi
    echo "$n pid=$P $ST"
  else
    echo "$n (no pidfile)"
  fi
done
echo "--- samples ---"
for db in central watch local-a; do
  [ -f "$SOAK/$db.db" ] && python3 -c "
import sqlite3
c=sqlite3.connect('$SOAK/$db.db')
try: print('$db rows:', c.execute('SELECT COUNT(*) FROM snapshots').fetchone()[0])
except Exception as e: print('$db err', e)"
done
echo "--- anomalies so far ---"
grep -h -c "ANOMALY" "$SOAK"/watch.log "$SOAK"/agent-a.log "$SOAK"/agent-b.log 2>/dev/null
echo "--- reconnects ---"
grep -h "reconnects=" "$SOAK"/agent-*.log 2>/dev/null
echo "--- sizes ---"
du -sh "$SOAK"/*.db 2>/dev/null
tail -2 "$SOAK/mem.csv" 2>/dev/null
