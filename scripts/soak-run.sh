#!/usr/bin/env bash
# 5-hour soak launcher. Everything detached (setsid+nohup) with PID files,
# all artifacts under ~/dist-observe/soak/. Safe to start and walk away;
# poll with: tail soak/*.log ; scripts/soak-status.sh
# Usage: scripts/soak-run.sh   (uses /tmp/certs from keygen; set CERTDIR to override)
set -u
SOAK=~/dist-observe/soak
CERTDIR="${CERTDIR:-/tmp/certs}"
BIN=~/dist-observe/target/debug/dist-observe
mkdir -p "$SOAK"
cd ~/dist-observe || exit 1

[ -x "$BIN" ] || { echo "build first: cargo build"; exit 1; }
for f in "$CERTDIR/ca-cert.pem" "$CERTDIR/server-cert.pem" "$CERTDIR/server-key.pem" \
         "$CERTDIR/client-soak-a-cert.pem"; do
  [ -f "$f" ] || { echo "missing cert $f — run keygen with --client soak-a --client soak-b first"; exit 1; }
done
rm -f "$SOAK"/*.pid

launch() { # name -- cmd...
  local name="$1"; shift; [ "${1:-}" = "--" ] && shift
  setsid nohup "$@" > "$SOAK/$name.log" 2>&1 < /dev/null &
  echo $! > "$SOAK/$name.pid"
  echo "started $name pid=$(cat "$SOAK/$name.pid")"
}

# 1. workload first (so ffi-track can grab its PID)
setsid nohup python3 scenario/soak_load.py > "$SOAK/load.log" 2>&1 < /dev/null &
echo $! > "$SOAK/load.pid"
sleep 4
LOADPID=$(grep -oP "^PID=\K[0-9]+" "$SOAK/load.log" | head -1)
echo "workload pid=$LOADPID"

# 2. collector (mTLS)
launch collector -- "$BIN" collector --bind 127.0.0.1:18099 --db "$SOAK/central.db" \
  --tls-ca "$CERTDIR/ca-cert.pem" --tls-cert "$CERTDIR/server-cert.pem" --tls-key "$CERTDIR/server-key.pem" \
  --audit-log "$SOAK/audit.log"
sleep 1

# 3. agents: A isolated in its own cgroup, B plain (the neighbor-contrast pair)
setsid nohup bash scripts/isolate.sh soak-a -- "$BIN" agent --collector 127.0.0.1:18099 \
  --node-id soak-a --interval 2 --count 9000 --local-db "$SOAK/local-a.db" \
  --tls-ca "$CERTDIR/ca-cert.pem" --tls-cert "$CERTDIR/client-soak-a-cert.pem" --tls-key "$CERTDIR/client-soak-a-key.pem" \
  > "$SOAK/agent-a.log" 2>&1 < /dev/null &
echo $! > "$SOAK/agent-a.pid"
launch agent-b -- "$BIN" agent --collector 127.0.0.1:18099 \
  --node-id soak-b --interval 2 --count 9000 \
  --tls-ca "$CERTDIR/ca-cert.pem" --tls-cert "$CERTDIR/client-soak-b-cert.pem" --tls-key "$CERTDIR/client-soak-b-key.pem"

# 4. single-node watch (swap/net/paging/retrans detectors)
launch watch -- "$BIN" watch --interval 2 --count 9000 --db "$SOAK/watch.db"

# 5. FFI trend on the workload PID
launch ffitrack -- "$BIN" ffi-track --pid "$LOADPID" --interval 10 --count 1800

# 6. nondet: benign every 30 min + ONE injected race at ~150 min
# (setsid: plain & jobs die with the launcher's process group)
setsid nohup bash -c "for i in \$(seq 1 10); do sleep 1800; $BIN nondet-demo --db $SOAK/nondet.db --input soak-benign-\$i >> $SOAK/nondet.log 2>&1; done" > "$SOAK/nondet.log" 2>&1 < /dev/null &
echo $! > "$SOAK/nondet.pid"
setsid nohup bash -c "sleep 9000; $BIN nondet-demo --db $SOAK/nondet.db --input soak-race --inject-race >> $SOAK/nondet.log 2>&1" > /dev/null 2>&1 < /dev/null &
echo $! > "$SOAK/nondet-race.pid"

# 7. self-memory + DB growth tracker
sleep 2
PIDS="$(cat "$SOAK"/collector.pid "$SOAK"/agent-a.pid "$SOAK"/agent-b.pid "$SOAK"/watch.pid "$SOAK"/ffitrack.pid 2>/dev/null | tr '\n' ' ') $LOADPID"
setsid nohup bash scripts/memtrack.sh "$SOAK/mem.csv" $PIDS > "$SOAK/memtrack.log" 2>&1 < /dev/null &
# shellcheck disable=SC2086 # intentional word-splitting: PIDs become separate argv entries
echo $! > "$SOAK/memtrack.pid"

echo "SOAK STARTED $(date -u +%FT%TZ) — poll: bash scripts/soak-status.sh"
