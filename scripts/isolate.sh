#!/usr/bin/env bash
# Run a command in a DEDICATED cgroup so tenant attribution (PSI/majflt)
# sees exactly this service — not the shell's noisy scope.
# Usage: scripts/isolate.sh <name> -- <cmd...>
#   e.g. scripts/isolate.sh node-a -- ./target/debug/dist-observe agent ...
# Falls back to running unisolated (with a warning) when cgroupfs is read-only.
set -u
NAME="${1:?usage: isolate.sh <name> -- <cmd...>}"
shift
[ "${1:-}" = "--" ] && shift

SELF_CG="$(tr ':' '\n' < /proc/self/cgroup | tail -1)"
PARENT="/sys/fs/cgroup${SELF_CG}"
CHILD="$PARENT/dist-observe-$NAME"

if [ -w "$PARENT/cgroup.procs" ] && mkdir -p "$CHILD" 2>/dev/null; then
    "$@" &
    PID=$!
    if echo "$PID" > "$CHILD/cgroup.procs" 2>/dev/null; then
        echo "isolated [$NAME] pid=$PID cgroup=$SELF_CG/dist-observe-$NAME" >&2
    else
        echo "WARNING: move failed, running unisolated" >&2
    fi
    wait "$PID"
    RC=$?
    rmdir "$CHILD" 2>/dev/null || true
    exit "$RC"
else
    echo "WARNING: cgroupfs not writable, running unisolated" >&2
    exec "$@"
fi
