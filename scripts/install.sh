#!/usr/bin/env bash
# Install dist-observe as system services. Run ONCE as root:
#   sudo bash scripts/install.sh
# Then follow the printed enable/verify steps (review before enabling).
#
# Testability: all destinations honor ${DESTDIR:-} (empty on real installs),
# so the full file layout can be verified rootless:
#   DESTDIR=/tmp/fakeroot PATH=test/stubs:$PATH bash scripts/install.sh
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN_SRC="${BIN_SRC:-$HERE/target/debug/dist-observe}"
UNIT_SRC="${UNIT_SRC:-$HERE/deploy}"
DESTDIR="${DESTDIR:-}"
APP_USER=dist-observe

[ "$(id -u)" = "0" ] || { echo "run as root: sudo bash scripts/install.sh"; exit 1; }
[ -x "$BIN_SRC" ] || { echo "build first: cargo build (and set BIN_SRC=)"; exit 1; }

# 1. Dedicated non-root user (no login, no home).
if ! id "$APP_USER" >/dev/null 2>&1; then
    NOLOGIN="$(command -v nologin || echo /bin/false)"
    useradd --system --no-create-home --shell "$NOLOGIN" "$APP_USER"
    echo "user $APP_USER created"
fi

# 2. Binary (-D creates leading dirs, needed for DESTDIR test trees).
install -D -m 0755 "$BIN_SRC" "$DESTDIR/usr/local/bin/dist-observe"

# 3. State + certs + logs with least privilege.
# (mkdir first: install -d does not create parents, needed for DESTDIR trees)
mkdir -p "$DESTDIR/var/lib" "$DESTDIR/etc" "$DESTDIR/var/log" "$DESTDIR/etc/systemd/system"
install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$DESTDIR/var/lib/dist-observe"
install -d -m 0750 -o root -g "$APP_USER" "$DESTDIR/etc/dist-observe"
install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$DESTDIR/var/log/dist-observe"
echo "place certs in /etc/dist-observe (root-owned, group-readable keys NOT world-readable):"
echo "  install -m 0640 -o root -g $APP_USER <dir>/ca-cert.pem /etc/dist-observe/"
echo "  install -m 0640 -o root -g $APP_USER <dir>/server-*.pem /etc/dist-observe/"
echo "  install -m 0640 -o root -g $APP_USER <dir>/client-<node>-*.pem /etc/dist-observe/"

# 4. Units.
install -m 0644 "$UNIT_SRC/dist-observe-collector.service" "$DESTDIR/etc/systemd/system/"
install -m 0644 "$UNIT_SRC/dist-observe-agent@.service" "$DESTDIR/etc/systemd/system/"
if [ -z "$DESTDIR" ]; then
    systemctl daemon-reload
else
    echo "(DESTDIR set: skipping systemctl daemon-reload — test mode)"
fi

cat <<'EOF'

next steps (review, then run):
  # collector (on the central host)
  sudo systemctl enable --now dist-observe-collector
  sudo systemctl status dist-observe-collector
  sudo journalctl -u dist-observe-collector -f
  # agent per node (needs client-<node>-*.pem from keygen first)
  sudo systemctl enable --now dist-observe-agent@web-1
  sudo systemctl status dist-observe-agent@web-1
  # verify end-to-end (from any host with a client cert):
  curl --cacert /etc/dist-observe/ca-cert.pem \
       --cert /etc/dist-observe/client-web-1-cert.pem \
       --key /etc/dist-observe/client-web-1-key.pem \
       https://COLLECTOR:18080/nodes
EOF
