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

# Confirm before touching the system (bypass with --yes for automation).
if [ "${1:-}" != "--yes" ]; then
    printf 'Are you sure? This will install dist-observe as system services [y/N]: '
    read -r ANSWER
    [ "$ANSWER" = "y" ] || [ "$ANSWER" = "Y" ] || { echo "Aborted."; exit 0; }
else
    shift
fi

[ "$(id -u)" = "0" ] || [ -n "$DESTDIR" ] || { echo "run as root: sudo bash scripts/install.sh"; exit 1; }
[ -x "$BIN_SRC" ] || { echo "build first: cargo build (and set BIN_SRC=)"; exit 1; }

# 1. Dedicated non-root user (no login, no home).
# Two layered defenses for the "invalid group" class of failures:
# (a) explicit groupadd first, user pinned with -g (distro login.defs differ);
# (b) retry getent after each creation (sssd/nscd can lag behind the files).
if [ -n "$DESTDIR" ]; then
    echo "(test mode: skipping user/group creation; ownership flags off)"
    OWN_LIB=()
    OWN_ETC=()
else
    if ! getent group "$APP_USER" >/dev/null; then
        groupadd --system "$APP_USER"
        echo "group $APP_USER created"
    fi
    # Retry loop: name services (sssd/nscd) can lag seconds behind the files
    # groupadd/useradd just wrote — a single getent may miss a group that
    # provably exists on disk ("invalid group" right after "created").
    wait_for() { # $1=name $2=getent-db
        local t=0
        while ! getent "$2" "$1" >/dev/null; do
            sleep 1; t=$((t + 1))
            [ "$t" -ge 10 ] && return 1
        done
    }
    wait_for "$APP_USER" group || { echo "FATAL: group $APP_USER not visible after creation"; exit 1; }
    if ! id "$APP_USER" >/dev/null 2>&1; then
        NOLOGIN="$(command -v nologin || echo /bin/false)"
        useradd --system --no-create-home --gid "$APP_USER" --shell "$NOLOGIN" "$APP_USER"
        echo "user $APP_USER created"
    fi
    wait_for "$APP_USER" passwd || { echo "FATAL: user $APP_USER not visible after creation"; exit 1; }
    OWN_LIB=(-o "$APP_USER" -g "$APP_USER")
    OWN_ETC=(-o root -g "$APP_USER")
fi

# 2. Binary (-D creates leading dirs, needed for DESTDIR test trees).
install -D -m 0755 "$BIN_SRC" "$DESTDIR/usr/local/bin/dist-observe"

# 3. State + certs + logs with least privilege.
# (mkdir first: install -d does not create parents, needed for DESTDIR trees)
mkdir -p "$DESTDIR/var/lib" "$DESTDIR/etc" "$DESTDIR/var/log" "$DESTDIR/etc/systemd/system"
install -d -m 0750 "${OWN_LIB[@]}" "$DESTDIR/var/lib/dist-observe"
install -d -m 0750 "${OWN_ETC[@]}" "$DESTDIR/etc/dist-observe"
install -d -m 0750 "${OWN_LIB[@]}" "$DESTDIR/var/log/dist-observe"
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
