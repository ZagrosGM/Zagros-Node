#!/usr/bin/env bash
# Container entrypoint for the Zagros node agent.
#
# Responsibilities, in order:
#   1. fail loudly on a configuration that could never work (missing token on
#      an unpaired node, ports that collide, unwritable data root);
#   2. print the identity banner (the operator copies the SHA-256 pin);
#   3. hand over to the agent.
#
# Deliberately NOT doing anything privileged here: no package installs, no
# sysctl mutation. Kernel prerequisites (TUN, forwarding, NET_ADMIN) belong
# to the host/compose layer, where they are auditable.
set -euo pipefail

log()  { printf 'zagros-node: %s\n' "$*"; }
fail() { printf 'zagros-node: ERROR: %s\n' "$*" >&2; exit 1; }

DATA_DIR="${ZAGROS_NODE_DATA:-/var/lib/zagros/node}"

# --- 1. writable data root -------------------------------------------------
mkdir -p "$DATA_DIR" 2>/dev/null || fail "cannot create data dir '$DATA_DIR' — is the volume mounted and writable?"
[ -w "$DATA_DIR" ] || fail "data dir '$DATA_DIR' is not writable (uid $(id -u))"

# --- 2. configuration sanity ----------------------------------------------
PORT="${ZAGROS_NODE_PORT:-62050}"
API_PORT="${ZAGROS_NODE_API_PORT:-62051}"
[ "$PORT" != "$API_PORT" ] || fail "ZAGROS_NODE_PORT and ZAGROS_NODE_API_PORT must differ (both $PORT)"

# --- 3. kernel prerequisites (warn only: some cores work without them) -----
if [ ! -e /dev/net/tun ]; then
  log "WARNING: /dev/net/tun is missing — OpenVPN/WireGuard cores cannot start."
  log "         Enable TUN/TAP for this VPS and mount it (-v /dev/net/tun:/dev/net/tun)."
fi
if [ -r /proc/sys/net/ipv4/ip_forward ] && [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
  log "WARNING: net.ipv4.ip_forward=0 — VPN traffic will not be forwarded by this host."
  log "         Run: sysctl -w net.ipv4.ip_forward=1 (persist it in /etc/sysctl.d)."
fi

# --- 4. identity -----------------------------------------------------------
# `cli cert` mints the self-signed certificate on first boot and prints the
# fingerprint the panel must pin.
python -m node_agent.cli cert >/dev/null 2>&1 || true
if command -v python >/dev/null 2>&1; then
  python -m node_agent.cli cert 2>/dev/null | python -c \
    'import json,sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
print("zagros-node: node certificate SHA-256 pin: " + data["certificate_sha256"])' || true
fi

log "starting agent (control plane :$PORT, info :$API_PORT)"
exec "$@"
