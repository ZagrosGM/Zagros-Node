# Zagros Node

Standalone **multi-core remote node** for the [Zagros](https://github.com/ZagrosGM/Zagros) panel.

It is a hard fork of the *shape* of [gozargah/marzban-node](https://github.com/gozargah/marzban-node) —
one container per server, Docker-first, certificate-based pairing with the panel — with the transport
and capability model rebuilt:

| | marzban-node | zagros-node |
|---|---|---|
| cores | xray only | **xray, sing-box, OpenVPN, WireGuard, SSH, SoftEther, PPTP** |
| transport | rpyc (pickle-over-TCP) | HTTPS + HMAC-SHA256 signed requests, replay-protected |
| pairing | panel-issued certificate | certificate pinning (SHA-256) + one-time registration token |
| long operations | inline request | **jobs** (`POST …/lifecycle` → poll `GET /v1/jobs/{id}`) |
| per-node core management | — | full catalog → install → start/stop/restart → logs → uninstall |
| CLI | — | `zagros-node up\|down\|status\|logs\|update\|cores\|env\|info` (+ `advanced …`) |

The panel drives every core on a node through the **same driver runtime the panel itself uses**
(`vendor/zagros`), so a core behaves identically on the master and on a node.

---

## Architecture

```
                         ┌──────────────────────────── Zagros panel ─────────────────────────────┐
                         │  Nodes page  →  Generate installer command  →  set manual / connect   │
                         │  Cores page  →  [ Master | node-1 | node-2 ]  (catalog + cores tabs)  │
                         └───────────────┬──────────────────────────────────────┬───────────────┘
                                         │ api_port (62051)                     │ port (62050)
                            GET /info    │ read-only bootstrap                  │ HTTPS, mutually
                            (cert + id)  │                                      │ authenticated
                                         ▼                                      ▼
                         ┌───────────────────────────────────────────────────────────────────────┐
                         │                        zagros-node container                          │
                         │  info_api.py ──► public: node id, versions, TLS certificate, pin      │
                         │  app.py      ──► /v1/register, /v1/heartbeat, /v1/health,             │
                         │                  /v1/cores/**, /v1/jobs/**   (HMAC-signed)            │
                         │  CoreManager ──► vendored drivers: xray sing-box openvpn wireguard    │
                         │                                    ssh softether pptp                 │
                         └───────────────────────────────────────────────────────────────────────┘
```

### Ports

| env | default | purpose |
|---|---|---|
| `ZAGROS_NODE_PORT` | 62050 | **HTTPS control plane.** Every request is HMAC-signed with the key exchanged at registration. |
| `ZAGROS_NODE_API_PORT` | 62051 | **Bootstrap/info.** Read-only, unauthenticated: node id, agent version, pairing state, and the TLS certificate the panel pins. |

### Security model

* **Certificate pinning.** The panel stores the SHA-256 of the node's leaf certificate and refuses
  to talk to anything else. Self-signed is by design — a node is usually reached by IP and no public
  CA will issue for it; trust comes from the pin, not a CA chain.
* **One-time registration token.** The panel generates it, the installer writes only its **SHA-256**
  into the node environment, and the hash is destroyed the instant pairing succeeds. A stolen disk
  image therefore cannot be claimed by a rogue panel.
* **Signed commands.** `HMAC-SHA256(method, path, timestamp, nonce, sha256(body))` with a 32-byte key,
  a 5-minute window and a persisted nonce cache — a captured command cannot be replayed, not even
  across an agent restart.
* **Minimal authority.** No shell endpoint, no Docker socket, no arbitrary file access. A lifecycle
  call is limited to an allowlisted core and to settings the driver's own schema declares; any
  path-valued setting must stay under the core root.
* **Explicit TOFU.** The info port is unauthenticated, so it can only be a convenience: the
  installer prints the fingerprint on the node's console and the panel shows it for confirmation
  before pairing — exactly like SSH host-key verification. `ZAGROS_NODE_INFO_BIND` lets you lock the
  port to the panel's address and remove even that window.

---

## Install (on a fresh node server)

The panel generates this command for you (**Nodes → add node → Generate installer command**):

```bash
curl -fsSL https://raw.githubusercontent.com/ZagrosGM/zagros-scripts/main/install-node.sh \
  | bash -s -- --panel-id panel-9f2c... --token <ONE-TIME-TOKEN> \
             --name de-1 --address 203.0.113.10 --port 62050 --api-port 62051
```

The installer lives in the **zagros-scripts** repository, next to the panel's own
installer — one place to fetch anything Zagros. It installs Docker (if missing), writes
`/opt/zagros-node/.env`, installs the `zagros-node` CLI (also from zagros-scripts), pulls
`ghcr.io/zagrosgm/zagros-node:latest`, starts the container and prints the
pairing material:

```
==> Pairing material — copy this into the panel
{
  "node_id": "3c8e84217b41095827045e8ee3c3c1c1",
  "node_name": "de-1",
  "certificate_sha256": "9e338246aa50539599d22c49acc186cb…",
  "registered": false,
  …
}
```

Then, in the panel: **Nodes → your node → set manual** (paste the fingerprint/token) or press
**connect** (the panel fetches `/info` itself and asks you to confirm the fingerprint).

Host requirements: Linux, **amd64**, root, Docker, and — for the TUN cores — `/dev/net/tun` plus
`net.ipv4.ip_forward=1`. The installer warns when either is missing.

### Build the image locally (no registry)

```bash
git clone https://github.com/ZagrosGM/zagros-node.git && cd zagros-node
ZAGROS_SCRIPTS_REF=main bash -c "$(curl -fsSL \
  https://raw.githubusercontent.com/ZagrosGM/zagros-scripts/main/install-node.sh)" \
  -- --local-build "$(pwd)" --token <TOKEN> --name de-1 --address 203.0.113.10
# or just:
docker build -t zagros-node:local .
```

---

## CLI

```bash
zagros-node up | down | restart          # container lifecycle
zagros-node status                       # container + per-core lifecycle state
zagros-node logs [-f | --tail N]         # agent logs
zagros-node info                         # node id, pairing state, cores (JSON)
zagros-node cert                         # certificate path + the SHA-256 pin
zagros-node cores                        # installed cores
zagros-node update [--image REF]         # pull the current image and recreate
zagros-node uninstall [--purge]          # remove the node (--purge deletes data)
zagros-node reset-registration <sha256>  # unpair; accept a new one-time token
zagros-node env                          # effective configuration
```

---

## Layout

```
node_agent/          the agent itself
  app.py             HTTPS control plane (signed)
  info_api.py        read-only bootstrap port
  security.py        registration, HMAC signing, replay guard
  state.py           sealed per-core lifecycle state
  jobs.py            async lifecycle jobs (installs take minutes)
  compat.py          audited stand-ins for panel-only modules
  tls.py             self-signed certificate + fingerprint
  cli.py             in-container CLI (used by the host CLI)
vendor/zagros/       pinned copy of the panel's core runtime (drivers + CoreManager)
scripts/             entrypoint.sh, install.sh, zagros-node host CLI
```

Development material — the agent-flow test suite and `sync-vendor.sh` — lives in
the [zagros-devkit](https://github.com/ZagrosGM/zagros-devkit) repository.

### Why vendored cores instead of importing the panel?

A node must be **standalone** — no panel code, no panel database, no panel web stack — but the core
drivers are owned by the panel. `sync-vendor.sh` (in zagros-devkit) therefore copies a pinned snapshot of the
driver runtime (79 files) plus its four tiny helpers, and the agent installs audited stand-ins for
the handful of panel modules the drivers touch (`node_agent/compat.py`). Two consequences:

* adding a core to the panel can never silently widen a node's attack surface — `NODE_CORE_ALLOWLIST`
  is explicit;
* the vendored tree is verified in CI to import **without** the panel and to expose all seven drivers.

```bash
git clone https://github.com/ZagrosGM/zagros-devkit.git
bash zagros-devkit/zagros-node/tools/sync-vendor.sh /path/to/Zagros
```

---

## Tests

The suite lives in [zagros-devkit](https://github.com/ZagrosGM/zagros-devkit).

```bash
git clone https://github.com/ZagrosGM/zagros-devkit.git
pip install -r requirements.txt requests
PYTHONPATH=vendor/zagros python zagros-devkit/zagros-node/tests/test_agent_flow.py            # real core install
PYTHONPATH=vendor/zagros python zagros-devkit/zagros-node/tests/test_agent_flow.py --no-core  # offline
```

The suite boots the agent on ephemeral ports and walks the whole path the panel takes: info port →
pinned registration → signed heartbeat → forged-signature and replay rejection → job-based core
install → catalog/inventory transitions.

---

## Known limits

* **amd64 only** (pinned accel-ppp/PPTP engine and PPP package manifest).
* User-account federation is per inbound document: the panel pushes each core's Config Studio
  document, which covers xray and sing-box clients completely. Per-user account federation for
  WireGuard/OpenVPN/SSH/SoftEther is roadmap work.
* One node belongs to one panel. Re-pairing requires `zagros-node reset-registration`.

## License

AGPL-3.0 — same as the Zagros panel.
