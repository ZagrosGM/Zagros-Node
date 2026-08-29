"""In-container CLI (``python -m node_agent.cli``).

The operator-facing CLI is ``scripts/zagros-node`` on the host; it
translates `status`, `cert`, `info`, ... into `docker exec` calls against
this module so nothing needs a Python environment on the host.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from node_agent import tls
from node_agent.config import AGENT_NAME, AGENT_VERSION, API_VERSION, load_config


def print_banner(cfg, certificate) -> None:
    """First-boot identity summary — the operator copies the fingerprint."""
    print(f"{AGENT_NAME} {AGENT_VERSION} (api v{API_VERSION})")
    print(f"  data dir       : {cfg.data_dir}")
    print(f"  control plane  : https://{cfg.host}:{cfg.port}  (signed)")
    print(f"  info port      : http://{cfg.info_bind}:{cfg.api_port}  (read-only)")
    print(f"  certificate    : {certificate.cert_path}")
    print(f"  SHA-256 pin    : {certificate.fingerprint}")
    if cfg.name:
        print(f"  node name      : {cfg.name}")


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_serve(_args) -> int:
    from node_agent.__main__ import main
    return main()


def cmd_cert(_args) -> int:
    cfg = load_config()
    certificate = tls.ensure(cfg)
    print(json.dumps({
        "node_name": cfg.name or None,
        "certificate_path": certificate.cert_path,
        "key_path": certificate.key_path,
        "certificate_sha256": certificate.fingerprint,
        "not_after": certificate.not_after,
        "sans": list(certificate.sans),
    }, indent=2))
    return 0


def cmd_info(args) -> int:
    cfg = load_config()
    certificate = tls.ensure(cfg)
    from node_agent.security import NodeIdentityStore

    # Instantiating the store is what mints (and persists) the node id, so
    # `info` is also the cheapest way to learn a fresh node's identity.
    store = NodeIdentityStore(cfg.data_dir, cfg.registration_hash or None)
    payload = {
        "node_id": store.node_id,
        "node_name": cfg.name or None,
        "agent": AGENT_NAME,
        "agent_version": AGENT_VERSION,
        "api_version": API_VERSION,
        "control_plane_port": cfg.port,
        "info_port": cfg.api_port,
        "image": cfg.image,
        "registered": store.signing_key() is not None,
        "registered_panel": store.registered_panel,
        "pending_token": store.has_pending_token,
        "certificate_sha256": certificate.fingerprint,
        "certificate_not_after": certificate.not_after,
        "cores": _cores_state(cfg),
    }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_status(_args) -> int:
    cfg = load_config()
    states = _cores_state(cfg)
    if not states:
        print("no cores installed — install one from the panel's node catalog")
        return 0
    width = max(len(core_id) for core_id in states)
    for core_id in sorted(states):
        record = states[core_id]
        print(f"{core_id:<{width}}  {record.get('state', '?'):<12}"
              f"  enabled={'yes' if record.get('enabled') else 'no'}")
    return 0


def cmd_reset_registration(args) -> int:
    cfg = load_config()
    from node_agent.security import NodeIdentityStore

    token_hash = (args.token_hash or "").strip().lower()
    if token_hash and len(token_hash) != 64:
        print("error: token hash must be the 64-char hex sha256 of the new token",
              file=sys.stderr)
        return 2
    identity = NodeIdentityStore(cfg.data_dir, token_hash or None)
    identity.reset_registration(token_hash)
    print(json.dumps({
        "node_id": identity.node_id,
        "registration_rearmed": bool(token_hash),
        "message": ("node is unpaired; it will accept the next one-time token "
                    "issued by a panel" if token_hash else
                    "node is unpaired; no token installed — the panel cannot "
                    "claim it until one is set"),
    }, indent=2))
    return 0


def cmd_audit(args) -> int:
    cfg = load_config()
    from node_agent.security import NodeIdentityStore

    for entry in NodeIdentityStore(cfg.data_dir, None).audit_tail(args.limit):
        print(json.dumps(entry, sort_keys=True))
    return 0


def cmd_version(_args) -> int:
    print(f"{AGENT_NAME} {AGENT_VERSION} (api v{API_VERSION})")
    return 0


def _cores_state(cfg) -> dict:
    path = Path(cfg.data_dir) / "cores.json"
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text())
    except ValueError:
        return {}
    return {core_id: {"state": record.get("state"), "enabled": record.get("enabled")}
            for core_id, record in raw.items() if isinstance(record, dict)}


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m node_agent.cli")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("serve", help="run the agent (default)")
    sub.add_parser("cert", help="show the pinned certificate + fingerprint")
    sub.add_parser("info", help="node identity, pairing state and core inventory")
    sub.add_parser("status", help="installed cores and their lifecycle state")
    reset = sub.add_parser("reset-registration",
                           help="unpair and accept a new one-time token")
    reset.add_argument("token_hash", nargs="?",
                       help="sha256 of the new one-time token (64 hex chars)")
    audit = sub.add_parser("audit", help="tail the signed local audit log")
    audit.add_argument("--limit", type=int, default=50)
    sub.add_parser("version", help="print the agent version")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "serve"
    handlers = {
        "serve": cmd_serve, "cert": cmd_cert, "info": cmd_info,
        "status": cmd_status, "reset-registration": cmd_reset_registration,
        "audit": cmd_audit, "version": cmd_version,
    }
    return handlers[command](args)


if __name__ == "__main__":
    sys.exit(main())
