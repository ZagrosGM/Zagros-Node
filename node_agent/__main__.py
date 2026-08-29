"""``python -m node_agent`` — run the agent (TLS is mandatory)."""
from __future__ import annotations

import asyncio
import sys

import uvicorn

from node_agent import tls
from node_agent.config import load_config
from node_agent.cli import print_banner


def main() -> int:
    try:
        cfg = load_config()
    except ValueError as exc:
        print(f"zagros-node: invalid configuration: {exc}", file=sys.stderr)
        return 2

    certificate = tls.ensure(cfg)
    print_banner(cfg, certificate)

    if not cfg.registration_hash and not _identity_registered(cfg):
        print(
            "zagros-node: WARNING — no registration token is configured "
            "(ZAGROS_NODE_REGISTRATION_HASH is empty) and this node is not "
            "paired yet.\n"
            "             The panel cannot claim it until a token is installed "
            "or the state is reset:\n"
            "               zagros-node reset-registration <sha256-of-new-token>",
            file=sys.stderr,
        )

    uvicorn.run(
        "node_agent.app:app",
        host=cfg.host,
        port=cfg.port,
        ssl_certfile=certificate.cert_path,
        ssl_keyfile=certificate.key_path,
        workers=1,
        proxy_headers=False,
        forwarded_allow_ips="",
        log_level="info",
    )
    return 0


def _identity_registered(cfg) -> bool:
    from node_agent.security import NodeIdentityStore

    return NodeIdentityStore(cfg.data_dir, None).signing_key() is not None


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:  # pragma: no cover
        asyncio.run(asyncio.sleep(0))
        sys.exit(130)
