"""Bootstrap/info endpoint — the node's *unauthenticated* front door.

Why it exists
-------------
The panel must pin the node's TLS certificate before it can speak to the
control plane, but the control plane is the only place that can hand out
that certificate. Marzban-node solved this circular dependency with a
second, credential-free REST port (62051) that publishes the certificate;
Zagros keeps that shape but makes it explicit and minimal.

What is published, and why it is safe
-------------------------------------
Only public material: the node id, the agent version, whether the node is
already paired, and the TLS **certificate** — a public document by
definition, sent in the clear during any TLS handshake anyway.

No secrets are served: not the registration token (only its hash is ever
stored), not the signing key, not core settings. The per-core inventory is
opt-in via ``ZAGROS_NODE_INFO_DETAIL=1`` because it is mildly
fingerprintable and not needed for pairing.

Trust model
-----------
This port is read-only and unauthenticated, so it can only ever be a
*convenience*. A network attacker could substitute their own certificate
here and try to intercept the one-time registration token. The defence is
operator verification: the installer prints the fingerprint on the node's
console, and the panel shows it for confirmation before pairing — exactly
like SSH host-key verification. ``ZAGROS_NODE_INFO_BIND`` lets an operator
lock the port to the panel's address and remove even that window.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import uvicorn
from fastapi import FastAPI

from node_agent.config import (
    AGENT_NAME,
    AGENT_VERSION,
    API_VERSION,
    NODE_CORE_ALLOWLIST,
    NodeConfig,
)


def _detailed(config: NodeConfig) -> bool:
    return os.environ.get("ZAGROS_NODE_INFO_DETAIL", "0").strip().lower() in (
        "1", "true", "yes", "on")


def build_info_app(config: NodeConfig, identity, core_manager,
                   certificate, *, started_at: float) -> FastAPI:
    info = FastAPI(title="Zagros Node Info", version=AGENT_VERSION,
                   docs_url=None, redoc_url=None, openapi_url=None)

    @info.get("/info")
    async def node_info() -> dict[str, Any]:
        payload: dict[str, Any] = {
            "node_id": identity.node_id,
            "name": config.name or None,
            "agent": AGENT_NAME,
            "agent_version": AGENT_VERSION,
            "api_version": API_VERSION,
            "control_plane_port": config.port,
            "info_port": config.api_port,
            "registered": identity.signing_key() is not None,
            "pending_token": identity.has_pending_token,
            "certificate_sha256": certificate.fingerprint,
            "certificate_pem": certificate.pem,
            "certificate_not_after": certificate.not_after,
            "uptime_seconds": round(time.time() - started_at, 1),
        }
        if _detailed(config):
            installed = set(core_manager.list_cores())
            payload["cores"] = {
                "installed": sorted(installed),
                "available": sorted(NODE_CORE_ALLOWLIST - installed),
            }
        return payload

    @info.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "registered": identity.signing_key() is not None}

    @info.get("/fingerprint")
    async def fingerprint() -> dict[str, Any]:
        # Convenience for operators verifying a node by hand:
        #   curl -s http://NODE:62051/fingerprint
        return {"node_id": identity.node_id,
                "certificate_sha256": certificate.fingerprint}

    return info


async def start_info_server(config: NodeConfig, identity, core_manager,
                            certificate, *, started_at: float | None = None):
    """Serve the info port inside the agent's own event loop.

    Returns an async callable that shuts the server down again.
    """
    app = build_info_app(config, identity, core_manager, certificate,
                         started_at=started_at if started_at is not None else time.time())
    server = uvicorn.Server(uvicorn.Config(
        app, host=config.info_bind, port=config.api_port,
        log_level="warning", access_log=False))
    task = asyncio.ensure_future(server.serve())

    for _ in range(200):                       # ≤ 10s for the socket to bind
        if server.started:
            break
        if task.done():                        # bind failed — surface it now
            await task
        await asyncio.sleep(0.05)
    else:
        task.cancel()
        raise RuntimeError(
            f"info port {config.api_port} did not bind within 10s "
            "(is it already in use? see ZAGROS_NODE_API_PORT)")

    async def stop() -> None:
        server.should_exit = True
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

    return stop
