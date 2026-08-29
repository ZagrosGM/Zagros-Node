"""Zagros Node Agent — standalone, multi-core remote node for the Zagros panel.

A fork of the *shape* of gozargah/marzban-node (Docker-first, one container
per server, certificate-based pairing with the panel) whose transport and
capability model were rebuilt:

* marzban-node ships a single core (xray) over rpyc;
  zagros-node manages every Zagros core — xray, sing-box, OpenVPN,
  WireGuard, SSH, SoftEther and PPTP — through the panel's own driver
  runtime, over a certificate-pinned HTTPS control plane with HMAC-signed,
  replay-protected commands.
"""
from node_agent.config import AGENT_NAME, AGENT_VERSION, API_VERSION

__all__ = ["AGENT_NAME", "AGENT_VERSION", "API_VERSION"]
__version__ = AGENT_VERSION
