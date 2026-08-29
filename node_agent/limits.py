"""Node-side bandwidth shaping.

The panel decides WHO is limited and by how much — it owns the user database.
The node decides HOW, because shaping is a host-level act: tc filters and nft
marks only change what happens on the machine that actually carries the
packets. A panel that tried to shape a node's traffic remotely would be
shaping nothing at all.

So the panel pushes the rates it computed, the node resolves the rest from
its own drivers (inner addresses, ssh uids) and installs the ruleset locally.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("node_agent.limits")


class _NodeRuntimeShim:
    """What the limiter needs on a node: the core manager, and nothing else.

    The account-owning paths (fail-closed suspension, recovery) stay dormant
    here on purpose: a node never suspends users, it only shapes them. They
    would only run if a fail-closed key existed, and only the panel writes
    those.
    """

    def __init__(self, core_manager: Any) -> None:
        self.core_manager = core_manager


class NodeBandwidthLimiter:
    """Applies the panel's per-user limits to this host."""

    def __init__(self, core_manager: Any, data_dir: str,
                 interface: str | None = None) -> None:
        self._core_manager = core_manager
        self._interface = interface or os.environ.get(
            "ZAGROS_BANDWIDTH_INTERFACE") or self._default_interface()
        self._path = Path(data_dir) / "bandwidth-limits.json"
        self._limits: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._last_error: str | None = None

    # ------------------------------------------------------------------ #
    # persistence — limits must survive an agent restart
    # ------------------------------------------------------------------ #
    @staticmethod
    def _default_interface() -> str:
        """The interface holding the default route (what `eth0` guesses)."""
        try:
            with open("/proc/net/route", encoding="ascii") as fh:
                for line in fh.read().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == "00000000":
                        return parts[0]
        except OSError:
            pass
        return "eth0"

    def load(self) -> None:
        if not self._path.exists():
            return
        try:
            stored = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("bandwidth limits could not be read: %s", exc)
            return
        if isinstance(stored, dict):
            self._limits = stored

    def _store(self, limits: dict[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            part = self._path.with_suffix(".part")
            part.write_text(json.dumps(limits, sort_keys=True), encoding="utf-8")
            part.replace(self._path)
        except OSError as exc:
            logger.warning("bandwidth limits could not be persisted: %s", exc)

    # ------------------------------------------------------------------ #
    # desired state
    # ------------------------------------------------------------------ #
    def _identities(self, core_id: str) -> dict[str, Any]:
        """This host's {account_id: identity} for one core."""
        try:
            if core_id not in self._core_manager.list_cores():
                return {}
            driver = self._core_manager.get(core_id)
            return dict(driver.bandwidth_identities() or {})
        except Exception as exc:  # noqa: BLE001 — a core without identities adds none
            # Visible on purpose: an empty result is indistinguishable from a
            # broken core otherwise, and "the node shaped nobody" is exactly
            # the bug an operator has to be able to see.
            logger.debug("bandwidth identities unavailable for %s: %s", core_id, exc)
            return {}

    def _identity_map(self) -> dict[str, dict[str, Any]]:
        """{core_id: {account_id: identity}} for every core that has any."""
        wanted: set[str] = set()
        for spec in (self._limits or {}).values():
            if not isinstance(spec, dict):
                continue
            wanted |= set(spec.get("accounts") or {})
        return {core_id: ids for core_id in wanted
                if (ids := self._identities(core_id))}

    def _desired(self) -> dict[int, Any]:
        from app.platform.bandwidth import UserLimit

        desired: dict[int, Any] = {}
        for raw_id, spec in (self._limits or {}).items():
            if not isinstance(spec, dict):
                continue
            try:
                user_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            limit = UserLimit(
                user_id=user_id,
                username=str(spec.get("username") or raw_id),
                upload_mbps=max(0, int(spec.get("upload_mbps") or 0)),
                download_mbps=max(0, int(spec.get("download_mbps") or 0)),
            )
            for core_id, account_ids in (spec.get("accounts") or {}).items():
                if not isinstance(account_ids, (list, tuple)):
                    continue
                if core_id == "softether":
                    limit.softether_accounts |= {str(a) for a in account_ids}
                identities = self._identities(core_id)
                for account_id in account_ids:
                    identity = identities.get(str(account_id)) or {}
                    for source in identity.get("inner_sources") or []:
                        try:
                            limit.inner_sources.add(
                                str(ipaddress.ip_interface(str(source)).ip))
                        except ValueError:
                            continue
                    for uid in identity.get("uids") or []:
                        try:
                            limit.ssh_uids.add(int(uid))
                        except (TypeError, ValueError):
                            continue
            desired[user_id] = limit
        return desired

    # ------------------------------------------------------------------ #
    # apply
    # ------------------------------------------------------------------ #
    def apply(self, limits: dict[str, Any] | None = None) -> dict[str, Any]:
        """Install the pushed ruleset; returns a small status dict."""
        from app.platform.bandwidth import BandwidthLimiter

        with self._lock:
            if limits is not None:
                self._limits = limits
                self._store(limits)
            try:
                limiter = BandwidthLimiter(
                    _NodeRuntimeShim(self._core_manager),
                    interface=self._interface,
                    desired_provider=self._desired,
                )
                state = limiter.reconcile()
                self._last_error = limiter.last_error
            except Exception as exc:  # noqa: BLE001 — report, never crash
                self._last_error = str(exc)
                logger.warning("bandwidth reconcile failed on this node: %s", exc)
                return {"ok": False, "error": str(exc),
                        "limited_users": self._limited_count()}
            return {
                "ok": True,
                "interface": self._interface,
                "limited_users": self._limited_count(),
                "applied_users": len((state or {}).get("users") or {}),
                # how many accounts each core could resolve to something
                # shapeable — an all-zero map means the node was handed a
                # limit it cannot enforce, which is a bug, not a no-op
                "identities": {core: len(ids) for core, ids in self._identity_map().items()},
                "sources": sum(
                    len(identity.get("inner_sources") or [])
                    for ids in self._identity_map().values()
                    for identity in ids.values()),
            }

    def _limited_count(self) -> int:
        return sum(
            1 for spec in (self._limits or {}).values()
            if isinstance(spec, dict)
            and (int(spec.get("upload_mbps") or 0) or int(spec.get("download_mbps") or 0))
        )

    def status(self) -> dict[str, Any]:
        return {
            "interface": self._interface,
            "limited_users": self._limited_count(),
            "known_users": len(self._limits or {}),
            "last_error": self._last_error,
        }
