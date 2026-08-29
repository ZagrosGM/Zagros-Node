"""Durable account state for a node.

The vendored drivers keep their accounts in memory: whatever the panel pushed
lives only in the running agent's heap. That is fine for *serving* traffic —
the tunnels are configured from files — but it is not fine for anything that
reads the account list:

* ``bandwidth_identities()`` resolves a user's inner addresses from the
  account settings, so after a restart a node silently stops shaping until the
  panel happens to sync again;
* presence and per-account usage do not need the list (they are derived from
  live sessions), which makes the gap easy to miss — one feature quietly
  degrades while the others look healthy.

The panel owns the desired state, so this store is a cache of it, not a
source of truth: it is written after a successful sync and replayed into the
driver at boot. A core that was uninstalled, or a payload the driver rejects,
is skipped with a warning — never fatal.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("node_agent.accounts")

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class AccountsStore:
    """Per-core JSON snapshots of the last account set the panel pushed."""

    def __init__(self, data_dir: str | Path) -> None:
        self._dir = Path(data_dir) / "accounts"

    # ------------------------------------------------------------------ #
    # paths
    # ------------------------------------------------------------------ #
    def _path(self, core_id: str) -> Path:
        return self._dir / f"{_SAFE.sub('_', str(core_id))}.json"

    # ------------------------------------------------------------------ #
    # write
    # ------------------------------------------------------------------ #
    def store(self, core_id: str, accounts: list[Any],
              replace: bool = True) -> list[dict]:
        """Persist ``accounts``; returns the full resulting set.

        ``replace=True`` (a full convergence) overwrites the snapshot;
        ``replace=False`` (an incremental user save) merges by account_id so a
        later full sync is never required to repair it.
        """
        incoming = [a for a in accounts if isinstance(a, dict)]
        stored: list[dict] = []
        if not replace:
            stored = self.load(core_id)
            known = {}
            for item in stored:
                key = str(item.get("account_id") or "")
                if key:
                    known[key] = item
            for item in incoming:
                key = str(item.get("account_id") or "")
                if key:
                    known[key] = item
                else:
                    stored.append(item)
            merged = list(known.values())
            # keep the historical order, append brand-new accounts at the end
            order = {str(i.get("account_id") or ""): n
                     for n, i in enumerate(stored)}
            merged.sort(key=lambda i: order.get(str(i.get("account_id") or ""),
                                                10 ** 6))
            stored = merged
        else:
            stored = incoming

        try:
            self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            part = self._path(core_id).with_suffix(".part")
            part.write_text(json.dumps(stored, sort_keys=True),
                            encoding="utf-8")
            part.replace(self._path(core_id))
        except OSError as exc:  # pragma: no cover - disk full / read-only
            logger.warning("accounts for '%s' could not be persisted: %s",
                           core_id, exc)
        return stored

    def forget(self, core_id: str) -> None:
        """Drop the snapshot of an uninstalled core."""
        try:
            self._path(core_id).unlink()
        except (OSError, FileNotFoundError):
            pass

    # ------------------------------------------------------------------ #
    # read
    # ------------------------------------------------------------------ #
    def load(self, core_id: str) -> list[dict]:
        path = self._path(core_id)
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("stored accounts for '%s' are unreadable: %s",
                           core_id, exc)
            return []
        return [item for item in data if isinstance(item, dict)] if isinstance(
            data, list) else []

    def all(self) -> dict[str, list[dict]]:
        if not self._dir.is_dir():
            return {}
        return {path.stem: self.load(path.stem)
                for path in sorted(self._dir.glob("*.json"))}
