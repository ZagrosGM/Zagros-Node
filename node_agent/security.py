"""Registration, request signing and replay protection for the node agent.

Threat model
------------
The control plane port is reachable by the panel over the public internet.
Every command is therefore authenticated with HMAC-SHA256 over a canonical
request encoding (method, path, timestamp, nonce, body hash) using a key
that was exchanged exactly once, over the certificate-pinned TLS channel,
during registration.

* **Bootstrap** — the installer seeds ``ZAGROS_NODE_REGISTRATION_HASH``
  (SHA-256 of a one-time token). The token itself is never stored, so a
  stolen disk image cannot be registered to a rogue panel.
* **Registration** — consumes the token and returns the signing key once.
  Re-registration requires a new token (``zagros-node reset-registration``).
* **Commands** — every request carries a nonce inside a 5-minute window;
  nonces are persisted so a restart cannot replay a captured command.

Wire format (shared with the panel's ``app.nodes.client``)::

    X-Zagros-Node      node id
    X-Zagros-Timestamp unix seconds
    X-Zagros-Nonce     16-byte hex, single use
    X-Zagros-Signature hex HMAC-SHA256 over
                       "\\n".join(METHOD, path, timestamp, nonce, sha256(body))
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

from app.persistence.cipher import SecretsCipher


class NodeSecurityError(ValueError):
    """Raised for every authentication/authorization failure."""


class NodeIdentityStore:
    """Sealed signer identity; the bootstrap token is stored as a hash only."""

    def __init__(self, root: str, registration_hash: str | None = None) -> None:
        self.root = Path(root)
        self.path = self.root / "identity.json"
        self.key_path = self.root / "identity.key"
        self.audit_path = self.root / "audit.jsonl"
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        if not self.key_path.exists():
            part = self.key_path.with_suffix(".part")
            part.write_bytes(os.urandom(32))
            os.chmod(part, 0o600)
            os.replace(part, self.key_path)
        local_key = self.key_path.read_bytes()
        if len(local_key) != 32:
            raise NodeSecurityError("identity.key must contain exactly 32 bytes")
        os.chmod(self.key_path, 0o600)
        self._cipher = SecretsCipher(local_key)
        self._lock = threading.RLock()

        if not self.path.exists():
            self._write({
                "node_id": secrets.token_hex(16),
                "registration_token_hash": registration_hash or "",
                "signing_key_enc": None,
                "registered_panel": None,
                "registered_at": None,
            })
        elif registration_hash:
            # An installer re-run refreshes the one-time token without
            # disturbing an existing identity or signing key.
            state = self._read()
            if state.get("registration_token_hash") != registration_hash:
                state["registration_token_hash"] = registration_hash
                self._write(state)

    # ----------------------------- storage ----------------------------- #
    def _read(self) -> dict:
        return json.loads(self.path.read_text())

    def _write(self, payload: dict) -> None:
        part = self.path.with_suffix(".part")
        part.write_text(json.dumps(payload, sort_keys=True) + "\n")
        os.chmod(part, 0o600)
        os.replace(part, self.path)

    def _seal_signing_key(self, key: bytes, node_id: str) -> str:
        return self._cipher.encrypt_json(
            {"key": base64.b64encode(key).decode("ascii")},
            aad=f"node-signing:{node_id}")

    # ---------------------------- identity ----------------------------- #
    @property
    def node_id(self) -> str:
        return str(self._read()["node_id"])

    @property
    def registered_panel(self) -> str | None:
        return self._read().get("registered_panel")

    @property
    def registered_at(self) -> int | None:
        return self._read().get("registered_at")

    @property
    def has_pending_token(self) -> bool:
        return bool(self._read().get("registration_token_hash"))

    def signing_key(self) -> bytes | None:
        state = self._read()
        value = state.get("signing_key_enc")
        if not value:
            return None
        try:
            unsealed = self._cipher.decrypt_json(
                str(value), aad=f"node-signing:{state['node_id']}")
            key = base64.b64decode(unsealed["key"])
        except Exception as exc:  # noqa: BLE001 — fail closed on any tamper/key loss
            raise NodeSecurityError("node signing key cannot be unsealed") from exc
        if len(key) != 32:
            raise NodeSecurityError("node signing key has invalid length")
        return key

    # -------------------------- registration --------------------------- #
    def register(self, token: str, panel_id: str) -> bytes:
        with self._lock:
            state = self._read()
            expected = str(state.get("registration_token_hash") or "")
            actual = hashlib.sha256(token.encode("utf-8")).hexdigest()
            if not expected or not hmac.compare_digest(expected, actual):
                raise NodeSecurityError("invalid or already-consumed registration token")
            key = secrets.token_bytes(32)
            state["registration_token_hash"] = ""       # burn the one-time token
            state["signing_key_enc"] = self._seal_signing_key(
                key, str(state["node_id"]))
            state["registered_panel"] = panel_id
            state["registered_at"] = int(time.time())
            self._write(state)
            self.audit("node.register", {"panel_id": panel_id})
            return key

    def revoke(self) -> None:
        with self._lock:
            state = self._read()
            state["signing_key_enc"] = None
            state["registered_panel"] = None
            state["registered_at"] = None
            self._write(state)
            self.audit("node.revoke", {})

    def reset_registration(self, registration_hash: str) -> None:
        """Local, root-only rearm: forget the panel and accept a new token.

        Used when a node is moved to another panel or its pairing is lost.
        Existing core state is untouched — only pairing authority is cleared.
        """
        with self._lock:
            state = self._read()
            state["signing_key_enc"] = None
            state["registered_panel"] = None
            state["registered_at"] = None
            state["registration_token_hash"] = registration_hash
            self._write(state)
            self.audit("node.reset_registration", {})

    def audit(self, action: str, detail: dict) -> None:
        row = {"ts": int(time.time()), "action": action, "detail": detail}
        with open(self.audit_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
        os.chmod(self.audit_path, 0o600)

    def audit_tail(self, limit: int = 100) -> list[dict]:
        if not self.audit_path.exists():
            return []
        lines = self.audit_path.read_text(encoding="utf-8").splitlines()[-limit:]
        rows: list[dict] = []
        for line in lines:
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        return rows


class ReplayGuard:
    """Bounded nonce cache that survives an agent process restart."""

    def __init__(self, root: str | None = None, *,
                 window_seconds: int = 300) -> None:
        self.window = window_seconds
        self._path = Path(root) / "replay.json" if root else None
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()
        if self._path and self._path.exists():
            try:
                value = json.loads(self._path.read_text())
                self._seen = {str(key): int(ts) for key, ts in value.items()}
            except (OSError, ValueError, TypeError):
                # Corrupt replay state must fail closed rather than forgetting
                # potentially live nonces inside the acceptance window.
                raise NodeSecurityError("node replay cache is invalid") from None

    def _write(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        part = self._path.with_suffix(".part")
        part.write_text(json.dumps(self._seen, sort_keys=True) + "\n")
        os.chmod(part, 0o600)
        os.replace(part, self._path)

    def accept(self, nonce: str, timestamp: int, *, now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        if abs(now - timestamp) > self.window:
            raise NodeSecurityError("request timestamp is outside the replay window")
        if not (16 <= len(nonce) <= 128 and nonce.isalnum()):
            raise NodeSecurityError("invalid request nonce")
        with self._lock:
            self._seen = {key: ts for key, ts in self._seen.items()
                          if now - ts <= self.window}
            if nonce in self._seen:
                raise NodeSecurityError("replayed request nonce")
            self._seen[nonce] = timestamp
            self._write()


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_request(method: str, path: str, timestamp: str,
                      nonce: str, body: bytes) -> bytes:
    return "\n".join((method.upper(), path, timestamp, nonce,
                      body_hash(body))).encode("utf-8")


def signature(key: bytes, method: str, path: str, timestamp: str,
              nonce: str, body: bytes) -> str:
    return hmac.new(
        key, canonical_request(method, path, timestamp, nonce, body),
        hashlib.sha256).hexdigest()


def verify_signature(key: bytes, provided: str, method: str, path: str,
                     timestamp: str, nonce: str, body: bytes) -> None:
    expected = signature(key, method, path, timestamp, nonce, body)
    if not hmac.compare_digest(expected, provided):
        raise NodeSecurityError("invalid request signature")
