"""End-to-end smoke test for the node agent (no Docker required).

Boots ``python -m node_agent`` on ephemeral ports with a throw-away data
directory and walks the whole pairing path the panel performs:

    info port → /info (certificate + fingerprint)
    → HTTPS /v1/register (one-time token, cert pinned)
    → signed /v1/heartbeat, /v1/health, /v1/cores
    → signed lifecycle job for a real core install (unless --no-core)

Run: python tests/test_agent_flow.py [--no-core] [--core xray]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VENDOR = REPO / "vendor" / "zagros"

TOKEN = "test-" + secrets.token_urlsafe(24)
TOKEN_HASH = hashlib.sha256(TOKEN.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# transport (mirrors app.nodes.client on the panel side)
# --------------------------------------------------------------------------- #
def _signature(key: bytes, method: str, path: str, timestamp: str,
               nonce: str, body: bytes) -> str:
    canonical = "\n".join(
        (method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest())
    ).encode()
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


class Client:
    def __init__(self, address: str, port: int, node_id: str, key: bytes,
                 certfile: str) -> None:
        self.base = f"https://{address}:{port}"
        self.node_id, self.key, self.certfile = node_id, key, certfile

    def _request(self, method: str, path: str, payload: dict | None = None,
                 signed: bool = True):
        import requests

        body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
        headers = {"Content-Type": "application/json"}
        query = ""
        if "?" in path:
            path, _, query = path.partition("?")
        full = path + (f"?{query}" if query else "")
        if signed:
            timestamp, nonce = str(int(time.time())), secrets.token_hex(16)
            headers.update({
                "X-Zagros-Node": self.node_id,
                "X-Zagros-Timestamp": timestamp,
                "X-Zagros-Nonce": nonce,
                "X-Zagros-Signature": _signature(
                    self.key, method, path, timestamp, nonce, body),
            })
        return requests.request(method, self.base + full, data=body or None,
                                headers=headers, verify=self.certfile, timeout=30)

    def get(self, path, **kw):
        return self._request("GET", path, **kw)

    def post(self, path, payload=None, **kw):
        return self._request("POST", path, payload=payload, **kw)

    def put(self, path, payload=None, **kw):
        return self._request("PUT", path, payload=payload, **kw)


# --------------------------------------------------------------------------- #
def wait_http(url: str, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                return json.loads(response.read().decode())
        except (urllib.error.URLError, ValueError, TimeoutError) as exc:
            last = exc
            time.sleep(0.3)
    raise AssertionError(f"{url} never became ready: {last}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", default="xray")
    parser.add_argument("--no-core", action="store_true",
                        help="skip the real core install (offline environments)")
    args = parser.parse_args()

    data_dir = tempfile.mkdtemp(prefix="zagros-node-test-")
    # Production images mount the node volume at /var/lib/zagros; a test run
    # has no right to that path, so relocate the core root instead.
    os.makedirs(os.path.join(data_dir, "root"), exist_ok=True)
    control_port, info_port = 62050, 62051
    env = {
        **os.environ,
        "PYTHONPATH": str(VENDOR),
        "ZAGROS_NODE_DATA": data_dir,
        "ZAGROS_CORE_ROOT": os.path.join(data_dir, "root"),
        "ZAGROS_NODE_PORT": str(control_port),
        "ZAGROS_NODE_API_PORT": str(info_port),
        "ZAGROS_NODE_NAME": "smoke-node",
        "ZAGROS_NODE_REGISTRATION_HASH": TOKEN_HASH,
        "ZAGROS_NODE_INFO_DETAIL": "1",
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "node_agent"], cwd=str(REPO), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}{f' — {detail}' if detail else ''}")

    try:
        print("booting agent…")
        info = wait_http(f"http://127.0.0.1:{info_port}/info")
        check("info port serves node id", bool(info.get("node_id")))
        check("info port serves certificate",
              info.get("certificate_pem", "").startswith("-----BEGIN CERTIFICATE-----"))
        check("info port reports pending token", info.get("pending_token") is True)
        check("info port does not leak secrets",
              "signing_key" not in json.dumps(info))

        pinned = info["certificate_sha256"]
        pem = info["certificate_pem"]
        certfile = os.path.join(data_dir, "pinned.pem")
        Path(certfile).write_text(pem)

        # ---- registration over the pinned channel ------------------------- #
        import requests

        register = requests.post(
            f"https://127.0.0.1:{control_port}/v1/register",
            json={"panel_id": "panel-smoketest", "registration_token": TOKEN},
            verify=certfile, timeout=30)
        check("register over pinned TLS", register.status_code == 200,
              f"HTTP {register.status_code} {register.text[:120]}")
        body = register.json()
        key = base64.b64decode(body["signing_key"])
        client = Client("127.0.0.1", control_port, body["node_id"], key, certfile)

        # the token is single use
        replay = requests.post(
            f"https://127.0.0.1:{control_port}/v1/register",
            json={"panel_id": "panel-smoketest", "registration_token": TOKEN},
            verify=certfile, timeout=30)
        check("one-time token is burned", replay.status_code == 401,
              f"HTTP {replay.status_code}")

        # ---- signed commands --------------------------------------------- #
        heartbeat = client.get("/v1/heartbeat")
        check("signed heartbeat", heartbeat.status_code == 200, heartbeat.text[:120])

        unsigned = requests.get(f"https://127.0.0.1:{control_port}/v1/heartbeat",
                                verify=certfile, timeout=30)
        check("unsigned command rejected", unsigned.status_code == 401)

        tampered = requests.get(
            f"https://127.0.0.1:{control_port}/v1/heartbeat",
            headers={"X-Zagros-Node": body["node_id"],
                     "X-Zagros-Timestamp": str(int(time.time())),
                     "X-Zagros-Nonce": secrets.token_hex(16),
                     "X-Zagros-Signature": "0" * 64},
            verify=certfile, timeout=30)
        check("forged signature rejected", tampered.status_code == 401,
              f"HTTP {tampered.status_code}")

        replayed = client.get("/v1/heartbeat")
        replay_nonce = replayed.request.headers["X-Zagros-Nonce"]
        replay_ts = replayed.request.headers["X-Zagros-Timestamp"]
        replay_path = "/v1/heartbeat"
        replay_sig = _signature(key, "GET", replay_path, replay_ts, replay_nonce, b"")
        replay_hit = requests.get(
            f"https://127.0.0.1:{control_port}/v1/heartbeat",
            headers={"X-Zagros-Node": body["node_id"],
                     "X-Zagros-Timestamp": replay_ts,
                     "X-Zagros-Nonce": replay_nonce,
                     "X-Zagros-Signature": replay_sig},
            verify=certfile, timeout=30)
        check("replayed nonce rejected", replay_hit.status_code == 401,
              f"HTTP {replay_hit.status_code}")

        health = client.get("/v1/health")
        check("signed health", health.status_code == 200, health.text[:120])

        cores = client.get("/v1/cores")
        check("core inventory", cores.status_code == 200)
        catalog = cores.json().get("available") or []
        check("catalog lists installable cores", len(catalog) >= 6, str(catalog))

        # ---- lifecycle job (real install, network required) --------------- #
        if args.no_core:
            print("  [SKIP] core install (--no-core)")
        else:
            core_id = args.core if args.core in catalog else catalog[0]
            print(f"installing core '{core_id}' (downloads a release binary)…")
            job = client.post(f"/v1/cores/{core_id}/lifecycle?wait=0",
                              {"action": "install", "settings": {},
                               "purge": False, "force": False})
            check("lifecycle accepted as a job", job.status_code == 200,
                  job.text[:160])
            job_id = job.json().get("job_id")
            terminal = None
            for _ in range(240):            # ≤ 20 min: release downloads are slow
                status = client.get(f"/v1/jobs/{job_id}").json()
                if status["state"] in ("succeeded", "failed", "cancelled"):
                    terminal = status
                    break
                time.sleep(5)
            check(f"install job for {core_id} completed",
                  terminal is not None and terminal["state"] == "succeeded",
                  json.dumps(terminal)[:400] if terminal else "no terminal state")

            if terminal and terminal["state"] == "succeeded":
                after = client.get("/v1/cores").json()
                check("installed core leaves the catalog",
                      core_id in (after.get("installed") or {})
                      and core_id not in (after.get("available") or []))
                logs = client.get(f"/v1/cores/{core_id}/logs?tail=20")
                check("core logs readable", logs.status_code == 200)
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
        output = process.stdout.read() if process.stdout else ""
        shutil.rmtree(data_dir, ignore_errors=True)

    failed = [name for name, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    if failed:
        print("failed: " + ", ".join(failed))
        print("\n--- agent log ---\n" + (output or "")[-4000:])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
