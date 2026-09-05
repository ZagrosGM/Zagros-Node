"""Node-local projection of panel-owned timed source-IP bans."""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

_TABLE = "zagros_ip_limit"


async def managed_ports(core_manager) -> tuple[set[int], set[int]]:
    tcp: set[int] = set()
    udp: set[int] = set()
    for core_id in core_manager.list_cores():
        if not core_manager.is_enabled(core_id):
            continue
        try:
            claims = await core_manager.get(core_id).listener_claims()
        except Exception:
            continue
        for claim in claims:
            try:
                if ipaddress.ip_address(str(claim.address)).is_loopback:
                    continue
            except ValueError:
                pass
            if claim.protocol == "accel-ppp-cli":
                continue
            target = udp if claim.transport.lower() == "udp" else tcp
            target.add(int(claim.port))
            if claim.protocol == "openvpn-clone":
                udp.add(int(claim.port))
    return tcp, udp


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        result = value
    else:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def _script(bans: list[dict], tcp: set[int], udp: set[int], now: datetime) -> str:
    groups: tuple[dict[str, int], dict[str, int]] = ({}, {})
    for row in bans:
        ip = str(ipaddress.ip_address(str(row["ip"])))
        seconds = max(1, int((_parse_time(row["expires_at"]) - now).total_seconds()))
        bucket = groups[1] if ipaddress.ip_address(ip).version == 6 else groups[0]
        bucket[ip] = max(bucket.get(ip, 0), seconds)
    elements = lambda rows: ", ".join(
        f"{ip} timeout {seconds}s" for ip, seconds in sorted(rows.items()))
    ports = lambda rows: ", ".join(str(port) for port in sorted(rows))

    def set_line(name: str, nft_type: str, values: str, *, timed: bool = False) -> str:
        flags = " flags timeout;" if timed else ""
        initial = f" elements = {{ {values} }};" if values else ""
        return f" set {name} {{ type {nft_type};{flags}{initial} }}"

    return f"""table inet {_TABLE} {{
{set_line('banned_v4', 'ipv4_addr', elements(groups[0]), timed=True)}
{set_line('banned_v6', 'ipv6_addr', elements(groups[1]), timed=True)}
{set_line('vpn_tcp_ports', 'inet_service', ports(tcp))}
{set_line('vpn_udp_ports', 'inet_service', ports(udp))}
 chain input {{
  type filter hook input priority -210; policy accept;
  ip saddr @banned_v4 tcp dport @vpn_tcp_ports counter drop
  ip saddr @banned_v4 udp dport @vpn_udp_ports counter drop
  ip6 saddr @banned_v6 tcp dport @vpn_tcp_ports counter drop
  ip6 saddr @banned_v6 udp dport @vpn_udp_ports counter drop
 }}
}}
"""


def apply(bans: list[dict], tcp: set[int], udp: set[int]) -> dict:
    nft = shutil.which("nft")
    if not nft:
        return {"ok": False, "error": "nft is not installed"}
    now = datetime.now(timezone.utc)
    active = [row for row in bans if _parse_time(row["expires_at"]) > now]
    exists = subprocess.run([nft, "list", "table", "inet", _TABLE],
                            capture_output=True, text=True).returncode == 0
    if not active:
        if exists:
            result = subprocess.run([nft, "delete", "table", "inet", _TABLE],
                                    capture_output=True, text=True)
            if result.returncode:
                return {"ok": False, "error": result.stderr.strip()}
        return {"ok": True, "active": 0}
    script = _script(active, tcp, udp, now)
    if exists:
        script = f"delete table inet {_TABLE}\n" + script
    result = subprocess.run([nft, "-f", "-"], input=script,
                            capture_output=True, text=True)
    return ({"ok": True, "active": len(active)} if result.returncode == 0
            else {"ok": False, "error": result.stderr.strip()})


def drop_conntrack(ips: set[str], tcp: set[int], udp: set[int]) -> int:
    tool = shutil.which("conntrack")
    if not tool:
        return 0
    closed = 0
    for ip in ips:
        for proto, ports in (("tcp", tcp), ("udp", udp)):
            for port in ports:
                result = subprocess.run(
                    [tool, "-D", "-s", ip, "-p", proto, "--dport", str(port)],
                    capture_output=True, text=True)
                if result.returncode == 0:
                    closed += 1
    return closed


async def terminate(core_manager, ips: set[str]) -> int:
    closed = 0
    for core_id in core_manager.list_cores():
        driver = core_manager.get(core_id)
        operation = getattr(driver, "terminate_source_ip", None)
        if callable(operation):
            for ip in ips:
                closed += int(await operation(ip) or 0)
    return closed
