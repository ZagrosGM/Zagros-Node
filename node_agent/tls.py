"""Node TLS material — self-signed by default, operator-supplied optionally.

The panel pins this certificate (SHA-256 of the DER leaf) and refuses to
talk to anything else, so the node's identity is cryptographic rather than
network-location based. A node that boots with no certificate generates one
immediately; an operator may instead mount their own pair through
``ZAGROS_NODE_TLS_CERT`` / ``ZAGROS_NODE_TLS_KEY``.

Self-signed is deliberate: a node is reached by IP, frequently behind no
DNS name at all, so no public CA can issue for it. Trust does not come
from a CA chain — it comes from the panel pinning the exact leaf, and from
the operator comparing the fingerprint this module prints at install time.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_DEFAULT_VALIDITY_DAYS = 3650


@dataclass(frozen=True)
class NodeCertificate:
    cert_path: str
    key_path: str
    fingerprint: str          # lowercase hex SHA-256 of the DER leaf
    not_after: str
    sans: tuple[str, ...]

    @property
    def pem(self) -> str:
        return Path(self.cert_path).read_text(encoding="utf-8")


def fingerprint_of_pem(pem: str) -> str:
    """SHA-256 of the DER leaf — the exact value the panel pins."""
    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    return cert.fingerprint(hashes.SHA256()).hex()


def _san_entries(names: list[str]) -> list[x509.GeneralName]:
    entries: list[x509.GeneralName] = []
    for raw in names:
        value = raw.strip()
        if not value:
            continue
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            entries.append(x509.DNSName(value))
    return entries


def generate(cert_path: str | os.PathLike[str], key_path: str | os.PathLike[str],
             *, names: list[str] | None = None,
             validity_days: int = _DEFAULT_VALIDITY_DAYS) -> NodeCertificate:
    """Create a fresh EC P-256 self-signed certificate (0600 key)."""
    cert_file = Path(cert_path)
    key_file = Path(key_path)
    cert_file.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(cert_file.parent, 0o700)

    sans = _san_entries(list(names or []))
    # A panel reaches a node by IP, so loopback + the node's own addresses
    # must be present or hostname verification fails on every connection.
    for guaranteed in ("localhost", "127.0.0.1", "::1"):
        entry = (_san_entries([guaranteed]) or [None])[0]
        if entry is not None and entry not in sans:
            sans.insert(0, entry)

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "zagros-node"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Zagros"),
    ])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    # Write atomically: a half-written key is worse than no key at all.
    key_part = key_file.with_suffix(".key.part")
    key_part.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    os.chmod(key_part, 0o600)
    os.replace(key_part, key_file)

    cert_part = cert_file.with_suffix(".crt.part")
    cert_part.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_part, 0o644)
    os.replace(cert_part, cert_file)

    return NodeCertificate(
        cert_path=str(cert_file), key_path=str(key_file),
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        not_after=cert.not_valid_after_utc.isoformat(),
        sans=tuple(
            entry.value if isinstance(entry, x509.DNSName) else str(entry.value)
            for entry in sans),
    )


def ensure(config) -> NodeCertificate:
    """Return the node's certificate, generating it on first boot."""
    cert_path, key_path = Path(config.tls_cert), Path(config.tls_key)
    if cert_path.is_file() and key_path.is_file():
        pem = cert_path.read_text(encoding="utf-8")
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        return NodeCertificate(
            cert_path=str(cert_path), key_path=str(key_path),
            fingerprint=fingerprint_of_pem(pem),
            not_after=cert.not_valid_after_utc.isoformat(),
            sans=tuple(_describe_sans(cert)),
        )
    names = [config.name] if config.name else []
    names += [part.strip() for part in config.address.split(",") if part.strip()]
    detected = detect_primary_ip()
    if detected:
        names.append(detected)
    return generate(cert_path, key_path, names=names)


def detect_primary_ip() -> str | None:
    """Best-effort local address of the default route (no packets are sent)."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))     # TEST-NET-1, never routed
        return str(sock.getsockname()[0])
    except OSError:
        return None
    finally:
        sock.close()


def _describe_sans(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    described: list[str] = []
    for entry in extension.value:
        if isinstance(entry, x509.DNSName):
            described.append(str(entry.value))
        elif isinstance(entry, x509.IPAddress):
            described.append(str(entry.value))
        else:
            described.append(str(getattr(entry, "value", entry)))
    return described


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
