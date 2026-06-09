from __future__ import annotations

import hashlib
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from CipherScope_local.scanner.models import LocalSeverity, LocalStatus
from cipherscope.scanners.pqc import classify_public_key_algorithm, classify_signature_algorithm


PQC_DEPENDENCY_MARKERS = (
    "oqs",
    "oqsprovider",
    "ml-kem",
    "mlkem",
    "kyber",
    "mldsa",
    "ml-dsa",
    "dilithium",
    "falcon",
    "sphincs",
)


def stable_id(*parts: object) -> str:
    raw = "|".join(str(part) for part in parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")[:48]
    return f"{slug}-{digest}" if slug else digest


def describe_public_key(public_key: object) -> tuple[str, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA-{public_key.key_size}", public_key.key_size
    if isinstance(public_key, rsa.RSAPrivateKey):
        return f"RSA-{public_key.key_size}", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECDSA {public_key.curve.name}", public_key.curve.key_size
    if isinstance(public_key, ec.EllipticCurvePrivateKey):
        return f"ECDSA {public_key.curve.name}", public_key.curve.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey | ed25519.Ed25519PrivateKey):
        return "Ed25519", None
    if isinstance(public_key, ed448.Ed448PublicKey | ed448.Ed448PrivateKey):
        return "Ed448", None
    if isinstance(public_key, dsa.DSAPublicKey):
        return f"DSA-{public_key.key_size}", public_key.key_size
    if isinstance(public_key, dsa.DSAPrivateKey):
        return f"DSA-{public_key.key_size}", public_key.key_size
    return public_key.__class__.__name__, None


def status_for_algorithm(algorithm: str | None, signature: str | None = None) -> LocalStatus:
    if _has_pqc_marker(algorithm) or _has_pqc_marker(signature):
        return LocalStatus.PQC_READY_DEPENDENCY_FOUND
    if classify_public_key_algorithm(algorithm) == "classical":
        return LocalStatus.QUANTUM_VULNERABLE
    if signature and classify_signature_algorithm(signature) == "classical":
        return LocalStatus.QUANTUM_VULNERABLE
    return LocalStatus.UNKNOWN


def severity_for_status(status: LocalStatus, *, private_material: bool = False) -> LocalSeverity:
    if private_material and status == LocalStatus.QUANTUM_VULNERABLE:
        return LocalSeverity.HIGH
    if status == LocalStatus.QUANTUM_VULNERABLE:
        return LocalSeverity.MEDIUM
    if status == LocalStatus.MIGRATION_LIMITED:
        return LocalSeverity.MEDIUM
    return LocalSeverity.INFO


def safe_path(path: Path) -> str:
    try:
        return str(path.expanduser())
    except Exception:
        return str(path)


def _has_pqc_marker(value: str | None) -> bool:
    normalized = (value or "").lower().replace("_", "-").replace(" ", "")
    return any(marker in normalized for marker in PQC_DEPENDENCY_MARKERS)
