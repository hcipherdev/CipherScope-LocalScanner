from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key

from CipherScope_local.scanner.models import LocalFinding, LocalSeverity, LocalStatus
from CipherScope_local.scanner.scanners.common import (
    describe_public_key,
    safe_path,
    stable_id,
    status_for_algorithm,
)
from cipherscope.scanners.certificates import describe_signature_algorithm


CERT_EXTENSIONS = {".pem", ".crt", ".cer"}
KEY_EXTENSIONS = {".key", ".pem"}
STORE_EXTENSIONS = {".p12", ".pfx", ".jks"}
SCAN_EXTENSIONS = CERT_EXTENSIONS | KEY_EXTENSIONS | STORE_EXTENSIONS


def scan_file_paths(
    paths: Iterable[Path],
    max_files: int = 5000,
    max_bytes: int = 2_000_000,
) -> list[LocalFinding]:
    findings: list[LocalFinding] = []
    for path in _iter_candidate_files(paths, max_files):
        if path.suffix.lower() in STORE_EXTENSIONS:
            findings.append(_store_finding(path))
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            findings.append(_unknown_file(path, f"Could not read file: {exc}"))
            continue
        if len(data) > max_bytes:
            findings.append(_unknown_file(path, f"Skipped file larger than {max_bytes} bytes."))
            continue
        parsed = _parse_certificates(path, data) + _parse_private_keys(path, data)
        if parsed:
            findings.extend(parsed)
        elif path.suffix.lower() in SCAN_EXTENSIONS:
            findings.append(
                _unknown_file(path, "No supported certificate or key structure parsed.")
            )
    return findings


def _iter_candidate_files(paths: Iterable[Path], max_files: int):
    seen = 0
    for root in paths:
        expanded = root.expanduser()
        if expanded.is_file() and expanded.suffix.lower() in SCAN_EXTENSIONS:
            yield expanded
            seen += 1
        elif expanded.is_dir():
            for candidate in expanded.rglob("*"):
                if seen >= max_files:
                    return
                try:
                    if candidate.is_symlink() or not candidate.is_file():
                        continue
                except OSError:
                    continue
                if candidate.suffix.lower() not in SCAN_EXTENSIONS:
                    continue
                yield candidate
                seen += 1
        if seen >= max_files:
            return


def _parse_certificates(path: Path, data: bytes) -> list[LocalFinding]:
    certs: list[x509.Certificate] = []
    try:
        certs.append(x509.load_pem_x509_certificate(data))
    except ValueError:
        try:
            certs.append(x509.load_der_x509_certificate(data))
        except ValueError:
            return []
    return [_certificate_finding(path, cert) for cert in certs]


def _parse_private_keys(path: Path, data: bytes) -> list[LocalFinding]:
    key = None
    try:
        key = load_pem_private_key(data, password=None)
    except (TypeError, ValueError):
        try:
            key = load_der_private_key(data, password=None)
        except (TypeError, ValueError):
            return []
    algorithm, key_size = describe_public_key(key)
    status = status_for_algorithm(algorithm)
    return [
        LocalFinding(
            id=stable_id("file-private-key", path, algorithm),
            category="private_key",
            asset=path.name,
            location=safe_path(path),
            algorithm=algorithm,
            key_size=key_size,
            status=status,
            severity=LocalSeverity.HIGH
            if status == LocalStatus.QUANTUM_VULNERABLE
            else LocalSeverity.INFO,
            evidence={"file_type": "private-key", "encrypted": False},
            recommendation=(
                "Protect this private key and include the dependent service in PQC migration "
                "planning. Do not transmit private key material."
            ),
        )
    ]


def _certificate_finding(path: Path, cert: x509.Certificate) -> LocalFinding:
    algorithm, key_size = describe_public_key(cert.public_key())
    signature = describe_signature_algorithm(cert)
    status = status_for_algorithm(algorithm, signature)
    return LocalFinding(
        id=stable_id("file-certificate", path, algorithm, signature),
        category="file_certificate",
        asset=path.name,
        location=safe_path(path),
        algorithm=algorithm,
        key_size=key_size,
        status=status,
        severity=LocalSeverity.MEDIUM
        if status == LocalStatus.QUANTUM_VULNERABLE
        else LocalSeverity.INFO,
        evidence={
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "signature_algorithm": signature,
            "expires": cert.not_valid_after_utc.isoformat(),
        },
        recommendation=(
            "Map this certificate to its owning service and plan replacement or hybrid "
            "migration when PQC certificate support is available."
        ),
    )


def _store_finding(path: Path) -> LocalFinding:
    return LocalFinding(
        id=stable_id("file-store", path),
        category="certificate_store",
        asset=path.name,
        location=safe_path(path),
        algorithm=None,
        key_size=None,
        status=LocalStatus.UNKNOWN,
        severity=LocalSeverity.INFO,
        evidence={"file_type": path.suffix.lower().lstrip("."), "parsed": False},
        recommendation=(
            "Inspect this key store with the owning application or password material; "
            "CipherScope did not extract secrets."
        ),
    )


def _unknown_file(path: Path, message: str) -> LocalFinding:
    return LocalFinding(
        id=stable_id("file-unknown", path, message),
        category="file",
        asset=path.name,
        location=safe_path(path),
        algorithm=None,
        key_size=None,
        status=LocalStatus.UNKNOWN,
        severity=LocalSeverity.INFO,
        evidence={"reason": message},
        recommendation="Review this file manually if it is part of a cryptographic deployment.",
    )
