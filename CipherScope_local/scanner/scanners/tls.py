from __future__ import annotations

from datetime import UTC
import socket
import ssl

from cryptography import x509

from CipherScope_local.scanner.models import LocalFinding, LocalSeverity, LocalStatus
from CipherScope_local.scanner.scanners.common import (
    describe_public_key,
    stable_id,
    status_for_algorithm,
)
from cipherscope.scanners.certificates import describe_signature_algorithm


def scan_tls_endpoint(host: str, port: int, timeout: float = 3.0) -> list[LocalFinding]:
    asset = f"{host}:{port}"
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                tls_version = tls.version() or "unknown"
                cert_der = tls.getpeercert(binary_form=True)
        if not cert_der:
            return [_unknown_tls_finding(asset, "TLS endpoint did not provide a certificate.")]
        return [_certificate_finding(asset, cert_der, tls_version)]
    except Exception as exc:
        return [_unknown_tls_finding(asset, f"TLS inspection failed: {exc}")]


def _certificate_finding(asset: str, cert_der: bytes, tls_version: str) -> LocalFinding:
    cert = x509.load_der_x509_certificate(cert_der)
    algorithm, key_size = describe_public_key(cert.public_key())
    signature = describe_signature_algorithm(cert)
    status = status_for_algorithm(algorithm, signature)
    severity = (
        LocalSeverity.HIGH
        if status == LocalStatus.QUANTUM_VULNERABLE
        else LocalSeverity.INFO
    )
    return LocalFinding(
        id=stable_id("tls", asset, algorithm, signature),
        category="tls_certificate",
        asset=asset,
        location=asset,
        algorithm=algorithm,
        key_size=key_size,
        status=status,
        severity=severity,
        evidence={
            "tls_version": tls_version,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "signature_algorithm": signature,
            "expires": cert.not_valid_after_utc.astimezone(UTC).isoformat(),
        },
        recommendation=_recommendation(status, "TLS certificate"),
    )


def _unknown_tls_finding(asset: str, message: str) -> LocalFinding:
    return LocalFinding(
        id=stable_id("tls", asset, "unknown"),
        category="tls_certificate",
        asset=asset,
        location=asset,
        algorithm=None,
        key_size=None,
        status=LocalStatus.UNKNOWN,
        severity=LocalSeverity.INFO,
        evidence={"error": message},
        recommendation="Inspect the TLS endpoint manually and confirm its certificate algorithm.",
    )


def _recommendation(status: LocalStatus, asset_type: str) -> str:
    if status == LocalStatus.QUANTUM_VULNERABLE:
        return (
            f"Inventory this {asset_type.lower()} for PQC migration planning and evaluate "
            "hybrid or post-quantum alternatives when your platform supports them."
        )
    if status == LocalStatus.PQC_READY_DEPENDENCY_FOUND:
        return "Validate interoperability before relying on this post-quantum certificate evidence."
    return f"Review this {asset_type.lower()} manually because the algorithm was not classified."
