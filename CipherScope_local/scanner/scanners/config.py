from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import re

from CipherScope_local.scanner.models import LocalFinding, LocalSeverity, LocalStatus
from CipherScope_local.scanner.scanners.common import safe_path, stable_id


MATCH_TERMS = (
    "RSA",
    "ECDSA",
    "Ed25519",
    "X25519",
    "secp256r1",
    "prime256v1",
    "secp384r1",
    "Diffie-Hellman",
    "dhparam",
    "ssl_certificate",
    "ssl_certificate_key",
    "SSLCertificateFile",
    "SSLCertificateKeyFile",
    "ssl_ecdh_curve",
)

CONFIG_EXTENSIONS = {
    ".conf",
    ".cnf",
    ".cfg",
    ".ini",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".properties",
    ".env",
}


def scan_config_paths(
    paths: Iterable[Path],
    max_files: int = 5000,
    max_bytes: int = 1_000_000,
) -> list[LocalFinding]:
    findings: list[LocalFinding] = []
    term_patterns = _term_patterns()
    for path in _iter_config_files(paths, max_files):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if len(data) > max_bytes or b"\0" in data[:4096]:
            continue
        text = data.decode("utf-8", errors="ignore")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for pattern, display_term in term_patterns:
                if not pattern.search(line):
                    continue
                findings.append(_finding(path, line_number, display_term, line))
    return findings


def _term_patterns() -> list[tuple[re.Pattern[str], str]]:
    return [(_compile_term(term), term) for term in MATCH_TERMS]


def _compile_term(term: str) -> re.Pattern[str]:
    escaped = re.escape(term)
    return re.compile(rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])", re.IGNORECASE)


def _iter_config_files(paths: Iterable[Path], max_files: int):
    seen = 0
    for root in paths:
        expanded = root.expanduser()
        if expanded.is_file():
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
                if candidate.suffix and candidate.suffix.lower() not in CONFIG_EXTENSIONS:
                    continue
                yield candidate
                seen += 1
        if seen >= max_files:
            return


def _finding(path: Path, line_number: int, term: str, line: str) -> LocalFinding:
    return LocalFinding(
        id=stable_id("config", path, line_number, term),
        category="configuration",
        asset=path.name,
        location=f"{safe_path(path)}:{line_number}",
        algorithm=term,
        key_size=None,
        status=LocalStatus.QUANTUM_VULNERABLE,
        severity=LocalSeverity.MEDIUM,
        evidence={"matched_term": term, "line": line.strip()[:240]},
        recommendation=(
            "Review this configuration reference and replace hardcoded classical "
            "cryptography choices during PQC migration planning."
        ),
    )
