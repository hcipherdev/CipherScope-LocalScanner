from __future__ import annotations

import re
import subprocess
import sys

from CipherScope_local.scanner.models import LocalFinding, LocalSeverity, LocalStatus
from CipherScope_local.scanner.scanners.common import PQC_DEPENDENCY_MARKERS, stable_id


BASE_COMMANDS = (
    ("OpenSSL", ["openssl", "version", "-a"]),
    ("BoringSSL", ["bssl", "version"]),
    ("Java", ["java", "-version"]),
    ("Go", ["go", "version"]),
    ("Node.js", ["node", "--version"]),
)


def scan_libraries(timeout: float = 2.0) -> list[LocalFinding]:
    return [_scan_command(asset, command, timeout) for asset, command in _commands()]


def _commands() -> tuple[tuple[str, list[str]], ...]:
    python_executable = sys.executable or "python"
    return BASE_COMMANDS + (
        ("Python", [python_executable, "--version"]),
        (
            "Python cryptography",
            [python_executable, "-c", "import cryptography; print(cryptography.__version__)"],
        ),
    )


def _scan_command(asset: str, command: list[str], timeout: float) -> LocalFinding:
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return _finding(
            asset,
            command,
            LocalStatus.UNKNOWN,
            LocalSeverity.INFO,
            "not-found",
            "Install or locate this runtime if it is part of your cryptographic stack.",
        )
    except Exception as exc:
        return _finding(
            asset,
            command,
            LocalStatus.UNKNOWN,
            LocalSeverity.INFO,
            f"error: {exc}",
            "Review this runtime manually; CipherScope could not inspect it.",
        )

    output = f"{proc.stdout}\n{proc.stderr}".strip()
    if _contains_pqc_marker(output):
        return _finding(
            asset,
            command,
            LocalStatus.PQC_READY_DEPENDENCY_FOUND,
            LocalSeverity.INFO,
            _truncate(output),
            "Validate this PQC-capable dependency in the application that uses it.",
            algorithm=_matched_marker(output),
        )
    if _is_migration_limited(asset, output):
        return _finding(
            asset,
            command,
            LocalStatus.MIGRATION_LIMITED,
            LocalSeverity.MEDIUM,
            _truncate(output),
            "Plan runtime upgrades before depending on hybrid or post-quantum cryptography.",
        )
    return _finding(
        asset,
        command,
        LocalStatus.MIGRATION_LIMITED,
        LocalSeverity.LOW,
        _truncate(output),
        "Track this dependency for PQC support and application compatibility.",
    )


def _finding(
    asset: str,
    command: list[str],
    status: LocalStatus,
    severity: LocalSeverity,
    output: str,
    recommendation: str,
    *,
    algorithm: str | None = None,
) -> LocalFinding:
    return LocalFinding(
        id=stable_id("library", asset, command),
        category="libraries",
        asset=asset,
        location=" ".join(command),
        algorithm=algorithm,
        key_size=None,
        status=status,
        severity=severity,
        evidence={"command": " ".join(command), "output": output},
        recommendation=recommendation,
    )


def _contains_pqc_marker(output: str) -> bool:
    normalized = output.lower().replace("_", "-")
    return any(marker in normalized for marker in PQC_DEPENDENCY_MARKERS)


def _matched_marker(output: str) -> str | None:
    normalized = output.lower().replace("_", "-")
    for marker in PQC_DEPENDENCY_MARKERS:
        if marker in normalized:
            return marker.upper()
    return None


def _is_migration_limited(asset: str, output: str) -> bool:
    if asset == "OpenSSL":
        match = re.search(r"(?:OpenSSL|LibreSSL)\s+(\d+)\.(\d+)\.(\d+)", output)
        if match:
            major, minor, patch = (int(part) for part in match.groups())
            return (major, minor, patch) < (3, 0, 0)
    if asset == "Java":
        match = re.search(r'version "(\d+)', output)
        if match:
            return int(match.group(1)) < 17
    return False


def _truncate(output: str) -> str:
    return output.replace("\0", "")[:500] if output else "available"
