from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Callable
from urllib.parse import unquote

try:
    import winreg
except ImportError:  # pragma: no cover - unavailable on non-Windows platforms
    winreg = None

from CipherScope_local.scanner.models import LocalFinding, LocalSeverity, LocalStatus
from CipherScope_local.scanner.scanners.common import safe_path, stable_id


PUBLIC_KEY_ALGORITHMS = {
    "ssh-rsa": "RSA",
    "rsa-sha2-256": "RSA",
    "rsa-sha2-512": "RSA",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA",
    "ssh-ed25519": "Ed25519",
}

PUTTY_HOST_KEY_ALGORITHMS = {
    "rsa2": "RSA",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA",
    "ed25519": "Ed25519",
}

PuttyRegistryData = tuple[list[dict[str, str]], list[dict[str, str]]]


def scan_ssh_paths(
    *,
    user_ssh_dir: Path | None = None,
    system_ssh_dir: Path | None = None,
    platform: str | None = None,
    putty_registry_reader: Callable[[], PuttyRegistryData] | None = None,
) -> list[LocalFinding]:
    platform = platform or sys.platform
    user_ssh_dir = user_ssh_dir or _default_user_ssh_dir(platform)
    system_ssh_dir = system_ssh_dir or _default_system_ssh_dir(platform)
    findings: list[LocalFinding] = []
    findings.extend(_scan_public_key_files(user_ssh_dir))
    findings.extend(_scan_public_key_files(system_ssh_dir))
    findings.extend(_scan_sshd_config(system_ssh_dir / "sshd_config"))
    findings.extend(_scan_known_hosts(user_ssh_dir / "known_hosts"))
    if platform.startswith("win"):
        reader = putty_registry_reader or _read_putty_registry
        findings.extend(_scan_putty_host_keys(reader))
        findings.extend(_scan_putty_sessions(reader))
    return findings


def _default_user_ssh_dir(platform: str) -> Path:
    if platform.startswith("win"):
        return Path.home() / ".ssh"
    return Path.home() / ".ssh"


def _default_system_ssh_dir(platform: str) -> Path:
    if platform.startswith("win"):
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(program_data) / "ssh"
    return Path("/etc/ssh")


def _scan_public_key_files(root: Path) -> list[LocalFinding]:
    findings: list[LocalFinding] = []
    if not root.exists():
        return findings
    for path in root.glob("*.pub"):
        try:
            first_token = path.read_text(encoding="utf-8", errors="ignore").split(None, 1)[0]
        except (OSError, IndexError):
            continue
        algorithm = PUBLIC_KEY_ALGORITHMS.get(first_token)
        if algorithm:
            findings.append(_ssh_finding(path, algorithm, "public-key", first_token))
    return findings


def _scan_known_hosts(path: Path) -> list[LocalFinding]:
    findings: list[LocalFinding] = []
    if not path.exists():
        return findings
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings
    for line_number, line in enumerate(lines, start=1):
        parts = line.split()
        if len(parts) < 2:
            continue
        key_type = parts[1] if parts[0].startswith("|") or "," in parts[0] else parts[0]
        algorithm = PUBLIC_KEY_ALGORITHMS.get(key_type)
        if algorithm:
            findings.append(_ssh_finding(path, algorithm, f"known-hosts:{line_number}", key_type))
    return findings


def _scan_sshd_config(path: Path) -> list[LocalFinding]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    findings: list[LocalFinding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.lower().startswith("hostkeyalgorithms"):
            continue
        for key_type, algorithm in PUBLIC_KEY_ALGORITHMS.items():
            if key_type in stripped:
                findings.append(
                    _ssh_finding(
                        path,
                        algorithm,
                        f"sshd-config:{line_number}",
                        key_type,
                        location_suffix=f":{line_number}",
                    )
                )
    return findings


def _scan_putty_host_keys(
    putty_registry_reader: Callable[[], PuttyRegistryData],
) -> list[LocalFinding]:
    findings: list[LocalFinding] = []
    host_keys, _ = putty_registry_reader()
    for entry in host_keys:
        value_name = entry.get("name", "")
        parsed = _parse_putty_host_key_name(value_name)
        if parsed is None:
            continue
        key_type, host = parsed
        algorithm = PUTTY_HOST_KEY_ALGORITHMS.get(key_type)
        if not algorithm:
            continue
        findings.append(
            LocalFinding(
                id=stable_id("putty-host-key", value_name),
                category="ssh",
                asset=host,
                location=rf"HKCU\Software\SimonTatham\PuTTY\SshHostKeys\{value_name}",
                algorithm=algorithm,
                key_size=None,
                status=LocalStatus.QUANTUM_VULNERABLE,
                severity=LocalSeverity.MEDIUM,
                evidence={"source": "putty-host-key", "key_type": key_type},
                recommendation=(
                    "Inventory this SSH algorithm for PQC migration planning and track "
                    "OpenSSH or PuTTY hybrid/post-quantum support."
                ),
            )
        )
    return findings


def _scan_putty_sessions(
    putty_registry_reader: Callable[[], PuttyRegistryData],
) -> list[LocalFinding]:
    findings: list[LocalFinding] = []
    _, sessions = putty_registry_reader()
    for session in sessions:
        protocol = session.get("protocol", "").lower()
        host_name = session.get("host_name", "")
        if protocol and protocol != "ssh":
            continue
        if not host_name and not session.get("public_key_file"):
            continue
        session_name = session.get("session_name", "PuTTY Session")
        evidence: dict[str, str | int | float | bool | None] = {
            "source": "putty-session",
            "host_name": host_name or "unknown",
            "protocol": protocol or "ssh",
        }
        if session.get("port_number"):
            evidence["port_number"] = session["port_number"]
        if session.get("public_key_file"):
            evidence["public_key_file"] = session["public_key_file"]
        findings.append(
            LocalFinding(
                id=stable_id(
                    "putty-session",
                    session_name,
                    host_name,
                    session.get("public_key_file"),
                ),
                category="ssh",
                asset=session_name,
                location=rf"HKCU\Software\SimonTatham\PuTTY\Sessions\{session_name}",
                algorithm=None,
                key_size=None,
                status=LocalStatus.UNKNOWN,
                severity=LocalSeverity.INFO,
                evidence=evidence,
                recommendation=(
                    "Review this PuTTY SSH session and any referenced key file manually; "
                    "CipherScope does not inspect PuTTY private key contents."
                ),
            )
        )
    return findings


def _parse_putty_host_key_name(value_name: str) -> tuple[str, str] | None:
    if "@" not in value_name or ":" not in value_name:
        return None
    key_type, remainder = value_name.split("@", 1)
    _, host = remainder.split(":", 1)
    host = host.strip()
    if not host:
        return None
    return key_type.strip().lower(), host


def _read_putty_registry() -> PuttyRegistryData:
    if winreg is None:
        return [], []
    return _read_putty_host_keys(), _read_putty_sessions()


def _read_putty_host_keys() -> list[dict[str, str]]:
    path = r"Software\SimonTatham\PuTTY\SshHostKeys"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            value_count = winreg.QueryInfoKey(key)[1]
            host_keys: list[dict[str, str]] = []
            for index in range(value_count):
                name, value, _ = winreg.EnumValue(key, index)
                host_keys.append({"name": name, "value": str(value)})
            return host_keys
    except OSError:
        return []


def _read_putty_sessions() -> list[dict[str, str]]:
    path = r"Software\SimonTatham\PuTTY\Sessions"
    sessions: list[dict[str, str]] = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as root:
            key_count = winreg.QueryInfoKey(root)[0]
            for index in range(key_count):
                encoded_name = winreg.EnumKey(root, index)
                with winreg.OpenKey(root, encoded_name) as session_key:
                    values = _registry_values(session_key)
                sessions.append(
                    {
                        "session_name": unquote(encoded_name),
                        "host_name": values.get("HostName", ""),
                        "protocol": values.get("Protocol", ""),
                        "port_number": values.get("PortNumber", ""),
                        "public_key_file": values.get("PublicKeyFile", ""),
                    }
                )
    except OSError:
        return []
    return sessions


def _registry_values(key) -> dict[str, str]:
    value_count = winreg.QueryInfoKey(key)[1]
    values: dict[str, str] = {}
    for index in range(value_count):
        name, value, _ = winreg.EnumValue(key, index)
        values[name] = str(value)
    return values


def _ssh_finding(
    path: Path,
    algorithm: str,
    source: str,
    key_type: str,
    *,
    location_suffix: str = "",
) -> LocalFinding:
    return LocalFinding(
        id=stable_id("ssh", path, source, key_type),
        category="ssh",
        asset=path.name,
        location=f"{safe_path(path)}{location_suffix}",
        algorithm=algorithm,
        key_size=None,
        status=LocalStatus.QUANTUM_VULNERABLE,
        severity=LocalSeverity.MEDIUM,
        evidence={"source": source, "key_type": key_type},
        recommendation=(
            "Inventory this SSH algorithm for PQC migration planning and track "
            "OpenSSH hybrid or post-quantum support."
        ),
    )
