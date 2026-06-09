from __future__ import annotations

import json
import subprocess
from typing import Any

from CipherScope_local.scanner.models import LocalFinding, LocalSeverity, LocalStatus
from CipherScope_local.scanner.scanners.common import PQC_DEPENDENCY_MARKERS, stable_id


DOCKER_PS_COMMAND = ["docker", "ps", "--format", "{{json .}}"]
PROBES = (
    ("OpenSSL", "openssl version -a"),
    ("Java", "java -version"),
    ("Python", "python3 --version"),
    ("Python cryptography", "python3 -c 'import cryptography; print(cryptography.__version__)'"),
    ("Go", "go version"),
    ("Node.js", "node --version"),
)


def scan_docker(timeout: float = 2.0) -> list[LocalFinding]:
    containers_result = _run(DOCKER_PS_COMMAND, timeout)
    if containers_result is None:
        return [_docker_unavailable("Docker CLI is not installed or not available on PATH.")]
    if containers_result.returncode != 0:
        return [_docker_unavailable(_output(containers_result) or "Docker daemon is unavailable.")]

    findings: list[LocalFinding] = []
    for container in _parse_ps_lines(containers_result.stdout):
        container_id = str(container.get("ID") or "").strip()
        if not container_id:
            continue
        inspect = _inspect_container(container_id, timeout)
        asset = _container_asset(container, inspect)
        findings.append(_container_finding(container_id, container, inspect, asset))
        findings.extend(_probe_container(container_id, asset, timeout))
    return findings


def _run(command: list[str], timeout: float) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return None


def _parse_ps_lines(output: str) -> list[dict[str, Any]]:
    containers: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            containers.append(parsed)
    return containers


def _inspect_container(container_id: str, timeout: float) -> dict[str, Any]:
    result = _run(["docker", "inspect", container_id], timeout)
    if result is None or result.returncode != 0:
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return payload[0]
    return {}


def _container_asset(container: dict[str, Any], inspect: dict[str, Any]) -> str:
    name = (
        str(container.get("Names") or "")
        or str(inspect.get("Name") or "").lstrip("/")
        or str(container.get("ID") or "unknown")
    )
    image = (
        str(container.get("Image") or "")
        or str(inspect.get("Config", {}).get("Image") or "")
        or "unknown"
    )
    return f"container:{name}:{image}"


def _container_finding(
    container_id: str,
    container: dict[str, Any],
    inspect: dict[str, Any],
    asset: str,
) -> LocalFinding:
    ports = container.get("Ports") or _inspect_ports(inspect)
    status = container.get("Status") or inspect.get("State", {}).get("Status") or "running"
    return LocalFinding(
        id=stable_id("docker-container", container_id, asset),
        category="docker_container",
        asset=asset,
        location=container_id,
        algorithm=None,
        key_size=None,
        status=LocalStatus.UNKNOWN,
        severity=LocalSeverity.INFO,
        evidence={
            "container_id": container_id,
            "name": asset.split(":", 2)[1] if ":" in asset else asset,
            "image": asset.rsplit(":", 1)[-1],
            "status": str(status),
            "ports": str(ports or "none"),
            "scope": "running-containers-only",
        },
        recommendation=(
            "Review this running container's cryptographic dependencies and service "
            "configuration as part of the local PQC inventory."
        ),
    )


def _probe_container(container_id: str, asset: str, timeout: float) -> list[LocalFinding]:
    findings: list[LocalFinding] = []
    for label, probe in PROBES:
        command = ["docker", "exec", container_id, "sh", "-lc", probe]
        result = _run(command, timeout)
        if result is None:
            return [_docker_unavailable("Docker CLI became unavailable during container probes.")]
        if result.returncode != 0:
            findings.append(_probe_unknown(container_id, asset, label, probe, _output(result)))
            continue
        output = _output(result)
        status, severity, algorithm = _classify_probe(output)
        findings.append(
            LocalFinding(
                id=stable_id("docker-library", container_id, label, output[:80]),
                category="docker_library",
                asset=asset,
                location=f"{container_id}: {probe}",
                algorithm=algorithm,
                key_size=None,
                status=status,
                severity=severity,
                evidence={
                    "container_id": container_id,
                    "probe": label,
                    "command": probe,
                    "output": _truncate(output),
                },
                recommendation=_probe_recommendation(status),
            )
        )
    return findings


def _probe_unknown(
    container_id: str,
    asset: str,
    label: str,
    probe: str,
    output: str,
) -> LocalFinding:
    return LocalFinding(
        id=stable_id("docker-library-unknown", container_id, label, output[:80]),
        category="docker_library",
        asset=asset,
        location=f"{container_id}: {probe}",
        algorithm=None,
        key_size=None,
        status=LocalStatus.UNKNOWN,
        severity=LocalSeverity.INFO,
        evidence={
            "container_id": container_id,
            "probe": label,
            "command": probe,
            "output": _truncate(output or "command unavailable in container"),
        },
        recommendation=(
            "The runtime probe was unavailable in this running container; inspect the "
            "container image or service owner documentation manually."
        ),
    )


def _classify_probe(output: str) -> tuple[LocalStatus, LocalSeverity, str | None]:
    marker = _matched_pqc_marker(output)
    if marker is not None:
        return LocalStatus.PQC_READY_DEPENDENCY_FOUND, LocalSeverity.INFO, marker
    return LocalStatus.MIGRATION_LIMITED, LocalSeverity.LOW, None


def _matched_pqc_marker(output: str) -> str | None:
    normalized = output.lower().replace("_", "-").replace(" ", "")
    for marker in PQC_DEPENDENCY_MARKERS:
        if marker.replace("-", "") in normalized:
            return marker.upper()
    return None


def _probe_recommendation(status: LocalStatus) -> str:
    if status == LocalStatus.PQC_READY_DEPENDENCY_FOUND:
        return "Validate this container dependency before relying on its PQC capability."
    return "Track this container dependency for PQC support and compatibility."


def _docker_unavailable(message: str) -> LocalFinding:
    return LocalFinding(
        id=stable_id("docker-unavailable", message),
        category="docker",
        asset="Docker",
        location="docker ps",
        algorithm=None,
        key_size=None,
        status=LocalStatus.UNKNOWN,
        severity=LocalSeverity.INFO,
        evidence={"error": _truncate(message), "scope": "running-containers-only"},
        recommendation=(
            "Start Docker only if you intend to scan active containers; CipherScope "
            "does not start Docker or stopped containers."
        ),
    )


def _inspect_ports(inspect: dict[str, Any]) -> str:
    ports = inspect.get("NetworkSettings", {}).get("Ports", {})
    if not isinstance(ports, dict) or not ports:
        return "none"
    return ", ".join(sorted(str(port) for port in ports))


def _output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}\n{result.stderr}".strip()


def _truncate(output: str) -> str:
    return output.replace("\0", "")[:500] if output else "available"
