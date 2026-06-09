from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_network
from pathlib import Path

from CipherScope_local.scanner import __version__
from CipherScope_local.scanner.models import LocalScanOptions, LocalScanReport
from CipherScope_local.scanner.reports.score import score_findings
from CipherScope_local.scanner.scanners.config import scan_config_paths
from CipherScope_local.scanner.scanners.docker import scan_docker
from CipherScope_local.scanner.scanners.files import scan_file_paths
from CipherScope_local.scanner.scanners.libraries import scan_libraries
from CipherScope_local.scanner.scanners.ssh import scan_ssh_paths
from CipherScope_local.scanner.scanners.tls import scan_tls_endpoint


def run_local_scan(options: LocalScanOptions) -> LocalScanReport:
    findings = []
    errors: list[str] = []
    targets = _targets(options)
    paths = [str(path.expanduser()) for path in options.paths]

    for host, port in _endpoints(options):
        findings.extend(scan_tls_endpoint(host, port, timeout=options.timeout))

    if options.paths:
        try:
            findings.extend(scan_file_paths(options.paths, max_files=options.max_files))
        except Exception as exc:
            errors.append(f"file scanner failed: {exc}")
        try:
            findings.extend(scan_config_paths(options.paths, max_files=options.max_files))
        except Exception as exc:
            errors.append(f"configuration scanner failed: {exc}")

    if options.ssh:
        try:
            findings.extend(scan_ssh_paths())
        except Exception as exc:
            errors.append(f"SSH scanner failed: {exc}")

    if options.libraries:
        try:
            findings.extend(scan_libraries(timeout=min(options.timeout, 5.0)))
        except Exception as exc:
            errors.append(f"library scanner failed: {exc}")

    if options.docker:
        try:
            findings.extend(scan_docker(timeout=min(options.timeout, 5.0)))
        except Exception as exc:
            errors.append(f"Docker scanner failed: {exc}")

    scored = score_findings(findings)
    return LocalScanReport(
        generated_at=datetime.now(UTC),
        scan_type="local",
        targets=targets,
        paths=paths,
        findings=findings,
        score=scored.score,
        score_raw_points=scored.raw_points,
        score_summary=scored.summary,
        score_factors=scored.score_factors,
        counts_by_status=scored.counts_by_status,
        counts_by_severity=scored.counts_by_severity,
        top_remediation_actions=scored.top_remediation_actions,
        errors=errors,
        technical_appendix={
            "scanner_version": __version__,
            "timeout_seconds": options.timeout,
            "max_files": options.max_files,
            "max_hosts": options.max_hosts,
            "ports": ",".join(str(port) for port in options.ports),
            "docker_scanning": (
                "running-containers-only" if options.docker else "disabled"
            ),
            "ssh_scanning": "enabled" if options.ssh else "disabled",
            "library_scanning": "enabled" if options.libraries else "disabled",
        },
    )


def _targets(options: LocalScanOptions) -> list[str]:
    values: list[str] = []
    if options.target:
        values.extend(f"{options.target}:{port}" for port in options.ports)
    if options.network:
        values.append(f"{options.network} on ports {','.join(str(port) for port in options.ports)}")
    return values


def _endpoints(options: LocalScanOptions):
    if options.target:
        for port in options.ports:
            yield options.target, port
    if not options.network:
        return
    network = ip_network(options.network, strict=False)
    hosts = list(network.hosts())
    if not hosts and network.num_addresses == 1:
        hosts = [network.network_address]
    for host in hosts[: options.max_hosts]:
        for port in options.ports:
            yield str(host), port


def paths_from_strings(values: list[str]) -> list[Path]:
    return [Path(value) for value in values]
