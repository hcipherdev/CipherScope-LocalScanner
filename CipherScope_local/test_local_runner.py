from __future__ import annotations

from pathlib import Path

from CipherScope_local.scanner.models import LocalScanOptions
from CipherScope_local.scanner.runner import run_local_scan


def test_runner_calls_docker_scanner_only_when_enabled(monkeypatch, tmp_path: Path) -> None:
    calls = []

    monkeypatch.setattr("CipherScope_local.scanner.runner.scan_ssh_paths", lambda: [])
    monkeypatch.setattr("CipherScope_local.scanner.runner.scan_libraries", lambda timeout: [])
    monkeypatch.setattr(
        "CipherScope_local.scanner.runner.scan_file_paths",
        lambda paths, max_files: [],
    )
    monkeypatch.setattr(
        "CipherScope_local.scanner.runner.scan_config_paths",
        lambda paths, max_files: [],
    )
    monkeypatch.setattr(
        "CipherScope_local.scanner.runner.scan_docker",
        lambda timeout: calls.append(timeout) or [],
    )

    run_local_scan(LocalScanOptions(paths=[tmp_path], docker=False))
    assert calls == []

    report = run_local_scan(LocalScanOptions(paths=[tmp_path], docker=True, timeout=2.5))

    assert calls == [2.5]
    assert report.technical_appendix["docker_scanning"] == "running-containers-only"
