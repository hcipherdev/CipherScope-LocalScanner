from __future__ import annotations

import json
import runpy
from datetime import UTC, datetime
from pathlib import Path

import pytest

from CipherScope_local.scanner import cli
from CipherScope_local.scanner.models import (
    LocalFinding,
    LocalScanReport,
    LocalSeverity,
    LocalStatus,
)
from CipherScope_local.scanner.reports.html import render_html_report
from CipherScope_local.scanner.reports.json import render_json_report
from CipherScope_local.scanner.reports.markdown import render_markdown_report
from CipherScope_local.scanner.reports import pdf
from CipherScope_local.scanner.reports.pdf import SWIFT_PDF_RENDERER
from CipherScope_local.scanner.reports.score import ScoredFindings


def test_json_report_is_machine_readable_and_deterministic() -> None:
    rendered = render_json_report(_report())

    parsed = json.loads(rendered)
    assert parsed["scan_type"] == "local"
    assert parsed["findings"][0]["status"] == "quantum-vulnerable"
    assert "  " in rendered


def test_markdown_report_contains_required_sections_without_safe_claims() -> None:
    rendered = render_markdown_report(_report())

    assert "## Executive summary" in rendered
    assert "## Why this score?" in rendered
    assert "## Technical appendix" in rendered
    assert "quantum safe" not in rendered.lower()


def test_html_report_inlines_website_style_and_omits_remote_assets() -> None:
    rendered = render_html_report(_report())

    assert "<style>" in rendered
    assert "--signal: #ffb000" in rendered
    assert 'class="report-shell local-report-shell"' in rendered
    assert 'class="report-head"' in rendered
    assert 'class="status-panel"' in rendered
    assert 'class="finding-section"' in rendered
    assert 'class="finding finding--high"' in rendered
    assert "_google_tag" not in rendered
    assert "googletagmanager" not in rendered
    assert "https://" not in rendered
    assert "BEGIN RSA PRIVATE KEY" not in rendered


def test_pdf_html_profile_adds_print_contrast_overrides() -> None:
    rendered = render_html_report(_report(), output_profile="pdf")

    assert "@page" in rendered
    assert "@media print" in rendered
    assert "background: #ffffff" in rendered
    assert "color: #10130f" in rendered
    assert "padding: 52px 68px 60px !important" in rendered
    assert "details.local-finding-group" in rendered


def test_pdf_html_profile_expands_folded_sections_and_keeps_html_brand_style() -> None:
    rendered = render_html_report(_grouped_report(), output_profile="pdf")

    assert '<details class="local-scope-details" open>' in rendered
    assert '<details class="local-finding-group" open>' in rendered
    assert '<details class="local-score-factors" open>' in rendered
    assert "--signal: #ffb000" in rendered
    assert "--signal: #2563eb" not in rendered
    assert "Space Grotesk" in rendered
    assert "Open this section" not in rendered


def test_pdf_renderer_paginates_webkit_pages_instead_of_single_viewport_snapshot() -> None:
    assert "WKPDFConfiguration" in SWIFT_PDF_RENDERER
    assert "PDFDocument" in SWIFT_PDF_RENDERER
    assert "dataRepresentation()" in SWIFT_PDF_RENDERER
    assert "renderPage(index:" in SWIFT_PDF_RENDERER
    assert "mergedDocument.insert" in SWIFT_PDF_RENDERER
    assert "finishLaunching()" in SWIFT_PDF_RENDERER
    assert "while !completed" in SWIFT_PDF_RENDERER
    assert "application.terminate" not in SWIFT_PDF_RENDERER
    assert "width: pageWidth, height: pageHeight" in SWIFT_PDF_RENDERER
    assert "width: width, height: height" not in SWIFT_PDF_RENDERER


def test_render_pdf_bytes_dispatches_to_macos_renderer(monkeypatch) -> None:
    monkeypatch.setattr(pdf.sys, "platform", "darwin")
    monkeypatch.setattr(pdf, "_render_pdf_bytes_macos", lambda html: b"mac-pdf")

    rendered = pdf.render_pdf_bytes("<html></html>")

    assert rendered == b"mac-pdf"


def test_render_pdf_bytes_dispatches_to_windows_renderer(monkeypatch) -> None:
    monkeypatch.setattr(pdf.sys, "platform", "win32")
    monkeypatch.setattr(pdf, "_render_pdf_bytes_windows", lambda html: b"windows-pdf")

    rendered = pdf.render_pdf_bytes("<html></html>")

    assert rendered == b"windows-pdf"


def test_windows_pdf_requires_supported_browser(monkeypatch) -> None:
    monkeypatch.setattr(pdf, "_find_windows_browser", lambda: None)

    with pytest.raises(RuntimeError) as exc:
        pdf._render_pdf_bytes_windows("<html></html>")

    assert "Microsoft Edge" in str(exc.value)
    assert "Google Chrome" in str(exc.value)
    assert "Chromium" in str(exc.value)


def test_html_report_shows_scan_scope_without_paths_wording() -> None:
    rendered = render_html_report(_report())

    assert "Scan scope" in rendered
    assert "TLS services plus local files and folders" in rendered
    assert "Local files and folders" in rendered
    assert "Local files and folders scanned" in rendered
    assert "Local folders" in rendered
    assert "<span>Paths</span>" not in rendered


def test_html_report_summarizes_docker_only_scope() -> None:
    rendered = render_html_report(_scope_report(targets=[], paths=[], docker=True))

    assert "Docker running containers only" in rendered
    assert "Docker containers" in rendered
    assert "Running containers only" in rendered
    assert "Stopped containers are not started or scanned" in rendered
    assert "SSH configuration and keys" in rendered
    assert "Installed crypto libraries" in rendered
    assert "<span>Paths</span>" not in rendered


def test_html_report_summarizes_docker_plus_local_folders_scope() -> None:
    rendered = render_html_report(
        _scope_report(targets=[], paths=["/etc"], docker=True)
    )

    assert "Docker running containers plus local files and folders" in rendered
    assert "Local files and folders scanned" in rendered
    assert "/etc" in rendered
    assert "<span>Paths</span>" not in rendered


def test_html_report_summarizes_tls_plus_local_folders_scope() -> None:
    rendered = render_html_report(
        _scope_report(
            targets=["localhost:443", "localhost:8443", "localhost:9443"],
            paths=["/etc", "/usr/local/etc", "~/.ssh", "~/projects"],
            docker=False,
        )
    )

    assert "TLS services plus local files and folders" in rendered
    assert "TLS services scanned" in rendered
    assert "Local files and folders scanned" in rendered
    assert "localhost:9443" in rendered
    assert "~/projects" in rendered
    assert "<span>Local folders</span>" in rendered
    assert "<strong>4</strong>" in rendered
    assert "<span>Paths</span>" not in rendered


def test_html_report_groups_evidence_into_foldable_asset_sections() -> None:
    rendered = render_html_report(_grouped_report())

    assert '<details class="local-finding-group">' in rendered
    assert '<details class="local-finding-group" open>' not in rendered
    assert '<summary class="local-finding-group__summary">' in rendered
    assert "httpd-ssl.conf" in rendered
    assert "3 findings" in rendered
    assert "1 of 3 quantum-vulnerable: RSA" in rendered
    assert "1 of 3 PQC-ready dependency found: ML-KEM" in rendered
    assert "1 of 3 unknown: unknown" in rendered
    assert rendered.index("httpd-ssl.conf") < rendered.index("ssl_certificate_key")


def test_html_report_folds_score_factors_by_default() -> None:
    rendered = render_html_report(_report())

    assert '<details class="local-score-factors">' in rendered
    assert '<details class="local-score-factors" open>' not in rendered
    assert '<summary class="local-score-factors__summary">' in rendered
    assert "Score factors" in rendered
    assert "1 factors" in rendered


def test_render_report_dispatches_pdf_format(monkeypatch) -> None:
    monkeypatch.setattr(
        cli,
        "render_pdf_report",
        lambda report: b"%PDF-1.7\nmock\n",
        raising=False,
    )

    rendered = cli.render_report(_report(), "pdf")

    assert rendered == b"%PDF-1.7\nmock\n"


def test_cli_scan_writes_requested_output_format(tmp_path: Path, monkeypatch, capsys) -> None:
    output = tmp_path / "report.html"

    monkeypatch.setattr(cli, "run_local_scan", lambda options: _report())

    exit_code = cli.main(
        ["scan", "--path", str(tmp_path), "--format", "html", "--output", str(output)]
    )

    assert exit_code == 0
    assert output.exists()
    assert "CipherScope Local Scanner" in output.read_text(encoding="utf-8")
    assert capsys.readouterr().out == ""


def test_cli_scan_writes_pdf_output(tmp_path: Path, monkeypatch, capsys) -> None:
    output = tmp_path / "report.pdf"

    monkeypatch.setattr(cli, "run_local_scan", lambda options: _report())
    monkeypatch.setattr(
        cli,
        "render_pdf_report",
        lambda report: b"%PDF-1.7\nmock\n",
        raising=False,
    )

    exit_code = cli.main(
        ["scan", "--path", str(tmp_path), "--format", "pdf", "--output", str(output)]
    )

    assert exit_code == 0
    assert output.read_bytes() == b"%PDF-1.7\nmock\n"
    assert capsys.readouterr().out == ""


def test_cli_scan_passes_docker_flag_to_runner(tmp_path: Path, monkeypatch) -> None:
    captured_options = []

    def fake_run(options):
        captured_options.append(options)
        return _report()

    monkeypatch.setattr(cli, "run_local_scan", fake_run)

    exit_code = cli.main(["scan", "--path", str(tmp_path), "--docker", "--format", "json"])

    assert exit_code == 0
    assert captured_options[0].docker is True


def test_cli_scan_accepts_docker_without_path_or_target(monkeypatch) -> None:
    captured_options = []

    def fake_run(options):
        captured_options.append(options)
        return _report()

    monkeypatch.setattr(cli, "run_local_scan", fake_run)

    exit_code = cli.main(["scan", "--docker", "--format", "json"])

    assert exit_code == 0
    assert captured_options[0].docker is True
    assert captured_options[0].paths == []


def test_cli_scan_prints_json_to_stdout_when_no_output(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "run_local_scan", lambda options: _report())

    exit_code = cli.main(["scan", "--target", "localhost", "--format", "json"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["scan_type"] == "local"
    assert captured.err == ""


def test_module_entrypoint_delegates_to_cli_main(monkeypatch) -> None:
    monkeypatch.setattr(cli, "main", lambda argv=None: 17)

    with pytest.raises(SystemExit) as exc:
        runpy.run_module("CipherScope_local.scanner", run_name="__main__", alter_sys=True)

    assert exc.value.code == 17


def _report() -> LocalScanReport:
    finding = LocalFinding(
        id="tls-localhost-443-rsa",
        category="tls_certificate",
        asset="localhost:443",
        location="localhost:443",
        algorithm="RSA-2048",
        key_size=2048,
        status=LocalStatus.QUANTUM_VULNERABLE,
        severity=LocalSeverity.HIGH,
        evidence={
            "subject": "CN=localhost",
            "private_material": "[redacted]",
        },
        recommendation=(
            "Replace or hybridize this dependency as PQC-capable options become available."
        ),
    )
    scored = ScoredFindings.from_findings([finding])
    return LocalScanReport(
        generated_at=datetime(2026, 5, 19, tzinfo=UTC),
        scan_type="local",
        targets=["localhost"],
        paths=["/tmp/example"],
        findings=[finding],
        score=scored.score,
        score_summary=scored.summary,
        score_factors=scored.score_factors,
        counts_by_status=scored.counts_by_status,
        counts_by_severity=scored.counts_by_severity,
        top_remediation_actions=scored.top_remediation_actions,
        errors=[],
        technical_appendix={"scanner": "tests"},
    )


def _scope_report(
    targets: list[str],
    paths: list[str],
    docker: bool,
) -> LocalScanReport:
    return LocalScanReport(
        generated_at=datetime(2026, 5, 19, tzinfo=UTC),
        scan_type="local",
        targets=targets,
        paths=paths,
        findings=[],
        score=0,
        score_summary="No score-changing factors were detected.",
        score_factors=[],
        counts_by_status={},
        counts_by_severity={},
        top_remediation_actions=[],
        errors=[],
        technical_appendix={
            "scanner": "tests",
            "docker_scanning": (
                "running-containers-only" if docker else "disabled"
            ),
        },
    )


def _grouped_report() -> LocalScanReport:
    findings = [
        LocalFinding(
            id="config-httpd-rsa",
            category="configuration",
            asset="httpd-ssl.conf",
            location="/etc/httpd/httpd-ssl.conf:42",
            algorithm="RSA",
            key_size=None,
            status=LocalStatus.QUANTUM_VULNERABLE,
            severity=LocalSeverity.MEDIUM,
            evidence={"matched_term": "RSA", "line": "SSLCertificateKeyFile rsa.key"},
            recommendation="Review RSA configuration.",
        ),
        LocalFinding(
            id="config-httpd-mlkem",
            category="configuration",
            asset="httpd-ssl.conf",
            location="/etc/httpd/httpd-ssl.conf:77",
            algorithm="ML-KEM",
            key_size=None,
            status=LocalStatus.PQC_READY_DEPENDENCY_FOUND,
            severity=LocalSeverity.INFO,
            evidence={"matched_term": "ML-KEM", "line": "ssl_groups ML-KEM"},
            recommendation="Validate PQC-capable configuration.",
        ),
        LocalFinding(
            id="config-httpd-unknown",
            category="configuration",
            asset="httpd-ssl.conf",
            location="/etc/httpd/httpd-ssl.conf:88",
            algorithm=None,
            key_size=None,
            status=LocalStatus.UNKNOWN,
            severity=LocalSeverity.INFO,
            evidence={"matched_term": "ssl_certificate_key"},
            recommendation="Review this certificate reference manually.",
        ),
    ]
    scored = ScoredFindings.from_findings(findings)
    return LocalScanReport(
        generated_at=datetime(2026, 5, 19, tzinfo=UTC),
        scan_type="local",
        targets=[],
        paths=["/etc/httpd"],
        findings=findings,
        score=scored.score,
        score_summary=scored.summary,
        score_factors=scored.score_factors,
        counts_by_status=scored.counts_by_status,
        counts_by_severity=scored.counts_by_severity,
        top_remediation_actions=scored.top_remediation_actions,
        errors=[],
        technical_appendix={"scanner": "tests"},
    )
