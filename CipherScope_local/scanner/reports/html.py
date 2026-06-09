from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from CipherScope_local.scanner.models import LocalFinding, LocalScanReport, LocalStatus


LOCAL_STYLE = """
.local-report-shell .status-panel {
  grid-template-columns: repeat(4, 1fr);
}
.local-score {
  font-size: clamp(3rem, 8vw, 7rem);
  line-height: 0.85;
  letter-spacing: -0.08em;
}
.local-counts {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 2rem;
}
.local-scope {
  border-top: 1px solid var(--line);
  padding-top: 2rem;
}
.local-scope h2 {
  margin: 0.35rem 0 1rem;
}
.local-scope-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 0.8rem;
}
.local-scope-card {
  border: 1px solid var(--line);
  background: var(--field);
  min-height: 6.5rem;
  padding: 0.85rem;
}
.local-scope-card span {
  color: var(--muted);
  display: block;
  font-family: "IBM Plex Mono", "JetBrains Mono", monospace;
  font-size: 0.72rem;
  font-weight: 800;
  text-transform: uppercase;
}
.local-scope-card strong {
  display: block;
  line-height: 1.15;
  margin-top: 0.55rem;
  overflow-wrap: anywhere;
}
.local-scope-details {
  border-top: 1px solid var(--line);
  margin-top: 1rem;
  padding-top: 1rem;
}
.local-scope-details summary {
  cursor: pointer;
  font-weight: 800;
}
.local-scope-detail-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}
.local-scope-detail-grid ul {
  margin: 0.6rem 0 0;
  padding-left: 1.2rem;
}
.local-counts ul,
.local-actions {
  margin: 0;
  padding-left: 1.2rem;
}
.local-finding-group {
  border-top: 1px solid var(--line);
}
.local-score-factors {
  border-top: 1px solid var(--line);
}
.local-finding-group__summary {
  display: grid;
  grid-template-columns: minmax(12rem, 0.45fr) 1fr;
  gap: 2rem;
  padding: 1.35rem 0;
  cursor: pointer;
}
.local-score-factors__summary {
  display: grid;
  grid-template-columns: minmax(12rem, 0.45fr) 1fr;
  gap: 2rem;
  padding: 1.35rem 0;
  cursor: pointer;
}
.local-finding-group__summary::marker {
  color: var(--signal-dark);
}
.local-score-factors__summary::marker {
  color: var(--signal-dark);
}
.local-finding-group__summary h3 {
  margin: 0.35rem 0 0;
}
.local-score-factors__summary h3 {
  margin: 0.35rem 0 0;
}
.local-group-count {
  color: var(--muted);
  font-weight: 800;
}
.local-score-factors .finding {
  border-top: 1px solid rgba(16, 19, 15, 0.1);
}
.local-status-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 0.55rem;
  margin-top: 0.6rem;
}
.local-status-pill {
  display: inline-flex;
  max-width: 100%;
  padding: 0.35rem 0.5rem;
  border: 1px solid var(--line);
  background: var(--field);
  color: var(--ink);
  font-family: "IBM Plex Mono", "JetBrains Mono", monospace;
  font-size: 0.78rem;
  overflow-wrap: anywhere;
}
.local-finding-group .finding {
  border-top: 1px solid rgba(16, 19, 15, 0.1);
}
.finding--critical .severity,
.finding--high .severity {
  color: var(--bad);
}
.finding--medium .severity {
  color: var(--warn);
}
.finding--low .severity,
.finding--info .severity {
  color: var(--muted);
}
@media (max-width: 820px) {
  .local-report-shell .status-panel,
  .local-scope-grid,
  .local-scope-detail-grid,
  .local-counts,
  .local-finding-group__summary,
  .local-score-factors__summary {
    grid-template-columns: 1fr;
  }
}
"""

PDF_STYLE = """
@page {
  size: A4;
  margin: 18mm 16mm;
}

:root {
  --ink: #10130f;
  --paper: #f3efe4;
  --field: #fffaf0;
  --muted: #706b60;
  --line: rgba(16, 19, 15, 0.18);
  --signal: #ffb000;
  --signal-dark: #6d4600;
  --accent: #6d4600;
  --good: #1b7a4d;
  --warn: #a86f00;
  --bad: #ad332b;
}

* {
  box-sizing: border-box;
}

html, body {
  background: #ffffff;
  color: var(--ink) !important;
  font-family: "Space Grotesk", "IBM Plex Sans", "Aptos", sans-serif;
  font-size: 10pt;
  line-height: 1.5;
}

@media print {
  html,
  body {
    background: #ffffff;
    color: #10130f;
  }

  body {
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }
}

/* --- Header --- */
.report-shell,
.local-report-shell {
  padding: 52px 68px 60px !important;
}

.report-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1.5rem 0 1.2rem;
  border-bottom: 2px solid var(--ink);
  margin-bottom: 1.8rem;
}

.brand-link {
  font-size: 0.9rem;
  font-weight: 800;
  letter-spacing: -0.02em;
  color: var(--ink);
}

.report-head .eyebrow {
  margin: 0;
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--signal-dark);
}

.report-head h1 {
  font-size: 1.6rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  line-height: 1.1;
  margin: 0.2rem 0 0;
  color: var(--ink);
}

/* --- Status Panel (KPI cards) --- */
.status-panel {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1px;
  margin: 0 0 2rem;
  background: var(--line);
  border: 1px solid var(--line);
  overflow: hidden;
}

.status-panel div {
  padding: 1rem 1.2rem;
  background: var(--field);
}

.status-panel span {
  display: block;
  font-size: 0.6rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 0.3rem;
}

.status-panel strong {
  display: block;
  font-size: 1.5rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  line-height: 1;
  color: var(--ink);
}

/* --- Section headings --- */
.eyebrow {
  font-size: 0.6rem;
  font-weight: 700;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--signal-dark);
  margin: 0 0 0.3rem;
}

h2 {
  font-size: 1.15rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  line-height: 1.2;
  color: var(--ink);
  margin: 0 0 0.8rem;
}

h3 {
  font-size: 0.85rem;
  font-weight: 700;
  color: var(--ink);
  margin: 0 0 0.3rem;
}

/* --- Scope section --- */
.local-scope {
  border-top: 1px solid var(--line);
  padding-top: 1.5rem;
  margin-bottom: 1.5rem;
}

.local-scope h2 {
  font-size: 1rem;
  margin: 0.2rem 0 1rem;
}

.local-scope-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 1px;
  background: var(--line);
  border: 1px solid var(--line);
  overflow: hidden;
}

.local-scope-card {
  padding: 0.8rem;
  background: var(--field);
  border-bottom: none;
  min-height: auto;
}

.local-scope-card span {
  display: block;
  font-size: 0.55rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--muted);
  font-family: "IBM Plex Mono", "JetBrains Mono", monospace;
}

.local-scope-card strong {
  display: block;
  font-size: 0.75rem;
  font-weight: 600;
  margin-top: 0.3rem;
  color: var(--ink);
  line-height: 1.3;
}

/* --- Scope details --- */
details.local-scope-details {
  display: block !important;
  margin-top: 0.8rem;
}

details.local-scope-details > summary {
  list-style: none;
  font-size: 0.7rem;
  font-weight: 700;
  color: var(--muted);
  margin-bottom: 0.5rem;
}

details.local-scope-details > summary::-webkit-details-marker {
  display: none;
}

details.local-scope-details > *:not(summary) {
  display: block !important;
}

.local-scope-detail-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}

.local-scope-detail-grid h3 {
  font-size: 0.7rem;
  color: var(--muted);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.local-scope-detail-grid ul {
  margin: 0.3rem 0 0;
  padding-left: 1rem;
  font-size: 0.75rem;
  color: var(--ink);
}

/* --- Summary text --- */
.summary {
  font-size: 0.8rem;
  color: var(--muted);
  line-height: 1.5;
  margin: 0 0 1.5rem;
  padding: 0.8rem 1rem;
  background: var(--field);
  border-left: 3px solid var(--signal);
}

/* --- Finding sections --- */
.finding-section {
  margin-top: 2rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--line);
}

.finding-section .eyebrow {
  margin-bottom: 0.2rem;
}

/* --- Executive summary lists --- */
.local-counts {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.5rem;
  margin-top: 0.8rem;
}

.local-counts h3 {
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  margin-bottom: 0.4rem;
}

.local-counts ul,
.local-actions {
  margin: 0;
  padding-left: 1.1rem;
  font-size: 0.8rem;
  line-height: 1.7;
  color: var(--ink);
}

.local-actions li {
  margin-bottom: 0.4rem;
}

/* --- Finding groups (evidence table) --- */
details.local-finding-group,
details.local-score-factors {
  display: block !important;
  border: 1px solid var(--line);
  margin-bottom: 0.6rem;
  overflow: hidden;
}

details.local-finding-group > summary,
details.local-score-factors > summary {
  list-style: none;
}

details.local-finding-group > summary::-webkit-details-marker,
details.local-score-factors > summary::-webkit-details-marker {
  display: none;
}

details.local-finding-group > *:not(summary),
details.local-score-factors > *:not(summary) {
  display: block !important;
}

.local-finding-group__summary,
.local-score-factors__summary {
  display: grid;
  grid-template-columns: 1fr auto;
  align-items: center;
  gap: 1rem;
  padding: 0.8rem 1rem;
  background: var(--field);
  cursor: default;
}

.local-finding-group__summary .severity,
.local-score-factors__summary .severity {
  font-size: 0.55rem;
  margin-bottom: 0.1rem;
}

.local-finding-group__summary h3 {
  font-size: 0.8rem;
  font-weight: 700;
  margin: 0;
}

.local-group-count {
  font-size: 0.65rem;
  font-weight: 600;
  color: var(--muted);
}

.local-status-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
}

.local-status-pill {
  display: inline-block;
  padding: 0.25rem 0.5rem;
  font-size: 0.6rem;
  font-weight: 600;
  font-family: "IBM Plex Mono", "JetBrains Mono", monospace;
  background: #ffffff;
  border: 1px solid var(--line);
  color: var(--ink);
}

/* --- Individual findings --- */
.finding {
  display: grid;
  grid-template-columns: 0.35fr 1fr;
  gap: 1rem;
  padding: 0.8rem 1rem;
  border-top: 1px solid var(--line);
}

.finding .severity {
  font-size: 0.55rem;
  font-weight: 800;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.finding h3 {
  font-size: 0.75rem;
  margin: 0.1rem 0 0;
}

.finding p {
  font-size: 0.75rem;
  margin: 0 0 0.3rem;
  color: var(--ink);
}

.finding .recommendation {
  font-weight: 600;
  color: var(--ink);
}

/* --- Severity colors --- */
.finding--critical .severity,
.finding--high .severity {
  color: var(--bad);
}

.finding--medium .severity {
  color: var(--warn);
}

.finding--low .severity,
.finding--info .severity {
  color: var(--muted);
}

/* --- Definition lists (metadata) --- */
dl {
  display: grid;
  grid-template-columns: 0.3fr 1fr;
  gap: 0.2rem 0.8rem;
  margin: 0.5rem 0 0;
  font-size: 0.68rem;
  font-family: "IBM Plex Mono", "JetBrains Mono", monospace;
}

dt {
  font-weight: 600;
  color: var(--muted);
}

dd {
  margin: 0;
  color: var(--ink);
  overflow-wrap: anywhere;
}

/* --- Score factors --- */
.local-score-factors__summary h2 {
  font-size: 0.9rem;
  margin: 0;
}

.local-score-factors__summary .summary {
  background: none;
  border-left: none;
  padding: 0;
  margin: 0;
  font-size: 0.7rem;
}

/* --- Page break control --- */
.finding-section {
  break-inside: avoid;
  page-break-inside: avoid;
}

details.local-finding-group {
  break-inside: avoid;
  page-break-inside: avoid;
}

/* --- Responsive override for PDF (force desktop) --- */
.local-report-shell .status-panel,
.local-scope-grid,
.local-scope-detail-grid,
.local-counts,
.local-finding-group__summary,
.local-score-factors__summary {
  grid-template-columns: unset;
}

.local-report-shell .status-panel {
  grid-template-columns: repeat(4, 1fr);
}

.local-scope-grid {
  grid-template-columns: repeat(5, 1fr);
}
"""


def render_html_report(report: LocalScanReport, output_profile: str = "screen") -> str:
    env = Environment(
        loader=FileSystemLoader(_template_dir()),
        autoescape=select_autoescape(("html", "xml")),
    )
    template = env.get_template("report.html")
    css = _site_css() + "\n" + LOCAL_STYLE
    if output_profile == "pdf":
        css += "\n" + PDF_STYLE
    return template.render(
        report=report,
        css=css,
        scan_scope=_scan_scope(report),
        finding_groups=_finding_groups(report.findings),
        pdf_profile=output_profile == "pdf",
    )


def _scan_scope(report: LocalScanReport) -> dict:
    has_docker = report.technical_appendix.get("docker_scanning") == (
        "running-containers-only"
    )
    has_tls = bool(report.targets)
    has_locations = bool(report.paths)
    return {
        "summary": _scan_scope_summary(has_docker, has_tls, has_locations),
        "scope_items": _scan_scope_items(report, has_docker, has_tls, has_locations),
        "targets": report.targets,
        "locations": report.paths,
        "has_docker": has_docker,
    }


def _scan_scope_summary(
    has_docker: bool,
    has_tls: bool,
    has_locations: bool,
) -> str:
    if has_docker and has_tls and has_locations:
        return "Docker running containers, TLS services, and local files and folders"
    if has_docker and has_tls:
        return "Docker running containers plus TLS services"
    if has_docker and has_locations:
        return "Docker running containers plus local files and folders"
    if has_docker and not has_tls:
        return "Docker running containers only"
    if has_tls and has_locations:
        return "TLS services plus local files and folders"
    if has_tls:
        return "TLS services"
    if has_locations:
        return "Local files, SSH, and library scan"
    return "SSH configuration and installed crypto libraries"


def _scan_scope_items(
    report: LocalScanReport,
    has_docker: bool,
    has_tls: bool,
    has_locations: bool,
) -> list[dict[str, str]]:
    items = [
        {
            "label": "Docker containers",
            "value": "Running containers only" if has_docker else "Not requested",
        },
        {
            "label": "TLS services",
            "value": f"{len(report.targets)} services" if has_tls else "Not requested",
        },
        {
            "label": "Local files and folders",
            "value": (
                f"{len(report.paths)} folders scanned"
                if has_locations
                else "Not requested"
            ),
        },
        {
            "label": "SSH configuration and keys",
            "value": "Included",
        },
        {
            "label": "Installed crypto libraries",
            "value": "Included",
        },
    ]
    return items


def _finding_groups(findings: list[LocalFinding]) -> list[dict]:
    grouped: OrderedDict[str, list[LocalFinding]] = OrderedDict()
    for finding in findings:
        grouped.setdefault(finding.asset, []).append(finding)
    return [
        {
            "name": asset,
            "findings": [_finding_view(finding) for finding in group_findings],
            "total": len(group_findings),
            "status_summaries": _status_summaries(group_findings),
        }
        for asset, group_findings in grouped.items()
    ]


def _status_summaries(findings: list[LocalFinding]) -> list[str]:
    summaries: list[str] = []
    total = len(findings)
    for status in LocalStatus:
        matching = [finding for finding in findings if finding.status == status]
        if not matching:
            continue
        algorithms = sorted({finding.algorithm or "unknown" for finding in matching})
        summaries.append(
            f"{len(matching)} of {total} {status.value}: {', '.join(algorithms)}"
        )
    return summaries


def _finding_view(finding: LocalFinding) -> dict:
    return {
        "id": finding.id,
        "category": finding.category,
        "location": finding.location,
        "key_size": finding.key_size,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "algorithm": finding.algorithm,
        "status_line": (
            f"{finding.status.value}: {finding.algorithm}"
            if finding.algorithm
            else finding.status.value
        ),
        "recommendation": finding.recommendation,
        "evidence": finding.evidence,
    }


def _template_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "templates"


def _site_css() -> str:
    static_dir = Path(__file__).resolve().parent.parent / "static"
    css = (static_dir / "styles.css").read_text(encoding="utf-8")
    return css.replace('a[href="https://www.hybridcipher.com"]', ".hybridcipher-link")
