from __future__ import annotations

from CipherScope_local.scanner.models import LocalFinding, LocalScanReport


def render_markdown_report(report: LocalScanReport) -> str:
    lines = [
        "# CipherScope Local Scanner Report",
        "",
        "## Executive summary",
        "",
        f"- Migration Priority: {report.score}/100"
        + (
            f" (capped from {report.score_raw_points} raw points)"
            if report.score_raw_points and report.score_raw_points > report.score
            else ""
        ),
        f"- Summary: {report.score_summary}",
        f"- Findings: {len(report.findings)}",
        "",
        "## Findings by status",
        "",
    ]
    lines.extend(_count_lines(report.counts_by_status))
    lines.extend(["", "## Findings by severity", ""])
    lines.extend(_count_lines(report.counts_by_severity))
    lines.extend(["", "## Top remediation actions", ""])
    if report.top_remediation_actions:
        lines.extend(f"- {action}" for action in report.top_remediation_actions)
    else:
        lines.append("- Continue expanding the local cryptographic inventory.")
    lines.extend(["", "## Detailed findings", ""])
    if report.findings:
        for finding in report.findings:
            lines.extend(_finding_lines(finding))
    else:
        lines.append("No findings in the selected scan scope.")
    lines.extend(["", "## Why this score?", ""])
    if report.score_factors:
        for factor in report.score_factors:
            lines.append(f"- {factor.points:+d}: {factor.reason}")
    else:
        lines.append("- No score-changing factors were detected.")
    lines.extend(["", "## Technical appendix", ""])
    for key, value in sorted(report.technical_appendix.items()):
        lines.append(f"- {key}: {value}")
    if report.errors:
        lines.extend(["", "## Scanner errors", ""])
        lines.extend(f"- {error}" for error in report.errors)
    return "\n".join(lines) + "\n"


def _count_lines(counts: dict[str, int]) -> list[str]:
    if not counts:
        return ["- None"]
    return [f"- {key}: {value}" for key, value in counts.items()]


def _finding_lines(finding: LocalFinding) -> list[str]:
    lines = [
        f"### {finding.asset}",
        "",
        f"- ID: `{finding.id}`",
        f"- Category: {finding.category}",
        f"- Location: `{finding.location}`",
        f"- Status: {finding.status.value}",
        f"- Severity: {finding.severity.value}",
        f"- Algorithm: {finding.algorithm or 'unknown'}",
        f"- Recommendation: {finding.recommendation}",
    ]
    if finding.evidence:
        lines.append("- Evidence:")
        for key, value in sorted(finding.evidence.items()):
            lines.append(f"  - {key}: {value}")
    lines.append("")
    return lines
