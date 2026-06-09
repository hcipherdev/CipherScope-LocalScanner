from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from CipherScope_local.scanner.models import LocalFinding, LocalSeverity, LocalStatus, ScoreFactor


SEVERITY_POINTS = {
    LocalSeverity.CRITICAL: 35,
    LocalSeverity.HIGH: 25,
    LocalSeverity.MEDIUM: 15,
    LocalSeverity.LOW: 6,
    LocalSeverity.INFO: 0,
}

CATEGORY_LIMITS = {
    "tls_certificate": {"full_count": 3, "hard_cap": 50},
    "private_key": {"full_count": 2, "hard_cap": 40},
    "ssh": {"full_count": 3, "hard_cap": 40},
    "configuration": {"full_count": 3, "hard_cap": 30},
    "file_certificate": {"full_count": 3, "hard_cap": 35},
    "certificate_store": {"full_count": 2, "hard_cap": 20},
    "libraries": {"full_count": 4, "hard_cap": 25},
    "docker_container": {"full_count": 3, "hard_cap": 20},
    "docker_library": {"full_count": 3, "hard_cap": 15},
}
DEFAULT_LIMIT = {"full_count": 3, "hard_cap": 30}


@dataclass(frozen=True)
class ScoredFindings:
    score: int
    raw_points: int
    summary: str
    score_factors: list[ScoreFactor]
    counts_by_status: dict[str, int]
    counts_by_severity: dict[str, int]
    top_remediation_actions: list[str]

    @classmethod
    def from_findings(cls, findings: list[LocalFinding]) -> "ScoredFindings":
        return score_findings(findings)


def score_findings(findings: list[LocalFinding]) -> ScoredFindings:
    points = 0
    raw_points = 0
    factors: list[ScoreFactor] = []
    pqc_credit = 0
    category_counts: dict[str, int] = {}
    category_totals: dict[str, int] = {}

    for finding in findings:
        if finding.status == LocalStatus.PQC_READY_DEPENDENCY_FOUND:
            credit = min(8, 10 - pqc_credit)
            if credit > 0:
                pqc_credit += credit
                factors.append(
                    ScoreFactor(
                        label=finding.asset,
                        points=-credit,
                        reason=(
                            f"{finding.asset} shows a PQC-ready dependency marker, "
                            "which slightly lowers migration priority."
                        ),
                    )
                )
            continue
        if finding.status == LocalStatus.HYBRID_CAPABLE:
            credit = min(12, 15 - pqc_credit)
            if credit > 0:
                pqc_credit += credit
                factors.append(
                    ScoreFactor(
                        label=finding.asset,
                        points=-credit,
                        reason=(
                            f"{finding.asset} appears hybrid-capable, but this does not "
                            "remove the need to review other assets."
                        ),
                    )
                )
            continue

        factor_points = _finding_points(finding)
        if factor_points == 0:
            continue

        raw_points += factor_points

        cat = finding.category
        k = category_counts.get(cat, 0) + 1
        category_counts[cat] = k
        limits = CATEGORY_LIMITS.get(cat, DEFAULT_LIMIT)

        if k <= limits["full_count"]:
            effective = factor_points
        else:
            effective = int(factor_points / (1 + (k - limits["full_count"])))

        current_total = category_totals.get(cat, 0)
        effective = min(effective, limits["hard_cap"] - current_total)
        effective = max(0, effective)
        category_totals[cat] = current_total + effective

        points += effective
        factors.append(
            ScoreFactor(
                label=finding.asset,
                points=effective,
                reason=_factor_reason(finding, effective),
            )
        )

    score = max(0, min(100, points - pqc_credit))
    return ScoredFindings(
        score=score,
        raw_points=raw_points,
        summary=_summary(score, findings),
        score_factors=factors,
        counts_by_status=_counts(finding.status.value for finding in findings),
        counts_by_severity=_counts(finding.severity.value for finding in findings),
        top_remediation_actions=_top_actions(findings),
    )


def _finding_points(finding: LocalFinding) -> int:
    points = SEVERITY_POINTS[finding.severity]
    if finding.status == LocalStatus.QUANTUM_VULNERABLE:
        points += 5
    elif finding.status == LocalStatus.MIGRATION_LIMITED:
        points += 3
    elif finding.status == LocalStatus.UNKNOWN:
        points += 1 if finding.severity == LocalSeverity.INFO else 4

    if finding.category == "tls_certificate" and finding.status == LocalStatus.QUANTUM_VULNERABLE:
        points += 8
    if (
        finding.category in {"private_key", "ssh"}
        and finding.status == LocalStatus.QUANTUM_VULNERABLE
    ):
        points += 6
    return points


def _factor_reason(finding: LocalFinding, points: int) -> str:
    category = (
        "TLS"
        if finding.category.startswith("tls")
        else finding.category.replace("_", " ").title()
    )
    algorithm = f" using {finding.algorithm}" if finding.algorithm else ""
    return (
        f"{category} finding on {finding.asset}{algorithm} adds {points} migration "
        f"priority points because it is classified as {finding.status.value}."
    )


def _summary(score: int, findings: list[LocalFinding]) -> str:
    if not findings:
        return "No local cryptographic evidence was found in the selected scan scope."
    if score >= 75:
        return "High local PQC migration priority based on classical cryptography evidence."
    if score >= 40:
        return "Moderate local PQC migration priority based on the selected scan scope."
    return "Lower local PQC migration priority in the selected scan scope; continue inventory work."


def _top_actions(findings: list[LocalFinding]) -> list[str]:
    actions: list[str] = []
    for finding in sorted(findings, key=lambda item: _action_rank(item)):
        if finding.recommendation in actions:
            continue
        if finding.severity in {
            LocalSeverity.CRITICAL,
            LocalSeverity.HIGH,
            LocalSeverity.MEDIUM,
        }:
            actions.append(finding.recommendation)
        if len(actions) == 5:
            break
    return actions


def _action_rank(finding: LocalFinding) -> tuple[int, str]:
    severity_rank = {
        LocalSeverity.CRITICAL: 0,
        LocalSeverity.HIGH: 1,
        LocalSeverity.MEDIUM: 2,
        LocalSeverity.LOW: 3,
        LocalSeverity.INFO: 4,
    }
    return severity_rank[finding.severity], finding.id


def _counts(values) -> dict[str, int]:
    counter = Counter(values)
    return {key: counter[key] for key in sorted(counter)}
