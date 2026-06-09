from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class LocalStatus(str, Enum):
    QUANTUM_VULNERABLE = "quantum-vulnerable"
    MIGRATION_LIMITED = "migration-limited"
    HYBRID_CAPABLE = "hybrid-capable"
    PQC_READY_DEPENDENCY_FOUND = "PQC-ready dependency found"
    UNKNOWN = "unknown"


class LocalSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LocalFinding(BaseModel):
    id: str
    category: str
    asset: str
    location: str
    algorithm: str | None = None
    key_size: int | None = None
    status: LocalStatus
    severity: LocalSeverity
    evidence: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    recommendation: str


class ScoreFactor(BaseModel):
    label: str
    points: int
    reason: str


class LocalScanOptions(BaseModel):
    target: str | None = None
    network: str | None = None
    ports: list[int] = Field(default_factory=lambda: [443])
    paths: list[Path] = Field(default_factory=list)
    timeout: float = 3.0
    max_files: int = 5000
    max_hosts: int = 256
    docker: bool = False
    ssh: bool = True
    libraries: bool = True


class LocalScanReport(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    generated_at: datetime
    scan_type: str = "local"
    targets: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    findings: list[LocalFinding] = Field(default_factory=list)
    score: int
    score_raw_points: int | None = None
    score_summary: str
    score_factors: list[ScoreFactor] = Field(default_factory=list)
    counts_by_status: dict[str, int] = Field(default_factory=dict)
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    top_remediation_actions: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    technical_appendix: dict[str, str | int | float | bool | list[str] | None] = Field(
        default_factory=dict
    )
