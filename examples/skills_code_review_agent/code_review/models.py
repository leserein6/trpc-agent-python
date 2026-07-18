"""Domain models for review, policy, sandbox, persistence and reports."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ReviewStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FilterDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


@dataclass(frozen=True)
class AddedLine:
    file: str
    line: int
    content: str


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str
    added_lines: list[AddedLine] = field(default_factory=list)


@dataclass
class ChangedFile:
    old_path: str
    new_path: str
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.new_path if self.new_path != "/dev/null" else self.old_path

    @property
    def added_lines(self) -> list[AddedLine]:
        return [line for hunk in self.hunks for line in hunk.added_lines]


@dataclass
class Finding:
    severity: Severity
    category: str
    file: str
    line: int
    title: str
    evidence: str
    recommendation: str
    confidence: float
    source: list[str]
    needs_human_review: bool = False

    def dedup_key(self) -> tuple[str, int, str, str]:
        return (self.file, self.line, self.category, self.title)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ToolExecutionRequest:
    tool_name: str
    command: str
    cwd: str = ""
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 0
    max_output_bytes: int = 0
    script_content: str = ""


@dataclass
class FilterEvent:
    tool_name: str
    decision: FilterDecision
    risk_level: str
    rule_id: str
    reason: str
    evidence: str = ""
    elapsed_ms: float = 0.0
    created_at: str = field(default_factory=utc_now)

    @property
    def blocked(self) -> bool:
        return self.decision != FilterDecision.ALLOW

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["decision"] = self.decision.value
        data["blocked"] = self.blocked
        return data


@dataclass
class SandboxRun:
    backend: str
    command: str
    status: str
    elapsed_ms: float
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False
    error_type: str = ""
    output_files: list[str] = field(default_factory=list)


@dataclass
class ReviewMetrics:
    total_elapsed_ms: float = 0.0
    parser_elapsed_ms: float = 0.0
    rule_elapsed_ms: float = 0.0
    model_elapsed_ms: float = 0.0
    sandbox_elapsed_ms: float = 0.0
    tool_calls: int = 0
    blocked_calls: int = 0
    finding_count: int = 0
    warning_count: int = 0
    severity_distribution: dict[str, int] = field(default_factory=dict)
    exception_distribution: dict[str, int] = field(default_factory=dict)


@dataclass
class ReviewReport:
    task_id: str
    status: ReviewStatus
    input_sha256: str
    input_kind: str
    input_summary: str
    changed_files: list[str]
    findings: list[Finding]
    warnings: list[Finding]
    filter_events: list[FilterEvent]
    sandbox_runs: list[SandboxRun]
    metrics: ReviewMetrics
    created_at: str = field(default_factory=utc_now)
    error: str | None = None

    def severity_counts(self) -> dict[str, int]:
        counts = {value.value: 0 for value in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def filter_summary(self) -> dict[str, int]:
        counts = {value.value: 0 for value in FilterDecision}
        for event in self.filter_events:
            counts[event.decision.value] += 1
        return counts

    def sandbox_summary(self) -> dict[str, int]:
        summary = {
            "total": len(self.sandbox_runs),
            "succeeded": 0,
            "failed": 0,
            "timed_out": 0
        }
        for run in self.sandbox_runs:
            if run.timed_out:
                summary["timed_out"] += 1
            elif run.exit_code == 0:
                summary["succeeded"] += 1
            else:
                summary["failed"] += 1
        return summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "created_at": self.created_at,
            "input": {
                "sha256": self.input_sha256,
                "kind": self.input_kind,
                "summary": self.input_summary,
                "changed_files": self.changed_files,
            },
            "summary": {
                "finding_count": len(self.findings),
                "human_review_count": len(self.warnings),
                "severity": self.severity_counts(),
                "filter": self.filter_summary(),
                "sandbox": self.sandbox_summary(),
            },
            "findings": [value.to_dict() for value in self.findings],
            "needs_human_review": [value.to_dict() for value in self.warnings],
            "filter_events": [value.to_dict() for value in self.filter_events],
            "sandbox_runs": [asdict(value) for value in self.sandbox_runs],
            "metrics": asdict(self.metrics),
            "error": self.error,
        }
