"""Model-review abstraction. Fake mode is deterministic and API-key free."""
from __future__ import annotations

import time
from typing import Protocol
from .models import ChangedFile, Finding


class ModelReviewer(Protocol):

    def review(self, files: list[ChangedFile]) -> tuple[list[Finding], float]:
        ...


class FakeModelReviewer:
    """No-op model that preserves the complete orchestration path for tests."""

    def review(self, files: list[ChangedFile]) -> tuple[list[Finding], float]:
        started = time.perf_counter()
        _ = files
        return [], (time.perf_counter() - started) * 1000


class PayloadModelReviewer:
    """Validate structured candidates produced by the tRPC model path."""

    def __init__(self, payload: list[dict] | None):
        self.payload = payload or []

    def review(self, files: list[ChangedFile]) -> tuple[list[Finding], float]:
        from .models import Severity
        started = time.perf_counter()
        known_files = {value.path for value in files}
        findings: list[Finding] = []
        for item in self.payload:
            file = str(item.get("file", ""))
            if file not in known_files:
                continue
            try:
                severity = Severity(str(item.get("severity", "medium")).lower())
                line = max(1, int(item.get("line", 1)))
                confidence = min(1.0, max(0.0, float(item.get("confidence", 0.5))))
            except (TypeError, ValueError):
                continue
            findings.append(Finding(
                severity=severity,
                category=str(item.get("category", "model_review")),
                file=file,
                line=line,
                title=str(item.get("title", "Model review candidate")),
                evidence=str(item.get("evidence", "")),
                recommendation=str(item.get("recommendation", "Review manually.")),
                confidence=confidence,
                source=["llm"],
                needs_human_review=bool(item.get("needs_human_review", False)),
            ))
        return findings, (time.perf_counter() - started) * 1000
