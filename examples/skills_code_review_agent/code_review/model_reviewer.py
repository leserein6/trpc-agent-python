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
