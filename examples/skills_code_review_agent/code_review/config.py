"""Configuration and YAML policy loading."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class SafetyPolicy:
    allowed_commands: list[str] = field(
        default_factory=lambda: ["python", "python3", "pytest"])
    denied_commands: list[str] = field(
        default_factory=lambda: ["sudo", "su", "rm", "dd", "mkfs", "mount"])
    forbidden_paths: list[str] = field(
        default_factory=lambda: ["/", "/etc", "/root", "~/.ssh", ".env"])
    allowed_network_domains: list[str] = field(default_factory=list)
    environment_allowlist: list[str] = field(
        default_factory=lambda: ["PATH", "PYTHONPATH", "LANG", "LC_ALL"])
    max_timeout_seconds: float = 30.0
    max_output_bytes: int = 65536
    container_image: str = "python:3.12-slim"
    memory_limit: str = "256m"
    pids_limit: int = 128
    nano_cpus: int = 1_000_000_000

    @classmethod
    def from_yaml(cls, path: str | Path) -> "SafetyPolicy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ValueError("policy must be a YAML mapping")
        section = raw.get("tool_safety", raw)
        if not isinstance(section, dict):
            raise ValueError("tool_safety must be a mapping")
        known = {name for name in cls.__dataclass_fields__}
        return cls(**{
            key: value
            for key, value in section.items() if key in known
        })


@dataclass
class ReviewConfig:
    confidence_threshold: float = 0.85
    model_mode: str = "fake"
    sandbox_mode: str = "container"
    execute_checks: bool = True
    analyzer_commands: list[str] = field(default_factory=lambda: [
        "python scripts/analyze_diff.py $WORK_DIR/inputs/change.diff --output /out/tool_findings.json"
    ])

    def validate(self) -> None:
        if not 0 <= self.confidence_threshold <= 1:
            raise ValueError("confidence_threshold must be between 0 and 1")
        if self.model_mode not in {"fake", "agent"}:
            raise ValueError("model_mode must be fake or agent")
        if self.sandbox_mode not in {"container", "fake", "local"}:
            raise ValueError("sandbox_mode must be container, fake or local")
