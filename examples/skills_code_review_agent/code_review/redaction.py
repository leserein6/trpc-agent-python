"""Credential redaction for prompts, reports, logs and database rows."""
from __future__ import annotations

import re
from typing import Any

_PATTERNS = [
    re.compile(
        r"(?i)((?:api[_-]?key|token|password|passwd|secret|client_secret)\s*[:=]\s*[\"']?)([^\s\"']{4,})"
    ),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._~-]{12,})"),
    re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
]


def redact_text(value: str) -> str:
    result = value
    for pattern in _PATTERNS:
        if pattern.groups >= 2:
            result = pattern.sub(
                lambda match: f"{match.group(1)}***REDACTED***", result)
        else:
            result = pattern.sub("***REDACTED***", result)
    return result


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value
