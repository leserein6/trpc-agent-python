"""Explainable baseline rules used in fake-model and regression modes."""
from __future__ import annotations

import re
import time
from collections.abc import Iterable
from .models import ChangedFile, Finding, Severity
from .redaction import redact_text

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|token|password|passwd|secret|client_secret)\b\s*[:=]\s*[\"']([^\"']{4,})[\"']"
)
_TOKEN_SHAPES = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|"
    r"xox[baprs]-[0-9A-Za-z-]{10,})\b")
_SHELL_EXEC = re.compile(
    r"\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system)\b")
_SQL_INTERPOLATION = re.compile(
    r"(?:execute|executemany)\s*\(\s*(?:f[\"']|[\"'].*(?:%s|\{).*[\"']\s*[%\.format])",
    re.I)
_CREATE_TASK = re.compile(r"\basyncio\.create_task\s*\(")
_UNAWAITED_ASYNC = re.compile(r"^\s*[A-Za-z_][\w\.]*_async\s*\(")
_DB_CONNECT = re.compile(
    r"\b(?:sqlite3|psycopg2|pymysql|mysql\.connector|asyncpg)\.(?:connect|create_pool)\s*\(",
    re.I)
_OPEN_RESOURCE = re.compile(r"(?<!with\s)\bopen\s*\(")
_CLOSE_CALL = re.compile(r"\.(?:close|aclose|release)\s*\(")
_TRANSACTION_BEGIN = re.compile(r"\b(?:begin|transaction)\b", re.I)
_ROLLBACK = re.compile(r"\brollback\s*\(", re.I)


def _finding(**kwargs) -> Finding:
    kwargs["evidence"] = redact_text(kwargs["evidence"].strip())
    kwargs["source"] = [kwargs["source"]]
    return Finding(**kwargs)


def scan_files(files: Iterable[ChangedFile]) -> tuple[list[Finding], float]:
    started = time.perf_counter()
    findings: list[Finding] = []
    changed_files = list(files)
    for changed_file in changed_files:
        added = changed_file.added_lines
        full_text = "\n".join(value.content for value in added)
        for value in added:
            line = value.content
            if _SECRET_ASSIGNMENT.search(line) or _TOKEN_SHAPES.search(line):
                findings.append(
                    _finding(
                        severity=Severity.CRITICAL,
                        category="sensitive_information",
                        file=value.file,
                        line=value.line,
                        title="Hard-coded sensitive credential",
                        evidence=line,
                        recommendation=("Remove the plaintext value, rotate the credential, "
                                        "and use an approved secret store or injected environment variable."
                                        ),
                        confidence=0.99,
                        source="static_rule:secret"))
            if _SHELL_EXEC.search(line) and ("shell=True" in line
                                             or "os.system" in line
                                             or "bash -c" in line):
                findings.append(
                    _finding(
                        severity=Severity.HIGH,
                        category="security",
                        file=value.file,
                        line=value.line,
                        title="Potential shell command injection",
                        evidence=line,
                        recommendation=("Avoid shell execution; pass an argument vector and validate "
                                        "the executable and each argument against an allowlist."
                                        ),
                        confidence=0.96,
                        source="static_rule:shell-injection"))
            if _SQL_INTERPOLATION.search(line):
                findings.append(
                    _finding(
                        severity=Severity.HIGH,
                        category="security",
                        file=value.file,
                        line=value.line,
                        title="Potential SQL injection",
                        evidence=line,
                        recommendation="Use parameterized SQL and keep untrusted values out of the query string.",
                        confidence=0.93,
                        source="static_rule:sql-injection"))
            if _CREATE_TASK.search(line) and "=" not in line.split(
                    "asyncio.create_task", 1)[0]:
                findings.append(
                    _finding(
                        severity=Severity.MEDIUM,
                        category="async_lifecycle",
                        file=value.file,
                        line=value.line,
                        title="Background task handle is not retained",
                        evidence=line,
                        recommendation=(
                            "Retain the Task, propagate/capture exceptions, and await "
                            "or cancel it during shutdown."
                        ),
                        confidence=0.83,
                        source="static_rule:untracked-task",
                        needs_human_review=True))
            stripped = line.strip()
            if _UNAWAITED_ASYNC.search(stripped) and not stripped.startswith(
                    ("await ", "return ", "#")):
                findings.append(
                    _finding(
                        severity=Severity.MEDIUM,
                        category="async_lifecycle",
                        file=value.file,
                        line=value.line,
                        title="Possible un-awaited async call",
                        evidence=line,
                        recommendation=(
                            "Await the coroutine or explicitly schedule and manage it "
                            "as a task."
                        ),
                        confidence=0.76,
                        source="static_rule:unawaited-async",
                        needs_human_review=True))
            if _DB_CONNECT.search(line) and not (_CLOSE_CALL.search(full_text)
                                                 or "with " in full_text):
                findings.append(
                    _finding(
                        severity=Severity.MEDIUM,
                        category="database_lifecycle",
                        file=value.file,
                        line=value.line,
                        title="Database connection lifecycle is incomplete",
                        evidence=line,
                        recommendation=("Use a context manager or finally block and define commit, rollback, "
                                        "release and close behavior."),
                        confidence=0.82,
                        source="static_rule:db-lifecycle",
                        needs_human_review=True))
            if _OPEN_RESOURCE.search(line) and not (
                    _CLOSE_CALL.search(full_text) or "with open" in line):
                findings.append(
                    _finding(
                        severity=Severity.MEDIUM,
                        category="resource_lifecycle",
                        file=value.file,
                        line=value.line,
                        title="Opened resource may not be closed",
                        evidence=line,
                        recommendation="Use a context manager or close the resource in a finally block.",
                        confidence=0.80,
                        source="static_rule:resource-lifecycle",
                        needs_human_review=True))
        if _TRANSACTION_BEGIN.search(
                full_text) and not _ROLLBACK.search(full_text):
            first = added[0] if added else None
            if first:
                findings.append(
                    _finding(
                        severity=Severity.MEDIUM,
                        category="database_transaction",
                        file=first.file,
                        line=first.line,
                        title="Transaction error path may not roll back",
                        evidence=full_text[:300],
                        recommendation="Add an exception path that rolls back before releasing the connection.",
                        confidence=0.78,
                        source="static_rule:transaction-rollback",
                        needs_human_review=True))
    production = [
        f for f in changed_files
        if f.added_lines and _is_source(f.path) and not _is_test(f.path)
    ]
    tests = [f for f in changed_files if f.added_lines and _is_test(f.path)]
    if production and not tests and not findings:
        first = production[0].added_lines[0]
        findings.append(
            _finding(
                severity=Severity.LOW,
                category="testing",
                file=first.file,
                line=first.line,
                title="Production change has no accompanying test change",
                evidence=first.content,
                recommendation=("Add automated tests for normal, error, boundary and regression paths, "
                                "or document why no test is required."),
                confidence=0.72,
                source="static_rule:missing-tests",
                needs_human_review=True))
    return deduplicate(findings), (time.perf_counter() - started) * 1000


def _is_source(path: str) -> bool:
    return path.lower().endswith((".py", ".go", ".cc", ".cpp", ".c", ".h",
                                  ".hpp", ".java", ".ts", ".js"))


def _is_test(path: str) -> bool:
    normalized = path.lower().replace("\\", "/")
    name = normalized.rsplit("/", 1)[-1]
    return "/tests/" in f"/{normalized}/" or "/test/" in f"/{normalized}/" or name.startswith(
        "test_") or any(
            name.endswith(suffix)
            for suffix in ("_test.py", "_test.go", "_test.cc", "_test.cpp",
                           ".spec.ts", ".test.js"))


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    merged: dict[tuple[str, int, str, str], Finding] = {}
    for finding in findings:
        previous = merged.get(finding.dedup_key())
        if previous is None:
            merged[finding.dedup_key()] = finding
            continue
        previous.confidence = max(previous.confidence, finding.confidence)
        previous.source = sorted(set(previous.source + finding.source))
        previous.needs_human_review = previous.needs_human_review and finding.needs_human_review
    return sorted(merged.values(),
                  key=lambda value:
                  (value.file, value.line, value.category, value.title))
