"""JSON, Markdown and JSONL audit report generation."""
from __future__ import annotations

import json
from pathlib import Path
from .models import Finding, ReviewReport
from .redaction import redact_value


def write_reports(report: ReviewReport,
                  output_dir: str | Path) -> tuple[Path, Path, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    payload = redact_value(report.to_dict())
    json_path = directory / "review_report.json"
    md_path = directory / "review_report.md"
    audit_path = directory / "review_audit.jsonl"
    json_path.write_text(json.dumps(payload,
                                    ensure_ascii=False,
                                    indent=2,
                                    sort_keys=True),
                         encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    with audit_path.open("w", encoding="utf-8") as handle:
        for event in payload["filter_events"]:
            handle.write(
                json.dumps({
                    "type": "filter",
                    **event
                }, ensure_ascii=False) + "\n")
        for run in payload["sandbox_runs"]:
            handle.write(
                json.dumps({
                    "type": "sandbox",
                    **run
                }, ensure_ascii=False) + "\n")
    return json_path, md_path, audit_path


def render_markdown(report: ReviewReport) -> str:
    lines = [
        "# Code Review Report", "", f"- Task: `{report.task_id}`",
        f"- Status: `{report.status.value}`",
        f"- Input: `{report.input_kind}` — {report.input_summary}",
        f"- Changed files: {len(report.changed_files)}",
        f"- Confirmed findings: {len(report.findings)}",
        f"- Needs human review: {len(report.warnings)}", "",
        "## Finding Summary", ""
    ]
    for severity, count in report.severity_counts().items():
        lines.append(f"- {severity}: {count}")
    lines += ["", "## Confirmed Findings", ""]
    if not report.findings:
        lines.append("No high-confidence findings.")
    for value in report.findings:
        lines += _finding(value)
    lines += ["", "## Needs Human Review", ""]
    if not report.warnings:
        lines.append("No human-review items.")
    for value in report.warnings:
        lines += _finding(value)
    lines += ["", "## Filter Interceptions", ""]
    if not report.filter_events:
        lines.append("No tool execution was requested.")
    for event in report.filter_events:
        lines.append(
            f"- `{event.decision.value}` `{event.rule_id}` ({event.risk_level}): {event.reason}"
        )
    lines += ["", "## Sandbox Execution Summary", ""]
    if not report.sandbox_runs:
        lines.append("No sandbox run was executed.")
    for run in report.sandbox_runs:
        lines.append(
            f"- `{run.backend}` `{run.status}` exit={run.exit_code} timeout={run.timed_out} "
            f"duration={run.elapsed_ms:.2f}ms truncated={run.truncated}")
    lines += [
        "", "## Monitoring Metrics", "",
        f"- Total duration: {report.metrics.total_elapsed_ms:.2f} ms",
        f"- Sandbox duration: {report.metrics.sandbox_elapsed_ms:.2f} ms",
        f"- Tool calls: {report.metrics.tool_calls}",
        f"- Blocked calls: {report.metrics.blocked_calls}",
        f"- Exception distribution: `{json.dumps(report.metrics.exception_distribution, sort_keys=True)}`",
        ""
    ]
    return "\n".join(lines)


def _finding(value: Finding) -> list[str]:
    return [
        f"### [{value.severity.value.upper()}] {value.title}", "",
        f"- Location: `{value.file}:{value.line}`",
        f"- Category: `{value.category}`",
        f"- Confidence: `{value.confidence:.2f}`",
        f"- Source: `{', '.join(value.source)}`",
        f"- Evidence: `{value.evidence}`",
        f"- Recommendation: {value.recommendation}", ""
    ]
