"""End-to-end review orchestration."""
from __future__ import annotations

import hashlib
import time
import uuid
from pathlib import Path

from .config import ReviewConfig, SafetyPolicy
from .diff_parser import parse_unified_diff
from .filtering import evaluate_request
from .model_reviewer import FakeModelReviewer, ModelReviewer
from .models import FilterDecision, ReviewMetrics, ReviewReport, ReviewStatus, Severity, ToolExecutionRequest
from .reporting import write_reports
from .rules import deduplicate, scan_files
from .sandbox import DockerSandboxRunner, FakeSandboxRunner, LocalFallbackSandboxRunner, SandboxRunner
from .storage import ReviewStore, SQLiteReviewStore
from .telemetry import span


class ReviewPipeline:

    def __init__(self,
                 *,
                 db_path: str | Path,
                 output_dir: str | Path,
                 policy: SafetyPolicy | None = None,
                 config: ReviewConfig | None = None,
                 store: ReviewStore | None = None,
                 model_reviewer: ModelReviewer | None = None,
                 sandbox_runner: SandboxRunner | None = None,
                 skill_root: str | Path | None = None):
        self.policy = policy or SafetyPolicy()
        self.config = config or ReviewConfig()
        self.config.validate()
        self.store = store or SQLiteReviewStore(db_path)
        self.output_dir = Path(output_dir)
        self.model_reviewer = model_reviewer or FakeModelReviewer()
        self.skill_root = Path(
            skill_root
            or Path(__file__).resolve().parents[1] / "skills" / "code-review")
        self.sandbox_runner = sandbox_runner or self._build_sandbox()

    def _build_sandbox(self) -> SandboxRunner:
        if self.config.sandbox_mode == "fake":
            return FakeSandboxRunner()
        if self.config.sandbox_mode == "local":
            return LocalFallbackSandboxRunner(self.policy)
        return DockerSandboxRunner(self.policy)

    def run(self,
            diff_text: str,
            *,
            input_kind: str = "diff_file",
            input_summary: str = "inline diff",
            tool_commands: list[str] | None = None) -> ReviewReport:
        started = time.perf_counter()
        task_id = str(uuid.uuid4())
        metrics = ReviewMetrics()
        input_hash = hashlib.sha256(diff_text.encode()).hexdigest()
        filter_events, sandbox_runs = [], []
        try:
            with span("code_review.parse", task_id=task_id):
                phase = time.perf_counter()
                changed_files = parse_unified_diff(diff_text)
                metrics.parser_elapsed_ms = (time.perf_counter()
                                             - phase) * 1000
            with span("code_review.rules", task_id=task_id):
                static, metrics.rule_elapsed_ms = scan_files(changed_files)
            with span("code_review.model",
                      task_id=task_id,
                      mode=self.config.model_mode):
                model, metrics.model_elapsed_ms = self.model_reviewer.review(
                    changed_files)
            findings = deduplicate(static + model)
            commands = list(tool_commands
                            or (self.config.analyzer_commands
                                if self.config.execute_checks else []))
            for command in commands:
                request = ToolExecutionRequest(
                    "skill_run",
                    command,
                    timeout_seconds=self.policy.max_timeout_seconds,
                    max_output_bytes=self.policy.max_output_bytes)
                event = evaluate_request(request, self.policy)
                filter_events.append(event)
                metrics.tool_calls += 1
                if event.decision != FilterDecision.ALLOW:
                    metrics.blocked_calls += 1
                    continue
                with span("code_review.sandbox",
                          task_id=task_id,
                          command=command):
                    run = self.sandbox_runner.run(request,
                                                  input_diff=diff_text,
                                                  skill_root=self.skill_root)
                sandbox_runs.append(run)
                metrics.sandbox_elapsed_ms += run.elapsed_ms
                if run.error_type:
                    metrics.exception_distribution[
                        run.error_type] = metrics.exception_distribution.get(
                            run.error_type, 0) + 1
            accepted = [
                f for f in findings
                if f.confidence >= self.config.confidence_threshold
                and not f.needs_human_review
            ]
            warnings = [f for f in findings if f not in accepted]
            metrics.finding_count, metrics.warning_count = len(accepted), len(
                warnings)
            metrics.severity_distribution = {
                value.value: 0
                for value in Severity
            }
            for finding in accepted:
                metrics.severity_distribution[finding.severity.value] += 1
            metrics.total_elapsed_ms = (time.perf_counter() - started) * 1000
            report = ReviewReport(task_id, ReviewStatus.COMPLETED, input_hash,
                                  input_kind, input_summary,
                                  [value.path for value in changed_files],
                                  accepted, warnings, filter_events,
                                  sandbox_runs, metrics)
        except Exception as exc:
            metrics.exception_distribution[type(exc).__name__] = 1
            metrics.total_elapsed_ms = (time.perf_counter() - started) * 1000
            report = ReviewReport(task_id,
                                  ReviewStatus.FAILED,
                                  input_hash,
                                  input_kind,
                                  input_summary, [], [], [],
                                  filter_events,
                                  sandbox_runs,
                                  metrics,
                                  error=f"{type(exc).__name__}: {exc}")
        self.store.save(report)
        write_reports(report, self.output_dir)
        return report
