from __future__ import annotations
import sqlite3
import time
from pathlib import Path
import pytest
from code_review.config import ReviewConfig, SafetyPolicy
from code_review.diff_parser import DiffParseError, parse_unified_diff
from code_review.filtering import evaluate_request
from code_review.input_loader import from_file_list
from code_review.models import FilterDecision, Finding, Severity, ToolExecutionRequest
from code_review.pipeline import ReviewPipeline
from code_review.redaction import redact_text
from code_review.rules import deduplicate
from code_review.sandbox import FakeSandboxRunner, LocalFallbackSandboxRunner

ROOT = Path(
    __file__).resolve().parents[3] / "examples" / "skills_code_review_agent"


def pipeline(tmp_path, sandbox=None, policy=None):
    return ReviewPipeline(db_path=tmp_path / "review.db",
                          output_dir=tmp_path / "out",
                          policy=policy or SafetyPolicy(),
                          config=ReviewConfig(model_mode="fake",
                                              sandbox_mode="fake"),
                          sandbox_runner=sandbox or FakeSandboxRunner())


def fixture(name):
    return (ROOT / "fixtures" / f"{name}.diff").read_text()


def test_all_public_fixtures_run_and_generate_reports(tmp_path):
    for name in ("clean", "secret", "shell_injection", "async_leak",
                 "database_lifecycle", "resource_leak", "sql_injection",
                 "duplicate", "missing_tests", "sandbox_failure"):
        out = tmp_path / name
        report = ReviewPipeline(db_path=out / "review.db",
                                output_dir=out / "out",
                                config=ReviewConfig(model_mode="fake",
                                                    sandbox_mode="fake"),
                                sandbox_runner=FakeSandboxRunner()).run(
                                    fixture(name),
                                    input_kind="fixture",
                                    input_summary=name)
        assert report.status.value == "completed"
        assert (out / "out/review_report.json").exists() and (
            out / "out/review_report.md").exists()


def test_parser_tracks_line_numbers_and_rejects_empty():
    files = parse_unified_diff(
        "--- a/a.py\n+++ b/a.py\n@@ -10,1 +10,2 @@\n x\n+y\n")
    assert files[0].added_lines[0].line == 11
    with pytest.raises(DiffParseError):
        parse_unified_diff("")


def test_secret_is_detected_and_never_persisted(tmp_path):
    secret = "sk-super-secret-123456"
    report = pipeline(tmp_path).run(fixture("secret"))
    assert any(f.category == "sensitive_information" for f in report.findings)
    data = (tmp_path / "out/review_report.json").read_text()
    assert secret not in data
    with sqlite3.connect(tmp_path / "review.db") as c:
        assert secret not in " ".join(
            str(row) for row in c.execute("SELECT evidence FROM findings"))


def test_filter_deny_review_allow_and_budget():
    p = SafetyPolicy(allowed_network_domains=["example.com"])
    assert evaluate_request(ToolExecutionRequest("skill_run", "rm -rf /"),
                            p).decision == FilterDecision.DENY
    assert evaluate_request(
        ToolExecutionRequest("skill_run", "python https://evil.example/x"),
        p).decision == FilterDecision.NEEDS_HUMAN_REVIEW
    assert evaluate_request(
        ToolExecutionRequest("skill_run", "python scripts/analyze_diff.py"),
        p).decision == FilterDecision.ALLOW
    assert evaluate_request(
        ToolExecutionRequest("skill_run", "python x", timeout_seconds=999),
        p).rule_id == "timeout-budget"


def test_filter_scans_script_content():
    p = SafetyPolicy()
    dangerous = ToolExecutionRequest(
        "skill_run",
        "python script.py",
        script_content="import shutil; shutil.rmtree('/tmp/x')")
    exfil = ToolExecutionRequest("skill_run",
                                 "python script.py",
                                 script_content="print(os.environ['API_KEY'])")
    assert evaluate_request(dangerous, p).decision == FilterDecision.DENY
    assert evaluate_request(exfil, p).decision == FilterDecision.DENY


def test_denied_or_review_command_is_not_executed(tmp_path):
    sandbox = FakeSandboxRunner(stdout="should-not-run")
    report = pipeline(tmp_path, sandbox=sandbox).run(
        fixture("clean"), tool_commands=["rm -rf /", "curl https://evil.test"])
    assert len(report.filter_events) == 2 and not report.sandbox_runs


def test_sandbox_failure_and_timeout_do_not_crash_task(tmp_path):
    report = pipeline(tmp_path,
                      sandbox=FakeSandboxRunner(
                          exit_code=1,
                          stderr="failed")).run(fixture("clean"),
                                                tool_commands=["python x.py"])
    assert report.status.value == "completed" and report.sandbox_runs[
        0].status == "failed"
    report = pipeline(tmp_path / 't',
                      sandbox=FakeSandboxRunner(timed_out=True)).run(
                          fixture("clean"), tool_commands=["python x.py"])
    assert report.status.value == "completed" and report.sandbox_runs[
        0].timed_out


def test_output_is_truncated_and_secrets_redacted(tmp_path):
    local = LocalFallbackSandboxRunner(
        SafetyPolicy(max_output_bytes=32, max_timeout_seconds=15))
    req = ToolExecutionRequest(
        "skill_run",
        "python -c \"print('x'*100+' token=abcdefghijklmnop')\"",
        timeout_seconds=15,
        max_output_bytes=32)
    run = local.run(req,
                    input_diff=fixture("clean"),
                    skill_root=ROOT / "skills/code-review")
    assert run.truncated and "abcdefghijklmnop" not in run.stdout


def test_database_has_task_run_filter_finding_and_report(tmp_path):
    report = pipeline(tmp_path).run(
        fixture("secret"), tool_commands=["python scripts/analyze_diff.py"])
    with sqlite3.connect(tmp_path / "review.db") as c:
        for table in ("review_tasks", "findings", "sandbox_runs",
                      "filter_events", "reports"):
            assert c.execute(f"SELECT COUNT(*) FROM {table} WHERE task_id=?",
                             (report.task_id, )).fetchone()[0] >= 1


def test_dedup_merges_sources():
    a = Finding(Severity.HIGH, "security", "a.py", 1, "x", "e", "r", .8, ["a"])
    b = Finding(Severity.HIGH, "security", "a.py", 1, "x", "e", "r", .9, ["b"])
    result = deduplicate([a, b])
    assert len(
        result) == 1 and result[0].confidence == .9 and result[0].source == [
            "a", "b"
    ]


def test_low_confidence_is_human_review(tmp_path):
    report = pipeline(tmp_path).run(fixture("async_leak"))
    assert any(f.category == "async_lifecycle" for f in report.warnings)
    assert not any(f.category == "async_lifecycle" for f in report.findings)


def test_file_list_input(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("password='abcd1234'\n")
    value = from_file_list(repo, ["a.py"])
    assert value.kind == "file_list" and "+++ b/a.py" in value.text


def test_fake_full_flow_is_fast(tmp_path):
    started = time.perf_counter()
    pipeline(tmp_path).run(fixture("secret"))
    assert time.perf_counter() - started < 2


def test_redaction_common_shapes():
    value = ("token=abcdefghijk password=secret sk-abcdefghijklmnop "
             "ghp_123456789012345678901234567890123456 "
             "Bearer abcdefghijklmnop xoxb-1234567890-abcdef")
    redacted = redact_text(value)
    for item in ("abcdefghijk", "password=secret", "sk-abcdefghijklmnop",
                 "ghp_123456789012345678901234567890123456",
                 "abcdefghijklmnop", "xoxb-1234567890-abcdef"):
        assert item not in redacted


def test_repo_input_includes_staged_unstaged_and_untracked_once(tmp_path):
    import subprocess
    from code_review.input_loader import from_repo
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "tracked.py").write_text("value = 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "tracked.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
    (repo / "tracked.py").write_text("value = 2\n")
    subprocess.run(["git", "-C", str(repo), "add", "tracked.py"], check=True)
    (repo / "tracked.py").write_text("value = 3\n")
    (repo / "new.py").write_text("token = 'abcdefghijk'\n")
    value = from_repo(repo)
    assert value.text.count("+++ b/tracked.py") == 1
    assert value.text.count("+++ b/new.py") == 1


def test_payload_model_reviewer_rejects_unknown_files():
    from code_review.model_reviewer import PayloadModelReviewer
    files = parse_unified_diff(fixture("clean"))
    findings, _ = PayloadModelReviewer([
        {"severity": "high", "file": "missing.py", "line": 1, "title": "x"},
        {"severity": "high", "file": "app.py", "line": 2, "title": "valid", "confidence": .9},
    ]).review(files)
    assert len(findings) == 1 and findings[0].source == ["llm"]
