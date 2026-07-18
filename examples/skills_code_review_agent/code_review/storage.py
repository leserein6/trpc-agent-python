"""SQLite implementation behind a replaceable review-store interface."""
from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from .models import ReviewReport
from .redaction import redact_text, redact_value

_SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS review_tasks(
 task_id TEXT PRIMARY KEY, status TEXT NOT NULL, input_sha256 TEXT NOT NULL, input_kind TEXT NOT NULL,
 input_summary TEXT NOT NULL, changed_files_json TEXT NOT NULL, metrics_json TEXT NOT NULL,
 created_at TEXT NOT NULL, error TEXT);
CREATE TABLE IF NOT EXISTS findings(
 id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES review_tasks(task_id) ON DELETE CASCADE,
 severity TEXT NOT NULL, category TEXT NOT NULL, file TEXT NOT NULL, line INTEGER NOT NULL, title TEXT NOT NULL,
 evidence TEXT NOT NULL, recommendation TEXT NOT NULL, confidence REAL NOT NULL, source_json TEXT NOT NULL,
 needs_human_review INTEGER NOT NULL, UNIQUE(task_id,file,line,category,title));
CREATE TABLE IF NOT EXISTS sandbox_runs(
 id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES review_tasks(task_id) ON DELETE CASCADE,
 backend TEXT NOT NULL, command TEXT NOT NULL, status TEXT NOT NULL, elapsed_ms REAL NOT NULL, exit_code INTEGER,
 stdout TEXT NOT NULL, stderr TEXT NOT NULL, timed_out INTEGER NOT NULL, truncated INTEGER NOT NULL,
 error_type TEXT NOT NULL, output_files_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS filter_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES review_tasks(task_id) ON DELETE CASCADE,
 tool_name TEXT NOT NULL, decision TEXT NOT NULL, risk_level TEXT NOT NULL, rule_id TEXT NOT NULL,
 reason TEXT NOT NULL, evidence TEXT NOT NULL, elapsed_ms REAL NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports(task_id TEXT PRIMARY KEY REFERENCES review_tasks(task_id) ON DELETE CASCADE,
 report_json TEXT NOT NULL);
"""


class ReviewStore(ABC):

    @abstractmethod
    def save(self, report: ReviewReport) -> None:
        ...

    @abstractmethod
    def load_report(self, task_id: str) -> dict:
        ...


class SQLiteReviewStore(ReviewStore):

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def save(self, report: ReviewReport) -> None:
        payload = redact_value(report.to_dict())
        with self._connect() as c:
            c.execute(
                "INSERT OR REPLACE INTO review_tasks VALUES(?,?,?,?,?,?,?,?,?)",
                (report.task_id, report.status.value, report.input_sha256,
                 report.input_kind, redact_text(report.input_summary),
                 json.dumps(report.changed_files, ensure_ascii=False),
                 json.dumps(
                     payload["metrics"], ensure_ascii=False, sort_keys=True),
                 report.created_at, redact_text(report.error or "") or None))
            c.execute("DELETE FROM findings WHERE task_id=?",
                      (report.task_id, ))
            for f in report.findings + report.warnings:
                c.execute(
                    """INSERT INTO findings(task_id,severity,category,file,line,title,evidence,recommendation,
                    confidence,source_json,needs_human_review) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (report.task_id, f.severity.value, f.category, f.file,
                     f.line, f.title, redact_text(f.evidence),
                     redact_text(f.recommendation), f.confidence,
                     json.dumps(f.source), int(f.needs_human_review)))
            c.execute("DELETE FROM sandbox_runs WHERE task_id=?",
                      (report.task_id, ))
            for r in report.sandbox_runs:
                c.execute(
                    """INSERT INTO sandbox_runs(task_id,backend,command,status,elapsed_ms,exit_code,stdout,stderr,
                    timed_out,truncated,error_type,output_files_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (report.task_id, r.backend, redact_text(r.command),
                     r.status, r.elapsed_ms, r.exit_code, redact_text(
                         r.stdout), redact_text(r.stderr), int(r.timed_out),
                     int(r.truncated), r.error_type, json.dumps(
                         r.output_files)))
            c.execute("DELETE FROM filter_events WHERE task_id=?",
                      (report.task_id, ))
            for e in report.filter_events:
                c.execute(
                    """INSERT INTO filter_events(task_id,tool_name,decision,risk_level,rule_id,reason,evidence,
                    elapsed_ms,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (report.task_id, e.tool_name, e.decision.value,
                     e.risk_level, e.rule_id, redact_text(e.reason),
                     redact_text(e.evidence), e.elapsed_ms, e.created_at))
            c.execute(
                "INSERT OR REPLACE INTO reports VALUES(?,?)",
                (report.task_id,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True)))

    def load_report(self, task_id: str) -> dict:
        with self._connect() as c:
            row = c.execute("SELECT report_json FROM reports WHERE task_id=?",
                            (task_id, )).fetchone()
        if row is None:
            raise KeyError(task_id)
        return json.loads(row["report_json"])

    def task_status(self, task_id: str) -> dict:
        with self._connect() as c:
            row = c.execute("SELECT * FROM review_tasks WHERE task_id=?",
                            (task_id, )).fetchone()
        if row is None:
            raise KeyError(task_id)
        return dict(row)
