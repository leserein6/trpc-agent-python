#!/usr/bin/env python3
from __future__ import annotations
import json
import tempfile
from pathlib import Path
from code_review.config import ReviewConfig
from code_review.pipeline import ReviewPipeline
from code_review.sandbox import FakeSandboxRunner

ROOT = Path(__file__).resolve().parent
expected = json.loads((ROOT / "fixtures/manifest.json").read_text())
tp = fp = fn = 0
with tempfile.TemporaryDirectory() as d:
    for name, categories in expected.items():
        p = Path(d) / name
        report = ReviewPipeline(db_path=p / "review.db",
                                output_dir=p / "out",
                                config=ReviewConfig(model_mode="fake",
                                                    sandbox_mode="fake"),
                                sandbox_runner=FakeSandboxRunner()).run(
                                    (ROOT / "fixtures"
                                     / f"{name}.diff").read_text(),
                                    input_kind="fixture",
                                    input_summary=name)
        actual = {f.category for f in report.findings + report.warnings}
        wanted = set(categories)
        tp += len(actual & wanted)
        fp += len(actual - wanted)
        fn += len(wanted - actual)
precision = tp / (tp + fp) if tp + fp else 1
recall = tp / (tp + fn) if tp + fn else 1
print(
    json.dumps(
        {
            "precision": precision,
            "recall": recall,
            "false_positive_rate": fp / max(1, tp + fp),
            "tp": tp,
            "fp": fp,
            "fn": fn
        },
        indent=2))
