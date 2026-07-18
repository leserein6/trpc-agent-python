#!/usr/bin/env python3
"""CLI for diff-file, git-repository, file-list and fixture review."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from code_review import ReviewConfig, ReviewPipeline, SafetyPolicy
from code_review.input_loader import from_diff_file, from_file_list, from_repo

ROOT = Path(__file__).resolve().parent


def parse_args():
    parser = argparse.ArgumentParser(
        description="Secure, auditable code-review Agent pipeline")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--diff-file", type=Path)
    group.add_argument("--repo-path", type=Path)
    group.add_argument("--fixture", type=str)
    group.add_argument("--files-from",
                       type=Path,
                       help="newline-separated files; requires --files-repo")
    parser.add_argument("--files-repo", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("./out"))
    parser.add_argument("--db-path",
                        type=Path,
                        default=Path("./out/reviews.sqlite3"))
    parser.add_argument("--policy",
                        type=Path,
                        default=ROOT / "tool_safety_policy.yaml")
    parser.add_argument("--sandbox-mode",
                        choices=["container", "fake", "local"],
                        default=None)
    parser.add_argument(
        "--fake-model",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use API-key-free deterministic model path (default)")
    parser.add_argument("--no-checks", action="store_true")
    parser.add_argument("--tool-command", action="append", default=[])
    return parser.parse_args()


def main():
    args = parse_args()
    if args.diff_file:
        review_input = from_diff_file(args.diff_file)
    elif args.repo_path:
        review_input = from_repo(args.repo_path)
    elif args.fixture:
        review_input = from_diff_file(
            ROOT / "fixtures" / f"{args.fixture}.diff", "fixture")
    else:
        if not args.files_repo:
            raise SystemExit("--files-repo is required with --files-from")
        files = [
            line.strip() for line in args.files_from.read_text().splitlines()
            if line.strip()
        ]
        review_input = from_file_list(args.files_repo, files)
    if not args.fake_model:
        raise SystemExit("Use run_agent.py for the real tRPC model path")
    sandbox_mode = args.sandbox_mode or "fake"
    config = ReviewConfig(model_mode="fake",
                          sandbox_mode=sandbox_mode,
                          execute_checks=not args.no_checks)
    pipeline = ReviewPipeline(db_path=args.db_path,
                              output_dir=args.output_dir,
                              policy=SafetyPolicy.from_yaml(args.policy),
                              config=config)
    report = pipeline.run(review_input.text,
                          input_kind=review_input.kind,
                          input_summary=review_input.summary,
                          tool_commands=args.tool_command or None)
    print(json.dumps(report.to_dict()["summary"], indent=2))
    return 0 if report.status.value == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
