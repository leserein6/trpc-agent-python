# Skills Code Review Agent

This example implements the complete Issue #92 prototype: tRPC Agent Skills, Container Workspace integration, configurable pre-execution Filter, deterministic and model review paths, SQLite persistence, OpenTelemetry spans, structured findings, redaction, deduplication, audit logs and JSON/Markdown reports.

## API-key-free regression

```bash
cd examples/skills_code_review_agent
python run_review.py --fixture secret --fake-model --sandbox-mode fake --output-dir out --db-path out/reviews.sqlite3
```

## Real Container path

Docker must be available. The production and real-agent path uses container isolation: network access is disabled, source/Skill mounts are read-only, and memory/CPU/process/output/time/environment limits are enforced. API-key-free regression defaults to the fake sandbox unless `--sandbox-mode container` is explicitly selected.

```bash
python run_review.py --diff-file change.diff --fake-model --sandbox-mode container
```

## tRPC Agent path

Set `TRPC_AGENT_MODEL_NAME`, `TRPC_AGENT_API_KEY`, and optionally `TRPC_AGENT_BASE_URL`, then run `python run_agent.py`. The agent loads the `code-review` Skill through a `SkillToolSet` backed by `create_container_workspace_runtime`; a tRPC `BaseFilter` blocks or escalates unsafe `skill_run` requests.

Inputs: `--diff-file`, `--repo-path`, `--fixture`, or `--files-from` + `--files-repo`. Outputs: `review_report.json`, `review_report.md`, `review_audit.jsonl`, and SQLite records queryable by task id.

Run `python evaluate_fixtures.py` to reproduce the public fixture precision/recall summary.

Local sandbox mode is an explicit development fallback only.

## Known boundaries

Binary patches and rename-only metadata are not analyzed. Container execution requires a reachable Docker daemon and the configured image. The fake path is for deterministic CI only and is not a security boundary.
