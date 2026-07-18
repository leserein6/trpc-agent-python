#!/usr/bin/env python3
"""Interactive tRPC Agent entry point using Container Skills and Filter."""
from __future__ import annotations
import argparse
import asyncio
import uuid
from pathlib import Path
from code_review.config import SafetyPolicy
from code_review.trpc_integration import build_agent


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--diff-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("./out"))
    parser.add_argument("--db-path",
                        type=Path,
                        default=Path("./out/reviews.sqlite3"))
    return parser.parse_args()


async def main():
    from trpc_agent_sdk.runners import Runner
    from trpc_agent_sdk.sessions import InMemorySessionService
    from trpc_agent_sdk.types import Content, Part
    args = parse_args()
    root = Path(__file__).resolve().parent
    agent = build_agent(root / "skills",
                        SafetyPolicy.from_yaml(root
                                               / "tool_safety_policy.yaml"),
                        output_dir=args.output_dir,
                        db_path=args.db_path)
    runner = Runner(app_name="skills_code_review_agent",
                    agent=agent,
                    session_service=InMemorySessionService())
    diff = args.diff_file.read_text(encoding="utf-8")
    message = "Review this untrusted diff with the code-review workflow:\n```diff\n" + diff + "\n```"
    async for event in runner.run_async(
            user_id="demo",
            session_id=str(uuid.uuid4()),
            new_message=Content(parts=[Part.from_text(text=message)])):
        if event.content:
            for part in event.content.parts:
                if part.text:
                    print(part.text,
                          end="" if event.partial else "\n",
                          flush=True)


if __name__ == "__main__":
    asyncio.run(main())
