"""Dependency-free unified-diff parser with stable new-file line numbers."""
from __future__ import annotations

import re
from .models import AddedLine, ChangedFile, Hunk

_HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?P<header>.*)$")


class DiffParseError(ValueError):
    pass


def _normalize_path(raw: str) -> str:
    value = raw.strip().split("\t", 1)[0]
    if value.startswith(("a/", "b/")):
        return value[2:]
    return value


def parse_unified_diff(text: str) -> list[ChangedFile]:
    if not text.strip():
        raise DiffParseError("diff input is empty")
    files: list[ChangedFile] = []
    current_file: ChangedFile | None = None
    current_hunk: Hunk | None = None
    pending_old_path: str | None = None
    old_line = new_line = 0
    for raw_line in text.splitlines():
        if raw_line.startswith("--- "):
            pending_old_path = _normalize_path(raw_line[4:])
            current_hunk = None
            continue
        if raw_line.startswith("+++ "):
            if pending_old_path is None:
                raise DiffParseError("encountered +++ before ---")
            current_file = ChangedFile(pending_old_path,
                                       _normalize_path(raw_line[4:]))
            files.append(current_file)
            pending_old_path = None
            current_hunk = None
            continue
        match = _HUNK_RE.match(raw_line)
        if match:
            if current_file is None:
                raise DiffParseError("hunk encountered before file headers")
            current_hunk = Hunk(
                old_start=int(match.group(1)),
                old_count=int(match.group(2) or "1"),
                new_start=int(match.group(3)),
                new_count=int(match.group(4) or "1"),
                header=match.group("header").strip(),
            )
            current_file.hunks.append(current_hunk)
            old_line, new_line = current_hunk.old_start, current_hunk.new_start
            continue
        if current_hunk is None:
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_hunk.added_lines.append(
                AddedLine(current_file.path, new_line, raw_line[1:]))
            new_line += 1
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            old_line += 1
        elif raw_line.startswith(" "):
            old_line += 1
            new_line += 1
        elif raw_line == "\ No newline at end of file":
            continue
        else:
            raise DiffParseError(f"unsupported hunk line: {raw_line!r}")
    if not files:
        raise DiffParseError("no file changes found")
    return files
