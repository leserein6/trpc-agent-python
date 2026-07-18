"""Load review input from a diff, git working tree, file list, or fixture."""
from __future__ import annotations

import difflib
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReviewInput:
    text: str
    kind: str
    summary: str


def from_diff_file(path: str | Path, kind: str = "diff_file") -> ReviewInput:
    value = Path(path)
    return ReviewInput(value.read_text(encoding="utf-8"), kind, str(value))


def from_repo(repo_path: str | Path) -> ReviewInput:
    root = Path(repo_path).resolve()
    if not (root / ".git").exists():
        raise ValueError(f"not a git repository: {root}")
    command = [
        "git", "-C",
        str(root), "diff", "--no-ext-diff", "--unified=3", "HEAD", "--"
    ]
    result = subprocess.run(command,
                            capture_output=True,
                            text=True,
                            timeout=20,
                            check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git diff failed")
    text = result.stdout
    untracked = subprocess.run([
        "git", "-C", str(root), "ls-files", "--others", "--exclude-standard"
    ], capture_output=True, text=True, timeout=20, check=False)
    if untracked.returncode != 0:
        raise RuntimeError(untracked.stderr.strip() or "git ls-files failed")
    files = [line.strip() for line in untracked.stdout.splitlines() if line.strip()]
    if files:
        text += from_file_list(root, files).text
    if not text.strip():
        raise ValueError("repository has no working-tree, staged, or untracked changes")
    return ReviewInput(text, "repo_path", str(root))


def from_file_list(repo_path: str | Path, files: list[str]) -> ReviewInput:
    root = Path(repo_path).resolve()
    chunks: list[str] = []
    for item in files:
        path = (root / item).resolve()
        if root not in path.parents and path != root:
            raise ValueError(f"file escapes repository root: {item}")
        if not path.is_file():
            raise FileNotFoundError(path)
        lines = path.read_text(encoding="utf-8",
                               errors="replace").splitlines(keepends=True)
        chunks.extend(
            difflib.unified_diff([],
                                 lines,
                                 fromfile="/dev/null",
                                 tofile=f"b/{item}",
                                 n=3))
    text = "".join(chunks)
    if not text:
        raise ValueError("file list is empty")
    return ReviewInput(text, "file_list", f"{root}: {', '.join(files)}")
