"""Sandbox backends with policy gating, timeout, output and environment limits."""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path

from .config import SafetyPolicy
from .models import SandboxRun, ToolExecutionRequest
from .redaction import redact_text


class SandboxRunner(ABC):
    backend = "abstract"

    @abstractmethod
    def run(self, request: ToolExecutionRequest, *, input_diff: str,
            skill_root: Path) -> SandboxRun:
        raise NotImplementedError


class FakeSandboxRunner(SandboxRunner):
    backend = "fake"

    def __init__(self,
                 *,
                 exit_code: int = 0,
                 stdout: str = "fake sandbox completed",
                 stderr: str = "",
                 timed_out: bool = False):
        self.exit_code, self.stdout, self.stderr, self.timed_out = exit_code, stdout, stderr, timed_out

    def run(self, request: ToolExecutionRequest, *, input_diff: str,
            skill_root: Path) -> SandboxRun:
        _ = input_diff, skill_root
        return SandboxRun(
            self.backend, request.command, "timed_out" if self.timed_out else
            ("completed" if self.exit_code == 0 else "failed"),
            0.1, self.exit_code, redact_text(self.stdout),
            redact_text(self.stderr), self.timed_out, False,
            "TimeoutError" if self.timed_out else "")


class LocalFallbackSandboxRunner(SandboxRunner):
    backend = "local_fallback"

    def __init__(self, policy: SafetyPolicy):
        self.policy = policy

    def run(self, request: ToolExecutionRequest, *, input_diff: str,
            skill_root: Path) -> SandboxRun:
        started = time.perf_counter()
        env = {
            key: value
            for key, value in request.env.items()
            if key in self.policy.environment_allowlist
        }
        with tempfile.TemporaryDirectory(prefix="trpc-review-") as temp:
            work = Path(temp)
            (work / "out").mkdir()
            (work / "change.diff").write_text(input_diff, encoding="utf-8")
            command = request.command.replace("$WORK_DIR/inputs/change.diff",
                                              str(work / "change.diff"))
            command = command.replace("scripts/",
                                      str(skill_root / "scripts") + "/")
            command = command.replace("/out/", str(work / "out") + "/")
            try:
                result = subprocess.run(shlex.split(command),
                                        cwd=skill_root,
                                        env={
                                            **os.environ,
                                            **env
                },
                    capture_output=True,
                    text=True,
                    timeout=min(
                                            request.timeout_seconds
                                            or self.policy.max_timeout_seconds,
                                            self.policy.max_timeout_seconds),
                    check=False)
                return _bounded_run(self.backend, request.command,
                                    result.returncode, result.stdout,
                                    result.stderr,
                                    (time.perf_counter() - started) * 1000,
                                    self.policy.max_output_bytes)
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout.decode() if isinstance(
                    exc.stdout, bytes) else (exc.stdout or "")
                stderr = exc.stderr.decode() if isinstance(
                    exc.stderr, bytes) else (exc.stderr or "")
                run = _bounded_run(self.backend, request.command, None, stdout,
                                   stderr,
                                   (time.perf_counter() - started) * 1000,
                                   self.policy.max_output_bytes)
                run.status, run.timed_out, run.error_type = "timed_out", True, "TimeoutExpired"
                return run


class DockerSandboxRunner(SandboxRunner):
    backend = "container"

    def __init__(self, policy: SafetyPolicy):
        self.policy = policy
        try:
            import docker
        except ImportError as exc:
            raise RuntimeError(
                "Docker sandbox requires the repository's docker dependency"
            ) from exc
        self._docker = docker
        self._client = docker.from_env()

    def run(self, request: ToolExecutionRequest, *, input_diff: str,
            skill_root: Path) -> SandboxRun:
        started = time.perf_counter()
        env = {
            key: value
            for key, value in request.env.items()
            if key in self.policy.environment_allowlist
        }
        with tempfile.TemporaryDirectory(
                prefix="trpc-review-input-"
        ) as input_dir, tempfile.TemporaryDirectory(
                prefix="trpc-review-out-") as out_dir:
            Path(input_dir, "change.diff").write_text(input_diff,
                                                      encoding="utf-8")
            command = request.command.replace("$WORK_DIR/inputs/change.diff",
                                              "/inputs/change.diff")
            container = None
            try:
                container = self._client.containers.run(
                    self.policy.container_image,
                    ["bash", "-lc", command],
                    detach=True,
                    network_disabled=True,
                    working_dir="/skills",
                    environment=env,
                    mem_limit=self.policy.memory_limit,
                    pids_limit=self.policy.pids_limit,
                    nano_cpus=self.policy.nano_cpus,
                    read_only=True,
                    volumes={
                        str(Path(input_dir).resolve()): {
                            "bind": "/inputs",
                            "mode": "ro"
                        },
                        str(skill_root.resolve()): {
                            "bind": "/skills",
                            "mode": "ro"
                        },
                        str(Path(out_dir).resolve()): {
                            "bind": "/out",
                            "mode": "rw"
                        }
                    },
                )
                try:
                    wait = container.wait(timeout=min(
                        request.timeout_seconds or self.policy.
                        max_timeout_seconds, self.policy.max_timeout_seconds))
                except Exception as exc:
                    container.kill()
                    stdout = container.logs(stdout=True, stderr=False).decode(
                        "utf-8", "replace")
                    stderr = container.logs(stdout=False, stderr=True).decode(
                        "utf-8", "replace")
                    run = _bounded_run(self.backend, request.command, None,
                                       stdout, stderr,
                                       (time.perf_counter() - started) * 1000,
                                       self.policy.max_output_bytes)
                    run.status, run.timed_out, run.error_type = "timed_out", True, type(
                        exc).__name__
                    return run
                code = int(wait.get("StatusCode", 1))
                stdout = container.logs(stdout=True, stderr=False).decode(
                    "utf-8", "replace")
                stderr = container.logs(stdout=False, stderr=True).decode(
                    "utf-8", "replace")
                run = _bounded_run(self.backend, request.command, code, stdout,
                                   stderr,
                                   (time.perf_counter() - started) * 1000,
                                   self.policy.max_output_bytes)
                run.output_files = [
                    str(p.relative_to(out_dir))
                    for p in Path(out_dir).rglob("*") if p.is_file()
                ]
                return run
            except Exception as exc:
                return SandboxRun(self.backend, request.command, "failed",
                                  (time.perf_counter() - started) * 1000, None,
                                  "", redact_text(str(exc)), False, False,
                                  type(exc).__name__)
            finally:
                if container is not None:
                    try:
                        container.remove(force=True)
                    except Exception:
                        pass


def _bounded_run(backend: str, command: str, exit_code: int | None,
                 stdout: str, stderr: str, elapsed_ms: float,
                 limit: int) -> SandboxRun:
    stdout, a = _truncate(redact_text(stdout), limit)
    stderr, b = _truncate(redact_text(stderr), limit)
    return SandboxRun(backend, command,
                      "completed" if exit_code == 0 else "failed", elapsed_ms,
                      exit_code, stdout, stderr, False, a or b)


def _truncate(value: str, limit: int) -> tuple[str, bool]:
    raw = value.encode("utf-8")
    if len(raw) <= limit:
        return value, False
    return raw[:limit].decode("utf-8", "ignore"), True
