"""Configurable pre-execution safety policy and tRPC Filter adapter."""
from __future__ import annotations

import os
import re
import shlex
import time
from urllib.parse import urlparse

from .config import SafetyPolicy
from .models import FilterDecision, FilterEvent, ToolExecutionRequest
from .redaction import redact_text

_URL_RE = re.compile(r"https?://[^\s\"']+", re.I)
_DANGEROUS_SHELL = re.compile(
    r"(?:^|\s)(?:rm\s+-rf|mkfs|dd\s+if=|: *\(\) *\{|chmod\s+-R\s+777|chown\s+-R)(?:\s|$)",
    re.I)
_SHELL_META = re.compile(r"(?:\|\||&&|[|;<>`])")
_INSTALL_RE = re.compile(
    r"\b(?:pip|pip3|npm|yarn|apt|apt-get|yum|dnf)\s+(?:install|add)\b", re.I)
_SCRIPT_DANGER = re.compile(
    r"(?:shutil\.rmtree|os\.remove|os\.unlink|subprocess\.|"
    r"os\.system|fork\s*\(|while\s+True|time\.sleep\s*\(\s*[3-9]\d{2,})", re.I)
_SCRIPT_CREDENTIAL_READ = re.compile(
    r"(?:\.ssh|\.env|credentials|private[_-]?key|os\.environ|getenv\s*\()",
    re.I)
_SCRIPT_NETWORK = re.compile(
    r"(?:requests\.|aiohttp\.|urllib\.|socket\.|httpx\.)", re.I)
_SCRIPT_EXFIL = re.compile(
    r"(?:print|logging\.\w+)\s*\([^\n]*(?:api[_-]?key|token|password|secret|os\.environ)",
    re.I)


def _event(request: ToolExecutionRequest, decision: FilterDecision, risk: str,
           rule: str, reason: str, evidence: str,
           started: float) -> FilterEvent:
    return FilterEvent(
        tool_name=request.tool_name,
        decision=decision,
        risk_level=risk,
        rule_id=rule,
        reason=reason,
        evidence=redact_text(evidence),
        elapsed_ms=(time.perf_counter() - started) * 1000,
    )


def evaluate_request(request: ToolExecutionRequest,
                     policy: SafetyPolicy) -> FilterEvent:
    started = time.perf_counter()
    command = request.command.strip()
    script = request.script_content or ""
    if not command:
        return _event(request, FilterDecision.DENY, "high", "empty-command",
                      "Empty command is not executable.", command, started)
    if request.timeout_seconds and request.timeout_seconds > policy.max_timeout_seconds:
        return _event(request, FilterDecision.DENY, "high", "timeout-budget",
                      "Requested timeout exceeds policy budget.",
                      str(request.timeout_seconds), started)
    if request.max_output_bytes and request.max_output_bytes > policy.max_output_bytes:
        return _event(request, FilterDecision.DENY, "high", "output-budget",
                      "Requested output limit exceeds policy budget.",
                      str(request.max_output_bytes), started)
    denied_env = sorted(set(request.env) - set(policy.environment_allowlist))
    if denied_env:
        return _event(request, FilterDecision.DENY, "high",
                      "environment-allowlist",
                      "Environment contains non-allowlisted keys.",
                      ",".join(denied_env), started)
    if _DANGEROUS_SHELL.search(command):
        return _event(request, FilterDecision.DENY, "critical",
                      "dangerous-shell",
                      "Dangerous destructive command was blocked.", command,
                      started)
    if script and _SCRIPT_DANGER.search(script):
        return _event(
            request, FilterDecision.DENY, "critical", "dangerous-script",
            "Script contains destructive, process-spawning, or resource-abuse behavior.",
            script[:240], started)
    if script and _SCRIPT_EXFIL.search(script):
        return _event(request, FilterDecision.DENY, "critical",
                      "secret-exfiltration",
                      "Script may emit sensitive information.", script[:240],
                      started)
    if script and _SCRIPT_CREDENTIAL_READ.search(script):
        return _event(request, FilterDecision.NEEDS_HUMAN_REVIEW, "high",
                      "credential-read",
                      "Script may access credentials or environment secrets.",
                      script[:240], started)
    if script and _SCRIPT_NETWORK.search(
            script) and not policy.allowed_network_domains:
        return _event(
            request, FilterDecision.NEEDS_HUMAN_REVIEW, "high",
            "script-network",
            "Script contains network APIs while no domains are allowlisted.",
            script[:240], started)
    try:
        args = shlex.split(command)
    except ValueError as exc:
        return _event(request, FilterDecision.DENY, "high", "shell-parse",
                      "Command cannot be parsed safely.", str(exc), started)
    executable = os.path.basename(args[0]) if args else ""
    if executable in set(policy.denied_commands):
        return _event(request, FilterDecision.DENY, "critical",
                      "denied-command", "Executable is denied by policy.",
                      executable, started)
    if policy.allowed_commands and executable not in set(
            policy.allowed_commands):
        return _event(request, FilterDecision.NEEDS_HUMAN_REVIEW, "medium",
                      "unlisted-command",
                      "Executable is not in the allowlist.", executable,
                      started)
    normalized = command.replace("~", "/home/sandbox")
    for forbidden in policy.forbidden_paths:
        target = forbidden.replace("~", "/home/sandbox")
        if target == "/":
            if re.search(r"(?:^|\s)/(?:\s|$)", normalized):
                return _event(request, FilterDecision.DENY, "critical",
                              "forbidden-path",
                              "Command references a forbidden path.", target,
                              started)
        elif target and target in normalized:
            return _event(request, FilterDecision.DENY, "critical",
                          "forbidden-path",
                          "Command references a forbidden path.", target,
                          started)
    urls = _URL_RE.findall(command)
    for raw in urls:
        host = (urlparse(raw).hostname or "").lower()
        if not any(host == allowed or host.endswith("." + allowed)
                   for allowed in policy.allowed_network_domains):
            return _event(request, FilterDecision.NEEDS_HUMAN_REVIEW, "high",
                          "network-domain",
                          "Network destination is not allowlisted.", host,
                          started)
    if _INSTALL_RE.search(command):
        return _event(
            request, FilterDecision.NEEDS_HUMAN_REVIEW, "medium",
            "dependency-install",
            "Dependency installation changes the execution environment.",
            command, started)
    if _SHELL_META.search(command):
        return _event(request, FilterDecision.NEEDS_HUMAN_REVIEW, "medium",
                      "shell-meta",
                      "Shell composition requires explicit review.", command,
                      started)
    return _event(request, FilterDecision.ALLOW, "low", "allow-policy",
                  "Request satisfies the configured policy.", executable,
                  started)


def build_trpc_tool_filter(policy: SafetyPolicy, audit_callback=None):
    """Build a tRPC BaseFilter without importing tRPC at module import time."""
    from trpc_agent_sdk.filter import BaseFilter, FilterResult

    class CodeReviewToolSafetyFilter(BaseFilter):

        def __init__(self):
            super().__init__()
            self.name = "code_review_tool_safety"

        async def _before(self, ctx, req, rsp: FilterResult):
            args = req if isinstance(req,
                                     dict) else getattr(req, "args", {}) or {}
            request = ToolExecutionRequest(
                tool_name=str(args.get("tool_name", "skill_run")),
                command=str(args.get("command", "")),
                cwd=str(args.get("cwd", "")),
                env=dict(args.get("env", {}) or {}),
                timeout_seconds=float(args.get("timeout", 0) or 0),
                max_output_bytes=policy.max_output_bytes,
                script_content=str(args.get("editor_text", "")),
            )
            event = evaluate_request(request, policy)
            if audit_callback:
                audit_callback(event)
            if event.decision != FilterDecision.ALLOW:
                rsp.error = PermissionError(
                    f"{event.decision.value}: {event.rule_id}: {event.reason}")
                rsp.is_continue = False

    return CodeReviewToolSafetyFilter()
