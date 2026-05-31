"""Scanning engine for MCP configs and agent instruction files."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .rules import (
    COMMAND_RULES,
    PACKAGE_RUNNERS,
    PROMPT_INJECTION_PATTERNS,
    PROMPT_INJECTION_RULE,
    RISKY_ENV_NAMES,
    RISKY_ENV_RULE,
    SECRET_PATTERNS,
    SECRET_RULE,
    SEVERITY_ORDER,
    SHELL_FLAGS,
    SHELL_LAUNCHERS,
    looks_pinned_package,
)

DEFAULT_FILENAMES = {
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    "claude-desktop-config.json",
    "AGENTS.md",
    "CLAUDE.md",
    ".cursorrules",
}

DEFAULT_NESTED = {
    Path(".cursor/mcp.json"),
    Path(".vscode/mcp.json"),
}

TEXT_SUFFIXES = {".md", ".txt", ".rules"}
JSON_SUFFIXES = {".json"}


@dataclass(frozen=True)
class Finding:
    path: str
    location: str
    rule_id: str
    severity: str
    message: str
    fix: str
    evidence: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def scan_paths(paths: Iterable[str | Path]) -> list[Finding]:
    findings: list[Finding] = []
    for raw_path in paths:
        path = Path(raw_path)
        candidates = list(_iter_candidates(path))
        if not candidates and path.exists():
            candidates = [path]
        for candidate in candidates:
            findings.extend(scan_file(candidate))
    return sorted(_dedupe(findings), key=lambda item: (-SEVERITY_ORDER[item.severity], item.path, item.location))


def scan_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="ignore")

    findings = _scan_text(path, text)
    if path.suffix.lower() in JSON_SUFFIXES or path.name.endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            findings.append(
                Finding(
                    str(path),
                    f"line {exc.lineno}",
                    "invalid-json",
                    "medium",
                    "File looks like JSON but could not be parsed.",
                    "Fix JSON syntax so agent hosts and scanners read the same configuration.",
                    exc.msg,
                )
            )
        else:
            findings.extend(_scan_json(path, data))
    return findings


def _iter_candidates(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
        return
    if not path.is_dir():
        return

    for name in DEFAULT_FILENAMES:
        candidate = path / name
        if candidate.is_file():
            yield candidate
    for nested in DEFAULT_NESTED:
        candidate = path / nested
        if candidate.is_file():
            yield candidate


def _scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append(_finding(path, f"line {line_number}", SECRET_RULE, _redact(match.group(0))))
                break
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"AGENTS.md", "CLAUDE.md", ".cursorrules"}:
            for pattern in PROMPT_INJECTION_PATTERNS:
                match = pattern.search(line)
                if match:
                    findings.append(_finding(path, f"line {line_number}", PROMPT_INJECTION_RULE, _clip(line)))
                    break
    return findings


def _scan_json(path: Path, data: Any) -> list[Finding]:
    findings: list[Finding] = []
    servers = _extract_servers(data)
    for server_name, server in servers:
        if not isinstance(server, dict):
            continue
        base = f"mcpServers.{server_name}"
        command = _as_str(server.get("command"))
        args = [_as_str(arg) for arg in server.get("args", []) if _as_str(arg)]
        if command:
            findings.extend(_scan_command(path, base, command, args))
        env = server.get("env")
        if isinstance(env, dict):
            for key, value in env.items():
                if str(key).upper() in RISKY_ENV_NAMES:
                    findings.append(_finding(path, f"{base}.env.{key}", RISKY_ENV_RULE, str(key)))
                if isinstance(value, str):
                    for pattern in SECRET_PATTERNS:
                        match = pattern.search(value)
                        if match:
                            findings.append(_finding(path, f"{base}.env.{key}", SECRET_RULE, _redact(match.group(0))))
                            break
    return findings


def _extract_servers(data: Any) -> list[tuple[str, Any]]:
    if isinstance(data, dict):
        if isinstance(data.get("mcpServers"), dict):
            return [(str(name), server) for name, server in data["mcpServers"].items()]
        if isinstance(data.get("servers"), dict):
            return [(str(name), server) for name, server in data["servers"].items()]
        if "command" in data:
            return [("default", data)]
    return []


def _scan_command(path: Path, base: str, command: str, args: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    command_lower = Path(command).name.lower()
    args_lower = [arg.lower() for arg in args]
    joined = " ".join([command, *args])
    joined_lower = joined.lower()

    if command_lower in SHELL_LAUNCHERS and any(arg in SHELL_FLAGS for arg in args_lower[:2]):
        findings.append(_finding(path, f"{base}.command", COMMAND_RULES["shell-launcher"], joined))

    remote_markers = ("curl ", "wget ", "irm ", "iwr ", "invoke-webrequest")
    shell_markers = (" | sh", " | bash", "iex ", "invoke-expression")
    if any(marker in joined_lower for marker in remote_markers) and any(marker in joined_lower for marker in shell_markers):
        findings.append(_finding(path, f"{base}.args", COMMAND_RULES["remote-shell-install"], joined))

    if command_lower in PACKAGE_RUNNERS:
        target = _first_package_target(command_lower, args)
        if target and not _looks_pinned_target(command_lower, target):
            findings.append(_finding(path, f"{base}.args[0]", COMMAND_RULES["unpinned-package-runner"], target))

    if command_lower == "docker" and any(arg in {"--privileged", "--net=host", "--network=host", "-v", "--volume"} for arg in args_lower):
        findings.append(_finding(path, f"{base}.args", COMMAND_RULES["docker-privileged"], joined))

    return findings


def _first_package_target(command: str, args: list[str]) -> str | None:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in {"--yes", "-y", "dlx", "run", "tool", "run"}:
            continue
        if arg in {"--package", "-p"}:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if command == "docker" and arg in {"run", "exec"}:
            continue
        return arg
    return None


def _looks_pinned_target(command: str, target: str) -> bool:
    if command == "docker":
        return "@sha256:" in target or (":" in target and not target.endswith(":latest"))
    return looks_pinned_package(target)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.path, finding.rule_id, finding.severity, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _finding(path: Path, location: str, rule: Any, evidence: str) -> Finding:
    return Finding(
        str(path),
        location,
        rule.rule_id,
        rule.severity,
        rule.message,
        rule.fix,
        _clip(evidence),
    )


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _clip(value: str, limit: int = 140) -> str:
    value = " ".join(value.strip().split())
    return value if len(value) <= limit else value[: limit - 1] + "..."


def _redact(value: str) -> str:
    value = _clip(value)
    if len(value) <= 10:
        return "[redacted]"
    return f"{value[:4]}...{value[-4:]}"
