"""Rule definitions for MCP config and instruction scanning."""

from __future__ import annotations

import re
from dataclasses import dataclass


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    message: str
    fix: str


SHELL_LAUNCHERS = {
    "bash",
    "sh",
    "zsh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
}

SHELL_FLAGS = {
    "-c",
    "/c",
    "-command",
    "-encodedcommand",
    "-enc",
}

PACKAGE_RUNNERS = {
    "npx",
    "pnpm",
    "yarn",
    "bunx",
    "uvx",
    "pipx",
    "docker",
}

RISKY_ENV_NAMES = {
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_CLIENT_SECRET",
    "GITHUB_TOKEN",
    "GOOGLE_API_KEY",
    "OPENAI_API_KEY",
    "POSTGRES_PASSWORD",
    "SLACK_BOT_TOKEN",
    "SUPABASE_SERVICE_ROLE_KEY",
}

COMMAND_RULES = {
    "shell-launcher": Rule(
        "shell-launcher",
        "high",
        "Server starts through a shell launcher. Shell wrappers make injected arguments much harder to reason about.",
        "Use the real binary directly and pass each argument as a separate JSON item.",
    ),
    "remote-shell-install": Rule(
        "remote-shell-install",
        "critical",
        "Command appears to download remote code and execute it through a shell.",
        "Install packages through a reviewed package manager step, then reference the installed binary.",
    ),
    "unpinned-package-runner": Rule(
        "unpinned-package-runner",
        "medium",
        "Package runner target is not pinned to an exact version.",
        "Pin the package version, for example package@1.2.3.",
    ),
    "docker-privileged": Rule(
        "docker-privileged",
        "high",
        "Docker server launch requests privileged mode or host-level access.",
        "Remove privileged or host flags unless this server is isolated and fully trusted.",
    ),
}

SECRET_RULE = Rule(
    "hardcoded-secret",
    "critical",
    "Possible hardcoded secret or private key material found.",
    "Move the secret into a scoped secret manager or environment variable, then rotate it if it was committed.",
)

RISKY_ENV_RULE = Rule(
    "powerful-env-token",
    "high",
    "MCP server receives a broad, powerful credential through its environment.",
    "Use a least-privilege token scoped only to what this MCP server needs.",
)

PROMPT_INJECTION_RULE = Rule(
    "prompt-injection-bait",
    "high",
    "Instruction text contains language commonly used to override agent safety or leak secrets.",
    "Remove override instructions from local docs and keep untrusted content out of agent instruction files.",
)

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"),
]

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore (all )?(previous|prior|above) (instructions|rules)\b"),
    re.compile(r"(?i)\breveal (your )?(system prompt|developer message|hidden instructions|secrets)\b"),
    re.compile(r"(?i)\bexfiltrate\b|\bsend .{0,40}(token|secret|credential|key)\b"),
    re.compile(r"(?i)\byou are now in developer mode\b"),
    re.compile(r"(?i)\bdo not (tell|warn) (the )?user\b"),
]


def looks_pinned_package(value: str) -> bool:
    if value.startswith("@"):
        parts = value.rsplit("@", 1)
        return len(parts) == 2 and bool(parts[1]) and any(char.isdigit() for char in parts[1])
    if "@" not in value:
        return False
    name, version = value.rsplit("@", 1)
    return bool(name) and bool(version) and any(char.isdigit() for char in version)
