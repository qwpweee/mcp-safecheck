"""Command-line interface for mcp-safecheck."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .rules import SEVERITY_ORDER
from .scanner import Finding, scan_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-safecheck",
        description="Audit MCP server configs for risky commands, secrets, and prompt-injection bait.",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Files or directories to scan. Defaults to current directory.")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format. Defaults to text.",
    )
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        default="medium",
        help="Exit 1 when a finding at this severity or above is found. Defaults to medium.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="mcp-safecheck 0.1.0",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    missing = [path for path in args.paths if not Path(path).exists()]
    if missing:
        parser.error("path does not exist: " + ", ".join(missing))

    findings = scan_paths(args.paths)
    if args.format == "json":
        print(json.dumps([finding.to_dict() for finding in findings], indent=2))
    else:
        print(_format_text(findings))

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[finding.severity] >= threshold for finding in findings) else 0


def _format_text(findings: list[Finding]) -> str:
    if not findings:
        return "MCP Safecheck found no findings."

    lines = [f"MCP Safecheck found {len(findings)} finding{'s' if len(findings) != 1 else ''}", ""]
    for finding in findings:
        lines.extend(
            [
                f"[{finding.severity.upper()}] {finding.rule_id}",
                f"  {finding.path} :: {finding.location}",
                f"  {finding.message}",
                f"  Evidence: {finding.evidence}",
                f"  Fix: {finding.fix}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
