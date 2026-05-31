# mcp-safecheck

`mcp-safecheck` is a tiny, dependency-free CLI that audits Model Context Protocol
(MCP) server configs before you hand local files, tokens, or shell access to an
AI coding agent.

It looks for the mistakes that are easy to miss when copying config snippets:

- shell launchers such as `bash -c`, `sh -c`, `powershell -Command`, or `cmd /c`
- remote install or pipe-to-shell patterns
- hardcoded API keys, tokens, and private-key blocks
- dangerous MCP environment variables such as broad `GITHUB_TOKEN` or `AWS_SECRET_ACCESS_KEY`
- unpinned package launches with `npx`, `uvx`, `pipx`, and similar runners
- prompt-injection bait in local instruction files

The goal is not to replace a real security review. It is the fast preflight
check you run before adding a new MCP server to Claude Desktop, Cursor, VS Code,
Codex, or any other agent host.

## Install

From the repository:

```bash
python3 -m pip install -e .
```

Or run without installing:

```bash
python3 -m mcp_safecheck examples/risky.mcp.json
```

## Quick Start

Scan one file:

```bash
mcp-safecheck examples/risky.mcp.json
```

Scan a project folder:

```bash
mcp-safecheck .
```

Emit JSON for CI:

```bash
mcp-safecheck . --format json
```

Fail only on high severity findings:

```bash
mcp-safecheck . --fail-on high
```

## Example Output

```text
MCP Safecheck found 5 findings

[HIGH] shell-launcher
  examples/risky.mcp.json :: mcpServers.github.command
  Server starts through a shell launcher. Shell wrappers make injected arguments
  much harder to reason about.
  Fix: Use the real binary directly and pass each argument as a separate JSON item.

[MEDIUM] unpinned-package-runner
  examples/risky.mcp.json :: mcpServers.filesystem.args[0]
  Package runner target is not pinned to an exact version.
  Fix: Pin the package version, for example package@1.2.3.
```

## What It Scans

`mcp-safecheck` automatically looks for common MCP and agent config files:

- `.mcp.json`
- `mcp.json`
- `.cursor/mcp.json`
- `.vscode/mcp.json`
- `claude_desktop_config.json`
- `claude-desktop-config.json`
- `AGENTS.md`
- `CLAUDE.md`
- `.cursorrules`

You can also pass any JSON, Markdown, or text file explicitly.

## Exit Codes

- `0`: no finding at or above the selected `--fail-on` severity
- `1`: finding at or above the selected `--fail-on` severity
- `2`: invalid CLI usage

## Why This Can Get Stars

Agent tools are exploding, MCP configs are being copied around quickly, and
local agents often inherit powerful credentials. A small, memorable scanner that
catches obvious footguns is easy to understand, easy to share, and useful on day
one.

## Roadmap

- SARIF output for GitHub code scanning
- allowlist comments for known-safe internal servers
- per-host profiles for Claude Desktop, Cursor, VS Code, and Codex
- config auto-fixer for common shell-wrapper and unpinned-runner findings
- GitHub Action wrapper

## License

MIT
