# Security Policy

`mcp-safecheck` is a defensive scanner. Please report security issues privately
instead of opening a public issue.

When reporting, include:

- the affected version or commit
- a minimal reproduction
- whether the issue causes missed findings, unsafe output, or code execution

This project does not intentionally execute MCP server commands during scans.
If you find a path where scanning a file can execute code, treat it as critical.
