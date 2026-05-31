# Contributing

Thanks for helping make MCP configs safer.

Good first contributions:

- add a real-world risky MCP config pattern as a fixture
- reduce false positives in an existing rule
- add host-specific docs for Claude Desktop, Cursor, VS Code, Codex, or other agent tools
- add a new output format such as SARIF

## Development

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Run the CLI locally:

```bash
PYTHONPATH=src python3 -m mcp_safecheck examples/risky.mcp.json
```

Rules should include:

- a clear severity
- a short explanation of why the pattern is risky
- a practical fix
- at least one test

Please avoid adding dependencies unless they unlock a meaningful capability.
