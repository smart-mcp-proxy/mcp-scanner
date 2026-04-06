# Quickstart: MCP AI Security Scanner

## Prerequisites

- Python 3.12+
- Docker (for container builds)
- Claude OAuth token at `~/.claude/.credentials.json` (from Claude Code login)

## Development Setup

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Run scanner locally
uv run mcp-scanner scan --source-dir /path/to/mcp-server
uv run mcp-scanner scan --tools-file /path/to/tools.json
```

## Docker Build

```bash
docker build -t mcp-ai-scanner .

# Run with Claude OAuth token
docker run --rm \
  -v ~/.claude:/app/.claude:ro \
  -v /path/to/source:/scan/source:ro \
  -v /tmp/report:/scan/report \
  -e CLAUDE_CONFIG_DIR=/app/.claude \
  mcp-ai-scanner
```

## MCPProxy Integration

The scanner is registered in MCPProxy as `mcp-ai-scanner`. After installation:

```bash
mcpproxy security install mcp-ai-scanner
mcpproxy security scan <server-name>
mcpproxy security report <server-name>
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SCANNER_MODEL` | `claude-sonnet-4-6` | Claude model for analysis |
| `CLAUDE_CONFIG_DIR` | `~/.claude` | Path to Claude credentials |
| `SCANNER_TIMEOUT` | `300` | Max scan time in seconds |
| `SIGNATURES_URL` | (built-in) | URL for online signature updates |
| `SCANNER_MODULES` | `tool_descriptions,source_code` | Modules to run |
