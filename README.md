# MCP AI Security Scanner

AI-powered security scanner for MCP (Model Context Protocol) servers using Claude Agent SDK.

## Features

- **Tool Description Analysis**: Intelligently analyzes MCP tool descriptions for tool poisoning, prompt injection, data exfiltration, and credential harvesting
- **Source Code Scanning**: Detects malicious patterns in MCP server source code (obfuscated code, backdoors, reverse shells, crypto miners)
- **SARIF Output**: Standard SARIF 2.1.0 format with detailed evidence for each finding
- **MCPProxy Integration**: Runs as a Docker-based scanner plugin for MCPProxy
- **Signature Updates**: Downloads and caches vulnerability signatures from online sources
- **AI + Pattern Matching**: Combines fast regex-based pattern scanning with Claude AI analysis for deeper understanding

## Quick Start

```bash
# Install
uv sync

# Scan tool definitions
mcp-scanner scan --tools-file /path/to/tools.json

# Scan source code
mcp-scanner scan --source-dir /path/to/mcp-server

# Docker (MCPProxy plugin)
docker run --rm \
  -v ~/.claude:/app/.claude:ro \
  -v /path/to/source:/scan/source:ro \
  -v /tmp/report:/scan/report \
  ghcr.io/smart-mcp-proxy/mcp-scanner:latest
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_MODEL` | `claude-sonnet-4-6` | Claude model for AI analysis |
| `CLAUDE_CONFIG_DIR` | `~/.claude` | Claude credentials directory |
| `SCANNER_TIMEOUT` | `300` | Max scan time (seconds) |
| `SCANNER_MODULES` | `tool_descriptions,source_code` | Modules to run |

## License

Apache-2.0
