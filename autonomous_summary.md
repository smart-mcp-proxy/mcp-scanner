# Autonomous Summary: MCP AI Security Scanner

**Date**: 2026-04-06  
**Repository**: https://github.com/smart-mcp-proxy/mcp-scanner  
**Branch**: `main`

## What Was Built

An AI-powered MCP security scanner that combines pattern-based detection with Claude Agent SDK for intelligent analysis of MCP server tool descriptions and source code.

## Architecture

```
src/mcp_scanner/
├── cli.py               # Click CLI (mcp-scanner scan ...)
├── entrypoint.py         # Docker/MCPProxy plugin entrypoint
├── scanner.py            # Orchestrator combining tool + source analysis
├── tool_analyzer.py      # AI + pattern analysis of tool descriptions
├── source_analyzer.py    # AI + pattern analysis of source code
├── mcp_client.py         # Load tool definitions from JSON
├── sarif.py              # SARIF 2.1.0 report generation
├── signatures.py         # Vulnerability signature DB management
├── models.py             # Pydantic data models (MCPProxy-compatible)
└── auth.py               # Claude OAuth token handling
```

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Python 3.12 | Agent SDK is Python-native |
| Auth | Claude OAuth via CLAUDE_CONFIG_DIR | Proven pattern from searcher project |
| Output | SARIF 2.1.0 | MCPProxy already parses SARIF |
| Detection | Pattern + AI hybrid | Patterns are fast; AI catches subtle threats |
| Signatures | Baseline (shipped) + online updates | Works offline, improves with updates |

## Test Results

**30 tests passing** covering:
- Data models, risk scoring, finding summarization
- SARIF generation with evidence fields
- Tool description analysis (malicious + clean fixtures)
- Source code analysis (malicious + clean fixtures)
- Signature loading and validation
- MCP client tool loading

## End-to-End Verification

| Test | Result | Details |
|------|--------|---------|
| Malicious tools scan | 6 findings, score 95/100 | Detected tool poisoning, exfiltration, credential harvesting, prompt injection, excessive permissions |
| Clean tools scan | 0 findings, score 0/100 | Zero false positives |
| Malicious source scan | 7 findings, score 90/100 | Detected reverse shells, obfuscated code, crypto miners |
| Clean source scan | 0 findings, score 0/100 | Zero false positives |
| Real MCP server tools (13 tools) | 0 findings, score 0/100 | No false positives on legitimate MCP servers |
| SARIF output validation | Valid | Correct SARIF 2.1.0 with evidence and threat classification |

## What's Working

- **Pattern-based scanning**: 10 baseline signatures covering tool poisoning, prompt injection, malicious code, credential harvesting, crypto miners
- **SARIF output**: Full SARIF 2.1.0 with evidence fields, threat_type/threat_level properties
- **CLI**: `mcp-scanner scan --tools-file / --source-dir` with configurable model, modules, timeout
- **MCPProxy integration**: Added to bundled scanner registry in mcpproxy-go
- **Docker**: Dockerfile following MCPProxy scanner plugin protocol
- **Tests**: 30 passing unit tests

## What Needs Manual Steps

1. **GitHub Actions workflow**: The file exists at `.github/workflows/build.yml` but couldn't be pushed (OAuth token lacks `workflow` scope). User needs to push it with a token that has workflow scope, or create it via GitHub web UI.
2. **AI analysis**: Requires Claude OAuth token (`~/.claude/.credentials.json`). Without it, scanner runs in pattern-only mode. Pattern-only mode works well but AI adds deeper contextual understanding.
3. **Docker image build**: Run `docker build -t ghcr.io/smart-mcp-proxy/mcp-scanner:latest .` locally or wait for CI/CD workflow to push automatically once workflow scope is fixed.

## MCPProxy Integration

Added `mcp-ai-scanner` to the bundled scanner registry in `/Users/user/repos/mcpproxy-go/internal/security/scanner/registry_bundled.go`. Once the Docker image is built and available, users can:

```bash
mcpproxy security install mcp-ai-scanner
mcpproxy security scan <server-name>
```

## Detection Categories

| Category | Signature IDs | What It Detects |
|----------|--------------|-----------------|
| Tool Poisoning | MCP-TP-001/002/003 | Hidden instructions, data exfiltration, credential harvesting in tool descriptions |
| Prompt Injection | MCP-PI-001/002 | Jailbreak patterns, tool name shadowing |
| Malicious Code | MCP-MC-001/002/003/004 | Obfuscated code, env exfiltration, reverse shells, crypto miners |
| Excessive Permissions | MCP-EP-001 | Tools requesting more access than needed |
