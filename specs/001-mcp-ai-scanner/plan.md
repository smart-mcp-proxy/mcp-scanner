# Implementation Plan: MCP AI Security Scanner

**Branch**: `001-mcp-ai-scanner` | **Date**: 2026-04-06 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/001-mcp-ai-scanner/spec.md`

## Summary

Build an AI-powered MCP security scanner that uses Claude Agent SDK to intelligently analyze MCP server tool descriptions and source code for security threats. Outputs SARIF 2.1.0 format, integrates with MCPProxy as a Docker-based scanner plugin, uses Claude OAuth tokens for authentication. Python CLI tool with Dockerfile and GitHub Actions CI/CD.

## Technical Context

**Language/Version**: Python 3.12  
**Primary Dependencies**: claude-agent-sdk, click (CLI), mcp (MCP protocol client), pydantic (data models)  
**Storage**: JSON files (vulnerability signatures cache)  
**Testing**: pytest, pytest-asyncio  
**Target Platform**: Linux server (Docker container), macOS (development)  
**Project Type**: CLI tool / Docker container  
**Performance Goals**: Scan 20 tools + 1000 source files in <5 minutes  
**Constraints**: <2Gi memory, works offline with cached signatures  
**Scale/Scope**: Single scanner, ~2000 LOC

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Status | Notes |
|------|--------|-------|
| Scanner-as-Container | PASS | Docker container with MCPProxy protocol |
| AI-First Analysis | PASS | Claude Agent SDK for intelligent analysis |
| Test-First | PASS | pytest with TDD workflow |
| SARIF Output | PASS | SARIF 2.1.0 with evidence fields |
| Simplicity | PASS | Single Python package, CLI with click |

## Project Structure

### Documentation (this feature)

```text
specs/001-mcp-ai-scanner/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
└── tasks.md             # Phase 2 output
```

### Source Code (repository root)

```text
src/
├── mcp_scanner/
│   ├── __init__.py
│   ├── cli.py               # Click CLI entry point
│   ├── scanner.py            # Main scanner orchestrator
│   ├── tool_analyzer.py      # AI-powered tool description analysis
│   ├── source_analyzer.py    # AI-powered source code analysis
│   ├── mcp_client.py         # MCP protocol client for tool retrieval
│   ├── sarif.py              # SARIF 2.1.0 report generation
│   ├── signatures.py         # Vulnerability signature DB management
│   ├── models.py             # Pydantic data models
│   └── auth.py               # Claude OAuth token handling
├── signatures/
│   └── baseline.json         # Built-in baseline detection rules
└── pyproject.toml

tests/
├── conftest.py
├── test_cli.py
├── test_scanner.py
├── test_tool_analyzer.py
├── test_source_analyzer.py
├── test_mcp_client.py
├── test_sarif.py
├── test_signatures.py
└── fixtures/
    ├── malicious_tools.json     # Test fixtures: malicious tool definitions
    ├── clean_tools.json         # Test fixtures: clean tool definitions
    ├── malicious_source/        # Test fixtures: malicious source files
    └── clean_source/            # Test fixtures: clean source files

Dockerfile
.github/workflows/build.yml
```

## Implementation Phases

### Phase 1: Core Data Models and SARIF Output (~1 hour)

1. **Setup project** - pyproject.toml with dependencies, src layout
2. **Data models** - Pydantic models: ScanFinding, ScanReport, ToolDefinition, ScanConfig
3. **SARIF generator** - Generate valid SARIF 2.1.0 from ScanFindings with evidence
4. **Tests** - Unit tests for models and SARIF output

### Phase 2: Tool Description Analyzer (~1.5 hours)

1. **Auth module** - Claude OAuth token handling (copy to writable tmpdir pattern)
2. **Tool analyzer** - Agent SDK-based analysis of tool descriptions
3. **Built-in signatures** - Baseline detection patterns JSON
4. **Tests** - Test with malicious/clean fixtures

### Phase 3: Source Code Analyzer (~1.5 hours)

1. **Source analyzer** - Agent SDK-based source code analysis
2. **File walker** - Walk source directory, filter binary files, respect size limits
3. **Tests** - Test with malicious/clean source fixtures

### Phase 4: MCP Client and Scanner Orchestrator (~1 hour)

1. **MCP client** - Connect to MCP server, retrieve tool definitions
2. **Scanner orchestrator** - Combine tool + source analysis, aggregate findings
3. **CLI** - Click CLI with model, timeout, modules flags
4. **Tests** - Integration tests

### Phase 5: Docker and MCPProxy Integration (~1 hour)

1. **Dockerfile** - Python 3.12-slim, uv, claude-agent-sdk
2. **Entrypoint** - MCPProxy scanner protocol (read /scan/source, write /scan/report)
3. **MCPProxy registry entry** - Add to mcpproxy-go bundled scanners
4. **Tests** - Docker build and run tests

### Phase 6: Vulnerability Signatures and Online DB (~45 min)

1. **Signature manager** - Download, cache, merge online + baseline signatures
2. **GitHub Actions** - Build and push to ghcr.io
3. **Tests** - Signature download and cache tests

### Phase 7: End-to-End Verification (~30 min)

1. **E2E test** - Run scanner on real MCP servers via mcpproxy
2. **MCPProxy integration test** - Verify scanner works as mcpproxy plugin
3. **Documentation** - autonomous_summary.md
