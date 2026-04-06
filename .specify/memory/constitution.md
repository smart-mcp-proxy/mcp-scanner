# MCP Scanner Constitution

## Core Principles

### I. Scanner-as-Container
Every scanner capability is packaged as a Docker container following MCPProxy's scanner plugin protocol. Source mounted at `/scan/source:ro`, reports written to `/scan/report/results.sarif`.

### II. AI-First Analysis
Use Claude Agent SDK for intelligent analysis that goes beyond pattern matching. The AI agent reasons about tool descriptions and code intent, not just regex patterns.

### III. Test-First (NON-NEGOTIABLE)
TDD mandatory: Tests written first, verified to fail, then implementation makes them pass. Red-Green-Refactor cycle strictly enforced.

### IV. SARIF Output Standard
All findings output in SARIF 2.1.0 format with evidence fields. Compatible with MCPProxy's existing report aggregation system.

### V. Simplicity
Start simple, YAGNI principles. Single Python package, no unnecessary abstractions. CLI tool with clear arguments.

## Security Requirements

- Never expose Claude OAuth tokens in logs or output
- Scanner runs with minimal privileges (no-new-privileges, read-only source mount)
- No secrets in Docker image layers

## Governance

Constitution supersedes all other practices. Amendments require documentation.

**Version**: 1.0.0 | **Ratified**: 2026-04-06 | **Last Amended**: 2026-04-06
