# Research: MCP AI Security Scanner

## Decision: Python with Claude Agent SDK

**Decision**: Use Python 3.12 with `claude-agent-sdk` for AI-powered analysis.
**Rationale**: Agent SDK provides native Python support, Claude OAuth integration, and tool orchestration. All existing agents in the ecosystem (searcher) use this pattern.
**Alternatives considered**: Go (rejected: no Agent SDK), Node.js (rejected: less mature SDK support).

## Decision: Claude OAuth via CLAUDE_CONFIG_DIR

**Decision**: Mount `~/.claude` read-only, copy `.credentials.json` to writable tmpdir, set `CLAUDE_CONFIG_DIR`.
**Rationale**: Proven pattern from searcher project. Agent SDK requires writable config dir for session files, but source credentials should be read-only.
**Alternatives considered**: API key (rejected: user requirement explicitly forbids it).

## Decision: SARIF 2.1.0 Output Format

**Decision**: Output native SARIF 2.1.0 JSON with MCPProxy-compatible threat classification.
**Rationale**: MCPProxy already parses SARIF (see `internal/security/scanner/sarif.go`). SARIF is the industry standard for static analysis. Evidence field maps to SARIF message text + properties.
**Alternatives considered**: Custom JSON (rejected: MCPProxy already supports SARIF), Ramparts format (rejected: not standard).

## Decision: Two Analysis Modes

**Decision**: Tool description analysis (via MCP protocol or tools.json) + Source code analysis (via mounted source directory).
**Rationale**: MCPProxy provides both `tools.json` export and source directory to scanners. Tool descriptions catch MCP-specific attacks; source code catches traditional malicious patterns.
**Alternatives considered**: Tool-only (rejected: misses source-level threats), Source-only (rejected: misses tool poisoning).

## Decision: Click CLI Framework

**Decision**: Use Click for CLI interface with environment variable support.
**Rationale**: Click is the standard Python CLI framework, supports env vars natively, and is well-tested. Matches the simplicity principle.
**Alternatives considered**: argparse (too basic), typer (extra dependency for no gain).

## Decision: Baseline + Online Signatures

**Decision**: Ship baseline detection patterns in the Docker image; optionally download updated signatures from GitHub release assets.
**Rationale**: Offline operation is required. Online updates provide fresher detection. GitHub releases are free hosting for JSON files.
**Alternatives considered**: External signature server (overengineered), Git clone (too heavy for a JSON file).

## MCP Vulnerability Research Summary

Key MCP attack vectors the scanner must detect:

1. **Tool Poisoning (TPA)**: Hidden instructions in tool descriptions telling the AI to ignore safety, exfiltrate data, or call other tools
2. **Prompt Injection**: Tool descriptions or responses that override the agent's system prompt
3. **Tool Name Shadowing**: Tools named to impersonate trusted tools (e.g., "read_file" vs "readfile")
4. **Rug Pull**: Tool definitions that change after initial approval
5. **Data Exfiltration**: Tools requesting environment variables, credentials, file system access beyond their stated purpose
6. **Credential Harvesting**: Tools that ask for or access authentication tokens
7. **Command Injection**: Tool parameters that allow shell command execution
8. **Excessive Permissions**: Tools requesting broader access than needed for their function
