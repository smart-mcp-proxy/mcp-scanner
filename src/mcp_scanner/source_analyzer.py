"""AI-powered source code analysis for malicious patterns.

Two-phase approach:
1. Pattern scan: Fast regex matching against vulnerability signatures
2. AI agent scan: Claude agent with file tools (Read, Grep, Glob) explores
   the codebase like a security specialist - discovers structure, traces
   data flows, and validates findings.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from mcp_scanner.models import (
    ScanFinding,
    Severity,
    ThreatLevel,
    ThreatType,
    VulnerabilitySignature,
)

logger = logging.getLogger(__name__)


def _sdk_kwargs(config_dir: str) -> dict:
    """Build ClaudeAgentOptions kwargs based on available auth method.

    Local: system claude CLI, no env override needed.
    Docker with API key: bundled CLI + ANTHROPIC_API_KEY in env.
    Docker with OAuth: bundled CLI + CLAUDE_CONFIG_DIR in env.
    """
    import shutil
    kwargs: dict = {}
    system_claude = shutil.which("claude")
    if system_claude:
        # Local: system CLI handles its own auth
        kwargs["cli_path"] = system_claude
    else:
        # Docker: bundled CLI needs env vars
        env = {"CLAUDE_CONFIG_DIR": config_dir}
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            env["ANTHROPIC_API_KEY"] = api_key
        kwargs["env"] = env
    return kwargs


# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".rb", ".php", ".sh", ".bash",
    ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
}

# Data/config extensions where escape sequences (\uXXXX, \xNN) are legitimate
# encoding rather than obfuscation. Signatures marked with skip_on_data_files
# (e.g. MCP-MC-001 "Obfuscated code pattern") are not run against these files
# to avoid false positives on serialized data emitted by JSON/YAML encoders.
DATA_EXTENSIONS = {
    ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini",
}

# Files to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    "site-packages", "dist-packages", ".next", ".nuxt",
}

MAX_FILE_SIZE = 100_000
MAX_FILES = 1000

# System prompt for the security auditor agent
SECURITY_AGENT_PROMPT = """You are an expert MCP (Model Context Protocol) security auditor. You have been given
access to an MCP server's source code directory. Your job is to find REAL security
threats — not speculate about theoretical risks.

## Critical Rules — Avoiding False Positives

1. **Judge code by the server's purpose.** You will be told the server name. A server called
   "mcp-server-filesystem" that reads/writes files is doing its job. A server called
   "mcp-server-calculator" that reads /etc/passwd is suspicious.
2. **Absence of code is NOT a finding.** If the source directory is empty or only contains
   config files, that means source code was not provided for this scan. Report [] — do NOT
   flag this as "suspicious", "supply chain risk", or "obfuscated."
3. **Standard patterns are NOT threats.** Reading env vars for configuration, using subprocess
   for the tool's stated purpose, making HTTP requests in a web-related tool — all normal.
4. **Only flag with CONCRETE evidence.** "Could potentially" and "might indicate" are not
   findings. You need actual malicious code, actual data exfiltration, actual hidden behavior.

## Your Approach

Work methodically through these phases:

### Phase 1: Discovery
1. Use Glob to find project manifests: package.json, pyproject.toml, go.mod, Cargo.toml, Gemfile
2. Read the manifest to understand: language, dependencies, entry point
3. If no source files exist, return [] immediately — source was not provided
4. Use Glob to map the project structure and identify the MCP server entry point

### Phase 2: Dependency Analysis
1. Check dependencies for known suspicious packages
2. Look for vendored/inline code that bypasses package managers
3. Check for dynamic imports or runtime package installation (pip install, npm install at runtime)

### Phase 3: Tool Handler Audit (CRITICAL)
1. Find all registered MCP tools (grep for server.tool, @mcp.tool, tool decorators, etc.)
2. For EACH tool handler:
   - Read the full implementation
   - Trace ALL inputs: where do tool parameters go?
   - Check for: command injection, path traversal, SSRF, SQL injection
   - Check for: credential access, network calls, file system access
3. Compare tool descriptions with actual behavior — flag only CLEAR mismatches
   (description says "calculator" but code reads files is a real mismatch)

### Phase 4: Suspicious Pattern Hunt
1. Grep for dangerous patterns but ALWAYS trace the data flow before flagging
2. Look for: data exfiltration to hardcoded URLs, credential theft, crypto mining,
   backdoors, hidden network connections unrelated to the tool's purpose
3. For each potential finding, ask: "Is this consistent with the server's purpose?"
   If yes, it's not a finding.

### Phase 5: Data Flow Tracing
For any suspicious patterns, trace the complete flow before flagging:
- Where does data originate? Where does it go?
- Is there sanitization/validation?
- Is this behavior consistent with the server's stated purpose?

## Output Format

After your analysis, output ONLY a JSON array of findings:
```json
{
  "rule_id": "AI-XX-NNN",
  "severity": "critical|high|medium|low|info",
  "threat_type": "malicious_code|tool_poisoning|prompt_injection|supply_chain|uncategorized",
  "threat_level": "dangerous|warning|info",
  "title": "brief title",
  "description": "detailed explanation of the CONCRETE threat with data flow evidence",
  "location": "file_path:line_number",
  "evidence": "exact code snippet (max 300 chars)"
}
```

If the server is clean, return: []
Most legitimate servers ARE clean — returning [] is the expected result.

## Rules
- ONLY flag genuinely malicious patterns with concrete evidence.
- Every finding MUST include exact code evidence and file location.
- Trace data flows BEFORE flagging — context determines whether a pattern is malicious.
- Do NOT flag: missing source code, grammar issues, empty schemas, standard library usage,
  framework patterns, or behavior consistent with the server's purpose.
"""


def walk_source_dir(source_dir: str) -> list[tuple[str, str]]:
    """Walk source directory and return (relative_path, content) tuples."""
    files: list[tuple[str, str]] = []
    source_path = Path(source_dir)

    for root, dirs, filenames in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in filenames:
            if len(files) >= MAX_FILES:
                break

            filepath = Path(root) / filename
            ext = filepath.suffix.lower()

            if ext not in SCANNABLE_EXTENSIONS:
                continue

            try:
                size = filepath.stat().st_size
                if size > MAX_FILE_SIZE or size == 0:
                    continue
            except OSError:
                continue

            try:
                content = filepath.read_text(errors="replace")
                rel_path = str(filepath.relative_to(source_path))
                files.append((rel_path, content))
            except (OSError, UnicodeDecodeError):
                continue

    return files


def _pattern_scan_source(
    files: list[tuple[str, str]],
    signatures: list[VulnerabilitySignature],
) -> list[ScanFinding]:
    """Fast pattern-based scan of source files."""
    findings: list[ScanFinding] = []

    for rel_path, content in files:
        ext = Path(rel_path).suffix.lower()
        is_data_file = ext in DATA_EXTENSIONS
        for sig in signatures:
            if sig.category not in ("malicious_code",):
                continue

            # Skip signatures whose patterns overlap with legitimate
            # JSON/YAML/TOML escape encodings on data files (e.g. MCP-MC-001
            # matches "\\uXXXX" which is just JSON's encoding for non-ASCII
            # characters and not actual code obfuscation).
            if is_data_file and sig.skip_on_data_files:
                continue

            for pattern in sig.patterns:
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        line_num = content[:match.start()].count("\n") + 1
                        start = max(0, match.start() - 30)
                        end = min(len(content), match.end() + 30)
                        evidence = content[start:end].strip()
                        if len(evidence) > 200:
                            evidence = evidence[:200] + "..."

                        finding = ScanFinding(
                            rule_id=sig.id,
                            severity=Severity(sig.severity),
                            category=sig.category,
                            threat_type=ThreatType.MALICIOUS_CODE,
                            threat_level=ThreatLevel.DANGEROUS if sig.severity in ("critical", "high") else ThreatLevel.WARNING,
                            title=f"{sig.name} in {rel_path}",
                            description=sig.description,
                            location=f"{rel_path}:{line_num}",
                            evidence=evidence,
                        )
                        findings.append(finding)
                        break
                except re.error:
                    pass

    return findings


async def _ai_analyze_source(
    source_dir: str,
    model: str,
    config_dir: str,
    quiet: bool = False,
    server_name: str = "",
) -> list[ScanFinding]:
    """Use Claude Agent SDK with file tools to audit the source code.

    The agent gets Read, Grep, Glob tools and explores the codebase
    autonomously like a security specialist - discovering structure,
    tracing data flows, and validating findings.
    """
    from claude_agent_sdk import (
        AssistantMessage,
        ClaudeAgentOptions,
        ResultMessage,
        TextBlock,
        ThinkingBlock,
        ToolResultBlock,
        ToolUseBlock,
        query,
    )

    from mcp_scanner.progress import AgentProgress

    server_ctx = f"Server name: {server_name}\n" if server_name else ""
    prompt = (
        f"{server_ctx}"
        f"Audit the MCP server source code at: {source_dir}\n\n"
        "Follow the phased approach from your system prompt. "
        "Start by discovering the project structure. If no source code files exist, "
        "return [] immediately. Otherwise trace data flows through tool handlers. "
        "Output your findings as a JSON array at the end."
    )

    logger.info("AI agent auditing source at %s with model %s", source_dir, model)
    progress = AgentProgress(label="source-audit", quiet=quiet)
    progress.start()

    try:
        result_text = ""
        stream = query(
            prompt=prompt,
            options=ClaudeAgentOptions(
                system_prompt=SECURITY_AGENT_PROMPT,
                model=model,
                max_turns=30,
                permission_mode="bypassPermissions",
                allowed_tools=["Read", "Grep", "Glob"],
                cwd=source_dir,
                **_sdk_kwargs(config_dir),
            ),
        )

        try:
            async for message in stream:
                if isinstance(message, AssistantMessage):
                    progress.on_turn()
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            result_text += block.text
                            progress.on_text(block.text)
                        elif isinstance(block, ThinkingBlock):
                            progress.on_thinking(block.thinking)
                        elif isinstance(block, ToolUseBlock):
                            progress.on_tool_use(block.name, block.input)
                        elif isinstance(block, ToolResultBlock):
                            progress.on_tool_result(block.is_error)
                elif isinstance(message, ResultMessage):
                    if message.result:
                        result_text += "\n" + message.result
                    cost = message.total_cost_usd or 0
                    progress.on_complete(message.num_turns, cost)
                    logger.info(
                        "AI audit complete: %d turns, $%.4f",
                        message.num_turns, cost,
                    )
        finally:
            await stream.aclose()

        if not result_text:
            logger.warning("AI audit returned empty result")
            return []

        logger.debug("AI audit output (last 500): %s", result_text[-500:])

        # Extract the JSON findings from the agent's output
        # The agent may produce lots of text (its analysis) with JSON at the end
        findings_data = _extract_json_array(result_text)
        if findings_data is None:
            logger.warning("Could not extract JSON findings from AI audit output")
            return []

        findings = []
        for fd in findings_data:
            try:
                finding = ScanFinding(
                    rule_id=fd.get("rule_id", "AI-UNKNOWN"),
                    severity=Severity(fd.get("severity", "medium")),
                    category=fd.get("category", "security"),
                    threat_type=ThreatType(fd.get("threat_type", "malicious_code")),
                    threat_level=ThreatLevel(fd.get("threat_level", "info")),
                    title=fd.get("title", "AI-detected issue"),
                    description=fd.get("description", ""),
                    location=fd.get("location", ""),
                    evidence=fd.get("evidence", ""),
                )
                findings.append(finding)
            except (ValueError, KeyError) as e:
                logger.warning("Skipping malformed AI finding: %s", e)

        logger.info("AI audit produced %d findings", len(findings))
        return findings

    except Exception as e:
        logger.error("AI source audit failed: %s", e)
        return []


def _extract_json_array(text: str) -> list[dict[str, Any]] | None:
    """Extract the LAST JSON array from text (agent output has analysis before JSON)."""
    text = text.strip()

    # Find the last JSON array in the text
    last_start = -1
    i = len(text) - 1
    while i >= 0:
        if text[i] == "]":
            # Find matching opening bracket
            depth = 0
            for j in range(i, -1, -1):
                if text[j] == "]":
                    depth += 1
                elif text[j] == "[":
                    depth -= 1
                    if depth == 0:
                        last_start = j
                        break
            if last_start >= 0:
                try:
                    return json.loads(text[last_start : i + 1])
                except json.JSONDecodeError:
                    last_start = -1
                    i = i - 1
                    continue
            break
        i -= 1

    # Fallback: try from the beginning
    bracket_start = text.find("[")
    if bracket_start == -1:
        return None
    depth = 0
    for i in range(bracket_start, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[bracket_start : i + 1])
                except json.JSONDecodeError:
                    return None
    return None


async def analyze_source(
    source_dir: str,
    signatures: list[VulnerabilitySignature],
    model: str = "claude-sonnet-4-6",
    config_dir: str | None = None,
    use_ai: bool = True,
    quiet: bool = False,
    server_name: str = "",
) -> tuple[list[ScanFinding], list[str], int]:
    """Analyze source code for security threats.

    Returns (findings, scanned_files, total_files).
    """
    files = walk_source_dir(source_dir)
    scanned_files = [f[0] for f in files]
    total_files = len(files)

    all_findings: list[ScanFinding] = []

    # Phase 1: Fast pattern scan
    pattern_findings = _pattern_scan_source(files, signatures)
    all_findings.extend(pattern_findings)
    logger.info("Pattern scan found %d issues in %d files", len(pattern_findings), total_files)

    # Phase 2: AI agent audit (explores code with tools)
    if use_ai and config_dir:
        ai_findings = await _ai_analyze_source(source_dir, model, config_dir, quiet=quiet, server_name=server_name)
        existing = {(f.location, f.rule_id) for f in pattern_findings}
        for af in ai_findings:
            if (af.location, af.rule_id) not in existing:
                all_findings.append(af)
        logger.info("AI agent found %d additional source issues", len(ai_findings))

    return all_findings, scanned_files, total_files


def analyze_source_sync(
    source_dir: str,
    signatures: list[VulnerabilitySignature],
    model: str = "claude-sonnet-4-6",
    config_dir: str | None = None,
    use_ai: bool = True,
    quiet: bool = False,
    server_name: str = "",
) -> tuple[list[ScanFinding], list[str], int]:
    """Synchronous wrapper for analyze_source."""
    return asyncio.run(
        analyze_source(source_dir, signatures, model, config_dir, use_ai, quiet=quiet, server_name=server_name)
    )
