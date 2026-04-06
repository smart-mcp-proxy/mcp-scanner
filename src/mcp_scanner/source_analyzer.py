"""AI-powered source code analysis for malicious patterns."""

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
    """Build SDK kwargs - local uses system CLI, Docker uses bundled with env."""
    import shutil
    kwargs: dict = {}
    system_claude = shutil.which("claude")
    if system_claude:
        kwargs["cli_path"] = system_claude
    else:
        kwargs["env"] = {"CLAUDE_CONFIG_DIR": config_dir}
    return kwargs

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".rb", ".php", ".sh", ".bash",
    ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
}

# Files to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    "site-packages", "dist-packages", ".next", ".nuxt",
}

# Max file size to read (100KB)
MAX_FILE_SIZE = 100_000

# Max files to scan
MAX_FILES = 1000

# Max total content for AI analysis (50KB)
MAX_AI_CONTENT = 50_000

SOURCE_ANALYSIS_PROMPT = """You are an MCP (Model Context Protocol) security code analyst. Analyze the following source code files from an MCP server for security threats.

Check for:
1. **Data Exfiltration**: Code that reads credentials/env vars and sends them to external services
2. **Backdoors/Reverse Shells**: Code that opens network connections for remote access
3. **Obfuscated Code**: Base64-encoded, hex-encoded, or otherwise obfuscated payloads
4. **Credential Harvesting**: Code that collects API keys, tokens, or passwords
5. **Command Injection**: Unsafe use of os.system, subprocess with shell=True, eval, exec
6. **Crypto Miners**: Cryptocurrency mining code
7. **Hidden Network Calls**: Undisclosed HTTP requests to external servers
8. **Environment Variable Leaks**: Reading sensitive env vars without legitimate purpose

Output your analysis as a JSON array of findings. Each finding must have:
- "rule_id": string (e.g., "AI-MC-001")
- "severity": "critical" | "high" | "medium" | "low" | "info"
- "threat_type": "malicious_code" | "tool_poisoning" | "prompt_injection" | "uncategorized"
- "threat_level": "dangerous" | "warning" | "info"
- "title": brief title
- "description": detailed explanation
- "location": "file_path:line_number" (approximate line if needed)
- "evidence": the EXACT code snippet that triggered this finding (quote verbatim, max 200 chars)

If all code is clean, return an empty array: []
IMPORTANT: Only output the JSON array. Avoid false positives - flag genuinely suspicious patterns only.

## Source Code Files

"""


def walk_source_dir(source_dir: str) -> list[tuple[str, str]]:
    """Walk source directory and return (relative_path, content) tuples."""
    files: list[tuple[str, str]] = []
    source_path = Path(source_dir)

    for root, dirs, filenames in os.walk(source_dir):
        # Filter out skip directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in filenames:
            if len(files) >= MAX_FILES:
                break

            filepath = Path(root) / filename
            ext = filepath.suffix.lower()

            if ext not in SCANNABLE_EXTENSIONS:
                continue

            # Skip large files
            try:
                size = filepath.stat().st_size
                if size > MAX_FILE_SIZE or size == 0:
                    continue
            except OSError:
                continue

            # Read file
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
        for sig in signatures:
            if sig.category not in ("malicious_code",):
                continue

            for pattern in sig.patterns:
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        # Find line number
                        line_num = content[:match.start()].count("\n") + 1

                        # Extract evidence with context
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
                        break  # One match per signature per file
                except re.error:
                    pass

    return findings


async def _ai_analyze_source(
    files: list[tuple[str, str]],
    model: str,
    config_dir: str,
) -> list[ScanFinding]:
    """Use Claude Agent SDK to analyze source code."""
    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

    # Build content for analysis (respect size limit)
    source_text = ""
    total_size = 0
    included_files = 0

    for rel_path, content in files:
        entry = f"\n### File: {rel_path}\n```\n{content}\n```\n"
        if total_size + len(entry) > MAX_AI_CONTENT:
            break
        source_text += entry
        total_size += len(entry)
        included_files += 1

    if not source_text:
        return []

    prompt = SOURCE_ANALYSIS_PROMPT + source_text
    logger.info("AI analyzing %d files (%.1f KB)", included_files, total_size / 1024)

    try:
        from claude_agent_sdk import AssistantMessage, TextBlock

        result_text = ""
        stream = query(
            prompt=prompt,
            options=ClaudeAgentOptions(
                model=model,
                max_turns=1,
                permission_mode="bypassPermissions",
                **_sdk_kwargs(config_dir),
            ),
        )

        async for message in stream:
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        result_text += block.text
            elif isinstance(message, ResultMessage):
                if message.result:
                    result_text += "\n" + message.result

        if not result_text:
            return []

        logger.debug("AI raw output (first 500): %s", result_text[:500])

        findings_data = _extract_json_array(result_text)
        if findings_data is None:
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

        return findings

    except Exception as e:
        logger.error("AI source analysis failed: %s", e)
        return []


def _extract_json_array(text: str) -> list[dict[str, Any]] | None:
    """Extract a JSON array from text."""
    text = text.strip()
    if text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

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
) -> tuple[list[ScanFinding], list[str], int]:
    """Analyze source code for security threats.

    Returns (findings, scanned_files, total_files).
    """
    files = walk_source_dir(source_dir)
    scanned_files = [f[0] for f in files]
    total_files = len(files)

    all_findings: list[ScanFinding] = []

    # Phase 1: Pattern scan
    pattern_findings = _pattern_scan_source(files, signatures)
    all_findings.extend(pattern_findings)
    logger.info("Pattern scan found %d issues in %d files", len(pattern_findings), total_files)

    # Phase 2: AI analysis
    if use_ai and config_dir and files:
        ai_findings = await _ai_analyze_source(files, model, config_dir)
        existing = {(f.location, f.rule_id) for f in pattern_findings}
        for af in ai_findings:
            if (af.location, af.rule_id) not in existing:
                all_findings.append(af)
        logger.info("AI analysis found %d additional source issues", len(ai_findings))

    return all_findings, scanned_files, total_files


def analyze_source_sync(
    source_dir: str,
    signatures: list[VulnerabilitySignature],
    model: str = "claude-sonnet-4-6",
    config_dir: str | None = None,
    use_ai: bool = True,
) -> tuple[list[ScanFinding], list[str], int]:
    """Synchronous wrapper for analyze_source."""
    return asyncio.run(
        analyze_source(source_dir, signatures, model, config_dir, use_ai)
    )
