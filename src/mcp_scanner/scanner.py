"""Main scanner orchestrator - combines tool and source analysis."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

from mcp_scanner.auth import ensure_writable_config
from mcp_scanner.mcp_client import load_tools_from_file
from mcp_scanner.models import (
    ScanConfig,
    ScanContext,
    ScanFinding,
    ScanReport,
    calculate_risk_score,
    summarize_findings,
)
from mcp_scanner.sarif import sarif_to_json
from mcp_scanner.signatures import get_signatures
from mcp_scanner.source_analyzer import analyze_source
from mcp_scanner.tool_analyzer import analyze_tools

logger = logging.getLogger(__name__)


async def run_scan(config: ScanConfig, quiet: bool = False) -> ScanReport:
    """Execute a full security scan based on configuration.

    Orchestrates tool description analysis, source code analysis,
    and produces a SARIF-compatible report.
    """
    all_findings: list[ScanFinding] = []
    scan_context = ScanContext()

    # Resolve Claude config for AI analysis
    config_dir = None
    use_ai = True
    try:
        config_dir = ensure_writable_config()
    except RuntimeError as e:
        logger.warning("Claude credentials not available, running pattern-only scan: %s", e)
        use_ai = False

    # Load signatures
    logger.info("Loading vulnerability signatures...")
    signatures = get_signatures(
        cache_dir=config.signatures_cache_dir,
        signatures_url=config.signatures_url,
        no_network=config.no_network,
    )
    logger.info("Loaded %d signatures", len(signatures))

    # Resolve server name: CLI/env > tools.json > empty
    server_name = config.server_name

    # Tool description analysis
    if "tool_descriptions" in config.modules:
        tools = []
        tools_file = config.tools_file

        # Auto-detect tools.json in source dir
        if not tools_file and config.source_dir:
            auto_path = os.path.join(config.source_dir, "tools.json")
            if os.path.exists(auto_path):
                tools_file = auto_path

        if tools_file:
            try:
                tools, file_server_name = load_tools_from_file(tools_file)
                if not server_name and file_server_name:
                    server_name = file_server_name
                scan_context.tools_exported = len(tools)
                scan_context.source_method = "tools_json"
            except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
                logger.error("Failed to load tools: %s", e)

        scan_context.server_name = server_name
        if server_name:
            logger.info("Server name: %s", server_name)

        if tools:
            logger.info("Analyzing %d tool definitions...", len(tools))
            tool_findings = await analyze_tools(
                tools=tools,
                signatures=signatures,
                model=config.model,
                config_dir=config_dir,
                use_ai=use_ai,
                quiet=quiet,
                server_name=server_name,
            )
            all_findings.extend(tool_findings)
            logger.info("Tool analysis complete: %d findings", len(tool_findings))

    # Source code analysis
    if "source_code" in config.modules and config.source_dir:
        if os.path.isdir(config.source_dir):
            logger.info("Scanning source directory: %s", config.source_dir)
            scan_context.source_path = config.source_dir
            if scan_context.source_method == "none":
                scan_context.source_method = "local_path"

            source_findings, scanned_files, total_files = await analyze_source(
                source_dir=config.source_dir,
                signatures=signatures,
                model=config.model,
                config_dir=config_dir,
                use_ai=use_ai,
                quiet=quiet,
                server_name=server_name,
            )
            all_findings.extend(source_findings)
            scan_context.scanned_files = scanned_files[:100]  # Cap for report size
            scan_context.total_files = total_files
            logger.info("Source analysis complete: %d findings in %d files", len(source_findings), total_files)
        else:
            logger.warning("Source directory not found: %s", config.source_dir)

    # Build report
    report = ScanReport(
        findings=all_findings,
        risk_score=calculate_risk_score(all_findings),
        summary=summarize_findings(all_findings),
        scanned_at=datetime.now(timezone.utc),
        scan_context=scan_context,
    )

    logger.info(
        "Scan complete: %d findings, risk score %d/100",
        len(all_findings),
        report.risk_score,
    )

    return report


def run_scan_sync(config: ScanConfig, quiet: bool = False) -> ScanReport:
    """Synchronous wrapper for run_scan."""
    return asyncio.run(run_scan(config, quiet=quiet))


def write_sarif_report(report: ScanReport, output_path: str) -> None:
    """Write SARIF report to file."""
    sarif_json = sarif_to_json(report)
    with open(output_path, "w") as f:
        f.write(sarif_json)
    logger.info("SARIF report written to %s", output_path)
