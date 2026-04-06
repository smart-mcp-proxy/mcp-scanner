"""Docker entrypoint for MCPProxy scanner plugin protocol.

When run as a Docker container by MCPProxy:
- Source files are at /scan/source (read-only)
- Tool definitions at /scan/source/tools.json (if exported by MCPProxy)
- SARIF output goes to /scan/report/results.sarif
- Claude config at /app/.claude or via CLAUDE_CONFIG_DIR env
"""

from __future__ import annotations

import logging
import os
import sys

from mcp_scanner.models import ScanConfig
from mcp_scanner.scanner import run_scan_sync, write_sarif_report

logger = logging.getLogger(__name__)


def main():
    """MCPProxy scanner plugin entrypoint."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    source_dir = os.environ.get("SCANNER_SOURCE_DIR", "/scan/source")
    report_dir = os.environ.get("SCANNER_REPORT_DIR", "/scan/report")
    server_name = os.environ.get("SCANNER_SERVER_NAME", "")
    model = os.environ.get("SCANNER_MODEL", "claude-sonnet-4-6")
    modules = os.environ.get("SCANNER_MODULES", "tool_descriptions,source_code")
    timeout = int(os.environ.get("SCANNER_TIMEOUT", "300"))

    # Check for tools.json
    tools_file = None
    tools_path = os.path.join(source_dir, "tools.json")
    if os.path.exists(tools_path):
        tools_file = tools_path

    # Ensure report directory exists
    os.makedirs(report_dir, exist_ok=True)
    output_path = os.path.join(report_dir, "results.sarif")

    logger.info("MCP AI Scanner starting")
    logger.info("Source: %s, Tools: %s, Server: %s, Model: %s", source_dir, tools_file or "none", server_name or "unknown", model)

    config = ScanConfig(
        source_dir=source_dir if os.path.isdir(source_dir) else None,
        tools_file=tools_file,
        server_name=server_name,
        model=model,
        modules=[m.strip() for m in modules.split(",")],
        timeout=timeout,
        signatures_cache_dir=os.environ.get("SCANNER_CACHE_DIR", "/root/.cache/mcp-scanner"),
        no_network=os.environ.get("SCANNER_NO_NETWORK", "").lower() in ("1", "true"),
    )

    try:
        report = run_scan_sync(config)
        write_sarif_report(report, output_path)

        logger.info(
            "Scan complete: %d findings, risk score %d/100, output: %s",
            report.summary.total,
            report.risk_score,
            output_path,
        )

        if report.summary.critical > 0 or report.summary.high > 0:
            sys.exit(1)
        sys.exit(0)

    except Exception as e:
        logger.error("Scanner failed: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
