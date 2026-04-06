"""CLI interface for MCP AI Security Scanner."""

from __future__ import annotations

import json
import logging
import os
import sys

import click

from mcp_scanner.models import ScanConfig
from mcp_scanner.scanner import run_scan_sync, write_sarif_report
from mcp_scanner.sarif import sarif_to_json


@click.group()
@click.version_option()
def main():
    """MCP AI Security Scanner - Intelligent MCP server security analysis."""
    pass


@main.command()
@click.option("--source-dir", envvar="SCANNER_SOURCE_DIR", help="Path to MCP server source files")
@click.option("--tools-file", envvar="SCANNER_TOOLS_FILE", help="Path to tools.json file")
@click.option("--output", "-o", envvar="SCANNER_OUTPUT", help="Output SARIF file path (default: stdout)")
@click.option("--model", envvar="SCANNER_MODEL", default="claude-sonnet-4-6", help="Claude model for AI analysis")
@click.option("--modules", envvar="SCANNER_MODULES", default="tool_descriptions,source_code", help="Comma-separated modules to run")
@click.option("--timeout", envvar="SCANNER_TIMEOUT", default=300, type=int, help="Scan timeout in seconds")
@click.option("--signatures-url", envvar="SIGNATURES_URL", default=None, help="URL for online signature updates")
@click.option("--no-network", is_flag=True, help="Skip online signature updates")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging")
@click.option("--quiet", "-q", is_flag=True, help="Suppress agent progress output")
def scan(
    source_dir: str | None,
    tools_file: str | None,
    output: str | None,
    model: str,
    modules: str,
    timeout: int,
    signatures_url: str | None,
    no_network: bool,
    verbose: bool,
    quiet: bool,
):
    """Scan an MCP server for security threats."""
    # Setup logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if not source_dir and not tools_file:
        click.echo("Error: Provide --source-dir and/or --tools-file", err=True)
        sys.exit(2)

    config = ScanConfig(
        source_dir=source_dir,
        tools_file=tools_file,
        model=model,
        modules=[m.strip() for m in modules.split(",")],
        timeout=timeout,
        signatures_url=signatures_url,
        signatures_cache_dir=os.environ.get("SCANNER_CACHE_DIR", "/tmp/mcp-scanner-cache"),
        output_file=output,
        no_network=no_network,
    )

    report = run_scan_sync(config, quiet=quiet)

    # Output
    sarif_output = sarif_to_json(report)

    if output:
        write_sarif_report(report, output)
        click.echo(f"SARIF report written to {output}", err=True)
    else:
        click.echo(sarif_output)

    # Summary to stderr
    s = report.summary
    click.echo(
        f"\nScan complete: {s.total} findings "
        f"(critical={s.critical}, high={s.high}, medium={s.medium}, low={s.low}) "
        f"Risk score: {report.risk_score}/100",
        err=True,
    )

    # Exit code based on findings
    if s.critical > 0 or s.high > 0:
        sys.exit(1)
    sys.exit(0)


@main.command()
def version():
    """Show scanner version and configuration."""
    from mcp_scanner import __version__
    from mcp_scanner.auth import get_claude_config_dir

    config_dir = get_claude_config_dir()
    creds_exists = os.path.exists(os.path.join(config_dir, ".credentials.json"))

    click.echo(f"MCP AI Scanner v{__version__}")
    click.echo(f"Claude config: {config_dir}")
    click.echo(f"Credentials: {'found' if creds_exists else 'NOT FOUND'}")
    click.echo(f"Default model: {os.environ.get('SCANNER_MODEL', 'claude-sonnet-4-6')}")


if __name__ == "__main__":
    main()
