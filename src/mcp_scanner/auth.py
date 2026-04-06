"""Claude authentication for Agent SDK.

Supports three auth methods (in priority order):
1. ANTHROPIC_API_KEY env var - works everywhere (API billing)
2. System `claude` CLI - shares auth with Claude Code (local dev)
3. Mounted .credentials.json - OAuth tokens from K8s/Docker host
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile

logger = logging.getLogger(__name__)

# Known credential file names
CREDENTIAL_FILES = [
    ".credentials.json",  # Agent SDK / Docker deployments (K8s mounts)
    ".claude.json",       # Claude Code desktop app
]


def get_claude_config_dir() -> str:
    """Return Claude config directory from env or default."""
    return os.environ.get("CLAUDE_CONFIG_DIR", os.path.expanduser("~/.claude"))


def _find_credentials(config_dir: str) -> str | None:
    """Find the credentials file in the config directory."""
    for name in CREDENTIAL_FILES:
        path = os.path.join(config_dir, name)
        if os.path.exists(path):
            return path
    return None


def has_api_key() -> bool:
    """Check if ANTHROPIC_API_KEY is set."""
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def has_system_claude() -> bool:
    """Check if system claude CLI is available."""
    return shutil.which("claude") is not None


def ensure_writable_config() -> str:
    """Ensure a writable config dir with Claude credentials exists.

    Auth priority:
    1. ANTHROPIC_API_KEY env var - SDK uses it directly, no config dir needed
    2. System claude CLI - handles auth natively from ~/.claude
    3. Mounted .credentials.json - copy to writable tmpdir for bundled CLI

    Returns the path to the (writable) config directory.
    Raises RuntimeError if no auth method is available.
    """
    # If API key is set, the SDK handles auth directly
    if has_api_key():
        logger.info("Using ANTHROPIC_API_KEY for authentication")
        # Still need a writable config dir for SDK session files
        tmp_dir = tempfile.mkdtemp(prefix="mcp_scanner_claude_")
        return tmp_dir

    src_dir = get_claude_config_dir()
    creds_path = _find_credentials(src_dir)

    # System claude CLI handles its own auth (reads ~/.claude internally)
    if has_system_claude():
        if creds_path:
            logger.info("Found credentials at %s (system claude CLI will use natively)", creds_path)
        else:
            logger.info("System claude CLI found, will use its own auth")
        return src_dir

    # Docker/bundled CLI: need actual .credentials.json with OAuth tokens
    if not creds_path:
        raise RuntimeError(
            "No authentication available. Options:\n"
            "  1. Set ANTHROPIC_API_KEY environment variable\n"
            "  2. Install claude CLI and run 'claude login'\n"
            "  3. Mount ~/.claude with .credentials.json (Docker/K8s)"
        )

    # .claude.json from desktop app doesn't have raw tokens - bundled CLI can't use it
    if creds_path.endswith(".claude.json") and not has_system_claude():
        raise RuntimeError(
            f"Found {creds_path} but bundled CLI needs .credentials.json with OAuth tokens.\n"
            "Options:\n"
            "  1. Set ANTHROPIC_API_KEY environment variable\n"
            "  2. Mount .credentials.json from a host with 'claude login' (K8s pattern)"
        )

    logger.info("Found credentials at %s", creds_path)

    # Check if source dir is writable
    test_file = os.path.join(src_dir, ".write_test")
    try:
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return src_dir
    except OSError:
        pass

    # Read-only mount - copy to writable tmpdir
    tmp_dir = tempfile.mkdtemp(prefix="mcp_scanner_claude_")

    for name in CREDENTIAL_FILES:
        src = os.path.join(src_dir, name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(tmp_dir, name))

    for extra in ["settings.json", "settings.local.json"]:
        src = os.path.join(src_dir, extra)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(tmp_dir, extra))

    logger.info("Created writable config dir at %s", tmp_dir)
    return tmp_dir
