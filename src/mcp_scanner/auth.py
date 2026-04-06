"""Claude OAuth token handling for Agent SDK."""

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


def ensure_writable_config() -> str:
    """Ensure a writable config dir with Claude credentials exists.

    Two deployment scenarios:
    1. **Local (dev)**: ~/.claude/ is writable and has .claude.json from Claude Code.
       System `claude` CLI is available and handles auth natively.
    2. **Docker (mcpproxy)**: ~/.claude/ is mounted read-only with .credentials.json.
       Bundled SDK CLI is used. We copy credentials to a writable tmpdir.

    Returns the path to the (writable) config directory.
    """
    src_dir = get_claude_config_dir()
    creds_path = _find_credentials(src_dir)

    if not creds_path:
        raise RuntimeError(
            f"No credentials found in {src_dir}. "
            f"Looked for: {', '.join(CREDENTIAL_FILES)}. "
            "Run 'claude login' to authenticate."
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

    # Source is read-only (Docker mount) - copy to writable tmpdir
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
