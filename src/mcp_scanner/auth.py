"""Claude OAuth token handling for Agent SDK."""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile

logger = logging.getLogger(__name__)


def get_claude_config_dir() -> str:
    """Return Claude config directory from env or default."""
    return os.environ.get("CLAUDE_CONFIG_DIR", os.path.expanduser("~/.claude"))


def ensure_writable_config() -> str:
    """Create a writable config dir with Claude credentials.

    The Agent SDK needs a writable config directory for session files,
    but we mount ~/.claude as read-only. This copies credentials to a
    writable tmpdir.

    Returns the path to the writable config directory.
    """
    src_dir = get_claude_config_dir()
    creds_path = os.path.join(src_dir, ".credentials.json")

    if not os.path.exists(creds_path):
        raise RuntimeError(
            f"No credentials found at {creds_path}. "
            "Set CLAUDE_CONFIG_DIR or ensure ~/.claude/.credentials.json exists. "
            "Run 'claude login' to authenticate."
        )

    # Validate credentials file
    try:
        with open(creds_path) as f:
            creds = json.load(f)
        if "claudeAiOauth" not in creds:
            raise RuntimeError(
                f"Credentials at {creds_path} missing claudeAiOauth section. "
                "Run 'claude login' to re-authenticate."
            )
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid credentials file at {creds_path}: {e}")

    # Check if source dir is writable
    test_file = os.path.join(src_dir, ".write_test")
    try:
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return src_dir
    except OSError:
        pass

    # Copy to writable temp dir
    tmp_dir = tempfile.mkdtemp(prefix="mcp_scanner_claude_")
    shutil.copy2(creds_path, os.path.join(tmp_dir, ".credentials.json"))

    settings_path = os.path.join(src_dir, "settings.json")
    if os.path.exists(settings_path):
        shutil.copy2(settings_path, os.path.join(tmp_dir, "settings.json"))

    logger.info("Created writable config dir at %s", tmp_dir)
    return tmp_dir
