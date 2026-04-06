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
    # Check for credentials: .credentials.json (Agent SDK) or .claude.json (Claude Code)
    creds_path = os.path.join(src_dir, ".credentials.json")
    claude_json_path = os.path.join(src_dir, ".claude.json")

    found_creds = None
    if os.path.exists(creds_path):
        found_creds = creds_path
    elif os.path.exists(claude_json_path):
        found_creds = claude_json_path
    else:
        raise RuntimeError(
            f"No credentials found at {creds_path} or {claude_json_path}. "
            "Set CLAUDE_CONFIG_DIR or ensure ~/.claude/.claude.json exists. "
            "Run 'claude login' to authenticate."
        )

    # Validate credentials file
    try:
        with open(found_creds) as f:
            creds = json.load(f)
        # .credentials.json uses claudeAiOauth, .claude.json uses oauthAccount
        if "claudeAiOauth" not in creds and "oauthAccount" not in creds:
            raise RuntimeError(
                f"Credentials at {found_creds} missing auth section. "
                "Run 'claude login' to re-authenticate."
            )
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid credentials file at {found_creds}: {e}")

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
    shutil.copy2(found_creds, os.path.join(tmp_dir, os.path.basename(found_creds)))

    # Copy additional config files the SDK may need
    for extra in (".credentials.json", ".claude.json", "settings.json"):
        extra_path = os.path.join(src_dir, extra)
        if os.path.exists(extra_path) and extra_path != found_creds:
            shutil.copy2(extra_path, os.path.join(tmp_dir, extra))

    logger.info("Created writable config dir at %s", tmp_dir)
    return tmp_dir
