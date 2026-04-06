"""Vulnerability signature database management."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import httpx

from mcp_scanner.models import VulnerabilitySignature

logger = logging.getLogger(__name__)

# Default URL for online signature updates
DEFAULT_SIGNATURES_URL = "https://raw.githubusercontent.com/smart-mcp-proxy/mcp-scanner/main/src/signatures/baseline.json"

# Cache expiry: 24 hours
CACHE_EXPIRY_SECONDS = 86400


def load_baseline_signatures() -> list[VulnerabilitySignature]:
    """Load built-in baseline signatures shipped with the scanner."""
    baseline_path = Path(__file__).parent.parent / "signatures" / "baseline.json"
    if not baseline_path.exists():
        logger.warning("Baseline signatures not found at %s", baseline_path)
        return []

    with open(baseline_path) as f:
        data = json.load(f)

    return [VulnerabilitySignature(**sig) for sig in data]


def download_signatures(
    url: str,
    cache_dir: str,
    *,
    force: bool = False,
) -> list[VulnerabilitySignature]:
    """Download updated signatures from a URL, with caching.

    Returns the downloaded signatures, or empty list on failure.
    """
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, "signatures.json")
    meta_file = os.path.join(cache_dir, "signatures.meta.json")

    # Check cache freshness
    if not force and os.path.exists(cache_file) and os.path.exists(meta_file):
        try:
            with open(meta_file) as f:
                meta = json.load(f)
            age = time.time() - meta.get("downloaded_at", 0)
            if age < CACHE_EXPIRY_SECONDS:
                logger.info(
                    "Using cached signatures (age: %.1f hours)",
                    age / 3600,
                )
                with open(cache_file) as f:
                    data = json.load(f)
                return [VulnerabilitySignature(**sig) for sig in data]
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Cache read failed, re-downloading: %s", e)

    # Download
    try:
        logger.info("Downloading signatures from %s", url)
        response = httpx.get(url, timeout=30, follow_redirects=True)
        response.raise_for_status()
        data = response.json()

        # Save to cache
        with open(cache_file, "w") as f:
            json.dump(data, f)
        with open(meta_file, "w") as f:
            json.dump({"downloaded_at": time.time(), "url": url}, f)

        logger.info("Downloaded %d signatures", len(data))
        return [VulnerabilitySignature(**sig) for sig in data]

    except (httpx.HTTPError, json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to download signatures: %s", e)
        # Try stale cache as fallback
        if os.path.exists(cache_file):
            logger.info("Using stale cached signatures as fallback")
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                return [VulnerabilitySignature(**sig) for sig in data]
            except (json.JSONDecodeError, OSError):
                pass
        return []


def get_signatures(
    cache_dir: str,
    signatures_url: str | None = None,
    *,
    no_network: bool = False,
) -> list[VulnerabilitySignature]:
    """Get merged signatures: baseline + online updates.

    Online signatures override baseline signatures with the same ID.
    """
    baseline = load_baseline_signatures()
    baseline_map = {sig.id: sig for sig in baseline}

    if not no_network and signatures_url:
        online = download_signatures(signatures_url, cache_dir)
        for sig in online:
            baseline_map[sig.id] = sig

    return list(baseline_map.values())
