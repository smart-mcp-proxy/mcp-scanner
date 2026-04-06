"""MCP protocol client for retrieving tool definitions."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from mcp_scanner.models import ToolDefinition

logger = logging.getLogger(__name__)


def load_tools_from_file(tools_file: str) -> list[ToolDefinition]:
    """Load tool definitions from a JSON file.

    Supports two formats:
    1. Array of tool objects: [{"name": "...", "description": "...", "inputSchema": {...}}]
    2. MCPProxy export format: {"tools": [{"name": "...", ...}]}
    """
    path = Path(tools_file)
    if not path.exists():
        raise FileNotFoundError(f"Tools file not found: {tools_file}")

    with open(path) as f:
        data = json.load(f)

    tools_list: list[dict] = []

    if isinstance(data, list):
        tools_list = data
    elif isinstance(data, dict):
        if "tools" in data:
            tools_list = data["tools"]
        else:
            # Single tool object
            tools_list = [data]
    else:
        raise ValueError(f"Unexpected tools file format: {type(data)}")

    tools: list[ToolDefinition] = []
    for td in tools_list:
        # Handle both "inputSchema" and "input_schema" field names
        input_schema = td.get("inputSchema", td.get("input_schema", {}))
        tools.append(ToolDefinition(
            name=td.get("name", "unknown"),
            description=td.get("description", ""),
            input_schema=input_schema,
        ))

    logger.info("Loaded %d tools from %s", len(tools), tools_file)
    return tools


def export_tools_json(tools: list[ToolDefinition], output_path: str) -> None:
    """Export tool definitions to a JSON file for scanners."""
    data = [
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.input_schema,
        }
        for t in tools
    ]
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    logger.info("Exported %d tools to %s", len(data), output_path)
