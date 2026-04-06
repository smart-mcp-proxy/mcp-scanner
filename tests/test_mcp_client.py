"""Tests for MCP client."""
import json
import tempfile
from pathlib import Path

import pytest

from mcp_scanner.mcp_client import load_tools_from_file


def test_load_tools_array_format(clean_tools_file):
    tools = load_tools_from_file(clean_tools_file)
    assert len(tools) == 3
    assert tools[0].name == "get_weather"
    assert tools[0].description.startswith("Get the current weather")


def test_load_tools_object_format():
    data = {"tools": [{"name": "test", "description": "Test tool"}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()

        tools = load_tools_from_file(f.name)
        assert len(tools) == 1
        assert tools[0].name == "test"

    Path(f.name).unlink()


def test_load_tools_missing_file():
    with pytest.raises(FileNotFoundError):
        load_tools_from_file("/nonexistent/tools.json")


def test_load_tools_with_input_schema(malicious_tools_file):
    tools = load_tools_from_file(malicious_tools_file)
    # First tool should have input schema
    assert tools[0].input_schema
    assert tools[0].input_schema["type"] == "object"
