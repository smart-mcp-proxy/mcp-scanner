"""Real-time progress reporting for agent execution.

Outputs agent thoughts, tool usage, and turn progress to stderr
so the user can follow what the scanner is doing during long runs.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field


@dataclass
class AgentProgress:
    """Tracks and displays agent execution progress."""

    label: str
    quiet: bool = False
    turn: int = 0
    tools_used: int = 0
    _start: float = field(default_factory=time.monotonic)

    def _write(self, msg: str) -> None:
        if not self.quiet:
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()

    def start(self) -> None:
        self._write(f"  [{self.label}] Starting AI analysis...")

    def on_thinking(self, text: str) -> None:
        # Show first line of thinking, truncated
        first_line = text.strip().split("\n")[0]
        if len(first_line) > 120:
            first_line = first_line[:117] + "..."
        self._write(f"  [{self.label}] Thinking: {first_line}")

    def on_tool_use(self, name: str, input_data: dict) -> None:
        self.tools_used += 1
        # Format tool call concisely
        summary = _summarize_tool_input(name, input_data)
        self._write(f"  [{self.label}] Tool: {name}({summary})")

    def on_tool_result(self, is_error: bool | None) -> None:
        if is_error:
            self._write(f"  [{self.label}] Tool returned error")

    def on_text(self, text: str) -> None:
        # Show brief snippet of agent reasoning (first meaningful line)
        first_line = text.strip().split("\n")[0]
        if not first_line:
            return
        if len(first_line) > 120:
            first_line = first_line[:117] + "..."
        self._write(f"  [{self.label}] Agent: {first_line}")

    def on_turn(self) -> None:
        self.turn += 1
        elapsed = time.monotonic() - self._start
        self._write(
            f"  [{self.label}] Turn {self.turn} "
            f"({elapsed:.0f}s elapsed, {self.tools_used} tool calls)"
        )

    def on_complete(self, num_turns: int, cost: float) -> None:
        elapsed = time.monotonic() - self._start
        self._write(
            f"  [{self.label}] Complete: {num_turns} turns, "
            f"{self.tools_used} tool calls, {elapsed:.1f}s, ${cost:.4f}"
        )

    def on_error(self, error: str) -> None:
        self._write(f"  [{self.label}] Error: {error}")


def _summarize_tool_input(name: str, input_data: dict) -> str:
    """Create a concise summary of tool input parameters."""
    if not input_data:
        return ""

    if name == "Read":
        path = input_data.get("file_path", "")
        return _short_path(path)
    elif name == "Grep":
        pattern = input_data.get("pattern", "")
        path = input_data.get("path", "")
        parts = [f'"{pattern}"']
        if path:
            parts.append(_short_path(path))
        return ", ".join(parts)
    elif name == "Glob":
        pattern = input_data.get("pattern", "")
        return f'"{pattern}"'
    else:
        # Generic: show first string value
        for v in input_data.values():
            if isinstance(v, str) and v:
                s = v if len(v) <= 60 else v[:57] + "..."
                return f'"{s}"'
        return ""


def _short_path(path: str) -> str:
    """Shorten a file path for display."""
    if len(path) <= 60:
        return path
    parts = path.split("/")
    if len(parts) > 3:
        return "/".join(["...", *parts[-3:]])
    return path
