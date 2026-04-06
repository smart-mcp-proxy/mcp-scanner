# Data Model: MCP AI Security Scanner

## Entities

### ScanConfig
Configuration for a scan run.
- `target_type`: str - "tools_json" | "mcp_server" | "source_dir"
- `source_dir`: str | None - Path to source files
- `tools_file`: str | None - Path to tools.json
- `mcp_url`: str | None - MCP server URL
- `model`: str - Claude model to use (default: "claude-sonnet-4-6")
- `modules`: list[str] - Which analysis modules to run (default: ["tool_descriptions", "source_code"])
- `timeout`: int - Max scan time in seconds (default: 300)
- `signatures_url`: str | None - URL to download signature updates
- `signatures_cache_dir`: str - Local cache dir for signatures

### ToolDefinition
An MCP tool definition retrieved from a server or tools.json.
- `name`: str - Tool name
- `description`: str - Tool description text
- `input_schema`: dict - JSON Schema for tool input

### ScanFinding
An individual security finding (compatible with mcpproxy-go ScanFinding).
- `rule_id`: str - Detection rule identifier
- `severity`: str - "critical" | "high" | "medium" | "low" | "info"
- `category`: str - SARIF category
- `threat_type`: str - "tool_poisoning" | "prompt_injection" | "rug_pull" | "supply_chain" | "malicious_code"
- `threat_level`: str - "dangerous" | "warning" | "info"
- `title`: str - Short finding title
- `description`: str - Detailed description
- `location`: str - File path or "tool:<name>"
- `scanner`: str - Scanner ID ("mcp-ai-scanner")
- `evidence`: str - The exact text/code that triggered the finding
- `help_uri`: str | None - Link to advisory
- `cvss_score`: float | None - CVSS score if applicable

### ScanReport
Aggregated scan results.
- `findings`: list[ScanFinding]
- `risk_score`: int - 0-100
- `summary`: ReportSummary
- `scanned_at`: datetime
- `scanner_id`: str
- `scan_context`: ScanContext

### VulnerabilitySignature
A detection rule from the signature database.
- `id`: str - Unique signature ID
- `name`: str - Human-readable name
- `category`: str - "tool_poisoning" | "prompt_injection" | "malicious_code" | etc.
- `severity`: str - Default severity
- `patterns`: list[str] - Regex patterns to match
- `description`: str - What this signature detects
- `examples`: list[str] - Example malicious text

## Relationships

```
ScanConfig ---> ScanReport (1:1, a config produces one report)
ScanReport ---> ScanFinding (1:N, a report contains many findings)
ToolDefinition ---> ScanFinding (1:N, analysis of one tool may produce multiple findings)
VulnerabilitySignature ---> ScanFinding (1:N, one signature may match multiple locations)
```
