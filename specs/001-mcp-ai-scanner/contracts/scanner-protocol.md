# Scanner Protocol Contract

## MCPProxy Scanner Plugin Interface

The scanner follows MCPProxy's Docker-based scanner protocol:

### Inputs
- **Source directory**: Mounted at `/scan/source:ro` (read-only)
  - Contains MCP server source files
  - May include `tools.json` with exported tool definitions
- **Report directory**: Mounted at `/scan/report:rw` (writable)
  - Scanner writes output here
- **Cache directory**: Mounted at `/root/.cache:rw` (writable)
  - Persistent cache for signature downloads

### Output
- **SARIF report**: Written to `/scan/report/results.sarif`
- **Format**: SARIF 2.1.0 JSON

### Environment Variables
- `CLAUDE_CONFIG_DIR`: Path to Claude credentials directory
- `SCANNER_MODEL`: Claude model override (optional)
- `SCANNER_TIMEOUT`: Timeout in seconds (optional)

### Exit Codes
- `0`: Scan completed successfully (may have findings)
- `1`: Scan failed (error in scanner operation)
- `2`: Configuration error (missing credentials, invalid params)

## CLI Interface

```
mcp-scanner scan [OPTIONS]

Options:
  --source-dir PATH    Path to MCP server source files
  --tools-file PATH    Path to tools.json file
  --output PATH        Output SARIF file path (default: stdout)
  --model TEXT          Claude model to use
  --modules TEXT        Comma-separated modules to run
  --timeout INTEGER    Scan timeout in seconds
  --signatures-url URL URL for signature updates
  --no-network         Skip online signature updates
```

## MCPProxy Registry Entry

```json
{
  "id": "mcp-ai-scanner",
  "name": "MCP AI Scanner",
  "vendor": "MCPProxy",
  "description": "AI-powered MCP security scanner using Claude Agent SDK. Intelligently analyzes tool descriptions and source code for tool poisoning, prompt injection, data exfiltration, and malicious code patterns.",
  "license": "Apache-2.0",
  "homepage": "https://github.com/smart-mcp-proxy/mcp-scanner",
  "docker_image": "ghcr.io/smart-mcp-proxy/mcp-scanner:latest",
  "inputs": ["source"],
  "outputs": ["sarif"],
  "required_env": [],
  "optional_env": [
    {"key": "SCANNER_MODEL", "label": "Claude model (default: claude-sonnet-4-6)", "secret": false}
  ],
  "command": null,
  "timeout": "300s",
  "network_required": false
}
```
