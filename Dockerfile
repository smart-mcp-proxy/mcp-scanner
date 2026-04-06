FROM python:3.12-slim

# Install uv + git (needed for claude-agent-sdk)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/

# Install dependencies
RUN uv sync --no-dev --no-editable

# Create non-root user (scanner doesn't need root)
RUN groupadd -g 1000 scanner && useradd -u 1000 -g 1000 -m scanner && \
    mkdir -p /scan/source /scan/report /root/.cache/mcp-scanner && \
    chown -R scanner:scanner /app /scan /root/.cache

USER scanner

# MCPProxy scanner plugin protocol:
# - Source files mounted at /scan/source (read-only)
# - Reports written to /scan/report
# - Claude config via CLAUDE_CONFIG_DIR env
ENV CLAUDE_CONFIG_DIR=/app/.claude
ENV SCANNER_CACHE_DIR=/root/.cache/mcp-scanner

ENTRYPOINT ["uv", "run", "python", "-m", "mcp_scanner.entrypoint"]
