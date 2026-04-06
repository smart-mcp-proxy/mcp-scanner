FROM python:3.13-slim

# Install uv + git (needed for claude-agent-sdk)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy lock file first for caching
COPY pyproject.toml README.md uv.lock ./
COPY src/ src/

# Install dependencies AND build the package (so no PyPI needed at runtime)
RUN uv sync --no-dev --frozen && \
    uv pip install --no-deps -e .

# Create non-root user (scanner doesn't need root)
RUN groupadd -g 1000 scanner && useradd -u 1000 -g 1000 -m scanner && \
    mkdir -p /scan/source /scan/report /app/.claude && \
    chown -R scanner:scanner /app /scan

USER scanner

# MCPProxy scanner plugin protocol:
# - Source files mounted at /scan/source (read-only)
# - Reports written to /scan/report
# - Claude config via CLAUDE_CONFIG_DIR env (mounted read-only from host)
ENV CLAUDE_CONFIG_DIR=/app/.claude
ENV UV_FROZEN=1

ENTRYPOINT ["uv", "run", "python", "-m", "mcp_scanner.entrypoint"]
