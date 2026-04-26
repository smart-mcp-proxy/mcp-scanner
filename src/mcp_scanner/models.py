"""Data models for MCP AI Security Scanner."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatType(str, Enum):
    TOOL_POISONING = "tool_poisoning"
    PROMPT_INJECTION = "prompt_injection"
    RUG_PULL = "rug_pull"
    SUPPLY_CHAIN = "supply_chain"
    MALICIOUS_CODE = "malicious_code"
    UNCATEGORIZED = "uncategorized"


class ThreatLevel(str, Enum):
    DANGEROUS = "dangerous"
    WARNING = "warning"
    INFO = "info"


class ToolDefinition(BaseModel):
    """An MCP tool definition."""
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)


class ScanFinding(BaseModel):
    """An individual security finding."""
    rule_id: str
    severity: Severity = Severity.MEDIUM
    category: str = "security"
    threat_type: ThreatType = ThreatType.UNCATEGORIZED
    threat_level: ThreatLevel = ThreatLevel.INFO
    title: str
    description: str
    location: str = ""
    scanner: str = "mcp-ai-scanner"
    evidence: str = ""
    help_uri: str = ""
    cvss_score: float | None = None


class ReportSummary(BaseModel):
    """Summary counts by severity and threat level."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    dangerous: int = 0
    warnings: int = 0
    info_level: int = 0


class ScanContext(BaseModel):
    """Metadata about what was scanned."""
    server_name: str = ""
    source_method: str = "none"
    source_path: str = ""
    tools_exported: int = 0
    scanned_files: list[str] = Field(default_factory=list)
    total_files: int = 0
    total_size_bytes: int = 0


class ScanReport(BaseModel):
    """Aggregated scan results."""
    findings: list[ScanFinding] = Field(default_factory=list)
    risk_score: int = 0
    summary: ReportSummary = Field(default_factory=ReportSummary)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scanner_id: str = "mcp-ai-scanner"
    scan_context: ScanContext = Field(default_factory=ScanContext)


class ScanConfig(BaseModel):
    """Configuration for a scan run."""
    source_dir: str | None = None
    tools_file: str | None = None
    mcp_url: str | None = None
    server_name: str = ""
    model: str = "claude-sonnet-4-6"
    modules: list[str] = Field(default_factory=lambda: ["tool_descriptions", "source_code"])
    timeout: int = 300
    signatures_url: str | None = None
    signatures_cache_dir: str = "/tmp/mcp-scanner-cache"
    output_file: str | None = None
    no_network: bool = False


class VulnerabilitySignature(BaseModel):
    """A detection rule from the signature database."""
    id: str
    name: str
    category: str
    severity: Severity = Severity.MEDIUM
    patterns: list[str] = Field(default_factory=list)
    description: str = ""
    examples: list[str] = Field(default_factory=list)
    # When true, this signature is skipped for data/config files (.json, .yaml,
    # .toml, .ini, .cfg) where its patterns would generate false positives.
    # Used for rules like MCP-MC-001 (obfuscated code) whose patterns (\\uXXXX,
    # \\xNN, fromCharCode) overlap with legitimate data-file escape encodings.
    skip_on_data_files: bool = False


def calculate_risk_score(findings: list[ScanFinding]) -> int:
    """Calculate risk score 0-100 from findings using mcpproxy-compatible scoring."""
    if not findings:
        return 0

    dangerous_score = 0
    warning_score = 0
    info_score = 0

    for f in findings:
        match f.threat_level:
            case ThreatLevel.DANGEROUS:
                dangerous_score += 30
            case ThreatLevel.WARNING:
                warning_score += 5
            case ThreatLevel.INFO:
                info_score += 1

    dangerous_score = min(dangerous_score, 90)
    warning_score = min(warning_score, 40)
    info_score = min(info_score, 10)

    return min(dangerous_score + warning_score + info_score, 100)


def summarize_findings(findings: list[ScanFinding]) -> ReportSummary:
    """Produce a ReportSummary from findings."""
    summary = ReportSummary(total=len(findings))
    for f in findings:
        match f.severity:
            case Severity.CRITICAL:
                summary.critical += 1
            case Severity.HIGH:
                summary.high += 1
            case Severity.MEDIUM:
                summary.medium += 1
            case Severity.LOW:
                summary.low += 1
            case Severity.INFO:
                summary.info += 1

        match f.threat_level:
            case ThreatLevel.DANGEROUS:
                summary.dangerous += 1
            case ThreatLevel.WARNING:
                summary.warnings += 1
            case ThreatLevel.INFO:
                summary.info_level += 1

    return summary
