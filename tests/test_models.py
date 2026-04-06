"""Tests for data models."""
from mcp_scanner.models import (
    ScanFinding,
    Severity,
    ThreatLevel,
    ThreatType,
    ToolDefinition,
    calculate_risk_score,
    summarize_findings,
)


def test_tool_definition_creation():
    tool = ToolDefinition(
        name="test_tool",
        description="A test tool",
        input_schema={"type": "object"},
    )
    assert tool.name == "test_tool"
    assert tool.description == "A test tool"


def test_scan_finding_defaults():
    finding = ScanFinding(
        rule_id="TEST-001",
        title="Test finding",
        description="Test description",
    )
    assert finding.severity == Severity.MEDIUM
    assert finding.threat_type == ThreatType.UNCATEGORIZED
    assert finding.threat_level == ThreatLevel.INFO
    assert finding.scanner == "mcp-ai-scanner"


def test_risk_score_empty():
    assert calculate_risk_score([]) == 0


def test_risk_score_dangerous():
    findings = [
        ScanFinding(
            rule_id="TP-001",
            title="Tool poisoning",
            description="Bad",
            threat_level=ThreatLevel.DANGEROUS,
        ),
    ]
    score = calculate_risk_score(findings)
    assert score == 30  # One dangerous = 30 points


def test_risk_score_mixed():
    findings = [
        ScanFinding(rule_id="TP-001", title="a", description="a", threat_level=ThreatLevel.DANGEROUS),
        ScanFinding(rule_id="TP-002", title="b", description="b", threat_level=ThreatLevel.DANGEROUS),
        ScanFinding(rule_id="W-001", title="c", description="c", threat_level=ThreatLevel.WARNING),
        ScanFinding(rule_id="I-001", title="d", description="d", threat_level=ThreatLevel.INFO),
    ]
    score = calculate_risk_score(findings)
    assert score == 66  # 60 dangerous + 5 warning + 1 info


def test_risk_score_capped():
    findings = [
        ScanFinding(rule_id=f"D-{i}", title="x", description="x", threat_level=ThreatLevel.DANGEROUS)
        for i in range(10)
    ]
    score = calculate_risk_score(findings)
    assert score == 90  # Capped at 90 for dangerous


def test_summarize_findings():
    findings = [
        ScanFinding(rule_id="1", title="a", description="a", severity=Severity.CRITICAL, threat_level=ThreatLevel.DANGEROUS),
        ScanFinding(rule_id="2", title="b", description="b", severity=Severity.HIGH, threat_level=ThreatLevel.WARNING),
        ScanFinding(rule_id="3", title="c", description="c", severity=Severity.LOW, threat_level=ThreatLevel.INFO),
    ]
    summary = summarize_findings(findings)
    assert summary.total == 3
    assert summary.critical == 1
    assert summary.high == 1
    assert summary.low == 1
    assert summary.dangerous == 1
    assert summary.warnings == 1
    assert summary.info_level == 1
