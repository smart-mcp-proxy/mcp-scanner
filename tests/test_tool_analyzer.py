"""Tests for tool description analysis."""
from mcp_scanner.mcp_client import load_tools_from_file
from mcp_scanner.signatures import load_baseline_signatures
from mcp_scanner.tool_analyzer import _pattern_scan_tools, analyze_tools_sync


def test_pattern_scan_detects_malicious_tools(malicious_tools_file):
    tools, _ = load_tools_from_file(malicious_tools_file)
    signatures = load_baseline_signatures()

    findings = _pattern_scan_tools(tools, signatures)

    # Should detect issues in malicious tools
    assert len(findings) > 0

    # Check specific detections
    tool_names_with_findings = {f.location for f in findings}
    assert "tool:read_file" in tool_names_with_findings  # Hidden instruction + exfiltration
    assert "tool:calculator" in tool_names_with_findings  # Credential harvesting
    assert "tool:search" in tool_names_with_findings  # Prompt injection


def test_pattern_scan_clean_tools(clean_tools_file):
    tools, _ = load_tools_from_file(clean_tools_file)
    signatures = load_baseline_signatures()

    findings = _pattern_scan_tools(tools, signatures)

    # Clean tools should have no findings
    assert len(findings) == 0


def test_pattern_scan_evidence_included(malicious_tools_file):
    tools, _ = load_tools_from_file(malicious_tools_file)
    signatures = load_baseline_signatures()

    findings = _pattern_scan_tools(tools, signatures)

    # All findings should have evidence
    for finding in findings:
        assert finding.evidence, f"Finding {finding.rule_id} missing evidence"
        assert len(finding.evidence) > 0


def test_analyze_tools_no_ai(malicious_tools_file):
    """Test full analysis without AI (pattern-only mode)."""
    tools, _ = load_tools_from_file(malicious_tools_file)
    signatures = load_baseline_signatures()

    findings = analyze_tools_sync(
        tools=tools,
        signatures=signatures,
        use_ai=False,
    )

    assert len(findings) > 0
    # Verify threat types are set
    for f in findings:
        assert f.threat_type is not None
        assert f.threat_level is not None
