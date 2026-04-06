"""Tests for source code analysis."""
from mcp_scanner.signatures import load_baseline_signatures
from mcp_scanner.source_analyzer import (
    _pattern_scan_source,
    analyze_source_sync,
    walk_source_dir,
)


def test_walk_source_dir(malicious_source_dir):
    files = walk_source_dir(malicious_source_dir)
    assert len(files) > 0
    paths = [f[0] for f in files]
    assert "evil_server.py" in paths


def test_walk_clean_source(clean_source_dir):
    files = walk_source_dir(clean_source_dir)
    assert len(files) > 0
    paths = [f[0] for f in files]
    assert "server.py" in paths


def test_pattern_scan_detects_malicious_source(malicious_source_dir):
    files = walk_source_dir(malicious_source_dir)
    signatures = load_baseline_signatures()

    findings = _pattern_scan_source(files, signatures)

    assert len(findings) > 0
    # Should detect env exfiltration, obfuscated code, reverse shell, crypto miner
    rule_ids = {f.rule_id for f in findings}
    assert any("MC" in rid for rid in rule_ids)  # Malicious code rules


def test_pattern_scan_clean_source(clean_source_dir):
    files = walk_source_dir(clean_source_dir)
    signatures = load_baseline_signatures()

    findings = _pattern_scan_source(files, signatures)

    # Clean source should have no findings
    assert len(findings) == 0


def test_pattern_scan_evidence_has_context(malicious_source_dir):
    files = walk_source_dir(malicious_source_dir)
    signatures = load_baseline_signatures()

    findings = _pattern_scan_source(files, signatures)

    for finding in findings:
        assert finding.evidence, f"Finding {finding.rule_id} missing evidence"
        assert finding.location, f"Finding {finding.rule_id} missing location"
        assert ":" in finding.location, "Location should include line number"


def test_analyze_source_no_ai(malicious_source_dir):
    """Test full analysis without AI."""
    signatures = load_baseline_signatures()

    findings, scanned_files, total_files = analyze_source_sync(
        source_dir=malicious_source_dir,
        signatures=signatures,
        use_ai=False,
    )

    assert len(findings) > 0
    assert len(scanned_files) > 0
    assert total_files > 0
