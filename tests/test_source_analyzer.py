"""Tests for source code analysis."""
import json

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


def test_mcp_mc_001_skips_json_data_files(tmp_path):
    """Regression: MCP-MC-001 must not fire on JSON files where \\uXXXX is
    just standard non-ASCII encoding emitted by serializers like Go's
    json.MarshalIndent — not code obfuscation.
    """
    # Real-world style tools.json: a tool description with non-ASCII chars
    # that json.dumps/MarshalIndent will encode as \uXXXX escapes.
    tools_payload = [
        {
            "name": "list_repos",
            "description": "Lists repositories. Uses UTF-8 characters: café é ñ 中",
            "input_schema": {"type": "object"},
        },
    ]
    tools_path = tmp_path / "tools.json"
    # ensure_ascii=True forces \uXXXX encoding (matches Go's json.MarshalIndent default)
    tools_path.write_text(json.dumps(tools_payload, ensure_ascii=True, indent=2))
    # Sanity check: the encoded form actually contains \u escapes
    raw = tools_path.read_text()
    assert "\\u00e9" in raw

    files = walk_source_dir(str(tmp_path))
    signatures = load_baseline_signatures()
    findings = _pattern_scan_source(files, signatures)

    mc001_findings = [f for f in findings if f.rule_id == "MCP-MC-001"]
    assert mc001_findings == [], (
        f"MCP-MC-001 false-positive on JSON data file: {mc001_findings}"
    )


def test_mcp_mc_001_still_detects_obfuscation_in_code(tmp_path):
    """Regression guard: skipping MCP-MC-001 on data files must NOT disable
    it for actual source files. A .py file with obfuscated payloads must
    still be flagged.
    """
    payload_py = tmp_path / "payload.py"
    payload_py.write_text(
        "import base64\n"
        "eval(base64.b64decode('aW1wb3J0IG9z'))\n"
        # Plus a \uXXXX escape inside Python code — also obfuscation-y
        'x = "\\u0065\\u0076\\u0061\\u006c"\n'
    )

    files = walk_source_dir(str(tmp_path))
    signatures = load_baseline_signatures()
    findings = _pattern_scan_source(files, signatures)

    mc001_findings = [f for f in findings if f.rule_id == "MCP-MC-001"]
    assert mc001_findings, "MCP-MC-001 should still detect obfuscation in .py files"


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
