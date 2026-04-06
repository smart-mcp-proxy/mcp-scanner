"""Tests for vulnerability signature management."""
from mcp_scanner.signatures import load_baseline_signatures


def test_baseline_signatures_load():
    sigs = load_baseline_signatures()
    assert len(sigs) > 0


def test_baseline_signatures_have_required_fields():
    sigs = load_baseline_signatures()
    for sig in sigs:
        assert sig.id, "Signature missing ID"
        assert sig.name, "Signature missing name"
        assert sig.category, "Signature missing category"
        assert len(sig.patterns) > 0, f"Signature {sig.id} has no patterns"


def test_baseline_covers_key_categories():
    sigs = load_baseline_signatures()
    categories = {sig.category for sig in sigs}
    assert "tool_poisoning" in categories
    assert "prompt_injection" in categories
    assert "malicious_code" in categories


def test_baseline_signature_ids_unique():
    sigs = load_baseline_signatures()
    ids = [sig.id for sig in sigs]
    assert len(ids) == len(set(ids)), "Duplicate signature IDs found"
