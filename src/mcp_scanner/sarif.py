"""SARIF 2.1.0 report generation."""

from __future__ import annotations

import json
from typing import Any

from mcp_scanner.models import ScanFinding, ScanReport


def _severity_to_sarif_level(severity: str) -> str:
    """Map scanner severity to SARIF level."""
    match severity:
        case "critical" | "high":
            return "error"
        case "medium":
            return "warning"
        case "low":
            return "note"
        case _:
            return "none"


def _build_sarif_result(finding: ScanFinding) -> dict[str, Any]:
    """Convert a ScanFinding to a SARIF result."""
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _severity_to_sarif_level(finding.severity),
        "message": {"text": finding.description},
        "properties": {
            "threat_type": finding.threat_type,
            "threat_level": finding.threat_level,
            "evidence": finding.evidence,
            "category": finding.category,
        },
    }

    if finding.location:
        location: dict[str, Any] = {}
        if finding.location.startswith("tool:"):
            location["logicalLocations"] = [
                {"name": finding.location, "kind": "function"}
            ]
        else:
            parts = finding.location.rsplit(":", 1)
            artifact: dict[str, Any] = {"uri": parts[0]}
            region = None
            if len(parts) == 2:
                try:
                    region = {"startLine": int(parts[1])}
                except ValueError:
                    pass
            phys: dict[str, Any] = {"artifactLocation": artifact}
            if region:
                phys["region"] = region
            location["physicalLocation"] = phys

        result["locations"] = [location]

    return result


def _build_sarif_rule(finding: ScanFinding) -> dict[str, Any]:
    """Build a SARIF rule definition from a finding."""
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {
            "level": _severity_to_sarif_level(finding.severity),
        },
        "properties": {
            "threat_type": finding.threat_type,
            "threat_level": finding.threat_level,
        },
    }
    if finding.help_uri:
        rule["helpUri"] = finding.help_uri
    if finding.cvss_score is not None:
        rule["properties"]["security-severity"] = str(finding.cvss_score)
    return rule


def generate_sarif(report: ScanReport) -> dict[str, Any]:
    """Generate a SARIF 2.1.0 report from a ScanReport."""
    # Deduplicate rules by rule_id
    rules_map: dict[str, dict[str, Any]] = {}
    results = []

    for finding in report.findings:
        if finding.rule_id not in rules_map:
            rules_map[finding.rule_id] = _build_sarif_rule(finding)
        results.append(_build_sarif_result(finding))

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-ai-scanner",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/smart-mcp-proxy/mcp-scanner",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif


def sarif_to_json(report: ScanReport) -> str:
    """Generate SARIF 2.1.0 JSON string from a ScanReport."""
    return json.dumps(generate_sarif(report), indent=2)
