"""Configurable heuristic indicators for static APK analysis.

Findings describe potentially relevant indicators. They do not prove that an
APK is malicious.
"""

import json
from pathlib import Path
from typing import Any

from analyzer.api_analyzer import find_suspicious_apis
from analyzer.permission_analyzer import find_permission_indicators
from analyzer.url_analyzer import find_url_indicators
from analyzer.component_analyzer import find_component_indicators
from security.models import Finding


def load_rules(rules_path: Path) -> dict[str, Any]:
    """Load editable heuristic rules from JSON."""
    with rules_path.open(encoding="utf-8") as rule_file:
        return json.load(rule_file)


class ThreatDetector:
    """Coordinate simple permission, API, and URL indicator checks."""

    def __init__(self, rules_path: Path) -> None:
        self.rules = load_rules(rules_path)

    def detect(self, permissions: list[str], apk: Any) -> list[Finding]:
        """Return heuristic findings without making a malware decision."""
        findings = find_permission_indicators(
            permissions, self.rules.get("permission_rules", {})
        )
        findings.extend(find_suspicious_apis(apk, self.rules.get("api_rules", {})))
        findings.extend(
            find_url_indicators(apk, self.rules.get("suspicious_tlds", []))
        )
        findings.extend(find_component_indicators(apk))
        return findings
