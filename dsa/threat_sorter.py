"""Sorting helpers for security findings."""

from security.models import Finding

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort by severity and configured score, highest first."""
    return sorted(
        findings,
        key=lambda finding: (SEVERITY_ORDER.get(finding.severity, 0), finding.score),
        reverse=True,
    )
