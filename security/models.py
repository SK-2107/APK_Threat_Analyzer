"""Small data models shared by the heuristic-analysis modules."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    """One heuristic indicator found during static analysis."""

    category: str
    indicator: str
    severity: str
    score: int
    description: str
    recommendation: str = "Review whether this indicator is required by the app's intended functionality."
    source: str = "Static APK analysis"
