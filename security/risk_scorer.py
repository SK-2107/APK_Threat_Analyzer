"""Simple, configurable-score based risk assessment."""

from dataclasses import dataclass

from security.models import Finding


@dataclass(frozen=True)
class RiskAssessment:
    """A transparent risk score and the findings that contributed to it."""

    score: int
    raw_score: int
    level: str
    contributions: list[Finding]

    def explanation(self) -> str:
        """Return a readable account of the score calculation."""
        if not self.contributions:
            return "No configured indicators contributed to the current score."
        rows = [f"+{item.score}  {item.indicator} ({item.category})" for item in self.contributions if item.score]
        if self.raw_score > 100:
            rows.append(f"Raw score: {self.raw_score}; final score capped at 100.")
        return "\n".join(rows)


class RiskScorer:
    """Calculate a capped score from heuristic finding weights."""

    def assess(self, findings: list[Finding]) -> RiskAssessment:
        """Return a 0-100 score and LOW/MEDIUM/HIGH/CRITICAL level."""
        raw_score = sum(finding.score for finding in findings)
        score = min(raw_score, 100)
        if score <= 20:
            level = "LOW"
        elif score <= 40:
            level = "MEDIUM"
        elif score <= 70:
            level = "HIGH"
        else:
            level = "CRITICAL"
        return RiskAssessment(score=score, raw_score=raw_score, level=level, contributions=findings)
