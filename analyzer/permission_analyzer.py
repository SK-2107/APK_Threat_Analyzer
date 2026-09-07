"""Permission lookups based on editable heuristic rules."""

from typing import Any

from security.models import Finding


def find_permission_indicators(
    permissions: list[str], rules: dict[str, Any]
) -> list[Finding]:
    """Match requested permissions against the configured risk dictionary."""
    findings: list[Finding] = []
    for permission in permissions:
        rule = rules.get(permission)
        if rule:
            findings.append(
                Finding(
                    category="Permission",
                    indicator=permission,
                    severity=rule["severity"],
                    score=int(rule["score"]),
                    description=rule.get("description", rule.get("reason", "Configured permission indicator.")),
                    recommendation="Confirm that this permission is needed for the app's stated feature.",
                    source="AndroidManifest.xml",
                )
            )
        else:
            findings.append(
                Finding(
                    category="Permission",
                    indicator=permission,
                    severity="INFO",
                    score=0,
                    description="No configured heuristic rule for this permission.",
                    recommendation="Review this permission in the context of the app's functionality.",
                    source="AndroidManifest.xml",
                )
            )
    return findings
