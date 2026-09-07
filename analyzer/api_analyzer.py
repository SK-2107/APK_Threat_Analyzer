"""Simple static search for configurable API strings in APK DEX files."""

from typing import Any

from security.models import Finding


def find_suspicious_apis(apk: Any, rules: dict[str, Any]) -> list[Finding]:
    """Search DEX bytes for configured indicators without executing code."""
    try:
        dex_text = _read_dex_text(apk)
    except (AttributeError, OSError, TypeError, ValueError):
        return []

    findings: list[Finding] = []
    for indicator, rule in rules.items():
        if indicator in dex_text:
            findings.append(
                Finding(
                    category=rule["category"],
                    indicator=indicator,
                    severity=rule["severity"],
                    score=int(rule["score"]),
                    description=rule.get("description", rule.get("reason", "Configured API indicator.")),
                    recommendation="Review why this API is used and whether it matches the app's intended purpose.",
                    source="DEX string search",
                )
            )
    return findings


def _read_dex_text(apk: Any) -> str:
    """Decode DEX bytes losslessly enough for simple string matching."""
    dex_parts: list[str] = []
    for dex_name in apk.get_dex_names():
        dex_bytes = apk.get_file(dex_name)
        if dex_bytes:
            dex_parts.append(dex_bytes.decode("latin-1", errors="ignore"))
    return "\n".join(dex_parts)
