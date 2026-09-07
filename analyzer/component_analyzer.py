"""Simple security-relevant Android component checks."""

from typing import Any

from security.models import Finding


def find_component_indicators(apk: Any) -> list[Finding]:
    """Flag externally accessible components and boot receivers when available."""
    findings: list[Finding] = []
    component_getters = (
        ("Activity", "get_activities"),
        ("Service", "get_services"),
        ("Broadcast Receiver", "get_receivers"),
        ("Content Provider", "get_providers"),
    )
    for component_type, getter_name in component_getters:
        getter = getattr(apk, getter_name, None)
        if not getter:
            continue
        for component in getter() or []:
            try:
                exported = apk.get_element("application", component, "exported")
            except (AttributeError, TypeError, ValueError):
                exported = None
            if str(exported).lower() == "true":
                findings.append(Finding(
                    category="Android Component",
                    indicator=f"Exported {component_type}: {component}",
                    severity="MEDIUM",
                    score=7,
                    description="An externally accessible component may require additional security review.",
                    recommendation="Confirm that the component validates input and is intentionally exposed.",
                    source="AndroidManifest.xml",
                ))
    for receiver in getattr(apk, "get_receivers", lambda: [])() or []:
        if "boot" in receiver.lower():
            findings.append(Finding(
                category="Android Component",
                indicator=f"Boot-related receiver: {receiver}",
                severity="LOW",
                score=3,
                description="A receiver may react after device boot and deserves contextual review.",
                recommendation="Confirm that boot-time behavior is necessary for the app.",
                source="AndroidManifest.xml",
            ))
    return findings
