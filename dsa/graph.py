"""Optional lightweight relationship graph for viva demonstration."""

from collections import defaultdict

from security.models import Finding


def build_indicator_graph(package_name: str, findings: list[Finding]) -> dict[str, list[str]]:
    """Build APK -> category -> indicator relationships as an adjacency list."""
    graph: dict[str, list[str]] = defaultdict(list)
    apk_node = f"APK: {package_name}"
    for finding in findings:
        category_node = f"{finding.category}"
        graph[apk_node].append(category_node)
        graph[category_node].append(finding.indicator)
    return dict(graph)
