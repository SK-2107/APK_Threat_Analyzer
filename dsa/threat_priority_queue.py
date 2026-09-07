"""Priority queue implementation for high-severity findings."""

import heapq

from security.models import Finding
from dsa.threat_sorter import SEVERITY_ORDER


class ThreatPriorityQueue:
    """Use a heap to retrieve the most important finding first."""

    def __init__(self) -> None:
        self._heap: list[tuple[int, int, Finding]] = []
        self._counter = 0

    def add(self, finding: Finding) -> None:
        """Insert a finding with high severity and score as high priority."""
        priority = -(SEVERITY_ORDER.get(finding.severity, 0) * 100 + finding.score)
        heapq.heappush(self._heap, (priority, self._counter, finding))
        self._counter += 1

    def ranked_findings(self) -> list[Finding]:
        """Remove and return findings from highest to lowest priority."""
        ranked: list[Finding] = []
        while self._heap:
            ranked.append(heapq.heappop(self._heap)[2])
        return ranked


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    """Rank a collection with the project's heap-based priority queue."""
    queue = ThreatPriorityQueue()
    for finding in findings:
        queue.add(finding)
    return queue.ranked_findings()
