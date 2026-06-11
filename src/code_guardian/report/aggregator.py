from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from code_guardian.config import Severity
from code_guardian.enrichment.github import Popularity
from code_guardian.scanner.models import TrivyReport, Vulnerability


@dataclass
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0

    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.unknown

    def as_dict(self) -> dict[str, int]:
        return {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
            "UNKNOWN": self.unknown,
        }

    def max_severity(self) -> Severity | None:
        if self.critical:
            return Severity.CRITICAL
        if self.high:
            return Severity.HIGH
        if self.medium:
            return Severity.MEDIUM
        if self.low:
            return Severity.LOW
        if self.unknown:
            return Severity.UNKNOWN
        return None


@dataclass
class RepoResult:
    repo: str
    scan_path: str
    popularity: Optional[Popularity]
    severity_counts: SeverityCounts
    vulnerabilities: list[Vulnerability]
    scan_error: Optional[str] = None
    duration_s: float = 0.0
    graph_dot_path: Optional[Path] = None
    graph_png_path: Optional[Path] = None
    result_file_path: Optional[Path] = None


def aggregate(report: TrivyReport, min_severity: Severity = Severity.LOW) -> tuple[SeverityCounts, list[Vulnerability]]:
    """Count severities and collect vulnerabilities at or above min_severity."""
    counts = SeverityCounts()
    vulns: list[Vulnerability] = []
    _order = list(Severity)

    for result in report.results:
        for vuln in result.vulnerabilities:
            match vuln.severity:
                case Severity.CRITICAL:
                    counts.critical += 1
                case Severity.HIGH:
                    counts.high += 1
                case Severity.MEDIUM:
                    counts.medium += 1
                case Severity.LOW:
                    counts.low += 1
                case _:
                    counts.unknown += 1

            if _order.index(vuln.severity) >= _order.index(min_severity):
                vulns.append(vuln)

    return counts, vulns
