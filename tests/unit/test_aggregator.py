from __future__ import annotations

import json
from pathlib import Path

from code_guardian.config import Severity
from code_guardian.report.aggregator import aggregate
from code_guardian.scanner.models import TrivyReport

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load_report(name: str) -> TrivyReport:
    data = json.loads((FIXTURES / name).read_text())
    return TrivyReport.model_validate(data)


class TestAggregator:
    def test_severity_counts(self) -> None:
        report = load_report("trivy_small.json")
        counts, _ = aggregate(report)
        assert counts.critical == 1
        assert counts.high == 1
        assert counts.medium == 1
        assert counts.low == 0

    def test_total(self) -> None:
        report = load_report("trivy_small.json")
        counts, _ = aggregate(report)
        assert counts.total() == 3

    def test_min_severity_filter(self) -> None:
        report = load_report("trivy_small.json")
        _, vulns_all = aggregate(report, min_severity=Severity.LOW)
        _, vulns_high = aggregate(report, min_severity=Severity.HIGH)
        assert len(vulns_all) == 3
        assert len(vulns_high) == 2  # HIGH + CRITICAL

    def test_critical_only(self) -> None:
        report = load_report("trivy_small.json")
        _, vulns = aggregate(report, min_severity=Severity.CRITICAL)
        assert len(vulns) == 1
        assert vulns[0].vuln_id == "CVE-2021-44906"

    def test_empty_report(self) -> None:
        report = load_report("trivy_empty.json")
        counts, vulns = aggregate(report)
        assert counts.total() == 0
        assert vulns == []

    def test_max_severity(self) -> None:
        report = load_report("trivy_small.json")
        counts, _ = aggregate(report)
        assert counts.max_severity() == Severity.CRITICAL

    def test_as_dict(self) -> None:
        report = load_report("trivy_small.json")
        counts, _ = aggregate(report)
        d = counts.as_dict()
        assert d["CRITICAL"] == 1
        assert d["HIGH"] == 1
        assert d["MEDIUM"] == 1
