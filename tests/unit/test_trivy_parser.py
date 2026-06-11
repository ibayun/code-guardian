from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_guardian.config import Severity
from code_guardian.scanner.models import TrivyReport

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load_report(name: str) -> TrivyReport:
    data = json.loads((FIXTURES / name).read_text())
    return TrivyReport.model_validate(data)


class TestTrivyParser:
    def test_parses_small_fixture(self) -> None:
        report = load_report("trivy_small.json")
        assert report.artifact_name == "test-repo"
        assert len(report.results) == 2

    def test_vulnerability_count(self) -> None:
        report = load_report("trivy_small.json")
        total = sum(len(r.vulnerabilities) for r in report.results)
        assert total == 3

    def test_severity_mapping(self) -> None:
        report = load_report("trivy_small.json")
        npm_result = next(r for r in report.results if r.target == "package-lock.json")
        severities = {v.vuln_id: v.severity for v in npm_result.vulnerabilities}
        assert severities["CVE-2021-23362"] == Severity.MEDIUM
        assert severities["CVE-2021-44906"] == Severity.CRITICAL

    def test_dependency_edges(self) -> None:
        report = load_report("trivy_small.json")
        assert len(report.dependencies) == 1
        dep = report.dependencies[0]
        assert dep.id == "package-lock.json"
        assert "Gemfile.lock" in dep.depends_on

    def test_empty_results(self) -> None:
        report = load_report("trivy_empty.json")
        assert report.results == []
        assert report.artifact_name == "clean-repo"

    def test_malformed_json_raises(self) -> None:
        raw = (FIXTURES / "trivy_malformed.json").read_bytes()
        with pytest.raises(json.JSONDecodeError):
            json.loads(raw)

    def test_extra_fields_ignored(self) -> None:
        data = json.loads((FIXTURES / "trivy_small.json").read_text())
        data["UnknownFutureField"] = "some value"
        report = TrivyReport.model_validate(data)
        assert report.artifact_name == "test-repo"
