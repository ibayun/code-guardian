from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_guardian.graph.renderer import _build_dot_source, _dot_id
from code_guardian.scanner.models import TrivyReport

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load_report(name: str) -> TrivyReport:
    data = json.loads((FIXTURES / name).read_text())
    return TrivyReport.model_validate(data)


class TestGraphRenderer:
    def test_dot_source_contains_targets(self) -> None:
        report = load_report("trivy_small.json")
        dot = _build_dot_source(report)
        assert "package_lock_json" in dot
        assert "Gemfile_lock" in dot

    def test_critical_node_highlighted(self) -> None:
        report = load_report("trivy_small.json")
        dot = _build_dot_source(report)
        # package-lock.json has CRITICAL vuln → should have red fillcolor
        assert "fillcolor=red" in dot

    def test_gemfile_not_critical(self) -> None:
        report = load_report("trivy_small.json")
        dot = _build_dot_source(report)
        # Gemfile.lock has only HIGH — not highlighted
        lines = [l for l in dot.splitlines() if "Gemfile_lock" in l]
        assert lines
        # No fillcolor on the non-critical node definition
        node_line = next(l for l in lines if "label=" in l)
        assert "fillcolor" not in node_line

    def test_dependency_edges_rendered(self) -> None:
        report = load_report("trivy_small.json")
        dot = _build_dot_source(report)
        assert "->" in dot

    def test_empty_report(self) -> None:
        report = load_report("trivy_empty.json")
        dot = _build_dot_source(report)
        assert "digraph" in dot

    def test_dot_id_safe(self) -> None:
        assert _dot_id("package-lock.json") == "package_lock_json"
        assert _dot_id("123abc") == "n_123abc"
        assert _dot_id("") == "unknown"
        assert _dot_id("valid_name") == "valid_name"
