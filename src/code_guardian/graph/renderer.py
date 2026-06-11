from __future__ import annotations

import shutil
from pathlib import Path

import structlog

from code_guardian.config import Severity
from code_guardian.scanner.models import TrivyReport

log = structlog.get_logger()


def render_dependency_graph(report: TrivyReport, output_dir: Path) -> tuple[Path, Path | None]:
    """
    Build a Graphviz dependency graph.
    Returns (dot_path, png_path). png_path is None if `dot` binary is unavailable.
    """
    try:
        import graphviz  # type: ignore[import]
    except ImportError:
        log.warning("graphviz.not_installed")
        dot_path = _write_dot_source(_build_dot_source(report), output_dir)
        return dot_path, None

    dot_source = _build_dot_source(report)
    dot_path = output_dir / "dependency_graph.dot"
    dot_path.write_text(dot_source)

    if not shutil.which("dot"):
        log.warning("graphviz.dot_not_in_path", detail="Install graphviz to render PNG")
        return dot_path, None

    gv = graphviz.Source(dot_source)
    png_path = output_dir / "dependency_graph"
    try:
        rendered = gv.render(str(png_path), format="png", cleanup=False)
        return dot_path, Path(rendered)
    except Exception as exc:
        log.warning("graphviz.render_failed", error=str(exc))
        return dot_path, None


def _write_dot_source(source: str, output_dir: Path) -> Path:
    dot_path = output_dir / "dependency_graph.dot"
    dot_path.write_text(source)
    return dot_path


def _build_dot_source(report: TrivyReport) -> str:
    """Build DOT source string without requiring graphviz package."""
    lines = ['digraph dependencies {', '  rankdir=LR;', '  node [shape=box];', '']

    # Targets with CRITICAL findings get highlighted
    critical_targets: set[str] = set()
    for result in report.results:
        if any(v.severity == Severity.CRITICAL for v in result.vulnerabilities):
            critical_targets.add(result.target)

    # Node declarations
    for result in report.results:
        node_id = _dot_id(result.target)
        label = result.target.replace('"', '\\"')
        if result.target in critical_targets:
            lines.append(
                f'  {node_id} [label="{label}" fillcolor=red style=filled fontcolor=white];'
            )
        else:
            vuln_count = len(result.vulnerabilities)
            if vuln_count:
                lines.append(f'  {node_id} [label="{label}\\n({vuln_count} vulns)"];')
            else:
                lines.append(f'  {node_id} [label="{label}"];')

    lines.append('')

    # Edges from Trivy dependency tree
    for dep in report.dependencies:
        src = _dot_id(dep.id)
        for child in dep.depends_on:
            dst = _dot_id(child)
            lines.append(f'  {src} -> {dst};')

    lines.append('}')
    return '\n'.join(lines)


def _dot_id(name: str) -> str:
    """Convert an arbitrary string to a safe DOT identifier."""
    safe = ''.join(c if c.isalnum() or c == '_' else '_' for c in name)
    if safe and safe[0].isdigit():
        safe = 'n_' + safe
    return safe or 'unknown'
