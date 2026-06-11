from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import structlog

from code_guardian.report.aggregator import RepoResult

log = structlog.get_logger()


def write_result(result: RepoResult, output_dir: Path, fmt: Literal["json", "html"]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "html":
        path = output_dir / "report.html"
        path.write_text(_render_html(result))
    else:
        path = output_dir / "report.json"
        path.write_text(_render_json(result), encoding="utf-8")

    log.info("report.written", path=str(path))
    return path


def _render_json(result: RepoResult) -> str:
    dot_source: str | None = None
    if result.graph_dot_path and result.graph_dot_path.exists():
        dot_source = result.graph_dot_path.read_text()

    image_path: str | None = None
    if result.graph_png_path:
        image_path = str(result.graph_png_path)

    payload = {
        "repo": result.repo,
        "scan_path": result.scan_path,
        "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
        "duration_s": round(result.duration_s, 2),
        "popularity": (
            {
                "stars": result.popularity.stars,
                "forks": result.popularity.forks,
                "description": result.popularity.description,
            }
            if result.popularity
            else None
        ),
        "scan_error": result.scan_error,
        "severity_counts": result.severity_counts.as_dict(),
        "vulnerabilities": [
            {
                "id": v.vuln_id,
                "package": v.pkg_name,
                "installed_version": v.installed_version,
                "fixed_version": v.fixed_version,
                "severity": v.severity.value,
                "title": v.title,
            }
            for v in result.vulnerabilities
        ],
        "graph": {
            "dot_source": dot_source,
            "image_path": image_path,
        },
    }
    return json.dumps(payload, indent=2, default=str)


def _render_html(result: RepoResult) -> str:
    json_data = _render_json(result)

    image_tag = ""
    if result.graph_png_path and result.graph_png_path.exists():
        b64 = base64.b64encode(result.graph_png_path.read_bytes()).decode()
        image_tag = f'<img src="data:image/png;base64,{b64}" alt="Dependency graph" style="max-width:100%"/>'

    counts = result.severity_counts
    severity_html = "".join(
        f'<span class="badge {sev.lower()}">{sev}: {count}</span>'
        for sev, count in counts.as_dict().items()
        if count > 0
    )

    vuln_rows = "".join(
        f"<tr><td>{v.vuln_id}</td><td>{v.pkg_name}</td>"
        f'<td class="{v.severity.value.lower()}">{v.severity.value}</td>'
        f"<td>{v.title or '—'}</td><td>{v.fixed_version or '—'}</td></tr>"
        for v in result.vulnerabilities
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Code Guardian — {result.repo}</title>
<style>
  body {{ font-family: sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
  h1 {{ color: #1a1a2e; }}
  .badge {{ display: inline-block; padding: 4px 10px; margin: 2px; border-radius: 4px; color: white; font-weight: bold; }}
  .critical {{ background: #c0392b; }} .high {{ background: #e67e22; }}
  .medium {{ background: #f1c40f; color: #333; }} .low {{ background: #27ae60; }}
  .unknown {{ background: #7f8c8d; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
  th, td {{ padding: 8px 12px; border: 1px solid #ddd; text-align: left; }}
  th {{ background: #f4f4f4; }}
  pre {{ background: #f8f8f8; padding: 1rem; overflow: auto; font-size: 0.8rem; }}
</style>
</head>
<body>
<h1>Code Guardian Report</h1>
<h2>{result.repo}</h2>
{"<p><strong>Error:</strong> " + result.scan_error + "</p>" if result.scan_error else ""}
{"<p>Stars: " + str(result.popularity.stars) + " | Forks: " + str(result.popularity.forks) + "</p>" if result.popularity else ""}
<div>{severity_html}</div>
<h3>Dependency Graph</h3>
{image_tag or "<p><em>Graph image not available — see .dot file.</em></p>"}
<h3>Vulnerabilities ({len(result.vulnerabilities)})</h3>
<table>
<tr><th>CVE</th><th>Package</th><th>Severity</th><th>Title</th><th>Fixed In</th></tr>
{vuln_rows or "<tr><td colspan='5'>No vulnerabilities found</td></tr>"}
</table>
<h3>Raw JSON</h3>
<pre>{json_data}</pre>
</body>
</html>"""
