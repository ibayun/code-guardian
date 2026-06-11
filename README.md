# Code Guardian

A CLI security scanner that wraps [Trivy](https://github.com/aquasecurity/trivy), enriches results with GitHub popularity metadata, renders a Graphviz dependency graph, and writes structured reports — all for one or more repositories in a single command.

Point it at any Git URL or local path and it will:

- Clone the repository (shallow, depth 1) if given a URL
- Run a Trivy filesystem scan and parse the vulnerability output
- Fetch the repository's GitHub stars and forks concurrently with the scan
- Render a dependency graph highlighting components with CRITICAL findings
- Write a `report.json` (or `report.html`) per repository
- Print a colour-coded summary to stdout as each scan finishes
- Exit with a meaningful code so CI pipelines can gate on severity

Multiple repositories are scanned in parallel, bounded by `--concurrency`. One repo failing does not abort the others.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    CLI  (cli.py)                    │
│              Typer — args, flags, exit codes        │
└──────────────────────────┬──────────────────────────┘
                           │  list[repo_url | local_path]
                           ▼
┌─────────────────────────────────────────────────────┐
│             Orchestrator  (orchestrator.py)         │
│   asyncio.gather  +  Semaphore(--concurrency)       │
│   one coroutine per repo, errors isolated           │
└───────────────┬─────────────────────┬───────────────┘
                │                     │
    ┌───────────▼──────────┐  ┌───────▼────────────┐
    │  Trivy Runner        │  │  GitHub Client     │
    │  (scanner/trivy.py)  │  │  (enrichment/      │
    │                      │  │   github.py)       │
    │  git clone --depth 1 │  │                    │
    │  → trivy fs (async   │  │  GET /repos/{o}/{r}│
    │    subprocess)       │  │  httpx async       │
    │  → timeout enforced  │  │  cached per run    │
    │  → Docker fallback   │  │  optional token    │
    └───────────┬──────────┘  └───────┬────────────┘
                │ TrivyReport          │ Popularity
                └──────────┬──────────┘
                           ▼
┌─────────────────────────────────────────────────────┐
│            Result Aggregator  (report/aggregator.py)│
│   counts by severity, filters by --severity flag   │
└──────────┬───────────────┬────────────────┬─────────┘
           │               │                │
    ┌──────▼──────┐  ┌─────▼──────┐  ┌─────▼──────────┐
    │  Graph      │  │  Writer    │  │  Console       │
    │  Renderer   │  │  (report/  │  │  (output/      │
    │  (graph/    │  │  writer.py)│  │  console.py)   │
    │  renderer.py│  │            │  │                │
    │             │  │  JSON/HTML │  │  Rich colour   │
    │  DOT source │  │  report    │  │  per-repo line │
    │  + PNG image│  │  per repo  │  │  + run summary │
    └─────────────┘  └────────────┘  └────────────────┘
```

### Data flow for a single repository

```
URL / path
  │
  ├─ is URL? → git clone --depth 1 → temp dir
  │
  ├─ trivy fs --format json  (async subprocess, timeout)
  │    └─ stdout → Pydantic TrivyReport model
  │
  ├─ GitHub API (concurrent with trivy, not blocking)
  │    └─ stars, forks → Popularity dataclass
  │
  ├─ aggregate()  →  SeverityCounts + filtered Vulnerability list
  │
  ├─ render_dependency_graph()
  │    └─ builds DOT source (no binary needed)
  │    └─ renders PNG via graphviz `dot` if available
  │
  ├─ write_result()  →  results/<slug>/report.json
  │
  └─ print_repo_result()  →  stdout (Rich / plain)
```

### Project layout

```
src/code_guardian/
├── cli.py               # Typer entry point, exit code logic
├── config.py            # Pydantic Settings (env vars + CLI overrides)
├── orchestrator.py      # async pipeline, semaphore, error isolation
├── scanner/
│   ├── trivy.py         # subprocess runner, timeout, Docker fallback
│   └── models.py        # Pydantic models for Trivy JSON output
├── enrichment/
│   └── github.py        # async GitHub API client, in-memory cache
├── graph/
│   └── renderer.py      # Graphviz DOT builder + PNG renderer
├── report/
│   ├── aggregator.py    # severity counts, vuln filtering
│   └── writer.py        # JSON + HTML report writer
└── output/
    └── console.py       # Rich colour summary printer
```

### Resilience table

| Failure | Handling |
|---|---|
| URL unreachable / invalid path | `ScanError` before Trivy runs; other repos continue |
| Trivy not in PATH | Try `docker run aquasec/trivy`; if neither found, exit 3 |
| Trivy non-zero exit | Stderr captured; scan marked failed; run continues |
| Trivy timeout | `asyncio.wait_for` kills process; scan marked failed |
| Malformed Trivy JSON | `TrivyParseError`; raw bytes saved to `trivy_raw.json` |
| GitHub API 404 / rate-limit | Warning logged; popularity set to `null`; scan continues |
| `dot` binary missing | `.dot` source written; PNG skipped with warning |
| Output dir not writable | OS error surfaced early; clear message |

---

## Quick Start

### Docker (recommended)

```bash
docker build -t code-guardian .

docker run --rm \
  -v $(pwd)/results:/workspace/results \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  code-guardian \
  https://github.com/OWASP/NodeGoat \
  https://github.com/OWASP/railsgoat \
  --output-dir /workspace/results \
  --fail-on CRITICAL
```

### Local install

```bash
uv sync --all-extras
uv run code-guardian https://github.com/OWASP/NodeGoat --fail-on CRITICAL
```

Requires: `trivy` and `git` in PATH; optionally `graphviz` for PNG rendering.

---

## CLI Reference

```
code-guardian [OPTIONS] REPO [REPO ...]

Arguments:
  REPO          One or more Git URLs or local filesystem paths

Options:
  --output-dir  Directory for result files          [default: ./results]
  --format      json | html                         [default: json]
  --concurrency Max parallel scans                  [default: 4]
  --timeout     Per-scan timeout seconds            [default: 300]
  --severity    Min severity to include in report   [default: LOW]
  --fail-on     Exit 1 if >= this severity found    [e.g. CRITICAL]
  --github-token  GitHub API token (or GITHUB_TOKEN env var)
  --trivy-backend  auto | native | docker           [default: auto]
  --log-level   debug | info | warning | error      [default: info]
  --log-format  text | json                         [default: text]
  --version     Show version and exit
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All repos scanned; no findings at `--fail-on` threshold |
| 1 | One or more repos had findings at or above `--fail-on` severity |
| 2 | One or more repos failed to scan (Trivy error, unreachable, timeout) |
| 3 | Fatal startup error (bad args, Trivy not found, etc.) |

---

## Output

For each repo a sub-directory is created under `--output-dir`:

```
results/
  OWASP_NodeGoat/
    report.json           # structured report
    dependency_graph.dot  # Graphviz DOT source
    dependency_graph.png  # rendered graph (if `dot` binary available)
```

CRITICAL components are highlighted in red in the graph.

---

## Running Tests

```bash
uv sync --all-extras

# Unit tests (no external deps)
uv run pytest tests/unit/ -v

# Integration tests (requires trivy in PATH)
uv run pytest tests/integration/ -v -m integration

# With coverage
uv run pytest tests/unit/ --cov=src --cov-report=term-missing
```

---

## Key Design Decisions

### Why asyncio over multiprocessing?

Scanning is I/O-bound — Trivy is a subprocess, GitHub is a network call. `asyncio` lets multiple scans and GitHub API fetches run concurrently with zero inter-process overhead. The semaphore caps simultaneous Trivy processes to avoid thrashing disk/CPU. If JSON parsing of a very large output were the bottleneck, `run_in_executor` would offload it to a thread pool without changing the async API.

### How large Trivy outputs are handled

Trivy's JSON for a large monorepo can reach 50–100 MB. Rather than streaming line-by-line (Trivy emits a single JSON object, not NDJSON), `communicate()` buffers the full output under a per-scan timeout. If the result exceeds 50 MB a warning is logged. For the pathological case, switching to `ijson` for incremental parsing is a one-line change in `trivy.py`; the architecture supports it without restructuring.

### Why separate exit codes for "found" vs "failed"?

In CI, exit 1 = "block this PR, we found critical vulns" is intentional. Exit 2 = "the scanner itself crashed" is infrastructure failure that needs different alerting. Conflating them is a footgun: a broken Trivy install would silently pass every scan.

### Why Pydantic for Trivy models?

Trivy's JSON schema evolves across versions (e.g. `Vulnerabilities` is absent rather than empty when there are none). Pydantic handles optional fields, type coercion, and `extra="ignore"` makes the models forward-compatible with new Trivy versions by default. A raw `dict` would either fail on missing keys or require defensive `.get()` everywhere.

### Why JSON as the default output format?

JSON is universally consumable: CI pipelines, SIEM tools, dashboards, Jira automation. HTML is the human-friendly format (`--format html` generates a self-contained single-file report with the graph embedded as base64). Picking JSON as default follows the principle of least surprise for a tool meant to integrate with pipelines.

### Why shallow clone?

`git clone --depth 1` fetches only the working tree, not the full history. For a large repo this saves minutes and gigabytes. Trivy's filesystem scanner only needs the working tree; history is irrelevant to dependency scanning.

### Why structlog over stdlib logging?

In containers, logs are ingested by aggregators (Datadog, CloudWatch, ELK). Structured JSON logs with consistent fields (`repo`, `duration_s`, `error`) are queryable; unstructured strings are not. `--log-format json` switches to JSON emission for production deployments.

### GitHub token is optional

Without a token the GitHub API allows 60 requests/hour per IP — enough for a one-off scan. If rate-limited, popularity is recorded as `null` and the scan continues. In CI set `GITHUB_TOKEN` for higher limits.

### Trivy backend fallback

`--trivy-backend auto` (default) tries native `trivy` first, then `docker run aquasec/trivy`. This means the tool works in environments where Trivy isn't installed natively (e.g. a plain Python container) without extra configuration.
