from __future__ import annotations

import asyncio
import shutil
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import structlog

from code_guardian.config import Config, Severity
from code_guardian.enrichment.github import fetch_popularity
from code_guardian.graph.renderer import render_dependency_graph
from code_guardian.output.console import print_repo_result
from code_guardian.report.aggregator import RepoResult, SeverityCounts, aggregate
from code_guardian.report.writer import write_result
from code_guardian.scanner.models import TrivyReport
from code_guardian.scanner.trivy import (
    ScanError,
    TrivyParseError,
    run_trivy,
)

log = structlog.get_logger()


def _repo_slug(repo: str) -> str:
    """Derive a filesystem-safe directory name from a repo URL or path."""
    parsed = urlparse(repo)
    if parsed.scheme in ("http", "https", "git", "ssh"):
        path_part = parsed.path.rstrip("/").lstrip("/")
        return path_part.replace("/", "_").replace(".git", "") or "repo"
    return Path(repo).name or "local"


def _is_url(repo: str) -> bool:
    scheme = urlparse(repo).scheme
    return scheme in ("http", "https", "git", "ssh")


async def _clone_repo(url: str, target: Path, timeout: int) -> None:
    log.info("repo.cloning", url=url)
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", "--quiet", url, str(target),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise ScanError(f"git clone timed out after {timeout}s")

    if proc.returncode != 0:
        msg = stderr.decode(errors="replace").strip()
        raise ScanError(f"git clone failed: {msg}")


async def scan_repo(repo: str, sem: asyncio.Semaphore, config: Config) -> RepoResult:
    slug = _repo_slug(repo)
    repo_output_dir = config.output_dir / slug
    repo_output_dir.mkdir(parents=True, exist_ok=True)

    start = time.monotonic()
    tmp_dir: tempfile.TemporaryDirectory[str] | None = None
    scan_path_str = repo

    try:
        # Resolve scan path
        if _is_url(repo):
            tmp_dir = tempfile.TemporaryDirectory()
            clone_target = Path(tmp_dir.name) / slug
            await _clone_repo(repo, clone_target, config.timeout)
            scan_path = clone_target
            scan_path_str = str(scan_path)
        else:
            scan_path = Path(repo)
            if not scan_path.exists():
                raise ScanError(f"Local path does not exist: {repo}")

        # Run Trivy + fetch popularity concurrently
        async with sem:
            log.info("scan.started", repo=repo)
            trivy_task = asyncio.create_task(run_trivy(scan_path, config))
            github_task = asyncio.create_task(
                fetch_popularity(repo, token=config.github_token)
            )
            report, popularity = await asyncio.gather(trivy_task, github_task)

        counts, vulns = aggregate(report, min_severity=config.severity)

        # Graph
        dot_path, png_path = render_dependency_graph(report, repo_output_dir)

        duration = time.monotonic() - start
        result = RepoResult(
            repo=repo,
            scan_path=scan_path_str,
            popularity=popularity,
            severity_counts=counts,
            vulnerabilities=vulns,
            duration_s=duration,
            graph_dot_path=dot_path,
            graph_png_path=png_path,
        )

        result.result_file_path = write_result(result, repo_output_dir, config.format)

        log.info("scan.complete", repo=repo, duration_s=round(duration, 2))

    except (ScanError, TrivyParseError) as exc:
        duration = time.monotonic() - start
        result = RepoResult(
            repo=repo,
            scan_path=scan_path_str,
            popularity=None,
            severity_counts=SeverityCounts(),
            vulnerabilities=[],
            scan_error=str(exc),
            duration_s=duration,
        )

        # Still write an error report
        try:
            result.result_file_path = write_result(result, repo_output_dir, config.format)
        except Exception:
            pass

        # Capture raw Trivy output for debugging
        if isinstance(exc, TrivyParseError) and exc.raw:
            raw_path = repo_output_dir / "trivy_raw.json"
            raw_path.write_bytes(exc.raw)
            log.error("scan.parse_error", repo=repo, raw_saved=str(raw_path))
        else:
            log.error("scan.failed", repo=repo, error=str(exc))

    finally:
        if tmp_dir:
            tmp_dir.cleanup()

    print_repo_result(result)
    return result


async def run(repos: list[str], config: Config) -> list[RepoResult]:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(config.concurrency)
    tasks = [scan_repo(repo, sem, config) for repo in repos]
    results = await asyncio.gather(*tasks)
    return list(results)
