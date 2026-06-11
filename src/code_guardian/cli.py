from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Annotated, Optional

import structlog
import typer

from code_guardian import __version__
from code_guardian.config import Config, Severity
from code_guardian.orchestrator import run
from code_guardian.output.console import print_run_summary
from code_guardian.scanner.trivy import TrivyNotFoundError

app = typer.Typer(
    name="code-guardian",
    help="Security scanner CLI wrapping Trivy with GitHub enrichment and Graphviz reports.",
    no_args_is_help=True,
)


def _configure_logging(level: str, fmt: str) -> None:
    log_level = getattr(logging, level.upper(), logging.INFO)

    if fmt == "json":
        processors = [
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    else:
        processors = [
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ]

    structlog.configure(
        processors=processors,  # type: ignore[arg-type]
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"code-guardian {__version__}")
        raise typer.Exit()


@app.command()
def scan(
    repos: Annotated[list[str], typer.Argument(help="Git URLs or local paths to scan")],
    output_dir: Annotated[Path, typer.Option(help="Directory for result files")] = Path("./results"),
    fmt: Annotated[str, typer.Option("--format", help="Output format: json | html")] = "json",
    concurrency: Annotated[int, typer.Option(help="Max parallel scans")] = 4,
    timeout: Annotated[int, typer.Option(help="Per-scan timeout in seconds")] = 300,
    severity: Annotated[str, typer.Option(help="Min severity to report: LOW|MEDIUM|HIGH|CRITICAL")] = "LOW",
    fail_on: Annotated[Optional[str], typer.Option(help="Exit 1 if >= severity found (e.g. CRITICAL)")] = None,
    github_token: Annotated[Optional[str], typer.Option(envvar="GITHUB_TOKEN", help="GitHub API token")] = None,
    trivy_backend: Annotated[str, typer.Option(help="Trivy backend: auto|native|docker")] = "auto",
    log_level: Annotated[str, typer.Option(help="Log level: debug|info|warning|error")] = "info",
    log_format: Annotated[str, typer.Option(help="Log format: text|json")] = "text",
    version: Annotated[Optional[bool], typer.Option("--version", callback=version_callback, is_eager=True)] = None,
) -> None:
    """Scan one or more Git repositories with Trivy and generate security reports."""

    _configure_logging(log_level, log_format)

    try:
        sev = Severity(severity.upper())
    except ValueError:
        typer.echo(f"Unknown severity: {severity}. Choose from: LOW, MEDIUM, HIGH, CRITICAL", err=True)
        raise typer.Exit(3)

    fail_on_sev: Severity | None = None
    if fail_on:
        try:
            fail_on_sev = Severity(fail_on.upper())
        except ValueError:
            typer.echo(f"Unknown --fail-on severity: {fail_on}", err=True)
            raise typer.Exit(3)

    if fmt not in ("json", "html"):
        typer.echo(f"Unknown format: {fmt}. Choose json or html.", err=True)
        raise typer.Exit(3)

    config = Config(
        output_dir=output_dir,
        format=fmt,  # type: ignore[arg-type]
        concurrency=concurrency,
        timeout=timeout,
        severity=sev,
        fail_on=fail_on_sev,
        github_token=github_token,
        trivy_backend=trivy_backend,  # type: ignore[arg-type]
        log_level=log_level.upper(),
        log_format=log_format,  # type: ignore[arg-type]
    )

    try:
        results = asyncio.run(run(repos, config))
    except TrivyNotFoundError as exc:
        typer.echo(f"Fatal: {exc}", err=True)
        raise typer.Exit(3)
    except KeyboardInterrupt:
        typer.echo("\nAborted.", err=True)
        raise typer.Exit(3)

    print_run_summary(results)

    failed_scans = [r for r in results if r.scan_error]
    if failed_scans:
        raise typer.Exit(2)

    if fail_on_sev:
        for r in results:
            max_sev = r.severity_counts.max_severity()
            if max_sev and max_sev >= fail_on_sev:
                raise typer.Exit(1)

    raise typer.Exit(0)
