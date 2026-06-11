from __future__ import annotations

import sys

from rich.console import Console
from rich.table import Table
from rich import box

from code_guardian.report.aggregator import RepoResult, SeverityCounts

_console = Console(stderr=False)
_err_console = Console(stderr=True)


def _severity_str(counts: SeverityCounts) -> str:
    parts = []
    if counts.critical:
        parts.append(f"[bold red]CRITICAL: {counts.critical}[/]")
    if counts.high:
        parts.append(f"[red]HIGH: {counts.high}[/]")
    if counts.medium:
        parts.append(f"[yellow]MEDIUM: {counts.medium}[/]")
    if counts.low:
        parts.append(f"[green]LOW: {counts.low}[/]")
    if counts.unknown:
        parts.append(f"[dim]UNKNOWN: {counts.unknown}[/]")
    return "  ".join(parts) if parts else "[dim]No findings[/]"


def print_repo_result(result: RepoResult) -> None:
    if result.scan_error:
        _console.print(
            f"[bold red]✗[/] [bold]{result.repo}[/]  "
            f"[[dim]{result.duration_s:.1f}s[/]]"
        )
        _console.print(f"  [red]Error:[/] {result.scan_error}")
        return

    _console.print(
        f"[bold green]✓[/] [bold]{result.repo}[/]  "
        f"[[dim]{result.duration_s:.1f}s[/]]"
    )

    if result.popularity:
        _console.print(
            f"  Stars: [cyan]{result.popularity.stars:,}[/]  "
            f"Forks: [cyan]{result.popularity.forks:,}[/]"
        )

    _console.print(f"  {_severity_str(result.severity_counts)}")

    if result.result_file_path:
        _console.print(f"  Report: [dim]{result.result_file_path}[/]")

    _console.print()


def print_run_summary(results: list[RepoResult]) -> None:
    succeeded = [r for r in results if not r.scan_error]
    failed = [r for r in results if r.scan_error]

    total_counts = SeverityCounts()
    for r in succeeded:
        total_counts.critical += r.severity_counts.critical
        total_counts.high += r.severity_counts.high
        total_counts.medium += r.severity_counts.medium
        total_counts.low += r.severity_counts.low
        total_counts.unknown += r.severity_counts.unknown

    _console.rule()
    _console.print(
        f"Run complete: [bold]{len(results)}[/] repos · "
        f"[green]{len(succeeded)} succeeded[/] · "
        f"[red]{len(failed)} failed[/]"
    )
    _console.print(f"Total: {_severity_str(total_counts)}")
    _console.rule()
