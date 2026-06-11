from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import structlog

from code_guardian.config import Config
from code_guardian.scanner.models import TrivyReport

log = structlog.get_logger()

_LARGE_OUTPUT_BYTES = 50 * 1024 * 1024  # 50 MB


class TrivyNotFoundError(RuntimeError):
    pass


class ScanError(RuntimeError):
    def __init__(self, message: str, stderr: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr


class TrivyParseError(RuntimeError):
    def __init__(self, message: str, raw: bytes = b"") -> None:
        super().__init__(message)
        self.raw = raw


def _find_trivy_command(backend: str) -> list[str]:
    """Return the command prefix for running Trivy."""
    if backend in ("auto", "native") and shutil.which("trivy"):
        return ["trivy"]
    if backend in ("auto", "docker") and shutil.which("docker"):
        return ["docker", "run", "--rm", "aquasec/trivy"]
    raise TrivyNotFoundError(
        "Trivy not found. Install it (https://github.com/aquasecurity/trivy) "
        "or have Docker available."
    )


async def run_trivy(path: Path, config: Config) -> TrivyReport:
    """Run Trivy on a local path and return a parsed TrivyReport."""
    cmd_prefix = _find_trivy_command(config.trivy_backend)

    # Docker mode: volume-mount the path
    if cmd_prefix[0] == "docker":
        cmd = [
            *cmd_prefix,
            "-v", f"{path}:/scan:ro",
            "fs", "--format", "json", "--quiet", "--dependency-tree", "/scan",
        ]
    else:
        cmd = [
            *cmd_prefix,
            "fs", "--format", "json", "--quiet", "--dependency-tree", str(path),
        ]

    log.debug("trivy.command", cmd=" ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=config.timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise ScanError(f"Trivy timed out after {config.timeout}s")

    if proc.returncode not in (0, 1):
        # Exit code 1 means "vulnerabilities found" in some Trivy versions — that's fine.
        # Any other non-zero is a real failure.
        raise ScanError(
            f"Trivy exited with code {proc.returncode}",
            stderr=stderr.decode(errors="replace"),
        )

    if not stdout.strip():
        # Empty output — no vulnerabilities found, return empty report
        log.info("trivy.no_output", path=str(path))
        return TrivyReport(artifact_name=str(path))

    if len(stdout) > _LARGE_OUTPUT_BYTES:
        log.warning(
            "trivy.large_output",
            size_mb=len(stdout) // (1024 * 1024),
            path=str(path),
        )

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise TrivyParseError(f"Failed to parse Trivy JSON: {exc}", raw=stdout) from exc

    try:
        return TrivyReport.model_validate(data)
    except Exception as exc:
        raise TrivyParseError(f"Trivy output schema error: {exc}", raw=stdout) from exc
