from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from code_guardian.config import Config
from code_guardian.scanner.trivy import run_trivy, TrivyNotFoundError

pytestmark = pytest.mark.integration


@pytest.fixture()
def tiny_repo(tmp_path: Path) -> Path:
    """Create a minimal repo with a package-lock.json that Trivy can scan."""
    pkg = tmp_path / "package-lock.json"
    pkg.write_text('{"name":"test","lockfileVersion":2,"packages":{}}')
    return tmp_path


@pytest.mark.skipif(not shutil.which("trivy"), reason="trivy not in PATH")
async def test_trivy_runs_on_local_path(tiny_repo: Path) -> None:
    config = Config()
    report = await run_trivy(tiny_repo, config)
    assert report.artifact_name != "" or report.results is not None


@pytest.mark.skipif(not shutil.which("trivy"), reason="trivy not in PATH")
async def test_trivy_returns_trivy_report_type(tiny_repo: Path) -> None:
    from code_guardian.scanner.models import TrivyReport
    config = Config()
    report = await run_trivy(tiny_repo, config)
    assert isinstance(report, TrivyReport)
