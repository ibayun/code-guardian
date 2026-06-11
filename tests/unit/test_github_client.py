from __future__ import annotations

import pytest
import respx
import httpx

from code_guardian.enrichment import github as gh_module
from code_guardian.enrichment.github import fetch_popularity, _parse_github_url


@pytest.fixture(autouse=True)
def clear_cache() -> None:
    gh_module._cache.clear()


class TestParseGithubUrl:
    def test_https_url(self) -> None:
        result = _parse_github_url("https://github.com/OWASP/NodeGoat")
        assert result == ("OWASP", "NodeGoat")

    def test_https_git_suffix(self) -> None:
        result = _parse_github_url("https://github.com/OWASP/NodeGoat.git")
        assert result == ("OWASP", "NodeGoat")

    def test_ssh_url(self) -> None:
        result = _parse_github_url("git@github.com:OWASP/NodeGoat.git")
        assert result == ("OWASP", "NodeGoat")

    def test_local_path(self) -> None:
        assert _parse_github_url("/tmp/my-repo") is None

    def test_non_github_url(self) -> None:
        assert _parse_github_url("https://gitlab.com/user/repo") is None


class TestFetchPopularity:
    @respx.mock
    async def test_successful_fetch(self) -> None:
        respx.get("https://api.github.com/repos/OWASP/NodeGoat").mock(
            return_value=httpx.Response(
                200,
                json={
                    "stargazers_count": 1847,
                    "forks_count": 891,
                    "description": "A vulnerable app for OWASP training",
                },
            )
        )
        result = await fetch_popularity("https://github.com/OWASP/NodeGoat")
        assert result is not None
        assert result.stars == 1847
        assert result.forks == 891

    @respx.mock
    async def test_404_returns_none(self) -> None:
        respx.get("https://api.github.com/repos/OWASP/NodeGoat").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await fetch_popularity("https://github.com/OWASP/NodeGoat")
        assert result is None

    @respx.mock
    async def test_rate_limit_returns_none(self) -> None:
        respx.get("https://api.github.com/repos/OWASP/NodeGoat").mock(
            return_value=httpx.Response(403, json={"message": "rate limit exceeded"})
        )
        result = await fetch_popularity("https://github.com/OWASP/NodeGoat")
        assert result is None

    async def test_local_path_returns_none(self) -> None:
        result = await fetch_popularity("/tmp/local-repo")
        assert result is None

    @respx.mock
    async def test_caching(self) -> None:
        respx.get("https://api.github.com/repos/OWASP/NodeGoat").mock(
            return_value=httpx.Response(
                200,
                json={"stargazers_count": 100, "forks_count": 50, "description": ""},
            )
        )
        r1 = await fetch_popularity("https://github.com/OWASP/NodeGoat")
        r2 = await fetch_popularity("https://github.com/OWASP/NodeGoat")
        assert r1 is r2
        # Only one real HTTP call should have been made
        assert respx.calls.call_count == 1
