from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import httpx
import structlog

log = structlog.get_logger()

_GITHUB_RE = re.compile(
    r"(?:https?://github\.com/|git@github\.com:)(?P<owner>[^/]+)/(?P<repo>[^/.]+?)(?:\.git)?$"
)
_TIMEOUT = 8.0


@dataclass
class Popularity:
    stars: int
    forks: int
    description: str


_cache: dict[str, Optional[Popularity]] = {}


def _parse_github_url(url: str) -> tuple[str, str] | None:
    m = _GITHUB_RE.match(url.strip())
    if m:
        return m.group("owner"), m.group("repo")
    return None


async def fetch_popularity(repo_url: str, token: str | None = None) -> Popularity | None:
    if repo_url in _cache:
        return _cache[repo_url]

    parsed = _parse_github_url(repo_url)
    if not parsed:
        _cache[repo_url] = None
        return None

    owner, repo = parsed
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    api_url = f"https://api.github.com/repos/{owner}/{repo}"

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(api_url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        log.warning("github.api_error", repo=repo_url, status=exc.response.status_code)
        _cache[repo_url] = None
        return None
    except Exception as exc:
        log.warning("github.fetch_failed", repo=repo_url, error=str(exc))
        _cache[repo_url] = None
        return None

    result = Popularity(
        stars=data.get("stargazers_count", 0),
        forks=data.get("forks_count", 0),
        description=data.get("description", "") or "",
    )
    _cache[repo_url] = result
    return result
