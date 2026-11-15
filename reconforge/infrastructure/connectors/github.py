"""GitHub public REST API connector.

Token is optional and read from GITHUB_TOKEN.
"""

from __future__ import annotations

import os
import urllib.parse
from typing import Any

from reconforge.infrastructure.http.client import HttpClient

API = "https://api.github.com"


def collect(
    query: str,
    client: HttpClient | None = None,
    max_pages: int = 2,
) -> list[dict[str, Any]]:
    """Search public GitHub repositories for the query."""
    client = client or HttpClient()

    headers = {"Accept": "application/vnd.github+json"}

    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results: list[dict[str, Any]] = []

    for page in range(1, max_pages + 1):
        params = urllib.parse.urlencode(
            {"q": query, "per_page": 30, "page": page}
        )
        url = f"{API}/search/repositories?{params}"

        data = client.get_json(url, headers=headers, cache_ttl=1800)

        items = data.get("items", [])
        results.extend(items)

        if len(items) < 30:
            break

    return [
        {
            "name": item.get("full_name"),
            "url": item.get("html_url"),
            "description": item.get("description"),
            "updated_at": item.get("updated_at"),
            "stars": item.get("stargazers_count"),
            "visibility": item.get("visibility"),
            "source": "github",
        }
        for item in results
    ]
