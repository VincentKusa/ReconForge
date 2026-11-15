"""Wikipedia public MediaWiki search connector."""

from __future__ import annotations

import urllib.parse
from typing import Any

from reconforge.infrastructure.http.client import HttpClient


def collect(
    query: str,
    client: HttpClient | None = None,
) -> list[dict[str, Any]]:
    """Search English Wikipedia for public reference material."""
    client = client or HttpClient(requests_per_minute=3)

    params = urllib.parse.urlencode(
        {
            "action": "query",
            "list": "search",
            "srsearch": query,
            "format": "json",
            "srlimit": 10,
        }
    )

    url = f"https://en.wikipedia.org/w/api.php?{params}"

    data = client.get_json(url, cache_ttl=86400)

    search_results = data.get("query", {}).get("search", []) if isinstance(
        data, dict
    ) else []

    return [
        {
            "title": item.get("title"),
            "snippet": (
                item.get("snippet", "")
                .replace('<span class="searchmatch">', "")
                .replace("</span>", "")
            ),
            "pageid": item.get("pageid"),
            "source": "wikipedia",
        }
        for item in search_results
    ]
