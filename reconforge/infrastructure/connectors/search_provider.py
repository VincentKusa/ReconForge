"""Search-provider adapter.

Uses configured APIs rather than HTML scraping.
"""

from __future__ import annotations

import os
import urllib.parse
from typing import Any

from reconforge.infrastructure.http.client import HttpClient


def _collect_brave(query: str, client: HttpClient) -> list[dict[str, Any]]:
    key = os.getenv("BRAVE_SEARCH_API_KEY")
    if not key:
        raise RuntimeError("BRAVE_SEARCH_API_KEY is not configured.")

    params = urllib.parse.urlencode({"q": query, "count": 10})
    url = f"https://api.search.brave.com/res/v1/web/search?{params}"

    data = client.get_json(
        url,
        headers={"X-Subscription-Token": key},
        cache_ttl=3600,
    )

    return [
        {
            "title": item.get("title"),
            "url": item.get("url"),
            "description": item.get("description"),
            "source": "brave",
        }
        for item in data.get("web", {}).get("results", [])
    ]


def _collect_serpapi(query: str, client: HttpClient) -> list[dict[str, Any]]:
    key = os.getenv("SERPAPI_API_KEY")
    if not key:
        raise RuntimeError("SERPAPI_API_KEY is not configured.")

    params = urllib.parse.urlencode(
        {"engine": "google", "q": query, "api_key": key}
    )
    url = f"https://serpapi.com/search.json?{params}"

    data = client.get_json(url, cache_ttl=3600)

    return [
        {
            "title": item.get("title"),
            "url": item.get("link"),
            "description": item.get("snippet"),
            "source": "google_via_serpapi",
        }
        for item in data.get("organic_results", [])
    ]


def collect(query: str, client: HttpClient | None = None) -> list[dict[str, Any]]:
    """Run the configured search provider; raise when none is configured."""
    provider = os.getenv("RECONFORGE_SEARCH_PROVIDER", "").lower()

    client = client or HttpClient(requests_per_minute=3)

    if provider == "brave":
        return _collect_brave(query, client)

    if provider == "serpapi":
        return _collect_serpapi(query, client)

    raise RuntimeError(
        "No search provider configured. "
        "Set RECONFORGE_SEARCH_PROVIDER=brave or serpapi and provide its API key."
    )
