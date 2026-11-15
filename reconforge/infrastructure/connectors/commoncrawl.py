"""Public Common Crawl index connector."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode, urlparse

from reconforge.infrastructure.http.client import HttpClient

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"


def _parse_records(raw: str) -> list[dict[str, Any]]:
    """Parse the line-delimited JSON index response."""
    records = []

    for line in raw.splitlines():
        if not line.strip():
            continue

        item = json.loads(line)
        records.append(
            {
                "url": item.get("url"),
                "timestamp": item.get("timestamp"),
                "status": item.get("status"),
                "mime": item.get("mime"),
                "filename": item.get("filename"),
                "offset": item.get("offset"),
                "length": item.get("length"),
            }
        )

    return records


def collect(
    domain: str,
    client: HttpClient | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Collect crawl-index records for the domain from the latest collection."""
    client = client or HttpClient(requests_per_minute=2)

    domain = domain.lower().strip().rstrip(".")

    indexes = client.get_json(COLLINFO_URL, cache_ttl=86400)

    if not indexes:
        return {"source": "commoncrawl", "domain": domain, "records": []}

    # Prefer the latest published collection.
    index_id = indexes[0]["id"]

    records: list[dict[str, Any]] = []
    errors: list[str] = []

    for pattern in (f"{domain}/*", f"*.{domain}/*"):
        params = urlencode(
            {
                "url": pattern,
                "output": "json",
                "filter": "status:200",
                "collapse": "urlkey",
                "limit": str(limit),
            }
        )

        url = f"https://index.commoncrawl.org/{index_id}-index?{params}"

        try:
            raw = client.get_text(url, cache_ttl=21600)
            records.extend(_parse_records(raw))
        except Exception as exc:
            errors.append(str(exc))

    # Deduplicate by URL and enforce the domain boundary.
    unique: dict[str, dict[str, Any]] = {}

    for item in records:
        host = (urlparse(item.get("url", "")).hostname or "").lower().rstrip(".")

        if host == domain or host.endswith("." + domain):
            unique[item["url"]] = item

    return {
        "source": "commoncrawl",
        "domain": domain,
        "index": index_id,
        "records": list(unique.values())[:limit],
        "count": len(unique),
        "errors": errors,
    }
