"""Internet Archive Wayback Machine CDX connector.

Queries the root domain and its subdomains separately. Historical URLs are
evidence of past publication, not proof that the URLs currently exist or
are safe to request.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, urlparse

from reconforge.infrastructure.http.client import HttpClient

CDX = "https://web.archive.org/cdx/search/cdx"


def query_cdx(
    domain: str,
    limit: int,
    client: HttpClient,
    subdomains: bool = False,
    fields: str = "timestamp,original,statuscode,mimetype,digest",
) -> list[dict[str, Any]]:
    """Run one CDX query and return the rows as dicts.

    Shared by this connector and ``reconforge.infrastructure.connectors.archive``, which queries
    the same endpoint with a different field selection.
    """
    pattern = f"*.{domain}/*" if subdomains else f"{domain}/*"

    params = urlencode(
        {
            "url": pattern,
            "output": "json",
            "fl": fields,
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "limit": str(limit),
        }
    )

    data = client.get_json(f"{CDX}?{params}", cache_ttl=21600)

    if not isinstance(data, list) or len(data) < 2:
        return []

    headers = data[0]

    return [
        # strict=False: a short CDX row truncates rather than raising, as before.
        dict(zip(headers, row, strict=False))
        for row in data[1:]
        if isinstance(row, list)
    ]


def _query(domain: str, limit: int, client: HttpClient, subdomains: bool) -> list[dict[str, Any]]:
    """Backward-compatible wrapper used by tests and older callers."""
    return query_cdx(domain, limit, client, subdomains)


def collect(
    domain: str,
    client: HttpClient | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """Collect deduplicated historical URLs for the domain and subdomains."""
    client = client or HttpClient(requests_per_minute=3)

    domain = domain.lower().strip().rstrip(".")

    rows: list[dict[str, Any]] = []
    errors: list[str] = []

    for subdomains in (False, True):
        try:
            rows.extend(query_cdx(domain, limit, client, subdomains))
        except Exception as exc:
            errors.append(str(exc))

    seen: set[str] = set()
    urls: list[dict[str, Any]] = []
    hostnames: set[str] = set()

    for row in rows:
        original = row.get("original", "")
        hostname = (urlparse(original).hostname or "").lower().rstrip(".")

        if not (hostname == domain or hostname.endswith("." + domain)):
            continue

        key = original.lower().rstrip("/")
        if key in seen:
            continue

        seen.add(key)
        hostnames.add(hostname)
        urls.append(row)

    return {
        "source": "internet_archive_wayback",
        "domain": domain,
        "urls": urls,
        "hostnames": sorted(hostnames),
        "count": len(urls),
        "errors": errors,
        "warning": (
            "Historical URLs are not confirmed live. "
            "Do not automatically request archived paths."
        ),
    }
