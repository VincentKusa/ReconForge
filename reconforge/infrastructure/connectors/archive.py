"""Internet Archive CDX historical URL discovery.

Delegates the CDX query to :mod:`reconforge.infrastructure.connectors.wayback`, which owns the
endpoint handling; this connector keeps its own field selection and
result shape (root JSON with a ``urls`` list).
"""

from __future__ import annotations

from typing import Any

from reconforge.infrastructure.connectors.wayback import query_cdx
from reconforge.infrastructure.http.client import HttpClient

ARCHIVE_FIELDS = "timestamp,original,statuscode,mimetype"


def collect(
    domain: str,
    client: HttpClient | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """Collect historical URLs for the domain's subdomains from the CDX."""
    client = client or HttpClient(requests_per_minute=3)

    domain = domain.lower().strip().rstrip(".")

    rows = query_cdx(
        domain,
        limit,
        client,
        subdomains=True,
        fields=ARCHIVE_FIELDS,
    )

    return {
        "domain": domain,
        "urls": rows,
    }
