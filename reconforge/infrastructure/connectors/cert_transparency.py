"""Certificate Transparency hostname discovery using crt.sh."""

from __future__ import annotations

import urllib.parse
from typing import Any

from reconforge.infrastructure.http.client import HttpClient


def collect(domain: str, client: HttpClient | None = None) -> dict[str, Any]:
    """Collect certificate hostnames for the domain from crt.sh."""
    client = client or HttpClient(requests_per_minute=3)

    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    url = f"https://crt.sh/?{query}"

    rows = client.get_json(url, cache_ttl=21600)

    names: set[str] = set()
    evidence: list[dict[str, Any]] = []

    for row in rows if isinstance(rows, list) else []:
        name_values = (row.get("name_value") or "").splitlines()

        for name in name_values:
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]

            if name == domain or name.endswith("." + domain):
                names.add(name)

        evidence.append(
            {
                "issuer": row.get("issuer_name"),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
                "common_name": row.get("common_name"),
            }
        )

    return {
        "domain": domain,
        "hostnames": sorted(names),
        "certificates": evidence,
    }
