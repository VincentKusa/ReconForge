"""Public RDAP domain registration lookup."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from reconforge.infrastructure.http.client import HttpClient


def collect(domain: str, client: HttpClient | None = None) -> dict[str, Any]:
    """Collect registration events, nameservers and entities via rdap.org."""
    client = client or HttpClient(requests_per_minute=2)

    domain = domain.lower().strip().rstrip(".")

    url = "https://rdap.org/domain/" + quote(domain, safe=".-")

    data = client.get_json(url, cache_ttl=86400)

    events = [
        {"event": item.get("eventAction"), "date": item.get("eventDate")}
        for item in data.get("events", [])
    ]

    nameservers = [
        item.get("ldhName")
        for item in data.get("nameservers", [])
        if item.get("ldhName")
    ]

    return {
        "source": "rdap",
        "domain": data.get("ldhName", domain),
        "handle": data.get("handle"),
        "status": data.get("status", []),
        "events": events,
        "nameservers": nameservers,
        "entities": [
            {
                "roles": item.get("roles", []),
                "handle": item.get("handle"),
            }
            for item in data.get("entities", [])
        ],
    }
