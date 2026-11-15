"""Single source of truth for turning connector results into leads.

Both the passive OSINT runner and the discovery enrichment loop derive
their database leads from the mapping below. Raw connector output always
remains in the JSON evidence files; leads are only the concise,
deduplicated index. Persistence itself lives in the infrastructure layer
(``EvidenceStore``); this module stays pure.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from reconforge.shared.utils import safe_list


@dataclass(frozen=True)
class LeadSpec:
    """How to derive database leads from one connector's result."""

    #: Key of the list inside the result dict; empty means the result itself
    #: is the list (GitHub, Wikipedia and search return bare lists).
    container: str
    #: Item field holding the lead value; empty means the item is the value
    #: (crt.sh hostnames are plain strings).
    value_field: str
    lead_type: str
    source: str
    confidence: int
    relevance: int
    #: Maximum number of leads to record, or None for unlimited.
    limit: int | None = None


LEAD_SPECS: dict[str, LeadSpec] = {
    "crtsh": LeadSpec(
        "hostnames", "", "hostname", "crt.sh", confidence=70, relevance=80,
    ),
    "archive": LeadSpec(
        "urls", "original", "historical_url", "internet_archive",
        confidence=70, relevance=65, limit=100,
    ),
    "wayback": LeadSpec(
        "urls", "original", "historical_url", "wayback_machine",
        confidence=65, relevance=70,
    ),
    "commoncrawl": LeadSpec(
        "records", "url", "historical_url", "commoncrawl",
        confidence=60, relevance=60,
    ),
    "github": LeadSpec(
        "", "url", "repository", "github", confidence=65, relevance=75,
    ),
    "wikipedia": LeadSpec(
        "", "title", "encyclopedia_reference", "wikipedia",
        confidence=45, relevance=35,
    ),
    "search": LeadSpec(
        "", "url", "search_result", "search_provider",
        confidence=45, relevance=55,
    ),
}


def extract_leads(name: str, data: Any) -> Iterator[dict[str, Any]]:
    """Yield lead records for connector *name* given its result *data*."""
    spec = LEAD_SPECS.get(name)

    if spec is None:
        return

    items = safe_list(data) if not spec.container else safe_list(
        data.get(spec.container) if isinstance(data, dict) else None
    )

    if spec.limit is not None:
        items = items[: spec.limit]

    for item in items:
        if spec.value_field:
            value = item.get(spec.value_field) if isinstance(item, dict) else None
        else:
            value = item

        if not value:
            continue

        yield {
            "lead_type": spec.lead_type,
            "value": value,
            "source": spec.source,
            "confidence": spec.confidence,
            "relevance": spec.relevance,
        }
