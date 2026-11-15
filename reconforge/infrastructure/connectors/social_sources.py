"""Policy-safe social platform connector registry.

No scraping, login automation, CAPTCHA bypass, or access-control
circumvention. Implementations should use official APIs or explicitly
permitted public datasets.
"""

from __future__ import annotations

from typing import Any

SUPPORTED: dict[str, dict[str, str]] = {
    "linkedin": {
        "status": "adapter_only",
        "method": "approved API / permitted public sources",
    },
    "x": {
        "status": "adapter_only",
        "method": "official API / permitted public sources",
    },
    "facebook": {
        "status": "adapter_only",
        "method": "official API / permitted public sources",
    },
}


def connector_status() -> dict[str, dict[str, str]]:
    """Return the registry of supported-but-adapter-only platforms."""
    return SUPPORTED.copy()


def collect(platform: str, query: str) -> Any:
    """Social collection is intentionally not implemented."""
    if platform not in SUPPORTED:
        raise ValueError(f"Unsupported platform: {platform}")

    raise NotImplementedError(
        f"{platform} is intentionally adapter-only "
        "until an approved API or permitted data source is configured."
    )
