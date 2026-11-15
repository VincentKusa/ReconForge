"""Clock helpers shared across layers (pure, no I/O)."""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo


def utcnow() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(ZoneInfo("Africa/Nairobi")).isoformat()
