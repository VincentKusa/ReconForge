"""Use case: list registered engagements."""

from __future__ import annotations

from typing import Any

from reconforge.application.ports import EngagementRepository


class ListEngagements:
    """Return every registered engagement record."""

    def __init__(self, engagements: EngagementRepository):
        self._engagements = engagements

    def execute(self) -> list[dict[str, Any]]:
        return self._engagements.list_all()
