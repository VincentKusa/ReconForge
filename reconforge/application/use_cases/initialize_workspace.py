"""Use case: create the local workspace database."""

from __future__ import annotations

from pathlib import Path

from reconforge.application.ports import EngagementRepository


class InitializeWorkspace:
    """Create the local database so engagements can be registered."""

    def __init__(self, engagements: EngagementRepository):
        self._engagements = engagements

    def execute(self) -> Path:
        """Ensure the database/schema exists; return its path."""
        return self._engagements.ensure_schema()
