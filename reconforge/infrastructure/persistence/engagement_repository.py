"""SQLite adapter for engagement records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reconforge.domain.errors import EngagementNotFoundError
from reconforge.infrastructure.persistence.database import (
    connect,
    get_engagement,
    list_engagements,
    register_engagement,
)


class SqliteEngagementRepository:
    """Engagement persistence bound to one database file."""

    def __init__(self, database_path: str | Path):
        self._database_path = str(database_path)

    def ensure_schema(self) -> Path:
        """Create the database/schema if needed; return its path."""
        path = Path(self._database_path)
        connect(path).close()
        return path

    def register(
        self,
        normalized_target: str,
        target_type: str,
        mode: str,
        authorization: str,
        owner: str,
    ) -> int:
        return register_engagement(
            self._database_path,
            normalized_target,
            target_type,
            mode,
            authorization,
            owner,
        )

    def get(self, engagement_id: int) -> dict[str, Any] | None:
        return get_engagement(self._database_path, engagement_id)

    def require(self, engagement_id: int) -> dict[str, Any]:
        """Return the engagement or raise EngagementNotFoundError."""
        engagement = self.get(engagement_id)

        if not engagement:
            raise EngagementNotFoundError("Engagement does not exist.")

        return engagement

    def list_all(self) -> list[dict[str, Any]]:
        return list_engagements(self._database_path)
