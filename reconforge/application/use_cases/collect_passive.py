"""Use case: collect passive OSINT intelligence for an engagement."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from reconforge.application.ports import EngagementRepository


@dataclass(frozen=True)
class PassiveCollectionRequest:
    engagement_id: int
    sources: list[str] = field(default_factory=list)
    search_query: str | None = None


class PassiveConnectorRunner(Protocol):
    """Runs the enabled passive connectors for one target."""

    def run(
        self,
        target: str,
        target_type: str,
        engagement_id: int,
        enabled: list[str] | None = None,
        search_query: str | None = None,
    ) -> dict[str, dict[str, Any]]: ...


class CollectPassiveOsint:
    """Run selected passive OSINT connectors for a registered engagement."""

    def __init__(
        self,
        engagements: EngagementRepository,
        runner: PassiveConnectorRunner,
    ):
        self._engagements = engagements
        self._runner = runner

    def execute(self, request: PassiveCollectionRequest) -> dict[str, dict[str, Any]]:
        engagement = self._engagements.require(request.engagement_id)

        return self._runner.run(
            engagement["target"],
            engagement["target_type"],
            request.engagement_id,
            request.sources,
            request.search_query,
        )
