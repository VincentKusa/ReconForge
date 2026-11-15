"""Use case: register an authorized engagement."""

from __future__ import annotations

from dataclasses import dataclass

from reconforge.application.ports import EngagementRepository
from reconforge.domain.scope import Validation, validate_target


@dataclass(frozen=True)
class RegisterEngagementRequest:
    target: str
    target_type: str
    mode: str
    authorization: str
    owner: str


@dataclass(frozen=True)
class RegistrationOutcome:
    """Validation result plus the registered id (or the reason there is none)."""

    validation: Validation
    engagement_id: int | None = None
    error: str | None = None


class RegisterEngagement:
    """Validate a target and record the authorized engagement."""

    def __init__(
        self,
        engagements: EngagementRepository,
        allow_person_targets: bool,
    ):
        self._engagements = engagements
        self._allow_person_targets = allow_person_targets

    def execute(self, request: RegisterEngagementRequest) -> RegistrationOutcome:
        validation = validate_target(
            request.target,
            request.target_type,
            request.mode,
            self._allow_person_targets,
        )

        if not validation.ok:
            return RegistrationOutcome(validation=validation)

        if not request.authorization.strip() or not request.owner.strip():
            return RegistrationOutcome(
                validation=validation,
                error="Authorization reference and owner must be non-empty.",
            )

        engagement_id = self._engagements.register(
            validation.normalized,
            request.target_type,
            request.mode,
            request.authorization.strip(),
            request.owner.strip(),
        )

        return RegistrationOutcome(validation=validation, engagement_id=engagement_id)
