"""Use case: validate a target against syntax and scope rules."""

from __future__ import annotations

from dataclasses import dataclass

from reconforge.domain.scope import Validation, validate_target


@dataclass(frozen=True)
class ValidateTargetRequest:
    target: str
    target_type: str
    mode: str


class ValidateTarget:
    """Check target syntax and engagement mode without persisting anything."""

    def __init__(self, allow_person_targets: bool):
        self._allow_person_targets = allow_person_targets

    def execute(self, request: ValidateTargetRequest) -> Validation:
        return validate_target(
            request.target,
            request.target_type,
            request.mode,
            self._allow_person_targets,
        )
