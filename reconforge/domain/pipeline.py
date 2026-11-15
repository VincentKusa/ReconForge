"""Pipeline vocabulary: readable, standard names for the workflow steps.

The historical implementation numbered its steps ("intel" ... "report").
This module gives every step of the engagement workflow a standard name
that is used consistently for CLI commands, artifact directories and
report files:

    register -> passive -> intel -> discover -> analyze -> report
"""

from __future__ import annotations

from enum import Enum


class PipelineStep(str, Enum):
    """Named steps of the engagement pipeline (formerly "stages")."""

    INTELLIGENCE = "intel"
    DISCOVERY = "discover"
    ANALYSIS = "analyze"
    ASSESSMENT = "report"

    @property
    def directory_name(self) -> str:
        """Artifact directory name under ``output/engagement-<id>/``."""
        return self.value
