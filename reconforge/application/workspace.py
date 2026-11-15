"""Filesystem layout of an engagement workspace.

Every artifact location is derived here once instead of being rebuilt
from string fragments in each pipeline step. The layout is immutable and
shared through dependency injection, so renaming an artifact (or adding
one) is a single-point change.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from reconforge.domain.pipeline import PipelineStep


@dataclass(frozen=True)
class EngagementLayout:
    """Artifact paths for one engagement (``output/engagement-<id>/``)."""

    root: Path

    @property
    def evidence(self) -> Path:
        """Raw connector output (one JSON file per collection run)."""
        return self.root / "evidence"

    # -- intelligence (formerly stage 3) ---------------------------------
    @property
    def intel(self) -> Path:
        return self.root / PipelineStep.INTELLIGENCE.value

    @property
    def intel_json(self) -> Path:
        return self.intel / "intel.json"

    @property
    def intel_markdown(self) -> Path:
        return self.intel / "intel-report.md"

    # -- discovery (formerly stage 4) ------------------------------------
    @property
    def discovery(self) -> Path:
        return self.root / PipelineStep.DISCOVERY.value

    @property
    def discovery_json(self) -> Path:
        return self.discovery / "discover.json"

    @property
    def discovery_markdown(self) -> Path:
        return self.discovery / "discover-report.md"

    @property
    def discovery_pdf(self) -> Path:
        return self.discovery / "discover-report.pdf"

    @property
    def nmap_output(self) -> Path:
        return self.discovery / "nmap"

    # -- analysis (formerly stage 5) -------------------------------------
    @property
    def analysis(self) -> Path:
        return self.root / PipelineStep.ANALYSIS.value

    @property
    def analysis_json(self) -> Path:
        return self.analysis / "analyze.json"

    @property
    def analysis_markdown(self) -> Path:
        return self.analysis / "analyze-report.md"

    # -- assessment (formerly stage 6) -----------------------------------
    @property
    def assessment(self) -> Path:
        return self.root / PipelineStep.ASSESSMENT.value

    @property
    def assessment_json(self) -> Path:
        return self.assessment / "assessment.json"

    @property
    def review_worksheet(self) -> Path:
        return self.assessment / "review-worksheet.json"

    @property
    def assessment_markdown(self) -> Path:
        return self.assessment / "assessment.md"

    @property
    def assessment_pdf(self) -> Path:
        return self.assessment / "assessment.pdf"


@dataclass(frozen=True)
class WorkspaceLayout:
    """Anchor for all engagement workspaces (the ``output/`` root)."""

    output_root: Path

    def engagement(self, engagement_id: int) -> EngagementLayout:
        return EngagementLayout(self.output_root / f"engagement-{engagement_id}")
