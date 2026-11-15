"""Use case: correlate and prioritize stored leads (the intel step)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reconforge.application.ports import ArtifactStore, Console, MarkdownRenderer
from reconforge.application.services.correlation import correlate_engagement
from reconforge.application.workspace import WorkspaceLayout
from reconforge.domain.prioritization import prioritize


@dataclass(frozen=True)
class IntelligenceRequest:
    engagement_id: int
    database: Path
    policy: Path
    exclusions: Path
    output_dir: Path | None = None


class CorrelateIntelligence:
    """Correlate stored leads, prioritize them, and write the intel brief."""

    def __init__(
        self,
        workspace: WorkspaceLayout,
        artifacts: ArtifactStore,
        renderer: MarkdownRenderer,
        console: Console,
    ):
        self._workspace = workspace
        self._artifacts = artifacts
        self._renderer = renderer
        self._console = console

    def execute(self, request: IntelligenceRequest) -> dict[str, Any]:
        """Write ``intel.json`` + Markdown brief; return the correlation summary."""
        layout = self._workspace.engagement(request.engagement_id)
        intel_dir = request.output_dir or layout.intel

        correlation = correlate_engagement(
            str(request.database),
            request.engagement_id,
            str(request.policy),
            str(request.exclusions),
        )

        ranked = prioritize(correlation)

        json_path = self._artifacts.write(intel_dir / "intel.json", ranked)
        markdown_path = self._renderer.markdown(
            ranked, intel_dir / "intel-report.md"
        )

        self._console.info("Intel completed.")
        self._console.info(f"JSON: {json_path}")
        self._console.info(f"Report: {markdown_path}")

        return correlation["summary"]
