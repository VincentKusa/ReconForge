"""Use case: the analyze step (local evidence analysis and consolidation)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reconforge.application.ports import ArtifactStore, Console, MarkdownRenderer
from reconforge.application.workspace import WorkspaceLayout
from reconforge.domain.evidence_analysis import build_analysis


@dataclass(frozen=True)
class AnalysisRequest:
    engagement_id: int
    output_root: Path


class AnalyzeEvidence:
    """Consolidate discovery + intel artifacts into the analysis result."""

    def __init__(
        self,
        artifacts: ArtifactStore,
        renderer: MarkdownRenderer,
        console: Console,
    ):
        self._artifacts = artifacts
        self._renderer = renderer
        self._console = console

    def execute(self, request: AnalysisRequest) -> dict[str, Any]:
        """Write ``analyze.json`` + Markdown report; return the analysis result."""
        layout = WorkspaceLayout(request.output_root).engagement(
            request.engagement_id
        )

        discovery = self._artifacts.load(layout.discovery_json)
        if discovery is None:
            raise FileNotFoundError(f"Required input not found: {layout.discovery_json}")
        intel = self._artifacts.load(layout.intel_json, required=False)

        result = build_analysis(discovery, intel)

        json_path = self._artifacts.write(layout.analysis_json, result)
        markdown_path = self._renderer.markdown(result, layout.analysis_markdown)

        self._console.info("Analysis completed.")
        self._console.info(f"JSON: {json_path}")
        self._console.info(f"Report: {markdown_path}")
        self._console.info(
            "Technical findings: "
            f"{result['summary']['technical_findings_recorded']}"
        )
        self._console.info(
            f"TCP open observations: {result['summary']['tcp_open_observations']}"
        )
        self._console.info(f"Evidence gaps: {result['summary']['evidence_gaps']}")

        return result
