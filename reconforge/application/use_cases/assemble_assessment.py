"""Use case: the report step (reviewer-led final assessment assembly)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reconforge.application.ports import (
    ArtifactStore,
    AssessmentContext,
    Console,
    MarkdownRenderer,
    PdfRenderer,
)
from reconforge.application.workspace import WorkspaceLayout
from reconforge.domain.assessment import (
    build_final_assessment,
    build_review_template,
    merge_review_template,
)


@dataclass(frozen=True)
class AssessmentRequest:
    engagement_id: int
    output_root: Path
    database: Path
    reviewer: str | None = None


class AssembleAssessment:
    """Assemble the final assessment from prior artifacts and the review."""

    def __init__(
        self,
        artifacts: ArtifactStore,
        context: AssessmentContext,
        markdown: MarkdownRenderer,
        pdf: PdfRenderer,
        console: Console,
    ):
        self._artifacts = artifacts
        self._context = context
        self._markdown = markdown
        self._pdf = pdf
        self._console = console

    def execute(self, request: AssessmentRequest) -> dict[str, Any]:
        """Write review worksheet, ``assessment.json`` and Markdown/PDF reports."""
        layout = WorkspaceLayout(request.output_root).engagement(
            request.engagement_id
        )

        intel = self._artifacts.load(layout.intel_json, required=False)
        discovery = self._artifacts.load(layout.discovery_json)
        if discovery is None:
            raise FileNotFoundError(
                f"Required input not found: {layout.discovery_json}"
            )
        analysis = self._artifacts.load(layout.analysis_json)
        if analysis is None:
            raise FileNotFoundError(
                f"Required input not found: {layout.analysis_json}"
            )

        discovery_engagement_id = discovery.get("engagement_id")
        if discovery_engagement_id is None:
            raise ValueError("Discovery artifact is missing engagement_id")
        if int(discovery_engagement_id) != request.engagement_id:
            raise ValueError("Discovery engagement_id does not match --engagement")

        template = build_review_template(discovery, analysis)
        existing_review = self._artifacts.load(layout.review_worksheet, required=False)
        review = merge_review_template(existing_review, template)
        if request.reviewer and not review.get("reviewer"):
            review["reviewer"] = request.reviewer

        layout.assessment.mkdir(parents=True, exist_ok=True)
        review_path = self._artifacts.write(
            layout.review_worksheet, review, trailing_newline=True
        )

        db_context = self._context.database_context(
            request.database, request.engagement_id
        )
        input_paths = [layout.discovery_json, layout.analysis_json]
        if layout.intel_json.exists():
            input_paths.append(layout.intel_json)
        manifest = self._context.source_manifest(
            layout.root, request.database, input_paths
        )

        result = build_final_assessment(
            intel, discovery, analysis, review, db_context, manifest
        )

        json_path = self._artifacts.write(
            layout.assessment_json, result, trailing_newline=True
        )

        markdown_path = self._markdown.markdown(result, layout.assessment_markdown)
        pdf_path = self._pdf.pdf(result, layout.assessment_pdf)

        self._console.info("Assessment completed (local-only).")
        self._console.info(f"JSON: {json_path}")
        self._console.info(f"Review worksheet: {review_path}")
        self._console.info(f"Markdown: {markdown_path}")
        self._console.info(f"PDF: {pdf_path}")
        self._console.info(
            "Confirmed vulnerabilities: "
            f"{result['summary']['confirmed_vulnerabilities']}"
        )
        self._console.info(
            f"Potential findings: {result['summary']['potential_findings']}"
        )
        self._console.info(f"Pending review: {result['summary']['pending_review']}")
        self._console.info(
            f"Evidence provenance files: {result['summary']['provenance_files']}"
        )
        if result["review"]["validation_issues"]:
            self._console.info(
                "Review validation issues: "
                f"{len(result['review']['validation_issues'])}"
            )

        return result
