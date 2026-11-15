"""Renderer adapters bridging the report modules to application ports.

The PDF-backed renderers import their report modules lazily inside the
methods so commands that never emit PDFs (init, validate, register,
engagements, passive, intel, analyze Markdown) work without reportlab.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class IntelBriefRenderer:
    """Markdown intelligence brief for the correlate step."""

    def markdown(self, ranked: dict[str, Any], path: Path) -> Path:
        from reconforge.infrastructure.reporting import intel_report

        intel_report.generate_report(ranked, path)
        return path


class DiscoveryReportRenderer:
    """Markdown + PDF reports for the discovery step."""

    def markdown(self, result: dict[str, Any], path: Path) -> Path:
        from reconforge.infrastructure.reporting import discovery_report

        discovery_report.generate_markdown(result, path)
        return path

    def pdf(self, result: dict[str, Any], path: Path) -> Path:
        from reconforge.infrastructure.reporting import pdf_engine

        pdf_engine.generate(result, path)
        return path


class AnalysisReportRenderer:
    """Markdown evidence-analysis report for the analyze step."""

    def markdown(self, result: dict[str, Any], path: Path) -> Path:
        from reconforge.infrastructure.reporting import analysis_report

        analysis_report.generate_markdown(result, path)
        return path


class AssessmentReportRenderer:
    """Markdown + PDF reports for the reviewer-led assessment step."""

    def markdown(self, result: dict[str, Any], path: Path) -> Path:
        from reconforge.infrastructure.reporting import assessment_report

        assessment_report.generate_markdown(result, path)
        return path

    def pdf(self, result: dict[str, Any], path: Path) -> Path:
        from reconforge.infrastructure.reporting import assessment_report

        assessment_report.generate_pdf(result, path)
        return path
