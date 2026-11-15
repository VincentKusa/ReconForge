"""Generate a concise Markdown intelligence report.

Accepts either a raw correlation result or an already-prioritized one;
prioritization is applied at most once.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reconforge.domain.prioritization import prioritize


def _escape(value: Any) -> str:
    return str(value).replace("|", "\\|")


def _prioritized_leads_table(result: dict[str, Any], lines: list[str]) -> None:
    """Render the ranked lead table."""
    lines.extend(
        [
            "",
            "## Prioritized leads",
            "",
            "| Priority | Score | Type | Lead | Sources |",
            "|---|---:|---|---|---|",
        ]
    )

    for lead in result["prioritized_leads"]:
        score = lead["assessment"]["score"]
        priority = lead["assessment"]["priority"]

        value = _escape(lead["canonical_value"])
        sources = _escape(", ".join(lead["sources"]))

        lines.append(
            f"| {priority} | {score} | {lead['lead_type']} | `{value}` | {sources} |"
        )


def _evidence_section(result: dict[str, Any], lines: list[str]) -> None:
    """List evidence paths per prioritized lead."""
    lines.extend(["", "## Evidence references", ""])

    for lead in result["prioritized_leads"]:
        lines.append(f"### {lead['lead_type']}: `{lead['canonical_value']}`")

        assessment = lead["assessment"]

        lines.append(f"- Priority: {assessment['priority']}")
        lines.append(f"- Score: {assessment['score']}/100")
        lines.append(f"- Independent sources: {assessment['source_count']}")

        for observation in lead["observations"]:
            lines.append(
                f"- {observation['source']}: "
                f"{observation.get('evidence_path') or 'No evidence path recorded'}"
            )

        lines.append("")


def generate_report(correlation_result: dict[str, Any], output_path: str | Path) -> str:
    """Generate the Markdown intelligence report and return its path."""
    result = (
        correlation_result
        if "prioritized_leads" in correlation_result
        else prioritize(correlation_result)
    )

    summary = result["summary"]

    lines = [
        "# ReconForge Intelligence Report",
        "",
        f"**Engagement:** {result['engagement_id']}",
        f"**Target:** {result['target']}",
        f"**Target type:** {result['target_type']}",
        f"**Mode:** {result['mode']}",
        "**Generated:** " + datetime.now(timezone.utc).isoformat(),
        "",
        "## Executive summary",
        "",
        f"- Observations reviewed: {summary['observations_reviewed']}",
        f"- In-scope lead groups: {summary['in_scope_groups']}",
        f"- Excluded observations: {summary['excluded_observations']}",
    ]

    _prioritized_leads_table(result, lines)
    _evidence_section(result, lines)

    lines.extend(
        [
            "",
            "## Excluded observations",
            "",
            "These observations were excluded from in-scope "
            "correlation. They must not be treated as authorized "
            "testing targets.",
            "",
        ]
    )

    for item in result["excluded_observations"]:
        lines.append(f"- `{item['value']}` — {item['scope_reason']}")

    lines.extend(
        [
            "",
            "## Assessment limitations",
            "",
            "- Scores are triage indicators, not vulnerability ratings.",
            "- Multiple observations do not necessarily mean independent confirmation.",
            "- Public-source discovery does not prove ownership or authorization.",
            "- Excluded assets require separate written authorization.",
            "- No active testing is authorized by this report.",
            "",
            "## Recommended next steps",
            "",
            "1. Manually verify high-priority leads.",
            "2. Review evidence and confirm source independence.",
            "3. Check every proposed assessment asset against written scope.",
            "4. Obtain explicit approval before any active testing.",
            "",
        ]
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")

    return str(output)


#: Descriptive alias so every report module exposes generate_markdown.
generate_markdown = generate_report
