"""Assessment Markdown and PDF report renderers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reconforge.shared.utils import safe_dict

#: Display order for severity roll-ups (most severe first).
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

#: Hex colors for severity highlighting in the PDF report.
SEVERITY_COLORS = {
    "Critical": "#7a0c0c",
    "High": "#b3261e",
    "Medium": "#b26a00",
    "Low": "#5f6b00",
    "Informational": "#555555",
}


def _md(value: Any) -> str:
    if value is None or value == "":
        return "Not recorded"
    return str(value).replace("|", "\\|").replace("\n", " ")


def generate_markdown(data: dict[str, Any], output_path: str | Path) -> str:
    """Generate the final assessment Markdown report."""
    summary = data.get("summary", {})
    stages = data.get("steps", {})
    coverage = data.get("coverage", {})
    review = data.get("review", {})
    provenance = data.get("evidence_provenance", {})

    lines = [
        f"# ReconForge Final Assessment — Engagement {_md(data.get('engagement_id'))}",
        "",
        f"- **Target:** {_md(data.get('target'))}",
        f"- **Target type:** {_md(data.get('target_type'))}",
        f"- **Mode:** {_md(data.get('mode'))}",
        f"- **Generated:** {_md(data.get('generated_at'))}",
        "- **Handling:** Confidential — authorized assessment stakeholders",
        "",
        "## 1. Executive Summary",
        "",
        (
            f"The final review contains {summary.get('confirmed_vulnerabilities', 0)} "
            "confirmed vulnerabilities, "
            f"{summary.get('potential_findings', 0)} potential findings, "
            f"{summary.get('accepted_observations', 0)} accepted observations, and "
            f"{summary.get('pending_review', 0)} items pending reviewer action."
        ),
        "",
        "A zero confirmed-finding count means no item has met the explicit reviewer-validation requirements in this report. It is not a statement that the target is vulnerability-free.",
        "",
        "## 2. Engagement and Stage Coverage",
        "",
        "| Stage | Status | Detail |",
        "|---|---|---|",
    ]

    for name, item_value in stages.items():
        item = item_value if isinstance(item_value, dict) else {}
        detail = (
            ", ".join(
                f"{key}: {value}"
                for key, value in item.items()
                if key != "status" and value not in (None, {}, [])
            )
            or "—"
        )
        lines.append(f"| {_md(name)} | {_md(item.get('status'))} | {_md(detail)} |")

    metadata = data.get("engagement_metadata") or {}
    lines.extend(
        [
            "",
            "### Engagement registration metadata",
            "",
            f"- **Owner:** {_md(metadata.get('owner'))}",
            f"- **Authorization reference:** {_md(metadata.get('authorization_reference'))}",
            f"- **Registered:** {_md(metadata.get('created_at'))}",
            f"- **Registration status:** {_md(metadata.get('status'))}",
            "",
            "## 3. Confirmed Vulnerabilities",
            "",
        ]
    )

    findings = data.get("final_findings", [])
    if findings:
        severity_counts: dict[str, int] = {}
        for item in findings:
            severity_key = str(item.get("severity") or "Unrated")
            severity_counts[severity_key] = severity_counts.get(severity_key, 0) + 1

        rollup = ", ".join(
            f"{level} {count}"
            for level, count in sorted(
                severity_counts.items(),
                key=lambda pair: -(
                    SEVERITY_ORDER.index(pair[0])
                    if pair[0] in SEVERITY_ORDER
                    else len(SEVERITY_ORDER)
                ),
            )
        )
        lines.extend([f"**Severity roll-up:** {rollup}", ""])

        for index, item in enumerate(findings, 1):
            severity = str(item.get("severity") or "Unrated")
            lines.extend(
                [
                    f"### 3.{index} {_md(item.get('title'))}",
                    "",
                    f"- **Severity:** **{severity.upper()}**",
                    f"- **CVE:** {_md(item.get('cve') or 'No applicable CVE established')}",
                    f"- **CWE:** {_md(item.get('cwe'))}",
                    f"- **CVSS v3.1 score:** {_md(safe_dict(item.get('cvss_v3_1')).get('score'))}",
                    f"- **CVSS v3.1 severity:** {_md(safe_dict(item.get('cvss_v3_1')).get('severity'))}",
                    f"- **CVSS v3.1 vector:** `{_md(safe_dict(item.get('cvss_v3_1')).get('vector'))}`",
                    f"- **CVSS scoring source:** {_md(safe_dict(item.get('cvss_v3_1')).get('source'))}",
                    f"- **Rationale:** {_md(item.get('rationale'))}",
                    f"- **Impact:** {_md(item.get('impact'))}",
                    f"- **Remediation:** {_md(item.get('remediation'))}",
                    f"- **Evidence:** {_md(', '.join(map(str, item.get('evidence_refs', []))))}",
                    f"- **Reviewer:** {_md(item.get('reviewer') or review.get('reviewer'))}",
                    "",
                ]
            )
    else:
        lines.extend(
            [
                "No confirmed vulnerabilities were accepted by the reviewer in the current review worksheet.",
                "",
            ]
        )

    lines.extend(["## 4. Potential Findings", ""])
    if data.get("potential_findings"):
        lines.extend(
            [
                "| Item | Title | Source severity | CWE | Review status | Source |",
                "|---|---|---|---|---|---|",
            ]
        )
        for item in data["potential_findings"]:
            lines.append(
                f"| {_md(item.get('item_id'))} | {_md(item.get('title'))} "
                f"| {_md(item.get('source_severity') or 'Not rated')} "
                f"| {_md(item.get('cwe') or 'Not mapped')} "
                f"| {_md(item.get('review_status'))} | {_md(item.get('source_file'))} |"
            )
    else:
        lines.append("No items were accepted as potential findings.")
    lines.append("")

    lines.extend(
        [
            "",
            "## 5. Accepted Observations",
            "",
            "| Item | Classification | Title | Source |",
            "|---|---|---|---|",
        ]
    )
    if data.get("accepted_observations"):
        for item in data["accepted_observations"]:
            lines.append(
                f"| {_md(item.get('item_id'))} | {_md(item.get('classification'))} "
                f"| {_md(item.get('title'))} | {_md(item.get('source_file'))} |"
            )
    else:
        lines.append("| — | — | No observations accepted through review | — |")

    lines.extend(["", "## 6. Review Queue and Decisions", ""])
    lines.extend(
        [
            "| Item | Source type | Reviewer classification | Status | CVE | CWE | CVSS v3.1 |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for item in review.get("items", []):
        lines.append(
            f"| {_md(item.get('item_id'))} | {_md(item.get('source_type'))} "
            f"| {_md(item.get('classification'))} | {_md(item.get('review_status'))} "
            f"| {_md(item.get('cve') or 'Not established')} | {_md(item.get('cwe'))} "
            f"| {_md(safe_dict(item.get('cvss_v3_1')).get('score'))} |"
        )
    if not review.get("items"):
        lines.append("| — | — | — | — | — | — | No review candidates generated |")

    lines.extend(["", "### Review validation issues", ""])
    if review.get("validation_issues"):
        lines.extend(f"- {issue}" for issue in review["validation_issues"])
    else:
        lines.append("No review schema issues detected.")

    lines.extend(
        [
            "",
            "## 7. Coverage and Limitations",
            "",
            "| Metric | Result |",
            "|---|---:|",
            f"| In-scope hosts | {_md(coverage.get('in_scope_hosts'))} |",
            f"| Excluded observations | {_md(coverage.get('excluded_observations'))} |",
            f"| Port inventory records | {_md(coverage.get('port_inventory_records'))} |",
            f"| TCP observations | {_md(coverage.get('tcp_observations'))} |",
            f"| TCP open observations | {_md(coverage.get('tcp_open_observations'))} |",
            f"| TCP errors | {_md(coverage.get('tcp_error_observations'))} |",
            f"| HTTP/TLS result sets | {_md(coverage.get('http_tls_results'))} |",
            "",
            "### Nmap coverage",
            "",
            "| Asset | Status | Scans | Completed | Timed out | Routing failures | Ports parsed |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )

    for item in coverage.get("nmap_assets", []):
        lines.append(
            f"| {_md(item.get('asset'))} | {_md(item.get('status'))} "
            f"| {_md(item.get('scan_count'))} | {_md(item.get('completed_scans'))} "
            f"| {_md(item.get('timed_out_scans'))} | {_md(item.get('routing_failed_scans'))} "
            f"| {_md(item.get('ports_parsed'))} |"
        )
    if not coverage.get("nmap_assets"):
        lines.append("| — | Not run | 0 | 0 | 0 | 0 | 0 |")

    for item in coverage.get("nmap_assets", []):
        for limitation in item.get("limitations", []):
            lines.append(
                f"- **{_md(item.get('asset'))} Nmap limitation:** {_md(limitation)}"
            )

    lines.extend(["", "### Evidence gaps", ""])
    for gap in coverage.get("evidence_gaps", []):
        lines.append(
            f"- **{_md(gap.get('area'))}** (`{_md(gap.get('status'))}`): "
            f"{_md(gap.get('detail'))}"
        )
    if not coverage.get("evidence_gaps"):
        lines.append("No Analysis evidence gaps were recorded.")

    intel = data.get("intel", {})
    intel_summary = intel.get("summary", {})
    lines.extend(
        [
            "",
            "## 8. Reconnaissance Intelligence (Not Vulnerability Findings)",
            "",
            f"- **Correlated leads:** {_md(summary.get('intel_correlated_leads'))}",
            f"- **Prioritized leads:** {_md(summary.get('intel_prioritized_leads'))}",
            f"- **Observations reviewed:** {_md(intel_summary.get('observations_reviewed'))}",
            "",
            "Intel scores are triage indicators. Leads remain intelligence until separately validated; they are not assigned vulnerability severity in this report.",
            "",
        ]
    )

    if intel.get("top_leads"):
        lines.extend(
            [
                "| Lead type | Value | Score | Priority | Sources |",
                "|---|---|---:|---|---|",
            ]
        )
        for lead in intel["top_leads"]:
            lines.append(
                f"| {_md(lead.get('lead_type'))} | {_md(lead.get('canonical_value'))} "
                f"| {_md(lead.get('score'))} | {_md(lead.get('priority'))} "
                f"| {_md(', '.join(lead.get('sources', [])))} |"
            )
        lines.append("")

    lines.extend(
        [
            "",
            "## 9. Evidence Provenance",
            "",
            f"- **Files hashed:** {_md(provenance.get('file_count'))}",
            f"- **Hash algorithm:** {_md(provenance.get('hash_algorithm'))}",
            "- Full file paths, sizes, and SHA-256 hashes are retained in `assessment.json`.",
            "",
            "| Evidence type | File count |",
            "|---|---:|",
        ]
    )
    for kind, count in provenance.get("counts_by_kind", {}).items():
        lines.append(f"| {_md(kind)} | {_md(count)} |")

    lines.extend(["", "## 10. Methodology and Limitations", ""])
    lines.extend(f"- {item}" for item in data.get("methodology", []))
    if data.get("interpretation_rules"):
        lines.extend(["", "### Evidence interpretation rules", ""])
        lines.extend(f"- {item}" for item in data.get("interpretation_rules", []))
    lines.extend(
        [
            "- CVE identifiers are recorded only when supported by authoritative advisory evidence and a validated affected product/version match; otherwise the report states that no applicable CVE is established.",
            "- CWE identifiers describe the demonstrated weakness. CVSS v3.1 score, severity, vector and scoring source are recorded for confirmed findings; ReconForge validates format/range but does not calculate the score.",
            "- No unverified severity, CWE, CVSS, CVE, exploitability, or impact is inferred.",
            "- The report reflects the evidence and review decisions available at generation time.",
            "",
        ]
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")

    return str(output_path)


def generate_pdf(data: dict[str, Any], output_path: str | Path) -> str:
    """Generate a concise, paginated A4 final assessment PDF.

    ReportLab is imported inside this function so the Markdown report can
    still be generated when the optional PDF dependency is unavailable.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
    )

    from reconforge.infrastructure.reporting.pdf_style import (
        build_styles,
        footer_text,
        make_table,
        para,
        pdf_text,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = build_styles("RF6", small_leading=9.5)

    summary = data.get("summary", {})
    coverage = data.get("coverage", {})

    story: list[Any] = [
        Spacer(1, 28 * mm),
        para("RECONFORGE", styles, "RF6Title"),
        Paragraph(
            pdf_text("Final Security Assessment Report"),
            getSampleStyleSheet()["Heading2"],
        ),
        Spacer(1, 8 * mm),
        para(f"Engagement: {data.get('engagement_id')}", styles, "BodyText"),
        para(f"Target: {data.get('target')}", styles, "BodyText"),
        para(f"Assessment mode: {data.get('mode')}", styles, "BodyText"),
        para(f"Generated: {data.get('generated_at')}", styles, "BodyText"),
        Spacer(1, 12 * mm),
        para(
            "CONFIDENTIAL — For authorized assessment stakeholders only",
            styles,
            "RF6Callout",
        ),
        PageBreak(),
        para("1. Executive Summary", styles, "RF6H1"),
        para(
            f"Confirmed vulnerabilities: {summary.get('confirmed_vulnerabilities', 0)}; "
            f"potential findings: {summary.get('potential_findings', 0)}; "
            f"accepted observations: {summary.get('accepted_observations', 0)}; "
            f"pending review: {summary.get('pending_review', 0)}.",
            styles,
            "BodyText",
        ),
        para(
            "A zero confirmed-finding count is not proof that the target is vulnerability-free. "
            "Only manually accepted items that satisfy the evidence requirements are published as confirmed.",
            styles,
            "RF6Callout",
        ),
        make_table(
            [
                ["Confirmed", "Potential", "Observations", "Pending"],
                [
                    str(summary.get("confirmed_vulnerabilities", 0)),
                    str(summary.get("potential_findings", 0)),
                    str(summary.get("accepted_observations", 0)),
                    str(summary.get("pending_review", 0)),
                ],
            ],
            [42 * mm] * 4,
            font=8,
        ),
        para("2. Stage Coverage", styles, "RF6H1"),
    ]

    step_rows: list[list[Any]] = [["Step", "Status", "Summary"]]
    for name, value in data.get("steps", {}).items():
        item = value if isinstance(value, dict) else {}
        detail = "; ".join(
            f"{key}: {val}"
            for key, val in item.items()
            if key != "status" and val not in (None, {}, [])
        )
        step_rows.append(
            [
                para(name, styles, "RF6Cell"),
                item.get("status", "unknown"),
                para(detail or "—", styles, "RF6Cell"),
            ]
        )

    story.append(make_table(step_rows, [55 * mm, 25 * mm, 88 * mm], font=6))

    metadata = data.get("engagement_metadata") or {}
    story.extend(
        [
            para("Engagement registration", styles, "RF6H2"),
            para(
                f"Owner: {metadata.get('owner', '-')} | Authorization reference: "
                f"{metadata.get('authorization_reference', '-')} | "
                f"Registered: {metadata.get('created_at', '-')} | "
                f"Status: {metadata.get('status', '-')}",
                styles,
                "RF6Small",
            ),
        ]
    )

    story.append(para("3. Confirmed Vulnerabilities", styles, "RF6H1"))
    findings = data.get("final_findings", [])
    if not findings:
        story.append(
            para(
                "No confirmed vulnerabilities were accepted by the reviewer in the current review worksheet.",
                styles,
                "BodyText",
            )
        )
    for index, item in enumerate(findings, 1):
        severity_label = str(item.get("severity") or "Unrated")
        severity_color = SEVERITY_COLORS.get(severity_label, "#555555")
        story.append(
            KeepTogether(
                [
                    para(f"3.{index} {item.get('title')}", styles, "RF6H2"),
                    para(
                        (
                            f"<b>Severity: <font color='{severity_color}'>"
                            f"{severity_label.upper()}</font></b> | "
                            f"CVE: {item.get('cve') or 'No applicable CVE established'} "
                            f"| CWE: {item.get('cwe')}"
                        ),
                        styles,
                        "RF6Small",
                    ),
                    para(
                        f"CVSS v3.1: {safe_dict(item.get('cvss_v3_1')).get('score', 'Not assessed')} "
                        f"({safe_dict(item.get('cvss_v3_1')).get('severity', 'Not assessed')}) | "
                        f"Vector: {safe_dict(item.get('cvss_v3_1')).get('vector', 'Not recorded')} | "
                        f"Source: {safe_dict(item.get('cvss_v3_1')).get('source', 'Not recorded')}",
                        styles,
                        "RF6Small",
                    ),
                    para(f"Rationale: {item.get('rationale')}", styles, "RF6Small"),
                    para(f"Impact: {item.get('impact')}", styles, "RF6Small"),
                    para(f"Remediation: {item.get('remediation')}", styles, "RF6Small"),
                    para(
                        f"Evidence references: {', '.join(map(str, item.get('evidence_refs', [])))}",
                        styles,
                        "RF6Small",
                    ),
                ]
            )
        )

    story.append(
        para("4. Potential Findings and Accepted Observations", styles, "RF6H1")
    )
    review_rows: list[list[Any]] = [
        ["Item", "Classification", "Status", "CVE", "CWE", "CVSS 3.1", "Title"]
    ]
    for item in data.get("review", {}).get("items", []):
        review_rows.append(
            [
                item.get("item_id", "-"),
                item.get("classification", "-"),
                item.get("review_status", "-"),
                item.get("cve") or "—",
                item.get("cwe") or "—",
                str(safe_dict(item.get("cvss_v3_1")).get("score") or "—"),
                para(item.get("title"), styles, "RF6Cell"),
            ]
        )
    if len(review_rows) == 1:
        review_rows.append(["—", "—", "—", "—", "—", "—", "No review items"])

    story.append(
        make_table(
            review_rows,
            [18 * mm, 27 * mm, 18 * mm, 24 * mm, 17 * mm, 18 * mm, 74 * mm],
            font=5,
        )
    )

    story.append(para("5. Coverage and Limitations", styles, "RF6H1"))
    coverage_rows: list[list[Any]] = [["Metric", "Result"]]
    for key in (
        "in_scope_hosts",
        "excluded_observations",
        "port_inventory_records",
        "tcp_observations",
        "tcp_open_observations",
        "tcp_error_observations",
        "http_tls_results",
    ):
        coverage_rows.append(
            [key.replace("_", " ").title(), str(coverage.get(key, 0))]
        )
    story.append(make_table(coverage_rows, [90 * mm, 78 * mm], font=7))

    nmap_rows: list[list[Any]] = [
        ["Asset", "Status", "Scans", "Complete", "Timeout", "Route fail", "Ports"]
    ]
    for item in coverage.get("nmap_assets", []):
        nmap_rows.append(
            [
                para(item.get("asset"), styles, "RF6Cell"),
                item.get("status", "unknown"),
                str(item.get("scan_count", 0)),
                str(item.get("completed_scans", 0)),
                str(item.get("timed_out_scans", 0)),
                str(item.get("routing_failed_scans", 0)),
                str(item.get("ports_parsed", 0)),
            ]
        )
    if len(nmap_rows) == 1:
        nmap_rows.append(["—", "not run", "0", "0", "0", "0", "0"])

    story.append(Spacer(1, 3 * mm))
    story.append(
        make_table(
            nmap_rows,
            [45 * mm, 22 * mm, 17 * mm, 20 * mm, 18 * mm, 23 * mm, 23 * mm],
            font=6,
        )
    )

    for item in coverage.get("nmap_assets", []):
        for limitation in item.get("limitations", []):
            story.append(
                para(
                    f"{item.get('asset')} Nmap limitation: {limitation}",
                    styles,
                    "RF6Small",
                )
            )
    for gap in coverage.get("evidence_gaps", []):
        story.append(
            para(
                f"{gap.get('area')} ({gap.get('status')}): {gap.get('detail')}",
                styles,
                "RF6Small",
            )
        )

    story.append(para("6. Reconnaissance Intelligence", styles, "RF6H1"))
    intel = data.get("intel", {})
    story.append(
        para(
            f"Correlated leads: {summary.get('intel_correlated_leads', 0)}; "
            f"prioritized leads: {summary.get('intel_prioritized_leads', 0)}. "
            "These are triage leads, not vulnerability findings.",
            styles,
            "BodyText",
        )
    )
    lead_rows: list[list[Any]] = [["Type", "Lead", "Score", "Priority"]]
    for lead in intel.get("top_leads", []):
        lead_rows.append(
            [
                para(lead.get("lead_type"), styles, "RF6Cell"),
                para(lead.get("canonical_value"), styles, "RF6Cell"),
                str(lead.get("score", "-")),
                str(lead.get("priority", "-")),
            ]
        )
    if len(lead_rows) > 1:
        story.append(make_table(lead_rows, [30 * mm, 100 * mm, 18 * mm, 20 * mm], font=6))

    story.extend(
        [
            para("7. Evidence Provenance and Methodology", styles, "RF6H1"),
            para(
                f"Files hashed: {data.get('evidence_provenance', {}).get('file_count', 0)}; "
                f"algorithm: {data.get('evidence_provenance', {}).get('hash_algorithm', 'SHA-256')}. "
                "The complete per-file manifest is available in assessment.json.",
                styles,
                "BodyText",
            ),
        ]
    )
    for item in data.get("methodology", []):
        story.append(para(f"• {item}", styles, "RF6Small"))
    if data.get("interpretation_rules"):
        story.append(para("Evidence interpretation rules", styles, "RF6H2"))
        for item in data.get("interpretation_rules", []):
            story.append(para(f"• {item}", styles, "RF6Small"))

    def footer(canvas: Any, document: Any) -> None:
        footer_text(canvas, document, A4[0], "RECONFORGE — CONFIDENTIAL")

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title=f"ReconForge Final Assessment — {data.get('target', '')}",
        author="ReconForge",
    )
    document.build(story, onFirstPage=footer, onLaterPages=footer)

    return str(output_path)
