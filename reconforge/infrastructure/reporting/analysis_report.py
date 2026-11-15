"""Analysis evidence-analysis Markdown report."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reconforge.shared.utils import safe_dict, safe_list

#: Display order for severity roll-ups (most severe first).
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def md(value: Any) -> str:
    """Render a value for a Markdown table cell."""
    if value is None:
        return "Not recorded"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _findings_section(data: dict[str, Any], lines: list[str]) -> None:
    """Render Discovery technical findings with severity and identifier
    highlighting (CWE / CVE / CVSS v3.1)."""
    lines.extend(["", "## 3. Technical Findings", ""])

    findings = safe_list(safe_dict(data.get("technical_assessment")).get("findings"))

    if not findings:
        lines.extend(
            [
                "Discovery recorded no technical findings in `assessment.findings`.",
                "",
                "**Interpretation:** This is an empty recorded findings set, not "
                "evidence that no vulnerabilities exist.",
                "",
            ]
        )
        return

    severity_counts: dict[str, int] = {}
    for finding_value in findings:
        severity_key = str(safe_dict(finding_value).get("severity") or "Unrated")
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

    for index, finding_value in enumerate(findings, 1):
        finding = finding_value if isinstance(finding_value, dict) else {}
        severity = str(finding.get("severity") or "Unrated")
        cvss31 = safe_dict(finding.get("cvss_v3_1"))

        if cvss31.get("vector"):
            cvss_line = (
                f"- **CVSS v3.1:** **{md(cvss31.get('score'))} "
                f"({md(cvss31.get('severity'))})** — `{md(cvss31.get('vector'))}`"
            )
        else:
            # Discovery findings carry an explicit unassigned statement.
            cvss_line = f"- **CVSS v3.1:** {md(finding.get('cvss'))}"

        lines.extend(
            [
                f"### 3.{index} {md(finding.get('title', finding.get('name', 'Finding')))}",
                "",
                f"- **Severity:** **{severity.upper()}**",
                f"- **CWE:** {md(finding.get('cwe'))}",
                f"- **CVE:** {md(finding.get('cve') or 'No applicable CVE established')}",
                cvss_line,
                f"- **Description:** {md(finding.get('description'))}",
                f"- **Evidence:** {md(finding.get('evidence'))}",
                "",
            ]
        )

    lines.extend(
        [
            (
                "CWE identifiers are mapped by the Discovery exposure rules; "
                "CVE identifiers and CVSS v3.1 scores appear only after "
                "reviewer validation — exposure alone never establishes them."
            ),
            "",
        ]
    )


def _tcp_section(tcp: dict[str, Any], lines: list[str]) -> None:
    """Render TCP connectivity observations."""
    lines.extend(
        [
            "",
            "## 4. TCP Observations",
            "",
            "| Asset | Connected IP | Port | State | Interpretation |",
            "|---|---|---:|---|---|",
        ]
    )

    for item in tcp.get("observations", []):
        lines.append(
            f"| {md(item.get('asset'))} "
            f"| {md(item.get('connected_ip'))} "
            f"| {md(item.get('port'))} "
            f"| {md(item.get('state'))} "
            "| Connectivity observation only |"
        )

    if not tcp.get("observations"):
        lines.append("| — | — | — | No observations | — |")

    lines.extend(
        [
            "",
            "TCP connection results indicate reachability from the assessment "
            "environment. They do not establish service identity, origin-server "
            "ownership, or vulnerability.",
        ]
    )


def _http_tls_section(http_tls: dict[str, Any], lines: list[str]) -> None:
    """Render HTTP/TLS result sets and missing-header observations."""
    lines.extend(["", "## 5. HTTP and TLS Observations", ""])

    for item in http_tls.get("results", []):
        lines.extend(
            [
                f"### {md(item.get('asset'))}",
                "",
                f"- **HTTP status:** {md(safe_dict(item.get('http')).get('status_code'))}",
                f"- **HTTPS status:** {md(safe_dict(item.get('https')).get('status_code'))}",
                f"- **TLS protocol:** {md(safe_dict(item.get('tls')).get('protocol'))}",
                f"- **Certificate expiry:** {md(safe_dict(item.get('tls')).get('not_after'))}",
                "",
            ]
        )

    missing = http_tls.get("missing_header_observations", [])
    if missing:
        lines.extend(
            [
                "### Missing-header observations",
                "",
                "| Asset | Scheme | Header | Classification |",
                "|---|---|---|---|",
            ]
        )
        for item in missing:
            lines.append(
                f"| {md(item.get('asset'))} "
                f"| {md(item.get('scheme'))} "
                f"| {md(item.get('header'))} "
                "| Observation — validate context |"
            )
        lines.append("")

    lines.extend(
        [
            "Missing headers are not automatically vulnerabilities. "
            "Review application behavior, deployment architecture, and "
            "applicable security requirements before raising a finding.",
        ]
    )


def _nmap_section(nmap: dict[str, Any], lines: list[str]) -> None:
    """Render Nmap coverage per asset."""
    lines.extend(
        [
            "",
            "## 6. Nmap Coverage",
            "",
            "| Asset | Status | Scans | Completed | Timed out | Failed | Ports parsed |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )

    for asset, result in nmap.items():
        result = safe_dict(result)
        lines.append(
            f"| {md(asset)} "
            f"| {md(result.get('status'))} "
            f"| {md(result.get('scan_count'))} "
            f"| {md(result.get('completed_scans'))} "
            f"| {md(result.get('timed_out_scans'))} "
            f"| {md(result.get('failed_scans'))} "
            f"| {md(result.get('ports_parsed'))} |"
        )

    if not nmap:
        lines.append("| — | Not run | 0 | 0 | 0 | 0 | 0 |")

    lines.extend(
        [
            "",
            "A scan marked partial, timed out, or failed cannot support a "
            "complete statement about port exposure. An empty parsed port list "
            "must not be interpreted as proof that all ports are closed.",
        ]
    )


def _intel_section(intel: dict[str, Any], lines: list[str]) -> None:
    """Render the Intel intelligence summary; leads are not findings."""
    lines.extend(
        [
            "",
            "## 7. Intel Intelligence",
            "",
            f"- **Correlated leads:** {md(intel.get('correlated_leads', 0))}",
            f"- **Prioritized leads:** {md(intel.get('prioritized_leads', 0))}",
            "",
            md(intel.get("interpretation")),
            "",
            "| Lead type | Value | Score | Priority | Sources |",
            "|---|---|---:|---|---:|",
        ]
    )

    for lead in intel.get("top_leads", []):
        lines.append(
            f"| {md(lead.get('lead_type'))} "
            f"| {md(lead.get('canonical_value'))} "
            f"| {md(lead.get('score'))} "
            f"| {md(lead.get('priority'))} "
            f"| {md(lead.get('independent_source_count'))} |"
        )

    if not intel.get("top_leads"):
        lines.append("| — | No Intel leads available | — | — | — |")

    lines.extend(
        [
            "",
            "Intel priority scores are reconnaissance triage indicators. "
            "They are not vulnerability severity ratings.",
        ]
    )


def _coverage_section(coverage: dict[str, Any], lines: list[str]) -> None:
    """Render the per-source evidence coverage matrix."""
    lines.extend(
        [
            "",
            "## 8. Evidence Source Coverage",
            "",
            "Every source consulted during the engagement, with observation "
            "counts. A source marked error failed and must not be treated as "
            "having found nothing; a source with zero observations may simply "
            "not have been attempted for this target type.",
            "",
            "| Source | Category | What it contributes | Observations | Status |",
            "|---|---|---|---:|---|",
        ]
    )

    rows = safe_list(coverage.get("rows"))

    for row in rows:
        status = md(row.get("status"))
        detail = md(row.get("detail"))
        if row.get("status") == "error" and detail != "Not recorded":
            status = f"error ({detail})"
        lines.append(
            f"| {md(row.get('source'))} "
            f"| {md(row.get('category'))} "
            f"| {md(row.get('description'))} "
            f"| {md(row.get('observations'))} "
            f"| {status} |"
        )

    if not rows:
        lines.append("| — | — | No evidence sources recorded | 0 | — |")

    summary = safe_dict(coverage.get("summary"))
    lines.extend(
        [
            "",
            (
                f"Coverage summary: {md(summary.get('sources_reported'))} sources "
                f"reported, {md(summary.get('sources_with_errors'))} with errors, "
                f"{md(summary.get('sources_without_data'))} without observations."
            ),
            "",
        ]
    )


def _gaps_section(gaps: list[dict[str, Any]], lines: list[str]) -> None:
    """Render evidence gaps with follow-up detail."""
    lines.extend(["", "## 9. Evidence Gaps and Follow-up", ""])

    if not gaps:
        lines.extend(["No automated evidence gaps were identified.", ""])
        return

    for index, gap in enumerate(gaps, 1):
        lines.extend(
            [
                f"### {index}. {md(gap.get('area'))}",
                f"- **Status:** {md(gap.get('status'))}",
                f"- **Detail:** {md(gap.get('detail'))}",
                "",
            ]
        )


def generate_markdown(data: dict[str, Any], output_path: str | Path) -> str:
    """Generate the Analysis Markdown report and return its path."""
    summary = data.get("summary", {})
    observations = safe_dict(data.get("observations"))
    tcp = safe_dict(observations.get("tcp"))
    http_tls = safe_dict(observations.get("http_tls"))
    intel = safe_dict(data.get("intel"))
    gaps = safe_list(data.get("evidence_gaps"))
    nmap = safe_dict(data.get("nmap"))
    coverage = safe_dict(data.get("source_coverage"))

    lines = [
        f"# Analysis Evidence Analysis — Engagement {md(data.get('engagement_id'))}",
        "",
        f"- **Target:** {md(data.get('target'))}",
        f"- **Target type:** {md(data.get('target_type'))}",
        f"- **Mode:** {md(data.get('mode'))}",
        f"- **Generated:** {md(data.get('generated_at'))}",
        "",
        "## 1. Executive Summary",
        "",
        (
            f"Analysis reviewed {md(summary.get('technical_findings_recorded'))} "
            "technical findings recorded by Discovery, "
            f"{md(summary.get('tcp_observations'))} TCP observations, and "
            f"{md(summary.get('http_tls_results'))} HTTP/TLS result sets."
        ),
        "",
        (
            "This report consolidates recorded evidence and identifies "
            "coverage limitations. It does not claim that the target is "
            "free of vulnerabilities."
        ),
        "",
        "## 2. Assessment Summary",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Discovery technical findings | {md(summary.get('technical_findings_recorded'))} |",
        f"| Port inventory records | {md(summary.get('port_inventory_records'))} |",
        f"| TCP observations | {md(summary.get('tcp_observations'))} |",
        f"| TCP open observations | {md(summary.get('tcp_open_observations'))} |",
        f"| TCP errors | {md(summary.get('tcp_error_observations'))} |",
        f"| HTTP/TLS result sets | {md(summary.get('http_tls_results'))} |",
        f"| Missing-header observations | {md(summary.get('missing_header_observations'))} |",
        f"| Evidence gaps | {md(summary.get('evidence_gaps'))} |",
    ]

    _findings_section(data, lines)
    _tcp_section(tcp, lines)
    _http_tls_section(http_tls, lines)
    _nmap_section(nmap, lines)
    _intel_section(intel, lines)
    _coverage_section(coverage, lines)
    _gaps_section(gaps, lines)

    lines.extend(
        [
            "",
            "## 10. Recommended Review Actions",
            "",
            "1. Validate whether the observed IP addresses belong to the "
            "authorized assessment target or a shared CDN/reverse-proxy provider.",
            "2. Obtain explicit authorization for any origin infrastructure "
            "before conducting further IP-level testing.",
            "3. Review incomplete Nmap runs and local IPv6 routing limitations "
            "before drawing port-exposure conclusions.",
            "4. Manually assess missing HTTP security headers against the "
            "application's actual requirements.",
            "5. Validate Intel leads before promoting them to technical findings.",
            "6. Assign vulnerability severity only after sufficient evidence "
            "supports impact and exploitability.",
            "",
            "## 11. Methodology and Limitations",
            "",
            "- Analysis performs local analysis of existing JSON evidence only.",
            "- No additional network requests, scans, or exploitation checks are run.",
            "- Intel intelligence and Discovery technical findings remain distinct.",
            "- No CVE, CWE, CVSS score, or vulnerability severity is inferred.",
            "- All conclusions are limited to the evidence available in the input files.",
            "",
        ]
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")

    return str(output_path)


#: Backward-compatible alias for existing callers.
generate_report = generate_markdown
