"""Evidence-led ReconForge Discovery PDF report generator.

Renders the complete technical reconnaissance output: scope, asset
inventory, every parsed port record, fingerprints, findings, decision
tree, artifacts and excluded observations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)

from reconforge.infrastructure.reporting.pdf_style import (
    build_styles,
    color,
    footer_text,
    make_table,
    para,
    pdf_text,
)

SECTION_WIDTHS_PORTS = [30, 12, 13, 12, 16, 20, 25, 65, 65]


def _decision_tree_drawing() -> Drawing:
    """Render the Discovery authorization decision-tree diagram."""
    drawing = Drawing(740, 285)
    center_x, box_w, box_h = 260, 220, 30

    rows = [
        (245, "Registered engagement / target"),
        (198, "Authorization and hostname scope valid?"),
        (151, "Resolved IP explicitly allowlisted?"),
        (104, "Nmap: TCP 1-65535 + service/version + OS"),
        (57, "Preserve raw outputs; parse every returned port"),
        (10, "Recommendations + complete PDF / JSON / Markdown"),
    ]

    for y, label in rows:
        drawing.add(
            Rect(
                center_x,
                y,
                box_w,
                box_h,
                rx=5,
                ry=5,
                fillColor=color("callout_bg"),
                strokeColor=color("blue"),
                strokeWidth=1,
            )
        )
        drawing.add(
            String(
                center_x + box_w / 2,
                y + 11,
                label,
                textAnchor="middle",
                fontName="Helvetica",
                fontSize=8,
                fillColor=color("navy"),
            )
        )

    # Main vertical connectors and arrow heads.
    x = center_x + box_w / 2
    for top, bottom in [(245, 228), (198, 181), (151, 134), (104, 87), (57, 40)]:
        drawing.add(
            Line(x, top, x, bottom, strokeColor=color("blue"), strokeWidth=1)
        )
        drawing.add(
            Polygon(
                [x - 4, bottom + 5, x + 4, bottom + 5, x, bottom],
                fillColor=color("blue"),
                strokeColor=color("blue"),
            )
        )

    # Negative decision branches.
    drawing.add(
        Line(
            center_x + box_w,
            213,
            525,
            213,
            strokeColor=color("alert"),
            strokeWidth=1,
        )
    )
    drawing.add(
        Rect(
            525,
            198,
            195,
            30,
            rx=4,
            ry=4,
            fillColor=color("alert_bg"),
            strokeColor=color("alert"),
        )
    )
    drawing.add(
        String(
            622,
            209,
            "NO: stop active checks",
            textAnchor="middle",
            fontSize=8,
            fillColor=color("alert_text"),
        )
    )

    drawing.add(
        Line(center_x, 166, 215, 166, strokeColor=color("alert"), strokeWidth=1)
    )
    drawing.add(
        Rect(
            10,
            151,
            205,
            30,
            rx=4,
            ry=4,
            fillColor=color("alert_bg"),
            strokeColor=color("alert"),
        )
    )
    drawing.add(
        String(
            112,
            162,
            "NO: exclude IP; no active scan",
            textAnchor="middle",
            fontSize=8,
            fillColor=color("alert_text"),
        )
    )

    drawing.add(String(480, 216, "NO", fontSize=7, fillColor=color("alert")))
    drawing.add(String(225, 169, "NO", fontSize=7, fillColor=color("alert")))
    drawing.add(String(495, 169, "YES", fontSize=7, fillColor=color("blue")))
    drawing.add(String(495, 216, "YES", fontSize=7, fillColor=color("blue")))

    return drawing


def _findings_section(story: list[Any], assessment: dict[str, Any], styles: Any) -> None:
    """Render finding blocks with full detail, kept together per finding."""
    findings = assessment.get("findings", [])

    if not findings:
        story.append(
            para(
                "No rule-based service exposure recommendations were "
                "generated. The full port inventory remains available "
                "above and in JSON evidence.",
                styles,
                "BodyText",
            )
        )

    for finding in findings:
        service = finding.get("service", {})

        story.append(
            KeepTogether(
                [
                    para(
                        f"{finding.get('id')} - "
                        f"{finding.get('title')} "
                        f"[{finding.get('severity')}]",
                        styles,
                        "RFH2",
                    ),
                    para(
                        f"Asset: {finding.get('asset')} | "
                        f"Port: {finding.get('protocol')}/"
                        f"{finding.get('port')} | "
                        f"Service: {service.get('name')} "
                        f"{service.get('product') or ''} "
                        f"{service.get('version') or ''}",
                        styles,
                        "RFSmall",
                    ),
                    para("Evidence: " + str(finding.get("evidence")), styles, "RFSmall"),
                    para(
                        "Potential impact: " + str(finding.get("impact")),
                        styles,
                        "RFSmall",
                    ),
                    para(
                        "Recommendation: " + str(finding.get("recommendation")),
                        styles,
                        "RFSmall",
                    ),
                    para(
                        "Verification: " + str(finding.get("verification")),
                        styles,
                        "RFSmall",
                    ),
                    para(
                        f"Confidence: {finding.get('confidence')} | "
                        f"Status: {finding.get('status')} | "
                        f"CWE: {finding.get('cwe')} | "
                        f"CVSS: {finding.get('cvss')}",
                        styles,
                        "RFSmall",
                    ),
                    HRFlowable(
                        width="100%",
                        thickness=0.4,
                        color=color("grid"),
                    ),
                    Spacer(1, 2 * mm),
                ]
            )
        )


def _inventory_rows(
    data: dict[str, Any], styles: Any
) -> tuple[list[list[Any]], str | None]:
    """Build port-inventory table rows and an explanatory note when empty."""
    assessment = data.get("assessment", {})

    ports: list[list[Any]] = [
        [
            "Asset",
            "Scan",
            "Proto",
            "Port",
            "State",
            "Reason",
            "Service",
            "Product / Version",
            "CPE",
        ]
    ]

    for port in assessment.get("port_inventory", []):
        prodver = " ".join(
            item
            for item in [port.get("product"), port.get("version"), port.get("extrainfo")]
            if item
        )

        ports.append(
            [
                para(port.get("asset"), styles, "RFCell"),
                port.get("scan_type", "-"),
                port.get("protocol", "-"),
                str(port.get("port", "-")),
                port.get("state", "-"),
                port.get("reason", "-"),
                para(port.get("service_name"), styles, "RFCell"),
                para(prodver, styles, "RFCell"),
                para(", ".join(port.get("cpe", [])), styles, "RFCell"),
            ]
        )

    if len(ports) > 1:
        return ports, None

    return _empty_inventory_row(data, styles)


def _empty_inventory_row(
    data: dict[str, Any], styles: Any
) -> tuple[list[list[Any]], str | None]:
    """Distinguish an unexecuted scan from a completed empty scan."""
    nmap_entries = []
    for asset, active_result in data.get("active", {}).items():
        nmap_result = active_result.get("nmap") or {}
        nmap_entries.append(
            (
                asset,
                nmap_result.get("status", "not_run"),
                nmap_result.get("reason") or nmap_result.get("error"),
            )
        )

    if nmap_entries and all(
        status in {"skipped", "not_run", "not_requested"} for _, status, _ in nmap_entries
    ):
        return (
            [
                [
                    para("No scan executed", styles, "RFCell"),
                    "-",
                    "-",
                    "-",
                    "Not run",
                    "Authorization / execution gate",
                    "-",
                    "-",
                    "-",
                ]
            ],
            (
                "Nmap was not executed for the active asset(s). No port results are available; "
                "this must not be interpreted as evidence that the hosts have no open ports. "
                + "; ".join(
                    f"{asset}: {reason or status}" for asset, status, reason in nmap_entries
                )
            ),
        )

    if nmap_entries and all(status == "completed" for _, status, _ in nmap_entries):
        return (
            [
                [
                    para("Scan completed; no records", styles, "RFCell"),
                    "-",
                    "-",
                    "-",
                    "No records",
                    "Nmap completed",
                    "-",
                    "-",
                    "-",
                ]
            ],
            (
                "Nmap completed but returned no individual port records. Review retained Nmap XML "
                "and host-state details before concluding that no ports were discovered."
            ),
        )

    return (
        [
            [
                para("No port records available", styles, "RFCell"),
                "-",
                "-",
                "-",
                "Unknown",
                "Partial / unavailable scan data",
                "-",
                "-",
                "-",
            ]
        ],
        (
            "The port inventory is incomplete: Nmap was not confirmed as completed for every "
            "active asset. Review individual Nmap statuses and error details."
        ),
    )


def _fingerprint_section(story: list[Any], data: dict[str, Any], styles: Any) -> None:
    """Render host/OS fingerprint details for every active asset."""
    for asset, scan in data.get("active", {}).items():
        nmap = scan.get("nmap") or {}

        for phase in ("tcp", "udp"):
            parsed = (nmap.get(phase) or {}).get("parsed") or {}

            for host in parsed.get("hosts", []):
                addrs = ", ".join(
                    str(item.get("address", ""))
                    + (" (" + str(item.get("vendor")) + ")" if item.get("vendor") else "")
                    for item in host.get("addresses", [])
                )

                story.append(
                    para(
                        f"{asset} ({phase}) - "
                        f"state: {host.get('status')}; "
                        f"addresses: {addrs}; "
                        f"hostnames: {', '.join(host.get('hostnames', [])) or '-'}; "
                        f"uptime: {host.get('uptime_seconds') or '-'} seconds; "
                        f"hop distance: {host.get('distance_hops') or '-'}.",
                        styles,
                        "RFSmall",
                    )
                )

                for extra in host.get("extraports", []):
                    story.append(
                        para(
                            f"Additional summarized ports: "
                            f"{extra.get('count')} {extra.get('state')} "
                            f"(reasons: {extra.get('reasons')}). "
                            f"These aggregate states are preserved by "
                            f"Nmap and are not expanded into individual ports by XML.",
                            styles,
                            "RFSmall",
                        )
                    )

                if host.get("os_matches"):
                    for match in host["os_matches"]:
                        story.append(
                            para(
                                f"OS match: {match.get('name')} "
                                f"(accuracy {match.get('accuracy')}%).",
                                styles,
                                "RFSmall",
                            )
                        )
                        for cls in match.get("classes", []):
                            story.append(
                                para(
                                    f"Device class: {cls.get('type')}; "
                                    f"vendor: {cls.get('vendor')}; "
                                    f"OS family/generation: {cls.get('osfamily')} "
                                    f"{cls.get('osgen')}; "
                                    f"CPE: {', '.join(cls.get('cpe', []))}",
                                    styles,
                                    "RFSmall",
                                )
                            )
                else:
                    story.append(
                        para(
                            "OS fingerprint: no reliable match returned.",
                            styles,
                            "RFSmall",
                        )
                    )

    if not data.get("active"):
        story.append(
            para("No active host fingerprinting was performed.", styles, "RFSmall")
        )


def _http_tls_tcp_section(
    story: list[Any], data: dict[str, Any], styles: Any
) -> None:
    """Render HTTP/TLS, authorization and TCP observations per asset."""
    for asset, scan in data.get("active", {}).items():
        http_tls = scan.get("http_tls") or {}

        # Backward compatibility with legacy list-based evidence.
        if isinstance(http_tls, list):
            story.append(
                para(f"{asset} - Legacy HTTP/TLS observations", styles, "RFSmall")
            )
            for entry in http_tls:
                story.append(
                    para(
                        f"Connected IP: {entry.get('connected_ip', '-')}; "
                        f"result: {entry.get('result', {})}",
                        styles,
                        "RFSmall",
                    )
                )

        # Current hostname-authorized HTTP/TLS evidence.
        elif isinstance(http_tls, dict):
            story.append(
                para(
                    f"{asset} - Hostname approval: "
                    f"{scan.get('hostname_approval', 'not recorded')}",
                    styles,
                    "RFSmall",
                )
            )
            story.append(
                para(
                    f"HTTP/TLS status: {http_tls.get('status', 'not recorded')} "
                    f"(authorization: {http_tls.get('authorization_basis', 'not recorded')})",
                    styles,
                    "RFSmall",
                )
            )

            http_result = http_tls.get("result") or {}
            for check_name in ("http", "https", "tls"):
                check = http_result.get(check_name) or {}
                story.append(
                    para(f"{asset} - {check_name.upper()}: {check}", styles, "RFSmall")
                )

        story.append(
            para(
                f"IP authorization: {scan.get('ip_authorization', 'not recorded')}",
                styles,
                "RFSmall",
            )
        )

        for item in scan.get("unauthorized_addresses", []):
            story.append(
                para(
                    f"IP not authorized for TCP/Nmap: "
                    f"{item.get('address')} - {item.get('reason')}",
                    styles,
                    "RFSmall",
                )
            )

        for item in scan.get("excluded_addresses", []):
            story.append(
                para(
                    f"Excluded IP: {item.get('address')} - {item.get('reason')}",
                    styles,
                    "RFSmall",
                )
            )

        nmap = scan.get("nmap") or {}
        story.append(
            para(
                f"{asset} - Nmap status: {nmap.get('status', 'not recorded')}; "
                f"reason/error: {nmap.get('reason') or nmap.get('error') or '-'}",
                styles,
                "RFSmall",
            )
        )

        for per_ip in scan.get("tcp") or []:
            for item in (per_ip.get("result") or {}).get("results", []):
                story.append(
                    para(
                        f"TCP connect observation ({per_ip.get('connected_ip', '-')}): {item}",
                        styles,
                        "RFSmall",
                    )
                )

    if not data.get("active"):
        story.append(
            para(
                "No HTTP/TLS, TCP, or Nmap active checks were performed.",
                styles,
                "RFSmall",
            )
        )


def _artifacts_section(story: list[Any], data: dict[str, Any], styles: Any) -> None:
    """Render Nmap execution artifacts and per-run diagnostics."""
    for asset, scan in data.get("active", {}).items():
        nmap_data = scan.get("nmap") or {}

        if nmap_data.get("error"):
            story.append(
                para(
                    f"{asset} Nmap execution error: {nmap_data.get('error')}",
                    styles,
                    "RFSmall",
                )
            )

        if nmap_data.get("scan_targets"):
            story.append(
                para(
                    f"{asset} approved scan IPs: "
                    f"{', '.join(nmap_data.get('scan_targets', []))}",
                    styles,
                    "RFSmall",
                )
            )

        artifacts = nmap_data.get("artifacts", [])
        if isinstance(artifacts, dict):
            artifacts = [artifacts]

        for artifact_set in artifacts:
            story.append(
                para(
                    f"{asset}: "
                    + "; ".join(
                        f"{key}: {value}" for key, value in artifact_set.items() if value
                    ),
                    styles,
                    "RFSmall",
                )
            )

        for phase in ("tcp", "udp"):
            phase_data = nmap_data.get(phase) or {}
            parsed_phase = phase_data.get("parsed") or {}

            if parsed_phase.get("scan_info") or parsed_phase.get("run_stats"):
                story.append(
                    para(
                        f"{asset} {phase} scan summary: "
                        f"scaninfo={parsed_phase.get('scan_info')}; "
                        f"runstats={parsed_phase.get('run_stats')}",
                        styles,
                        "RFSmall",
                    )
                )

            for run in phase_data.get("scans", []):
                story.append(
                    para(
                        f"{asset} {phase} Nmap run: "
                        f"return code {run.get('returncode')}; "
                        f"timeout={run.get('timed_out', False)}; "
                        f"execution error={run.get('execution_error', '-')}; "
                        f"command: {' '.join(run.get('command', []))}; "
                        f"stderr: {run.get('stderr') or '-'}",
                        styles,
                        "RFSmall",
                    )
                )


def _excluded_section(
    story: list[Any], data: dict[str, Any], styles: Any
) -> int:
    """Render excluded observations; return the count for the empty check."""
    inventory = data.get("inventory", {})
    excluded_count = 0

    for item in inventory.get("excluded", []):
        excluded_count += 1
        story.append(
            para(
                f"{item.get('original_value')} - {item.get('scope_reason')}",
                styles,
                "RFSmall",
            )
        )

    for asset, scan in data.get("active", {}).items():
        if scan.get("skipped"):
            excluded_count += 1
            story.append(
                para(
                    f"Active checks skipped for {asset}: {scan.get('reason')}",
                    styles,
                    "RFSmall",
                )
            )

        for item in scan.get("excluded_addresses", []):
            excluded_count += 1
            story.append(
                para(
                    f"Excluded resolved address for {asset}: "
                    f"{item.get('address')} - {item.get('reason')}",
                    styles,
                    "RFSmall",
                )
            )

    if not excluded_count:
        story.append(
            para("No excluded observations were recorded.", styles, "RFSmall")
        )

    return excluded_count


def generate_pdf(data: dict[str, Any], output_path: str | Path) -> str:
    """Generate the Discovery landscape PDF report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    styles = build_styles("RF")

    story: list[Any] = [
        Spacer(1, 30 * mm),
        para("RECONFORGE", styles, "RFTitle"),
        Paragraph(
            pdf_text("Comprehensive Technical Reconnaissance & Security Assessment"),
            getSampleStyleSheet()["Heading2"],
        ),
        Spacer(1, 8 * mm),
        para(f"Engagement: {data.get('engagement_id', '-')}", styles, "BodyText"),
        para(f"Target: {data.get('target', '-')}", styles, "BodyText"),
        para(f"Assessment mode: {data.get('mode', '-')}", styles, "BodyText"),
        para(
            f"Generated: {datetime.now(timezone.utc).isoformat()}",
            styles,
            "BodyText",
        ),
        Spacer(1, 12 * mm),
        para(
            "CONFIDENTIAL - For the authorized assessment stakeholders only",
            styles,
            "RFCallout",
        ),
        PageBreak(),
    ]

    inventory = data.get("inventory", {})
    assessment = data.get("assessment", {})
    summary = assessment.get("summary", {})

    # 1. Executive Summary
    story += [
        para("1. Executive Summary", styles, "RFH1"),
        para(
            f"In-scope discovered hosts: "
            f"{inventory.get('summary', {}).get('in_scope_hosts', 0)}. "
            f"Ports recorded: {summary.get('ports_recorded', 0)}; "
            f"open ports: {summary.get('open_ports', 0)}; "
            f"provisional recommendations: {summary.get('findings', 0)}.",
            styles,
            "BodyText",
        ),
        Spacer(1, 3 * mm),
    ]

    sev = summary.get("severity_counts", {})
    story.append(
        make_table(
            [
                ["Critical", "High", "Medium", "Low", "Informational"],
                [
                    str(sev.get("Critical", 0)),
                    str(sev.get("High", 0)),
                    str(sev.get("Medium", 0)),
                    str(sev.get("Low", 0)),
                    str(sev.get("Informational", 0)),
                ],
            ],
            [35 * mm] * 5,
            font=8,
        )
    )

    # 2. Scope and Methodology
    story += [
        para(
            "Interpretation: an open port or detected product/version "
            "is an exposure observation, not by itself proof of an "
            "exploitable vulnerability. Severity labels in this report "
            "are provisional triage recommendations and require "
            "contextual validation.",
            styles,
            "RFCallout",
        ),
        para("2. Scope and Methodology", styles, "RFH1"),
        para(
            f"Registered target: {data.get('target', '-')}; "
            f"target type: {data.get('target_type', '-')}; "
            f"mode: {data.get('mode', '-')}. Active discovery is limited "
            f"to assets explicitly approved in the engagement "
            f"configuration and accepted by scope policy.",
            styles,
            "BodyText",
        ),
        para("Passive sources", styles, "RFH2"),
    ]

    for name, result in data.get("passive", {}).items():
        count = (
            result.get("count", result.get("total", "collected"))
            if isinstance(result, dict)
            else "collected"
        )
        story.append(para(f"{name}: {count}", styles, "RFSmall"))

    # 3. Discovered Asset Inventory
    story.append(para("3. Discovered Asset Inventory", styles, "RFH1"))

    assets: list[list[Any]] = [["Hostname", "Sources", "Evidence"]]
    for asset in inventory.get("assets", []):
        hostname = asset.get("hostname") or "-"
        sources = ", ".join(asset.get("sources") or []) or "-"
        evidence_items = asset.get("evidence") or ["-"]

        # Keep every evidence item in its own row.
        for evidence_item in evidence_items:
            assets.append(
                [
                    para(hostname, styles, "RFCell"),
                    para(sources, styles, "RFCell"),
                    para(evidence_item, styles, "RFCell"),
                ]
            )

    if len(assets) == 1:
        assets.append(["No in-scope assets recorded", "-", "-"])

    story.append(make_table(assets, [55 * mm, 45 * mm, 75 * mm]))

    # 4. Complete Port and Service Inventory
    story += [
        para("4. Complete Port and Service Inventory", styles, "RFH1"),
        para(
            "Port records are listed below when available, including "
            "non-open states. Nmap may summarize groups of closed ports "
            "as extraports. If Nmap was skipped or failed, the inventory "
            "status and reason are stated explicitly; raw scan artifacts "
            "are retained when a scan actually runs.",
            styles,
            "RFSmall",
        ),
    ]

    ports, inventory_note = _inventory_rows(data, styles)
    story.append(
        make_table(ports, [w * mm for w in SECTION_WIDTHS_PORTS], font=6)
    )

    if inventory_note:
        story.append(para(inventory_note, styles, "RFCallout"))

    # 5. Host and Operating System Fingerprints
    story.append(para("5. Host and Operating System Fingerprints", styles, "RFH1"))
    _fingerprint_section(story, data, styles)

    # 6. HTTP/TLS and TCP Observations
    story.append(para("6. HTTP/TLS and TCP Observations", styles, "RFH1"))
    _http_tls_tcp_section(story, data, styles)

    # 7. Findings and Recommendations
    story.append(para("7. Findings and Recommendations", styles, "RFH1"))
    _findings_section(story, assessment, styles)

    # 8. Decision Tree
    story += [
        para("8. Decision Tree", styles, "RFH1"),
        _decision_tree_drawing(),
    ]

    for i, step in enumerate(assessment.get("decision_tree", []), 1):
        story.append(para(f"{i}. {step}", styles, "BodyText"))

    # 9. Nmap Execution Artifacts
    story.append(para("9. Nmap Execution Artifacts", styles, "RFH1"))
    _artifacts_section(story, data, styles)

    # 10. Excluded Observations
    story.append(para("10. Excluded Observations", styles, "RFH1"))
    _excluded_section(story, data, styles)

    # 11. Limitations and Interpretation
    story += [
        para("11. Limitations and Interpretation", styles, "RFH1"),
        para(
            "Nmap version detection is probe-based and can be incomplete "
            "or inaccurate. OS fingerprinting depends on privileges and "
            "network responses. UDP top-port scanning is not exhaustive. "
            "A port being open does not establish that a service is "
            "vulnerable, unauthenticated or exploitable. Software "
            "lifecycle status and CVE applicability must be checked "
            "against vendor advisories and exact build/configuration "
            "details. No NSE vulnerability scripts or exploitation "
            "checks are executed by this module.",
            styles,
            "BodyText",
        ),
        para(
            "All parsed port observations are retained in the report "
            "and machine-readable evidence; prioritization changes "
            "order, not inclusion.",
            styles,
            "RFCallout",
        ),
    ]

    page_width = landscape(A4)[0]

    def footer(canvas: Any, doc: Any) -> None:
        footer_text(
            canvas,
            doc,
            page_width,
            "ReconForge | Confidential assessment output",
        )

    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=18 * mm,
        title="ReconForge Technical Assessment",
        author="ReconForge",
    )

    doc.build(story, onFirstPage=footer, onLaterPages=footer)

    return str(path)


def generate(data: dict[str, Any], output_path: str | Path) -> str:
    """Backward-compatible alias for :func:`generate_pdf`."""
    return generate_pdf(data, output_path)
