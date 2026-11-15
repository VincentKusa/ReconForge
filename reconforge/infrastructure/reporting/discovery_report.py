"""Generate a Discovery technical reconnaissance Markdown report."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _nmap_status_summary(active: dict[str, Any]) -> list[dict[str, Any]]:
    """Return Nmap execution states for all active assets."""
    entries = []

    for asset, result in active.items():
        nmap = result.get("nmap") or {}
        entries.append(
            {
                "asset": asset,
                "status": nmap.get("status", "not_run"),
                "reason": nmap.get("reason") or nmap.get("error"),
            }
        )

    return entries


def _inventory_status(entries: list[dict[str, Any]]) -> tuple[str, str]:
    """Distinguish an unexecuted scan from a completed empty scan."""
    if not entries:
        return (
            "not_run",
            "No active assets were available for Nmap assessment.",
        )

    statuses = [item["status"] for item in entries]

    if all(status in {"skipped", "not_run", "not_requested"} for status in statuses):
        return (
            "not_run",
            "Nmap was not executed. No port results are available; "
            "this must not be interpreted as evidence that the hosts "
            "have no open ports.",
        )

    if all(status == "completed" for status in statuses):
        return (
            "completed_no_records",
            "Nmap completed but returned no individual port records. "
            "Review retained Nmap XML and host-state details before "
            "concluding that no ports were discovered.",
        )

    return (
        "incomplete",
        "The port inventory is incomplete. Nmap was not confirmed "
        "as completed for every active asset. Review individual "
        "Nmap statuses and error details.",
    )


def _assets_section(data: dict[str, Any], lines: list[str]) -> None:
    """Render the discovered-assets table."""
    lines.extend(
        [
            "",
            "## Discovered assets",
            "",
            "| Host | Sources |",
            "|---|---|",
        ]
    )

    for asset in data.get("inventory", {}).get("assets", []):
        hostname = str(asset.get("hostname", "-")).replace("|", "\\|")
        sources = ", ".join(asset.get("sources", []))
        lines.append(f"| `{hostname}` | {sources} |")


def _passive_section(data: dict[str, Any], lines: list[str]) -> None:
    """Render a field summary for every passive connector result."""
    lines.extend(["", "## Passive collection", ""])

    for name, result in data.get("passive", {}).items():
        lines.extend([f"### {name}", ""])

        if isinstance(result, dict):
            lines.append(f"- Result fields: {', '.join(result.keys())}")

            if result.get("count") is not None:
                lines.append(f"- Records: {result['count']}")

            if result.get("errors"):
                lines.append(f"- Provider errors: {len(result['errors'])}")

        lines.append("")


def _active_section(data: dict[str, Any], lines: list[str]) -> None:
    """Embed each asset's active-check result as JSON evidence."""
    lines.extend(["", "## Active checks", ""])

    if not data.get("active"):
        lines.append("No active checks were performed.")

    for host, result in data.get("active", {}).items():
        lines.extend(
            [
                f"### {host}",
                "",
                "```json",
                _dumps(result),
                "```",
                "",
            ]
        )


def _dumps(data: Any) -> str:
    import json

    return json.dumps(data, indent=2, ensure_ascii=False)


def _port_inventory_section(data: dict[str, Any], lines: list[str]) -> None:
    """Render the complete port inventory with status explanation."""
    assessment = data.get("assessment", {})
    port_inventory = assessment.get("port_inventory", [])

    lines.extend(
        [
            "",
            "## Complete Nmap port and service inventory",
            "",
            (
                "Port records are listed below when available, including "
                "non-open states. Nmap may summarize large groups of "
                "closed ports as extraports; those state counts are "
                "preserved separately. The inventory status distinguishes "
                "a scan that was not run from a completed scan with no "
                "individual port records."
            ),
            "",
            "| Asset | Scan | Protocol | Port | State | Reason | "
            "Service | Product | Version | CPE |",
            "|---|---|---|---:|---|---|---|---|---|---|",
        ]
    )

    for item in port_inventory:
        values = [
            item.get("asset", "-"),
            item.get("scan_type", "-"),
            item.get("protocol", "-"),
            item.get("port", "-"),
            item.get("state", "-"),
            item.get("reason", "-"),
            item.get("service_name") or "-",
            item.get("product") or "-",
            item.get("version") or "-",
            ", ".join(item.get("cpe", [])) or "-",
        ]

        safe_values = [
            str(value).replace("|", "\\|").replace("\n", " ") for value in values
        ]

        lines.append("| " + " | ".join(safe_values) + " |")

    if port_inventory:
        return

    entries = _nmap_status_summary(data.get("active", {}))
    status, explanation = _inventory_status(entries)

    placeholder = {
        "not_run": (
            "| No scan executed | - | - | - | Not run | "
            "Authorization / execution gate | - | - | - | - |"
        ),
        "completed_no_records": (
            "| Scan completed; no port records returned | - | - | "
            "- | No records | Nmap completed | - | - | - | - |"
        ),
        "incomplete": (
            "| No port records available | - | - | - | Unknown | "
            "Partial / unavailable scan data | - | - | - | - |"
        ),
    }[status]

    lines.append(placeholder)
    lines.extend(["", f"**Inventory status: {explanation}**", ""])

    for entry in entries:
        reason = entry["reason"] or "No execution reason recorded."
        lines.append(
            f"- `{entry['asset']}` — Nmap status: `{entry['status']}`. Reason: {reason}"
        )


def _host_details_section(data: dict[str, Any], lines: list[str]) -> None:
    """Render per-host state, addresses and OS matches."""
    lines.extend(["", "## Host and operating-system details", ""])

    for asset, scan in data.get("active", {}).items():
        nmap = scan.get("nmap") or {}

        for phase in ("tcp", "udp"):
            parsed = (nmap.get(phase) or {}).get("parsed") or {}

            for host in parsed.get("hosts", []):
                lines.extend(
                    [
                        f"### {asset} ({phase})",
                        "",
                        f"- Host state: {host.get('status', 'unknown')}",
                        "- Addresses: "
                        + ", ".join(
                            str(item.get("address", ""))
                            for item in host.get("addresses", [])
                        ),
                        "- Hostnames: "
                        + (", ".join(host.get("hostnames", [])) or "-"),
                        "- Uptime seconds: " + str(host.get("uptime_seconds") or "-"),
                    ]
                )

                if host.get("os_matches"):
                    for match in host["os_matches"]:
                        lines.append(
                            f"- OS match: {match.get('name')} "
                            f"(accuracy {match.get('accuracy')}%)"
                        )

                        for cls in match.get("classes", []):
                            lines.append(
                                "  - Device class: "
                                f"{cls.get('type')}; "
                                f"vendor: {cls.get('vendor')}; "
                                f"family: {cls.get('osfamily')}; "
                                f"generation: {cls.get('osgen')}; "
                                f"CPE: {', '.join(cls.get('cpe', []))}"
                            )
                else:
                    lines.append("- OS match: unavailable")

                for extra in host.get("extraports", []):
                    lines.append(
                        f"- Additional summarized ports: "
                        f"{extra.get('count')} {extra.get('state')} "
                        f"({extra.get('reasons')})"
                    )

                lines.append("")


def _fingerprint_summary_section(data: dict[str, Any], lines: list[str]) -> None:
    """Render the per-asset fingerprint summary: services, OS, web, WAF, CVEs."""
    fingerprints = data.get("fingerprints", [])
    if not fingerprints:
        return

    lines.extend(
        [
            "",
            "## Fingerprint summary",
            "",
            (
                "Each asset's fingerprinted services, operating-system "
                "guesses, web server metadata, WAF signal and unvalidated "
                "CVE candidates. CVE candidates are leads for the reviewer "
                "and are never confirmed findings."
            ),
        ]
    )

    for report in fingerprints:
        asset = report.get("asset", "-")
        lines.extend(["", f"### {asset}", ""])

        services = report.get("services", [])
        if services:
            lines.extend(
                [
                    "**Services**",
                    "",
                    "| Port | Proto | Service | Product | Version | Extra | Confidence |",
                    "|---:|---|---|---|---|---|---|",
                ]
            )
            for svc in services:
                values = [
                    str(svc.get("port", "-")),
                    svc.get("protocol") or "-",
                    svc.get("service") or "-",
                    svc.get("product") or "-",
                    svc.get("version") or "-",
                    svc.get("extrainfo") or "-",
                    svc.get("confidence") or "-",
                ]
                safe = [v.replace("|", "\\|").replace("\n", " ") for v in values]
                lines.append("| " + " | ".join(safe) + " |")
        else:
            lines.append("- Services: none fingerprinted")

        os_guesses = report.get("os_guesses", [])
        if os_guesses:
            lines.extend(["", "**Operating system**", ""])
            for guess in os_guesses:
                accuracy = guess.get("accuracy")
                accuracy_text = f"{accuracy}%" if accuracy is not None else "-"
                lines.append(
                    f"- {guess.get('name')} "
                    f"(family: {guess.get('family') or '-'}, "
                    f"accuracy: {accuracy_text}, "
                    f"source: {guess.get('source') or '-'})"
                )
        else:
            lines.extend(["", "- OS: no reliable match returned"])

        web = report.get("web", [])
        if web:
            lines.extend(["", "**Web server**", ""])
            for entry in web:
                technologies = ", ".join(entry.get("technologies") or []) or "-"
                lines.append(f"- URL: {entry.get('url')}")
                lines.append(f"  - Server: {entry.get('server_header') or '-'}")
                lines.append(f"  - Powered-By: {entry.get('powered_by') or '-'}")
                lines.append(f"  - Technologies: {technologies}")
                if entry.get("title"):
                    lines.append(f"  - Title: {entry.get('title')}")

        waf = report.get("waf") or {}
        if waf:
            lines.extend(["", "**WAF**", ""])
            if waf.get("detected"):
                lines.append(
                    f"- Detected: **{waf.get('vendor')}** "
                    f"({waf.get('evidence') or '-'}, confidence: "
                    f"{waf.get('confidence') or '-'})"
                )
            else:
                lines.append(
                    f"- Not detected ({waf.get('evidence') or '-'}, "
                    f"confidence: {waf.get('confidence') or '-'})"
                )

        cves = report.get("cve_candidates", [])
        if cves:
            lines.extend(
                [
                    "",
                    "**CVE candidates (unvalidated — reviewer must confirm)**",
                    "",
                    "| CVE | Product | Version | CVSS | Severity |",
                    "|---|---|---|---:|---|",
                ]
            )
            for cve in cves:
                values = [
                    cve.get("cve_id") or "-",
                    cve.get("product") or "-",
                    cve.get("version") or "-",
                    str(cve.get("cvss_score") if cve.get("cvss_score") is not None else "-"),
                    cve.get("cvss_severity") or "-",
                ]
                safe = [v.replace("|", "\\|").replace("\n", " ") for v in values]
                lines.append("| " + " | ".join(safe) + " |")
            lines.extend(
                [
                    "",
                    "> These are leads only. A banner match does not confirm "
                    "exploitability. The reviewer must validate each candidate "
                    "against vendor advisories and the actual installed build "
                    "before promoting it to a finding.",
                ]
            )


def _findings_section(data: dict[str, Any], lines: list[str]) -> None:
    """Render provisional findings with evidence and verification steps."""
    assessment = data.get("assessment", {})

    lines.extend(["", "## Findings and recommendations", ""])

    for finding in assessment.get("findings", []):
        lines.extend(
            [
                (
                    f"### {finding.get('id')} - "
                    f"{finding.get('title')} "
                    f"[{finding.get('severity')}]"
                ),
                "",
                (
                    f"- Asset: `{finding.get('asset')}`; "
                    f"port: `{finding.get('protocol')}/{finding.get('port')}`"
                ),
                f"- Evidence: {finding.get('evidence')}",
                f"- Potential impact: {finding.get('impact')}",
                f"- Recommendation: {finding.get('recommendation')}",
                f"- Verification: {finding.get('verification')}",
                (
                    f"- Confidence/status: {finding.get('confidence')} "
                    f"/ {finding.get('status')}"
                ),
                (
                    f"- CWE: {finding.get('cwe')}; "
                    f"CVSS: {finding.get('cvss')}"
                ),
                "",
            ]
        )

    lines.extend(["", "## Decision tree", ""])

    for index, decision in enumerate(assessment.get("decision_tree", []), 1):
        lines.append(f"{index}. {decision}")


def generate_markdown(data: dict[str, Any], output_path: str | Path) -> str:
    """Generate the Discovery Markdown report and return its path."""
    inventory_summary = data.get("inventory", {}).get("summary", {})

    lines = [
        "# ReconForge Discovery Technical Reconnaissance",
        "",
        f"**Engagement:** {data['engagement_id']}",
        f"**Target:** {data['target']}",
        f"**Mode:** {data['mode']}",
        "**Generated:** " + datetime.now(timezone.utc).isoformat(),
        "",
        "## Summary",
        "",
        f"- In-scope hosts: {inventory_summary.get('in_scope_hosts', 0)}",
        f"- Excluded observations: {inventory_summary.get('excluded_observations', 0)}",
        f"- Passive modules: {len(data.get('passive', {}))}",
        f"- Active hosts checked: {len(data.get('active', {}))}",
    ]

    _assets_section(data, lines)
    _passive_section(data, lines)
    _active_section(data, lines)
    _port_inventory_section(data, lines)
    _host_details_section(data, lines)
    _fingerprint_summary_section(data, lines)
    _findings_section(data, lines)

    lines.extend(
        [
            "",
            "## Excluded observations",
            "",
            "Excluded assets must not be treated as authorized testing targets.",
            "",
        ]
    )

    for item in data.get("inventory", {}).get("excluded", []):
        lines.append(f"- `{item['original_value']}` — {item['scope_reason']}")

    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- Historical URLs are not confirmed live endpoints.",
            "- DNS results can change and may be affected by caching.",
            "- HTTP headers are observations, not vulnerability proof.",
            "- TCP connectivity does not identify a vulnerability.",
            "- Discovery alone does not authorize active testing.",
            "- An unexecuted Nmap scan provides no evidence about open ports.",
            "- CVE candidates are unvalidated leads, not confirmed findings.",
            "- WAF detection through active probing may be logged or blocked.",
            "",
        ]
    )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")

    return str(path)


#: Backward-compatible alias used by existing callers and tests.
generate = generate_markdown