"""Analysis: local evidence analysis and consolidation.

Analysis reads Intel/4 artifacts and classifies Nmap/TCP/HTTP evidence
quality without interpreting gaps as clean results.

This module is a library; it is invoked through the single CLI entry point
(``recon.py analyze`` / ``core.cli``).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from reconforge.shared.utils import get_path, safe_dict, safe_list

PASSIVE_SOURCE_LABELS: dict[str, str] = {
    "wayback": "Wayback Machine archive URLs",
    "crtsh": "Certificate Transparency subdomains",
    "rdap": "RDAP/WHOIS registration data",
    "commoncrawl": "Common Crawl indexed paths",
    "dns": "DNS records",
    "whois": "WHOIS registration record",
    "github": "GitHub code/repo mentions",
    "search": "Search-engine results",
    "social": "Social-media profiles",
    "wikipedia": "Wikipedia mentions",
    "archive": "Archive.today snapshots",
}


def _count_payload(result: Any) -> int:
    """Generic observation count for a connector payload.

    Connectors return different shapes (lists of URLs, dicts of DNS
    records, ...); count list-valued fields — including lists nested one
    level deep in grouped dicts (e.g. ``{"records": {"A": [...]}}``) —
    else treat any truthy payload as one observation.
    """
    payload = safe_dict(result)

    if not payload:
        return 0
    if "error" in payload:
        return 0

    listed = 0
    for value in payload.values():
        if isinstance(value, list):
            listed += len(safe_list(value))
        elif isinstance(value, dict):
            listed += sum(
                len(safe_list(nested))
                for nested in value.values()
                if isinstance(nested, list)
            )
    if listed:
        return listed
    return 1 if any(value for value in payload.values()) else 0


def analyse_source_coverage(
    discover: dict[str, Any],
    intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Per-source evidence coverage across passive and active collection.

    Builds one row per evidence source so the report shows every area
    that was collected — not only Nmap — and marks sources that failed
    or returned nothing instead of leaving them invisible.
    """
    rows: list[dict[str, Any]] = []

    # Passive connectors recorded inside the discovery artifact.
    passive_results = safe_dict(discover.get("passive"))
    for name in sorted(passive_results):
        result = safe_dict(passive_results.get(name))
        observations = _count_payload(result)
        rows.append(
            {
                "source": name,
                "category": "passive",
                "description": PASSIVE_SOURCE_LABELS.get(name, "Passive source"),
                "observations": observations,
                "status": "error" if "error" in result else "ok",
                "detail": str(result.get("error")) if "error" in result else "",
            }
        )

    # Intel correlation: per-source observation counts across all leads.
    for source, count in sorted(
        _intel_source_counts(intel).items(), key=lambda item: item[0]
    ):
        rows.append(
            {
                "source": source,
                "category": "intel",
                "description": "Observations contributing to correlated leads",
                "observations": count,
                "status": "ok",
                "detail": "",
            }
        )

    # Active probes recorded per approved asset.
    active = safe_dict(discover.get("active"))
    tcp_observations = 0
    http_tls_assets = 0
    for asset_result in active.values():
        item = safe_dict(asset_result)
        tcp_observations += len(safe_list(safe_dict(item.get("tcp")).get("observations")))
        if item.get("http") or item.get("tls"):
            http_tls_assets += 1

    if active:
        rows.append(
            {
                "source": "tcp_connect",
                "category": "active_probe",
                "description": "TCP connectivity checks on approved IPs",
                "observations": tcp_observations,
                "status": "ok" if tcp_observations else "no_data",
                "detail": "",
            }
        )
        rows.append(
            {
                "source": "http_tls",
                "category": "active_probe",
                "description": "HTTP status + TLS certificate observations",
                "observations": http_tls_assets,
                "status": "ok" if http_tls_assets else "no_data",
                "detail": "",
            }
        )

    nmap_tcp = _nmap_coverage_row(active, "nmap")
    if nmap_tcp:
        rows.append(nmap_tcp)
    nmap_udp = _nmap_coverage_row(active, "nmap_udp")
    if nmap_udp:
        rows.append(nmap_udp)

    errors = [row for row in rows if row["status"] == "error"]
    empty = [row for row in rows if row["status"] == "no_data" or row["observations"] == 0]

    return {
        "rows": rows,
        "summary": {
            "sources_reported": len(rows),
            "sources_with_errors": len(errors),
            "sources_without_data": len(empty),
        },
    }


def _intel_source_counts(intel: dict[str, Any] | None) -> Counter:
    """Observation counts per source across all correlated leads."""
    counts: Counter = Counter()

    for lead in safe_list(safe_dict(intel).get("correlated_leads")):
        for observation in safe_list(safe_dict(lead).get("observations")):
            source = safe_dict(observation).get("source")
            if source:
                counts[str(source)] += 1

    return counts


def _nmap_coverage_row(active: dict[str, Any], key: str) -> dict[str, Any] | None:
    """Aggregate one Nmap scan-type row, or None when not present.

    Real per-asset blocks look like ``{"nmap": {"tcp": {...}, "udp":
    {...}}}`` where each aggregate is ``{"parsed": {"hosts": [...]},
    "scans": [...]}``.
    """
    ports = 0
    scans = 0

    for asset_result in active.values():
        nmap = safe_dict(safe_dict(asset_result).get("nmap"))
        block = nmap.get("tcp") if key == "nmap" else nmap.get("udp")
        if not block:
            continue

        block = safe_dict(block)
        scans += len(safe_list(block.get("scans")))
        for host in safe_list(safe_dict(block.get("parsed")).get("hosts")):
            ports += len(safe_list(safe_dict(host).get("ports")))

    if not scans and not ports:
        return None

    return {
        "source": "nmap_tcp_full_range" if key == "nmap" else "nmap_udp",
        "category": "active_probe",
        "description": (
            "Full TCP port range (-p-) with service/OS detection"
            if key == "nmap"
            else "UDP port sweep"
        ),
        "observations": ports,
        "status": "ok",
        "detail": f"{scans} scan(s) across approved assets",
    }


def analyse_nmap(nmap: Any) -> dict[str, Any]:
    """Classify Nmap coverage without interpreting an empty port list
    as proof that no services are exposed.

    Primary scan outcomes:
      - completed
      - timed out
      - routing failed
      - failed for another reason

    XML parse errors are diagnostic counts and may overlap with
    another primary scan outcome.
    """
    nmap = safe_dict(nmap)

    if not nmap:
        return {
            "status": "not_run",
            "scan_count": 0,
            "completed_scans": 0,
            "timed_out_scans": 0,
            "routing_failed_scans": 0,
            "failed_scans": 0,
            "parse_failed_scans": 0,
            "hosts_parsed": 0,
            "hosts_scanned": 0,
            "ports_parsed": 0,
            "scan_targets": [],
            "artifacts": [],
            "limitations": ["No Nmap result object was recorded."],
        }

    tcp = safe_dict(nmap.get("tcp"))
    udp = safe_dict(nmap.get("udp"))

    scans: list[Any] = []
    for protocol_data in (tcp, udp):
        scans.extend(safe_list(protocol_data.get("scans")))

    timed_out = 0
    routing_failed = 0
    failed = 0
    completed = 0
    parse_errors = 0

    hosts_parsed = 0
    hosts_scanned = 0
    ports_parsed = 0

    for scan in scans:
        if not isinstance(scan, dict):
            failed += 1
            continue

        parsed = safe_dict(scan.get("parsed"))
        diagnostics = (
            f"{scan.get('stdout') or ''}\n{scan.get('stderr') or ''}".lower()
        )

        scan_hosts = [
            host
            for host in safe_list(parsed.get("hosts"))
            if isinstance(host, dict)
        ]

        hosts_parsed += len(scan_hosts)

        if parsed.get("parse_error"):
            parse_errors += 1

        host_timeout = "host timeout" in diagnostics or any(
            str(host.get("timedout", "")).lower() == "true"
            for host in scan_hosts
        )

        route_failure = (
            "failed to determine route" in diagnostics
            or "no targets were specified" in diagnostics
        )

        if scan.get("timed_out") is True or host_timeout:
            timed_out += 1
            continue

        if route_failure:
            routing_failed += 1
            continue

        if scan.get("returncode", 0) not in (0, None):
            failed += 1
            continue

        if parsed.get("parse_error"):
            failed += 1
            continue

        completed += 1
        hosts_scanned += len(scan_hosts)

        for host in scan_hosts:
            ports_parsed += len(safe_list(host.get("ports")))

    # If there are no individual scan records, use protocol-level parsed
    # data as the available inventory evidence. Do not use protocol-level
    # aggregates to imply completed coverage when individual scan records
    # exist but are incomplete.
    if not scans:
        for protocol_data in (tcp, udp):
            parsed = safe_dict(protocol_data.get("parsed"))

            for host in safe_list(parsed.get("hosts")):
                if not isinstance(host, dict):
                    continue

                hosts_parsed += 1
                ports_parsed += len(safe_list(host.get("ports")))

    limitations = [str(item) for item in safe_list(nmap.get("limitations"))]

    if timed_out:
        limitations.append(
            f"{timed_out} Nmap scan(s) timed out; coverage is incomplete."
        )

    if routing_failed:
        limitations.append(
            f"{routing_failed} Nmap scan(s) failed because a network "
            "route could not be determined."
        )

    if failed:
        limitations.append(f"{failed} Nmap scan(s) failed for other reasons.")

    if parse_errors:
        limitations.append(
            f"{parse_errors} scan result(s) contained XML parse errors. "
            "This diagnostic count may overlap with timeout or failure counts."
        )

    if not scans:
        status = "unknown"
    elif timed_out or routing_failed or failed:
        status = "partial"
    elif completed == len(scans):
        status = "completed"
    else:
        status = "unknown"

    return {
        "status": status,
        "scanner_status": nmap.get("status", "unknown"),
        "scan_count": len(scans),
        "completed_scans": completed,
        "timed_out_scans": timed_out,
        "routing_failed_scans": routing_failed,
        "failed_scans": failed + routing_failed,
        "parse_failed_scans": parse_errors,
        "hosts_parsed": hosts_parsed,
        "hosts_scanned": hosts_scanned,
        "ports_parsed": ports_parsed,
        "scan_targets": safe_list(nmap.get("scan_targets")),
        "artifacts": safe_list(nmap.get("artifacts")),
        "limitations": limitations,
    }


def analyse_tcp(active: dict[str, Any]) -> dict[str, Any]:
    """Summarize TCP connect observations across active assets."""
    observations: list[dict[str, Any]] = []
    state_counts: Counter[str] = Counter()
    errors: list[dict[str, Any]] = []

    for asset, result in active.items():
        result = safe_dict(result)

        for entry in safe_list(result.get("tcp")):
            entry = safe_dict(entry)
            connected_ip = entry.get("connected_ip")
            tcp_result = safe_dict(entry.get("result"))

            for port_result in safe_list(tcp_result.get("results")):
                port_result = safe_dict(port_result)

                state = str(port_result.get("state", "unknown"))
                state_counts[state] += 1

                observation = {
                    "asset": asset,
                    "connected_ip": connected_ip,
                    "host": port_result.get("host"),
                    "port": port_result.get("port"),
                    "state": state,
                    "duration_seconds": port_result.get("duration_seconds"),
                    "error": port_result.get("error"),
                    "interpretation": (
                        "Connectivity observation only; service identity, "
                        "ownership, and security impact are unverified."
                    ),
                }

                observations.append(observation)

                if state == "error":
                    errors.append(observation)

    return {
        "observation_count": len(observations),
        "state_counts": dict(state_counts),
        "observations": observations,
        "errors": errors,
    }


def analyse_http_tls(active: dict[str, Any]) -> dict[str, Any]:
    """Summarize hostname-level HTTP/TLS results and missing headers."""
    results: list[dict[str, Any]] = []
    missing_headers: list[dict[str, Any]] = []

    for asset, active_result in active.items():
        active_result = safe_dict(active_result)
        wrapper = safe_dict(active_result.get("http_tls"))
        result = safe_dict(wrapper.get("result"))

        if not result:
            continue

        record: dict[str, Any] = {
            "asset": asset,
            "status": wrapper.get("status", "unknown"),
            "http": {},
            "https": {},
            "tls": {},
        }

        for scheme in ("http", "https"):
            response = safe_dict(result.get(scheme))
            headers = safe_dict(response.get("security_headers"))

            record[scheme] = {
                "status_code": response.get("status"),
                "server_header": response.get("server_header"),
                "content_type": response.get("content_type"),
                "security_headers": headers,
            }

            for header, value in headers.items():
                if value is None or value == "":
                    missing_headers.append(
                        {
                            "asset": asset,
                            "scheme": scheme,
                            "header": header,
                            "classification": "observation",
                            "note": (
                                "Header absence alone does not establish "
                                "a vulnerability; evaluate application "
                                "requirements and deployment architecture."
                            ),
                        }
                    )

        tls = safe_dict(result.get("tls"))

        record["tls"] = {
            "protocol": tls.get("protocol"),
            "cipher": tls.get("cipher"),
            "subject": tls.get("subject"),
            "issuer": tls.get("issuer"),
            "not_before": tls.get("not_before"),
            "not_after": tls.get("not_after"),
            "checked_at": tls.get("checked_at"),
        }

        results.append(record)

    return {
        "result_count": len(results),
        "results": results,
        "missing_header_observations": missing_headers,
    }


def analyse_intel(intel: dict[str, Any] | None) -> dict[str, Any]:
    """Summarize Intel intelligence; leads are never vulnerabilities."""
    if not intel:
        return {
            "available": False,
            "correlated_leads": 0,
            "prioritized_leads": 0,
            "priority_counts": {},
            "top_leads": [],
            "interpretation": (
                "Intel intelligence was not available. "
                "No lead conclusions were generated."
            ),
        }

    correlated = safe_list(intel.get("correlated_leads"))
    prioritized = safe_list(intel.get("prioritized_leads"))

    priority_counts: Counter[str] = Counter()
    for lead in prioritized:
        lead = safe_dict(lead)
        assessment = safe_dict(lead.get("assessment"))
        priority_counts[str(assessment.get("priority", "unclassified"))] += 1

    top_leads = []
    for lead in prioritized:
        lead = safe_dict(lead)
        assessment = safe_dict(lead.get("assessment"))

        top_leads.append(
            {
                "lead_type": lead.get("lead_type"),
                "canonical_value": lead.get("canonical_value"),
                "score": assessment.get("score"),
                "priority": assessment.get("priority"),
                "independent_source_count": lead.get("independent_source_count"),
                "observation_count": lead.get("observation_count"),
                "sources": safe_list(lead.get("sources")),
                "evidence_paths": sorted(
                    {
                        str(obs.get("evidence_path"))
                        for obs in safe_list(lead.get("observations"))
                        if isinstance(obs, dict) and obs.get("evidence_path")
                    }
                ),
                "classification": "reconnaissance_lead_not_vulnerability",
            }
        )

    top_leads.sort(
        key=lambda item: (
            item["score"] if isinstance(item["score"], (int, float)) else -1
        ),
        reverse=True,
    )

    return {
        "available": True,
        "correlated_leads": len(correlated),
        "prioritized_leads": len(prioritized),
        "priority_counts": dict(priority_counts),
        "top_leads": top_leads[:20],
        "interpretation": (
            "Intel leads are reconnaissance intelligence. "
            "They are not confirmed vulnerabilities."
        ),
    }


def build_analysis(
    discover: dict[str, Any],
    intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Consolidate Discovery observations and Intel intelligence."""
    assessment = safe_dict(discover.get("assessment"))
    active = safe_dict(discover.get("active"))

    technical_findings = safe_list(assessment.get("findings"))
    port_inventory = safe_list(assessment.get("port_inventory"))

    tcp = analyse_tcp(active)
    http_tls = analyse_http_tls(active)

    nmap_results = {
        asset: analyse_nmap(safe_dict(result).get("nmap"))
        for asset, result in active.items()
    }

    nmap_status_counts = Counter(
        result["status"] for result in nmap_results.values()
    )

    evidence_gaps: list[dict[str, str]] = []

    if not technical_findings:
        evidence_gaps.append(
            {
                "area": "technical_assessment",
                "status": "no_findings_recorded",
                "detail": (
                    "Discovery assessment.findings is empty. "
                    "This does not establish that the target is vulnerability-free."
                ),
            }
        )

    if not port_inventory:
        evidence_gaps.append(
            {
                "area": "port_inventory",
                "status": "no_port_records",
                "detail": (
                    "Discovery assessment.port_inventory is empty. "
                    "Review the underlying TCP and Nmap evidence separately."
                ),
            }
        )

    if any(item["status"] != "completed" for item in nmap_results.values()):
        evidence_gaps.append(
            {
                "area": "nmap_coverage",
                "status": "partial_or_unavailable",
                "detail": (
                    "At least one Nmap result is incomplete, failed, "
                    "or unavailable. Do not infer that unrecorded ports are closed."
                ),
            }
        )

    if tcp["errors"]:
        evidence_gaps.append(
            {
                "area": "tcp_connectivity",
                "status": "partial_errors",
                "detail": (
                    f"{len(tcp['errors'])} TCP connectivity checks returned errors."
                ),
            }
        )

    if http_tls["missing_header_observations"]:
        evidence_gaps.append(
            {
                "area": "http_security_headers",
                "status": "manual_review_required",
                "detail": (
                    "One or more response security headers were absent. "
                    "These are observations, not confirmed vulnerabilities."
                ),
            }
        )

    stage3_summary = analyse_intel(intel)
    source_coverage = analyse_source_coverage(discover, intel)

    severity_counts = safe_dict(
        get_path(assessment, "summary", "severity_counts")
    )

    return {
        "schema_version": "1.0",
        "stage": 5,
        "engagement_id": discover.get("engagement_id"),
        "target": discover.get("target"),
        "target_type": discover.get("target_type"),
        "mode": discover.get("mode"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "discover": "discover/discover.json",
            "intel_available": intel is not None,
            "intel": "intel/intel.json" if intel is not None else None,
        },
        "summary": {
            "technical_findings_recorded": len(technical_findings),
            "port_inventory_records": len(port_inventory),
            "tcp_observations": tcp["observation_count"],
            "tcp_open_observations": tcp["state_counts"].get("open", 0),
            "tcp_error_observations": tcp["state_counts"].get("error", 0),
            "http_tls_results": http_tls["result_count"],
            "missing_header_observations": len(
                http_tls["missing_header_observations"]
            ),
            "nmap_assets": len(nmap_results),
            "nmap_status_counts": dict(nmap_status_counts),
            "intel_correlated_leads": stage3_summary["correlated_leads"],
            "intel_prioritized_leads": stage3_summary["prioritized_leads"],
            "severity_counts": severity_counts,
            "evidence_gaps": len(evidence_gaps),
            "evidence_sources_reported": source_coverage["summary"][
                "sources_reported"
            ],
            "evidence_sources_with_errors": source_coverage["summary"][
                "sources_with_errors"
            ],
        },
        "technical_assessment": {
            "findings": technical_findings,
            "port_inventory": port_inventory,
            "source_summary": safe_dict(assessment.get("summary")),
        },
        "observations": {
            "tcp": tcp,
            "http_tls": http_tls,
        },
        "nmap": nmap_results,
        "intel": stage3_summary,
        "source_coverage": source_coverage,
        "evidence_gaps": evidence_gaps,
        "interpretation_rules": [
            "An empty findings array is not proof that no vulnerabilities exist.",
            "An empty port inventory is not proof that no ports are open.",
            "TCP connectivity observations do not establish service identity or ownership.",
            (
                "Shared CDN or reverse-proxy addresses must not be assumed "
                "to be origin infrastructure."
            ),
            "Missing HTTP security headers are observations pending contextual validation.",
            "Nmap timeouts, parse errors, and routing failures mean coverage is incomplete.",
            "Intel reconnaissance leads are not confirmed vulnerabilities.",
            "No CVE, CWE, CVSS score, or vulnerability severity is inferred by Analysis.",
        ],
    }


