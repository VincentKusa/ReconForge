"""Assessment: final assessment assembly and reviewer-controlled reporting.

Assessment is local-only. It reads the engagement database and Intel-5
artifacts, creates/preserves a manual review worksheet, and emits final
JSON, Markdown, and PDF reports. It never performs network activity.

This module is a library; it is invoked through the single CLI entry point
(``recon.py report`` / ``core.cli``).
"""

from __future__ import annotations

import re
from typing import Any

from reconforge.domain import cvss3
from reconforge.shared.clock import utcnow
from reconforge.shared.utils import safe_dict, safe_list

REVIEW_STATUSES = {"pending", "accepted", "rejected", "deferred"}
CLASSIFICATIONS = {
    "confirmed_vulnerability",
    "potential_finding",
    "observation",
    "intelligence_lead",
    "coverage_limitation",
    "not_applicable",
}
SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
OBSERVATION_CLASSIFICATIONS = {
    "observation",
    "intelligence_lead",
    "coverage_limitation",
}
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_PATTERN = re.compile(r"^CWE-\d+$", re.IGNORECASE)
CVSS31_VECTOR_PATTERN = re.compile(
    r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$"
)

CVSS_V3_1_EMPTY = {
    "version": "3.1",
    "score": None,
    "severity": None,
    "vector": None,
    "source": None,
}


def _cvss31_severity(score: float) -> str:
    """Map a CVSS v3.1 base score to the project's severity vocabulary."""
    return cvss3.severity(score)


def _apply_computed_cvss(item: dict[str, Any]) -> None:
    """Fill score/severity from the supplied vector when absent.

    The reviewer supplies the vector (their judgment); the score and
    severity band are spec-mandated math and are computed here. A
    reviewer-supplied score that disagrees with the vector is left for
    ``_cvss_validation`` to flag.
    """
    cvss = safe_dict(item.get("cvss_v3_1"))
    vector = str(cvss.get("vector") or "").strip()

    if not vector:
        return

    try:
        computed_score = cvss3.base_score(vector)
    except cvss3.CvssError:
        return

    if cvss.get("score") in (None, ""):
        cvss["score"] = computed_score
        cvss["severity"] = cvss3.severity(computed_score)
        if not cvss.get("source"):
            cvss["source"] = "ReconForge CVSS v3.1 calculator (FIRST spec 8.2)"
        item["cvss_v3_1"] = cvss


def _validate_identity(
    engagement_id: int,
    target: str,
    source_name: str,
    data: dict[str, Any] | None,
) -> None:
    """Reject stage artifacts that belong to a different engagement."""
    if data is None:
        return

    source_id = data.get("engagement_id")
    source_target = data.get("target")

    if source_id is not None and int(source_id) != engagement_id:
        raise ValueError(
            f"{source_name} engagement_id mismatch: expected {engagement_id}, got {source_id}"
        )
    if source_target and str(source_target).lower() != target.lower():
        raise ValueError(
            f"{source_name} target mismatch: expected {target}, got {source_target}"
        )


def _review_candidate(
    item_id: str,
    source_stage: int,
    source_file: str,
    source_pointer: str,
    source_type: str,
    title: str,
    description: Any,
    **extra: Any,
) -> dict[str, Any]:
    """Create one pending review worksheet candidate."""
    item: dict[str, Any] = {
        "item_id": item_id,
        "source_stage": source_stage,
        "source_file": source_file,
        "source_pointer": source_pointer,
        "source_type": source_type,
        "title": title,
        "description": description,
        "auto_classification": "observation"
        if source_type != "discovery_provisional_finding"
        else "potential_finding",
        "review_status": "pending",
        "classification": "observation"
        if source_type != "discovery_provisional_finding"
        else "potential_finding",
        "severity": None,
        "cve": None,
        "cwe": None,
        "cvss_v3_1": dict(CVSS_V3_1_EMPTY),
        "rationale": None,
        "impact": None,
        "remediation": None,
        "evidence_refs": [],
        "reviewer": None,
        "reviewed_at": None,
    }
    item.update(extra)
    return item


def build_review_template(
    discover: dict[str, Any], analyze: dict[str, Any]
) -> dict[str, Any]:
    """Create pending review candidates; nothing is confirmed by default."""
    engagement_id = discover.get("engagement_id")
    target = discover.get("target")
    items: list[dict[str, Any]] = []

    findings = safe_list(safe_dict(discover.get("assessment")).get("findings"))
    for index, finding_value in enumerate(findings, 1):
        finding = safe_dict(finding_value)
        items.append(
            _review_candidate(
                f"S4-F-{index:04d}",
                4,
                "discover/discover.json",
                f"/assessment/findings/{index - 1}",
                "discovery_provisional_finding",
                finding.get("title") or finding.get("name") or f"Discovery candidate {index}",
                finding.get("description") or finding.get("evidence"),
                source_severity=finding.get("severity"),
                cwe=finding.get("cwe"),
            )
        )

    tcp_observations = safe_list(
        safe_dict(safe_dict(analyze.get("observations")).get("tcp")).get("observations")
    )
    open_index = 0
    for observation_index, observation_value in enumerate(tcp_observations):
        observation = safe_dict(observation_value)
        if str(observation.get("state", "")).lower() != "open":
            continue

        open_index += 1
        items.append(
            _review_candidate(
                f"S5-TCP-{open_index:04d}",
                5,
                "analyze/analyze.json",
                f"/observations/tcp/observations/{observation_index}",
                "tcp_connectivity_observation",
                (
                    f"TCP connectivity observed: {observation.get('asset')} "
                    f"{observation.get('connected_ip')}:{observation.get('port')}"
                ),
                observation.get("interpretation"),
                asset=observation.get("asset"),
                connected_ip=observation.get("connected_ip"),
                port=observation.get("port"),
            )
        )

    headers = safe_list(
        safe_dict(safe_dict(analyze.get("observations")).get("http_tls")).get(
            "missing_header_observations"
        )
    )
    for index, header_value in enumerate(headers, 1):
        header = safe_dict(header_value)
        items.append(
            _review_candidate(
                f"S5-HDR-{index:04d}",
                5,
                "analyze/analyze.json",
                f"/observations/http_tls/missing_header_observations/{index - 1}",
                "http_header_observation",
                (
                    f"Missing response header: {header.get('asset')} "
                    f"{header.get('scheme')} {header.get('header')}"
                ),
                header.get("note"),
                asset=header.get("asset"),
                scheme=header.get("scheme"),
                header=header.get("header"),
            )
        )

    return {
        "schema_version": "1.0",
        "engagement_id": engagement_id,
        "target": target,
        "created_at": utcnow(),
        "reviewer": None,
        "instructions": [
            "Edit this file with vim; preserve item_id, source_file, and source_pointer.",
            "Set review_status to accepted, rejected, or deferred after manual review.",
            "Use classification to record the reviewer conclusion, not the automatic suggestion.",
            (
                "A confirmed_vulnerability requires severity, a CWE identifier, a CVSS "
                "v3.1 score/severity/vector/source, rationale, demonstrated impact, "
                "remediation, and at least one evidence_ref. CVE is optional when no "
                "applicable CVE is established."
            ),
            (
                "Only enter CVE/CWE identifiers supported by authoritative advisory or "
                "weakness evidence. Never infer a CVE from a banner or assign CVSS from "
                "an open port."
            ),
            (
                "CWE is prefilled from the Discovery rule where one exists; "
                "validate or correct it before accepting."
            ),
            (
                "Enter the CVSS v3.1 base vector for a confirmed finding; "
                "ReconForge computes the score and severity band from the "
                "vector using the FIRST CVSS v3.1 specification. Verify with "
                "a recognized calculator if you prefer."
            ),
            (
                "Do not treat TCP reachability, missing headers, or Intel leads as "
                "vulnerabilities without independent validation."
            ),
            (
                "Use evidence_refs as paths relative to the engagement directory or "
                "stable evidence identifiers."
            ),
        ],
        "items": items,
    }


def merge_review_template(
    existing: dict[str, Any] | None,
    template: dict[str, Any],
) -> dict[str, Any]:
    """Regenerate the worksheet while preserving existing reviewer decisions."""
    if existing is None:
        return template

    if existing.get("engagement_id") != template.get("engagement_id"):
        raise ValueError(
            "Review file engagement_id does not match the requested engagement"
        )
    if str(existing.get("target", "")).lower() != str(
        template.get("target", "")
    ).lower():
        raise ValueError("Review file target does not match the requested engagement")

    current_items = safe_list(existing.get("items"))
    current_by_id = {
        str(item.get("item_id")): item
        for item in current_items
        if isinstance(item, dict) and item.get("item_id")
    }

    # Migrate older review worksheets in place without overwriting decisions.
    for item in current_by_id.values():
        item.setdefault("cve", None)
        item.setdefault("cwe", None)
        item.setdefault("cvss_v3_1", dict(CVSS_V3_1_EMPTY))

    merged = dict(existing)
    merged["items"] = current_items + [
        item for item in template["items"] if item["item_id"] not in current_by_id
    ]
    merged.setdefault("instructions", template["instructions"])
    merged.setdefault("reviewer", None)

    return merged


def _review_validation(item: dict[str, Any]) -> list[str]:
    """Return validation issues for one review item."""
    issues: list[str] = []
    status = item.get("review_status", "pending")
    classification = item.get("classification", item.get("auto_classification"))

    if status not in REVIEW_STATUSES:
        issues.append(f"{item.get('item_id')}: invalid review_status {status!r}")
        return issues

    if classification not in CLASSIFICATIONS:
        issues.append(
            f"{item.get('item_id')}: invalid classification {classification!r}"
        )
        return issues

    if status == "accepted" and classification == "confirmed_vulnerability":
        for field in ("severity", "cwe", "rationale", "impact", "remediation"):
            if not item.get(field):
                issues.append(
                    f"{item.get('item_id')}: confirmed finding requires {field}"
                )

        if item.get("severity") not in SEVERITIES:
            issues.append(
                f"{item.get('item_id')}: severity must be one of {sorted(SEVERITIES)}"
            )

        cwe = str(item.get("cwe") or "").strip()
        if cwe and not CWE_PATTERN.fullmatch(cwe):
            issues.append(
                f"{item.get('item_id')}: cwe must use CWE-N format (for example CWE-79)"
            )

        cve = item.get("cve")
        if cve and not CVE_PATTERN.fullmatch(str(cve).strip()):
            issues.append(f"{item.get('item_id')}: cve must use CVE-YYYY-NNNN format")

        issues.extend(_cvss_validation(item))

        if not safe_list(item.get("evidence_refs")):
            issues.append(
                f"{item.get('item_id')}: confirmed finding requires evidence_refs"
            )

    return issues


def _cvss_validation(item: dict[str, Any]) -> list[str]:
    """Validate the CVSS v3.1 block of a confirmed-finding candidate."""
    item_id = item.get("item_id")
    cvss = safe_dict(item.get("cvss_v3_1"))
    issues: list[str] = []

    for field in ("score", "severity", "vector", "source"):
        if cvss.get(field) in (None, ""):
            issues.append(
                f"{item_id}: confirmed finding requires cvss_v3_1.{field}"
            )

    if not cvss:
        return issues

    if str(cvss.get("version", "3.1")) != "3.1":
        issues.append(f"{item_id}: CVSS version must be 3.1")

    try:
        score = float(cvss.get("score"))
        if not 0.0 <= score <= 10.0:
            raise ValueError

        expected = _cvss31_severity(score)
        if cvss.get("severity") and cvss.get("severity") != expected:
            issues.append(
                f"{item_id}: CVSS severity does not match score ({expected})"
            )
    except (TypeError, ValueError):
        issues.append(
            f"{item_id}: CVSS v3.1 score must be numeric from 0.0 to 10.0"
        )

    vector = str(cvss.get("vector") or "")
    if vector and not CVSS31_VECTOR_PATTERN.fullmatch(vector):
        issues.append(f"{item_id}: invalid CVSS:3.1 base vector syntax")

    # Cross-check a reviewer-supplied score against the vector-derived
    # score; the vector's score is spec math, not opinion.
    if vector and CVSS31_VECTOR_PATTERN.fullmatch(vector):
        try:
            score = float(cvss.get("score"))
            computed = cvss3.base_score(vector)
            if abs(score - computed) > 0.0505:
                issues.append(
                    f"{item_id}: supplied CVSS score {score} does not match "
                    f"the vector-derived score {computed}"
                )
        except (TypeError, ValueError):
            pass

    return issues


def _is_publishable_confirmed(item: dict[str, Any]) -> bool:
    return (
        item.get("review_status") == "accepted"
        and item.get("classification") == "confirmed_vulnerability"
        and not _review_validation(item)
    )


def build_final_assessment(
    intel: dict[str, Any] | None,
    discover: dict[str, Any],
    analyze: dict[str, Any],
    review: dict[str, Any],
    database_context: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the final assessment from reviewed candidates."""
    raw_engagement_id = discover.get("engagement_id")
    if raw_engagement_id is None:
        raise ValueError("Discovery artifact is missing engagement_id")

    engagement_id = int(raw_engagement_id)
    target = str(discover.get("target") or "")

    _validate_identity(engagement_id, target, "Intel", intel)
    _validate_identity(engagement_id, target, "Analysis", analyze)

    engagement = safe_dict(database_context.get("engagement"))
    if engagement:
        _validate_identity(
            engagement_id,
            target,
            "SQLite engagement record",
            {
                "engagement_id": engagement.get("id"),
                "target": engagement.get("target"),
            },
        )

    items = [item for item in safe_list(review.get("items")) if isinstance(item, dict)]
    ids = [str(item.get("item_id", "")) for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError("Review file contains duplicate item_id values")

    # Score/severity are computed from the vector before validation so a
    # reviewer who supplies only the vector gets a complete CVSS block.
    for item in items:
        _apply_computed_cvss(item)

    validation_issues: list[str] = []
    confirmed: list[dict[str, Any]] = []
    potential: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    rejected = deferred = pending = 0

    for item in items:
        validation_issues.extend(_review_validation(item))
        status = item.get("review_status", "pending")
        classification = item.get("classification", item.get("auto_classification"))

        if status == "rejected":
            rejected += 1
        elif status == "deferred":
            deferred += 1
        elif status == "pending":
            pending += 1
        elif _is_publishable_confirmed(item):
            confirmed.append(item)
        elif classification == "potential_finding":
            potential.append(item)
        elif classification in OBSERVATION_CLASSIFICATIONS:
            observations.append(item)

    stage5_summary = safe_dict(analyze.get("summary"))
    stage4_inventory = safe_dict(discover.get("inventory"))
    stage4_assessment = safe_dict(discover.get("assessment"))
    stage3_summary = safe_dict(intel.get("summary")) if intel else {}
    analysis_intel = safe_dict(analyze.get("intel"))
    nmap = safe_dict(analyze.get("nmap"))

    nmap_assets = []
    for asset, result_value in nmap.items():
        result = safe_dict(result_value)
        nmap_assets.append(
            {
                "asset": asset,
                "status": result.get("status", "unknown"),
                "scan_count": result.get("scan_count", 0),
                "completed_scans": result.get("completed_scans", 0),
                "timed_out_scans": result.get("timed_out_scans", 0),
                "routing_failed_scans": result.get("routing_failed_scans", 0),
                "failed_scans": result.get("failed_scans", 0),
                "ports_parsed": result.get("ports_parsed", 0),
                "limitations": safe_list(result.get("limitations")),
            }
        )

    gaps = safe_list(analyze.get("evidence_gaps"))
    inventory_summary = safe_dict(stage4_inventory.get("summary"))

    coverage = {
        "in_scope_hosts": inventory_summary.get("in_scope_hosts", 0),
        "excluded_observations": inventory_summary.get("excluded_observations", 0),
        "port_inventory_records": len(safe_list(stage4_assessment.get("port_inventory"))),
        "tcp_observations": stage5_summary.get("tcp_observations", 0),
        "tcp_open_observations": stage5_summary.get("tcp_open_observations", 0),
        "tcp_error_observations": stage5_summary.get("tcp_error_observations", 0),
        "http_tls_results": stage5_summary.get("http_tls_results", 0),
        "nmap_assets": nmap_assets,
        "evidence_gaps": gaps,
    }

    steps = {
        "stage1_engagement_registration": {
            "status": "available" if engagement else "unavailable",
            "source": "SQLite engagements table",
        },
        "stage2_passive_collection": {
            "status": "available" if database_context.get("available") else "unavailable",
            "lead_records": database_context.get("lead_count", 0),
            "lead_sources": database_context.get("lead_sources", {}),
            "evidence_files": manifest.get("counts_by_kind", {}).get("evidence", 0),
        },
        "intel_correlation": {
            "status": "available" if intel else "unavailable",
            "observations_reviewed": stage3_summary.get("observations_reviewed", 0),
            "correlated_leads": len(safe_list(intel.get("correlated_leads"))) if intel else 0,
            "prioritized_leads": len(safe_list(intel.get("prioritized_leads"))) if intel else 0,
            "excluded_observations": stage3_summary.get("excluded_observations", 0),
        },
        "stage4_technical_reconnaissance": {
            "status": "available",
            "findings_recorded": len(safe_list(stage4_assessment.get("findings"))),
            "port_inventory_records": len(
                safe_list(stage4_assessment.get("port_inventory"))
            ),
        },
        "stage5_evidence_analysis": {
            "status": "available",
            "evidence_gaps": len(gaps),
        },
    }

    return {
        "schema_version": "1.0",
        "stage": 6,
        "engagement_id": engagement_id,
        "target": target,
        "target_type": discover.get("target_type"),
        "mode": discover.get("mode"),
        "generated_at": utcnow(),
        "engagement_metadata": engagement or None,
        "steps": steps,
        "summary": {
            "confirmed_vulnerabilities": len(confirmed),
            "potential_findings": len(potential),
            "accepted_observations": len(observations),
            "review_items": len(items),
            "pending_review": pending,
            "rejected_review_items": rejected,
            "deferred_review_items": deferred,
            "intel_correlated_leads": steps["intel_correlation"]["correlated_leads"],
            "intel_prioritized_leads": steps["intel_correlation"]["prioritized_leads"],
            "evidence_gaps": len(gaps),
            "provenance_files": manifest.get("file_count", 0),
        },
        "final_findings": confirmed,
        "potential_findings": potential,
        "accepted_observations": observations,
        "review": {
            "reviewer": review.get("reviewer"),
            "items": items,
            "validation_issues": validation_issues,
        },
        "coverage": coverage,
        "intel": {
            "available": bool(intel),
            "summary": stage3_summary,
            "top_leads": safe_list(analysis_intel.get("top_leads"))[:10],
            "interpretation": (
                "Intel items remain reconnaissance intelligence and are not vulnerabilities."
            ),
        },
        "evidence_provenance": manifest,
        "interpretation_rules": safe_list(analyze.get("interpretation_rules")),
        "methodology": [
            "Assessment performs local-only consolidation of existing Stage 1-5 records.",
            "No network requests, scans, exploitation checks, or external lookups are performed.",
            (
                "Only reviewer-accepted items meeting the confirmed-finding evidence "
                "requirements appear as confirmed vulnerabilities."
            ),
            (
                "Discovery provisional recommendations remain potential candidates until "
                "manually validated."
            ),
            (
                "TCP reachability and missing HTTP headers remain observations unless "
                "impact is independently established."
            ),
            "Intel intelligence remains separate from technical findings.",
            (
                "CVE identifiers are included only when supported by an authoritative "
                "advisory or validated product/version match; no CVE is inferred from a "
                "service banner alone."
            ),
            (
                "CWE identifiers describe the demonstrated weakness and are "
                "prefilled from Discovery rules pending reviewer validation; "
                "the CVSS v3.1 score and severity are computed from the "
                "reviewer-supplied vector per the FIRST CVSS v3.1 "
                "specification."
            ),
            (
                "Coverage limitations are reported explicitly; missing evidence is not "
                "treated as a clean result."
            ),
        ],
    }


