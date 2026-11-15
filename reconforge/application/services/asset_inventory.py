"""Build an engagement asset inventory from stored leads."""

from __future__ import annotations

from typing import Any

from reconforge.domain.scope_policy import (
    DEFAULT_EXCLUSIONS_PATH,
    DEFAULT_POLICY_PATH,
    is_in_scope,
    load_exclusions,
    load_policy,
    normalize,
)
from reconforge.infrastructure.persistence.database import connect, fetch_engagement

# Lead types whose value references a host or URL worth inventorying.
HOST_LEAD_TYPES = {"hostname", "domain", "historical_url", "url"}


def build_inventory(
    db_path: str,
    engagement_id: int,
    policy_path: str = DEFAULT_POLICY_PATH,
    exclusions_path: str = DEFAULT_EXCLUSIONS_PATH,
) -> dict[str, Any]:
    """Group in-scope hosts from stored leads; report excluded observations."""
    db = connect(db_path)

    try:
        engagement = fetch_engagement(db, engagement_id)

        if not engagement:
            raise ValueError("Engagement not found.")

        rows = db.execute(
            """
            SELECT lead_type, value, source, evidence_path
            FROM leads
            WHERE engagement_id=?
            """,
            (engagement_id,),
        ).fetchall()
    finally:
        db.close()

    target = str(engagement["target"])
    target_type = str(engagement["target_type"])

    # Load policy once for the whole loop instead of per lead.
    policy = load_policy(policy_path)
    exclusions = load_exclusions(exclusions_path)

    assets: dict[str, dict[str, Any]] = {}
    excluded: list[dict[str, Any]] = []

    if target_type in {"domain", "ip"}:
        assets[target.lower()] = {
            "hostname": target.lower(),
            "sources": ["registered_engagement"],
            "evidence": [],
            "in_scope": True,
        }
    elif target_type == "url":
        url_host = normalize(target)
        if url_host:
            assets[url_host] = {
                "hostname": url_host,
                "sources": ["registered_engagement"],
                "evidence": [],
                "in_scope": True,
            }

    for lead_type, value, source, evidence_path in rows:
        if lead_type not in HOST_LEAD_TYPES:
            continue

        host = normalize(value)
        if not host:
            continue

        allowed, reason = is_in_scope(
            host,
            target,
            target_type,
            policy=policy,
            exclusions=exclusions,
        )

        record = {
            "hostname": host,
            "original_value": value,
            "source": source,
            "evidence_path": evidence_path,
            "in_scope": allowed,
            "scope_reason": reason,
        }

        if not allowed:
            excluded.append(record)
            continue

        asset = assets.setdefault(
            host,
            {"hostname": host, "sources": [], "evidence": [], "in_scope": True},
        )

        if source not in asset["sources"]:
            asset["sources"].append(source)
        if evidence_path:
            asset["evidence"].append(evidence_path)

    return {
        "engagement_id": engagement_id,
        "target": target,
        "target_type": target_type,
        "mode": engagement["mode"],
        "assets": sorted(assets.values(), key=lambda item: item["hostname"]),
        "excluded": excluded,
        "summary": {
            "in_scope_hosts": len(assets),
            "excluded_observations": len(excluded),
        },
    }
