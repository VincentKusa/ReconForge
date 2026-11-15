"""Correlate observations stored in the ReconForge database."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from reconforge.domain.scope_policy import (
    DEFAULT_EXCLUSIONS_PATH,
    DEFAULT_POLICY_PATH,
    is_in_scope,
    load_exclusions,
    load_policy,
    normalize,
)
from reconforge.infrastructure.persistence.database import connect, fetch_engagement

HOST_TYPES = {"hostname", "domain"}
URL_TYPES = {"historical_url", "search_result", "url"}
REPOSITORY_TYPES = {"repository"}


def canonical_value(lead_type: str, value: str) -> str:
    """Create a stable key for comparing equivalent observations."""
    raw = value.strip()

    if lead_type in HOST_TYPES:
        return normalize(raw)

    if lead_type in URL_TYPES:
        parsed = urlparse(raw)

        if parsed.scheme and parsed.hostname:
            host = parsed.hostname.lower().rstrip(".")
            path = parsed.path.rstrip("/") or "/"
            return f"{parsed.scheme.lower()}://{host}{path}"

        return raw.lower().rstrip("/")

    if lead_type in REPOSITORY_TYPES:
        return raw.lower().rstrip("/")

    if lead_type == "ip":
        return raw.strip()

    return re.sub(r"\s+", " ", raw).strip().lower()


def _observation_for(
    row: tuple,
    target: str,
    target_type: str,
    policy: dict[str, Any],
    exclusions: list[str],
) -> dict[str, Any]:
    """Build one observation dict with its scope decision attached."""
    (
        lead_id,
        lead_type,
        value,
        source,
        confidence,
        relevance,
        status,
        evidence_path,
        collected_at,
    ) = row

    # Check the actual asset, not merely the source record.
    candidate = value
    if lead_type in URL_TYPES:
        candidate = urlparse(value).hostname or value

    allowed, reason = is_in_scope(
        candidate,
        target,
        target_type,
        policy=policy,
        exclusions=exclusions,
    )

    return {
        "lead_id": lead_id,
        "lead_type": lead_type,
        "value": value,
        "source": source,
        "confidence": confidence,
        "relevance": relevance,
        "status": status,
        "evidence_path": evidence_path,
        "collected_at": collected_at,
        "scope_allowed": allowed,
        "scope_reason": reason,
    }


def correlate_engagement(
    db_path: str,
    engagement_id: int,
    policy_path: str = DEFAULT_POLICY_PATH,
    exclusions_path: str = DEFAULT_EXCLUSIONS_PATH,
) -> dict[str, Any]:
    """Group in-scope leads by canonical value; list out-of-scope ones."""
    db = connect(db_path)

    try:
        engagement = fetch_engagement(db, engagement_id)

        if not engagement:
            raise ValueError("Engagement does not exist.")

        rows = db.execute(
            """
            SELECT id, lead_type, value, source, confidence, relevance,
                   status, evidence_path, collected_at
            FROM leads
            WHERE engagement_id=?
            ORDER BY id
            """,
            (engagement_id,),
        ).fetchall()
    finally:
        db.close()

    target = str(engagement["target"])
    target_type = str(engagement["target_type"])

    policy = load_policy(policy_path)
    exclusions = load_exclusions(exclusions_path)

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    excluded: list[dict[str, Any]] = []

    for row in rows:
        observation = _observation_for(row, target, target_type, policy, exclusions)

        if not observation["scope_allowed"]:
            excluded.append(observation)
            continue

        lead_type = observation["lead_type"]
        key = (lead_type, canonical_value(lead_type, observation["value"]))
        groups[key].append(observation)

    correlated = [
        {
            "lead_type": lead_type,
            "canonical_value": canonical,
            "observations": observations,
            "sources": sorted({item["source"] for item in observations}),
            "independent_source_count": len({item["source"] for item in observations}),
            "observation_count": len(observations),
        }
        for (lead_type, canonical), observations in groups.items()
    ]

    return {
        "engagement_id": engagement_id,
        "target": target,
        "target_type": target_type,
        "mode": engagement["mode"],
        "correlated_leads": correlated,
        "excluded_observations": excluded,
        "summary": {
            "observations_reviewed": len(rows),
            "in_scope_groups": len(correlated),
            "excluded_observations": len(excluded),
        },
    }


def main() -> None:
    """Standalone correlation CLI (writes JSON or prints to stdout)."""
    parser = argparse.ArgumentParser(
        description="Correlate ReconForge engagement leads."
    )
    parser.add_argument("--engagement", type=int, required=True)
    parser.add_argument("--database", default="output/reconforge.sqlite3")
    parser.add_argument("--policy", default=DEFAULT_POLICY_PATH)
    parser.add_argument("--exclusions", default=DEFAULT_EXCLUSIONS_PATH)
    parser.add_argument("--output", default=None)

    args = parser.parse_args()

    result = correlate_engagement(
        args.database,
        args.engagement,
        args.policy,
        args.exclusions,
    )

    rendered = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
