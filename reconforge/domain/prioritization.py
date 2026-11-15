"""Confidence and priority scoring for correlated leads."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

#: Maximum corroboration credit; more than three sources adds no further score.
MAX_CORROBORATION = 30
CORROBORATION_STEP = 15

CONFIDENCE_WEIGHT = 0.25
RELEVANCE_WEIGHT = 0.25

RECENCY_BANDS = (
    (7, 20),
    (30, 15),
    (90, 10),
    (365, 5),
)

PRIORITY_BANDS = (
    (80, "high"),
    (60, "investigate"),
    (40, "corroborate"),
)


def priority_for_score(score: float) -> str:
    """Map a 0-100 triage score to a priority label."""
    for threshold, priority in PRIORITY_BANDS:
        if score >= threshold:
            return priority

    return "low"


def recency_score(timestamps: list[str | None]) -> int:
    """Score how recent the collected observations are (0-20)."""
    parsed: list[datetime] = []

    for value in timestamps:
        if not value:
            continue

        try:
            parsed.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            continue

    if not parsed:
        return 0

    newest = max(parsed)

    if newest.tzinfo is None:
        newest = newest.replace(tzinfo=timezone.utc)

    age_days = (datetime.now(timezone.utc) - newest).total_seconds() / 86400

    for max_age, score in RECENCY_BANDS:
        if age_days <= max_age:
            return score

    return 0


def _mean_observation(observations: list[dict[str, Any]], field: str) -> float:
    """Mean of a 0-100 integer field across observations (0 when empty)."""
    if not observations:
        return 0

    values = [
        max(0, min(100, int(item.get(field, 0))))
        for item in observations
    ]

    return sum(values) / len(values)


def score_correlated_lead(lead: dict[str, Any]) -> dict[str, Any]:
    """Score one correlated lead group; higher means review sooner."""
    observations = lead.get("observations", [])

    sources = {item.get("source") for item in observations if item.get("source")}
    independent_count = len(sources)

    # More than three sources does not inflate the score indefinitely.
    corroboration = min(
        MAX_CORROBORATION,
        max(0, independent_count - 1) * CORROBORATION_STEP,
    )

    source_score = round(_mean_observation(observations, "confidence") * CONFIDENCE_WEIGHT)
    relevance_score = round(_mean_observation(observations, "relevance") * RELEVANCE_WEIGHT)

    recency = recency_score([item.get("collected_at") for item in observations])

    total = min(100, corroboration + source_score + relevance_score + recency)

    return {
        "score": total,
        "priority": priority_for_score(total),
        "factors": {
            "corroboration": corroboration,
            "source_confidence": source_score,
            "relevance": relevance_score,
            "recency": recency,
        },
        "source_count": independent_count,
    }


def prioritize(correlation_result: dict[str, Any]) -> dict[str, Any]:
    """Attach assessments to correlated leads and sort them by score."""
    ranked = [
        {**lead, "assessment": score_correlated_lead(lead)}
        for lead in correlation_result.get("correlated_leads", [])
    ]

    ranked.sort(
        key=lambda item: (
            item["assessment"]["score"],
            item["independent_source_count"],
        ),
        reverse=True,
    )

    return {
        **correlation_result,
        "prioritized_leads": ranked,
    }
