"""Conservative lead triage helpers.

This module is a standalone triage API (rule-weighted scoring and suggested
next action). The stage pipeline itself uses :mod:`core.prioritization`,
which scores correlated lead groups; the two answer different questions and
are intentionally kept separate.
"""


def score_lead(
    direct_association: bool = False,
    independently_corroborated: bool = False,
    recent: bool = False,
    attack_surface_relevance: bool = False,
    actionable: bool = False,
) -> dict[str, object]:
    """Weighted triage score for a single lead."""
    score = (
        30 * bool(direct_association)
        + 25 * bool(independently_corroborated)
        + 15 * bool(recent)
        + 20 * bool(attack_surface_relevance)
        + 10 * bool(actionable)
    )

    if score >= 80:
        priority = "high"
    elif score >= 60:
        priority = "investigate"
    elif score >= 40:
        priority = "corroborate"
    else:
        priority = "archive_or_skip"

    return {"score": score, "priority": priority}


ACTIVE_CHECK_TYPES = {"domain", "ip", "network", "url"}
PUBLIC_SOURCE_TYPES = {"repository", "organization"}


def next_action(lead: dict, in_scope: bool, active_authorized: bool = False) -> str:
    """Suggest the next handling step for a lead."""
    if not in_scope:
        return "exclude"

    if lead.get("duplicate"):
        return "skip_duplicate"

    if lead.get("confidence", 0) < 40:
        return "seek_corroboration"

    if lead.get("asset_type") in ACTIVE_CHECK_TYPES:
        if not active_authorized:
            return "passive_enrichment"
        return "review_active_check"

    if lead.get("asset_type") in PUBLIC_SOURCE_TYPES:
        return "public_source_review"

    return "manual_review"
