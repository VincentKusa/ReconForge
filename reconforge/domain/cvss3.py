"""CVSS v3.1 base-score computation from a vector string.

Spec-compliant math from the FIRST CVSS v3.1 specification (section 8.2):
given a reviewer-supplied base vector, compute the base score and the
severity band. ReconForge does not choose the vector — the reviewer does;
this module only turns a valid vector into its mandated score.
"""

from __future__ import annotations

import math
from typing import Any

AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.44}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

SEVERITY_BANDS = (
    (0.0, "Informational"),
    (0.1, "Low"),
    (4.0, "Medium"),
    (7.0, "High"),
    (9.0, "Critical"),
)


class CvssError(ValueError):
    """The supplied CVSS v3.1 vector is invalid."""


def parse_vector(vector: str) -> dict[str, str]:
    """Parse ``CVSS:3.1/AV:N/...`` into a metric dict; raise on problems."""
    parts = [part.strip() for part in str(vector).strip().split("/") if part.strip()]

    if not parts or parts[0] != "CVSS:3.1":
        raise CvssError("Vector must start with CVSS:3.1")

    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise CvssError(f"Invalid metric segment: {part!r}")
        key, value = part.split(":", 1)
        if key in metrics:
            raise CvssError(f"Duplicated metric: {key}")
        metrics[key] = value

    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    missing = [key for key in required if key not in metrics]
    if missing:
        raise CvssError(f"Missing base metrics: {', '.join(missing)}")

    table: dict[str, set[str]] = {
        "AV": set(AV_WEIGHTS),
        "AC": set(AC_WEIGHTS),
        "PR": set(PR_WEIGHTS_UNCHANGED),
        "UI": set(UI_WEIGHTS),
        "S": {"U", "C"},
        "C": set(CIA_WEIGHTS),
        "I": set(CIA_WEIGHTS),
        "A": set(CIA_WEIGHTS),
    }
    for key, allowed in table.items():
        if metrics[key] not in allowed:
            raise CvssError(f"Invalid value {metrics[key]!r} for {key}")

    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest 1-decimal number >= value (spec section 8.2)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity(score: float) -> str:
    """Qualitative severity band for a base score."""
    label = "Informational"
    for threshold, name in SEVERITY_BANDS:
        if score >= threshold:
            label = name
    return label


def base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score for *vector*; raises CvssError."""
    m = parse_vector(vector)

    scope_changed = m["S"] == "C"

    iss = 1.0 - (
        (1.0 - CIA_WEIGHTS[m["C"]])
        * (1.0 - CIA_WEIGHTS[m["I"]])
        * (1.0 - CIA_WEIGHTS[m["A"]])
    )

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr_weight = (
        PR_WEIGHTS_CHANGED[m["PR"]] if scope_changed else PR_WEIGHTS_UNCHANGED[m["PR"]]
    )
    exploitability = (
        8.22 * AV_WEIGHTS[m["AV"]] * AC_WEIGHTS[m["AC"]] * pr_weight * UI_WEIGHTS[m["UI"]]
    )

    if impact <= 0:
        return 0.0

    # v3.1 applies a 1.08 multiplier when Scope is Changed.
    multiplier = 1.08 if scope_changed else 1.0
    return _roundup(min((impact + exploitability) * multiplier, 10.0))


def assess(vector: str) -> dict[str, Any]:
    """Full assessment block for a vector: version, score, severity."""
    return {
        "version": "3.1",
        "vector": str(vector).strip(),
        "score": base_score(vector),
        "severity": severity(base_score(vector)),
        "source": "computed from vector by ReconForge (FIRST CVSS v3.1 spec 8.2)",
    }
