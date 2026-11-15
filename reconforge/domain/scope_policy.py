"""Engagement scope policy for discovered assets.

Default behavior is conservative:
- A domain engagement covers its root domain and subdomains.
- Resolved IPs for domain targets require an explicit IP/CIDR/asset allowlist.
- An IP engagement covers only that IP.
- A network engagement covers only addresses within that network.
- Other target types require an exact match unless explicitly allowlisted.
- Exclusions always override allow rules.

This is a policy check, not proof of authorization.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_POLICY_PATH = "config/scope.json"
DEFAULT_EXCLUSIONS_PATH = "config/exclusions.txt"


def normalize(value: str) -> str:
    """Reduce a URL/hostname/wildcard string to a bare lowercase hostname."""
    value = value.strip()

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""

    value = value.strip().lower().rstrip(".")

    if value.startswith("*."):
        value = value[2:]

    return value


def load_policy(path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    """Load the scope policy JSON; a missing file means an empty policy."""
    policy_path = Path(path)

    if not policy_path.exists():
        return {"allow": {}, "exclude": {}}

    return json.loads(policy_path.read_text(encoding="utf-8"))


def load_exclusions(path: str | Path = DEFAULT_EXCLUSIONS_PATH) -> list[str]:
    """Load one-per-line exclusions, ignoring blank lines and comments."""
    exclusion_path = Path(path)

    if not exclusion_path.exists():
        return []

    return [
        line.strip()
        for line in exclusion_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _domain_match(value: str, domain: str) -> bool:
    value = normalize(value)
    domain = normalize(domain)

    return value == domain or value.endswith("." + domain)


def _ip_match(value: str, network_or_ip: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        network = ipaddress.ip_network(network_or_ip, strict=False)
        return address in network
    except ValueError:
        return False


def _exclusion_items(
    policy: dict[str, Any],
    exclusions: list[str] | None,
    exclusions_path: str | Path,
) -> list[str]:
    """Combine file exclusions with the policy's exclude section."""
    items = (
        list(exclusions)
        if exclusions is not None
        else load_exclusions(exclusions_path)
    )

    exclude = policy.get("exclude", {})
    for key in ("domains", "assets", "ips", "cidrs"):
        items.extend(exclude.get(key, []))

    return items


def _matches_exclusion(value: str, exclusions: list[str]) -> bool:
    normalized = normalize(value)

    for exclusion in exclusions:
        item = normalize(exclusion)

        if _domain_match(normalized, item):
            return True
        if _ip_match(normalized, item):
            return True
        if normalized == item:
            return True

    return False


def is_excluded(
    value: str,
    policy: dict[str, Any],
    exclusions: list[str] | None = None,
) -> bool:
    """True when *value* matches an exclusion (file and policy section).

    Exclusions override every allow rule, including ``--probe-resolved``.
    """
    items = _exclusion_items(policy, exclusions, DEFAULT_EXCLUSIONS_PATH)
    return _matches_exclusion(normalize(value), items)


def _check_domain_candidate(
    candidate: str, allow: dict[str, Any], root: str
) -> tuple[bool, str] | None:
    """Domain engagements never implicitly authorize resolved IP addresses.

    Returns a decision only when the candidate is an IP address; otherwise
    None lets the caller continue with hostname rules.
    """
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None

    explicit_assets = [normalize(item) for item in allow.get("assets", [])]
    if candidate in explicit_assets:
        return True, "IP explicitly listed in the asset allowlist."
    if any(_ip_match(candidate, item) for item in allow.get("ips", [])):
        return True, "IP explicitly allowlisted for this domain engagement."
    if any(_ip_match(candidate, item) for item in allow.get("cidrs", [])):
        return True, "IP is within an explicitly allowlisted CIDR."

    return (
        False,
        "Resolved IP is not explicitly allowlisted for this domain engagement.",
    )


def is_in_scope(
    value: str,
    target: str,
    target_type: str,
    policy_path: str | Path = DEFAULT_POLICY_PATH,
    exclusions_path: str | Path = DEFAULT_EXCLUSIONS_PATH,
    *,
    policy: dict[str, Any] | None = None,
    exclusions: list[str] | None = None,
    extra_allow: frozenset[str] | set[str] | None = None,
) -> tuple[bool, str]:
    """Return (allowed, reason) for a discovered asset.

    Callers that check many assets in a loop should load the policy and
    exclusion list once (``load_policy`` / ``load_exclusions``) and pass
    them via the keyword arguments to avoid re-reading the files per check.

    *extra_allow* carries addresses explicitly resolved from the
    engagement target when the operator requested probing them
    (``--probe-resolved``); exclusions still override it.
    """
    candidate = normalize(value)
    root = normalize(target)

    if not candidate:
        return False, "Empty or unparseable asset."

    policy = load_policy(policy_path) if policy is None else policy
    exclusion_items = _exclusion_items(policy, exclusions, exclusions_path)

    if _matches_exclusion(candidate, exclusion_items):
        return False, "Asset matches an explicit exclusion."

    if extra_allow and candidate in extra_allow:
        return True, (
            "Address resolved from the engagement target and probing was "
            "explicitly requested (--probe-resolved)."
        )

    # URL engagements authorize the URL's hostname and its subdomains,
    # following the same rules as a domain engagement.
    if target_type == "url":
        target_type = "domain"

    allow = policy.get("allow", {})

    if target_type == "domain":
        decision = _check_domain_candidate(candidate, allow, root)
        if decision is not None:
            return decision

    explicit_assets = [normalize(item) for item in allow.get("assets", [])]
    if explicit_assets and candidate in explicit_assets:
        return True, "Exact asset allowlist match."

    if target_type == "domain":
        if _domain_match(candidate, root):
            return True, "Root domain or subdomain match."

        if any(
            _domain_match(candidate, domain)
            for domain in allow.get("domains", [])
        ):
            return True, "Explicit domain allowlist match."

        return False, "Hostname is outside the authorized domain."

    if target_type == "ip":
        try:
            if ipaddress.ip_address(candidate) == ipaddress.ip_address(root):
                return True, "Exact IP target match."
        except ValueError:
            pass

        if any(_ip_match(candidate, item) for item in allow.get("ips", [])):
            return True, "Explicit IP allowlist match."

        return False, "IP is not explicitly in scope."

    if target_type == "network":
        if _ip_match(candidate, root):
            return True, "Address is within the registered network."

        for cidr in allow.get("cidrs", []):
            if _ip_match(candidate, cidr):
                return True, "Address is within an allowed CIDR."

        return False, "Address is outside the registered network."

    if target_type == "repository":
        if candidate == root:
            return True, "Exact repository target match."

        if candidate in [
            normalize(item) for item in allow.get("repositories", [])
        ]:
            return True, "Explicit repository allowlist match."

        return False, "Repository is not explicitly in scope."

    if target_type == "cloud-account":
        if candidate == root:
            return True, "Exact cloud account match."

        if candidate in [
            normalize(item) for item in allow.get("cloud_accounts", [])
        ]:
            return True, "Explicit cloud account allowlist match."

        return False, "Cloud account is not explicitly in scope."

    if candidate == root:
        return True, "Exact target match."

    return False, "This target type requires an exact scope match."
