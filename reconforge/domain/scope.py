"""Target parsing and conservative scope validation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,253}$")
AWS_ACCOUNT_RE = re.compile(r"aws:\d{12}")
CLOUD_LABEL_RE = re.compile(r"(azure|gcp):[a-z0-9._:-]{3,128}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")

MODES = {"external", "internal", "cloud", "hybrid"}

TARGET_TYPES = {
    "domain",
    "url",
    "ip",
    "network",
    "cloud-account",
    "username",
    "email",
    "person",
    "repository",
}

PERSON_TARGET_TYPES = {"username", "person", "email"}


@dataclass
class Validation:
    """Outcome of target syntax/mode validation."""

    ok: bool
    normalized: str
    message: str


def _validate_domain(raw: str) -> Validation:
    value = raw.lower().rstrip(".")
    ok = bool(DOMAIN_RE.fullmatch(value))

    return Validation(
        ok, value, "Valid domain syntax." if ok else "Invalid domain syntax."
    )


def _validate_ip(raw: str) -> Validation:
    try:
        return Validation(True, str(ipaddress.ip_address(raw)), "Valid IP address.")
    except ValueError:
        return Validation(False, raw, "Invalid IP address.")


def _validate_network(raw: str) -> Validation:
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return Validation(False, raw, "Invalid network/CIDR.")

    return Validation(
        True,
        str(network),
        "Valid network. Confirm exact written authorization before discovery.",
    )


def _validate_cloud_account(raw: str) -> Validation:
    lowered = raw.lower()

    if AWS_ACCOUNT_RE.fullmatch(lowered):
        return Validation(True, lowered, "Valid AWS account identifier.")

    if CLOUD_LABEL_RE.fullmatch(lowered):
        return Validation(
            True,
            raw,
            "Cloud scope label accepted; verify tenant/project scope separately.",
        )

    return Validation(
        False,
        raw,
        "Use aws:ACCOUNT_ID, azure:TENANT_OR_SUBSCRIPTION, or gcp:PROJECT_ID.",
    )


def _validate_username(raw: str) -> Validation:
    ok = bool(USERNAME_RE.fullmatch(raw))

    return Validation(
        ok, raw, "Username syntax accepted." if ok else "Invalid username syntax."
    )


def _validate_email(raw: str) -> Validation:
    ok = bool(EMAIL_RE.fullmatch(raw))

    return Validation(
        ok, raw, "Email syntax accepted." if ok else "Invalid email syntax."
    )


def _validate_person(raw: str) -> Validation:
    ok = 2 <= len(raw) <= 120 and not any(c in raw for c in "\r\n<>")

    return Validation(
        ok,
        raw,
        "Name accepted as a scoped lead, not proof of identity."
        if ok
        else "Invalid name input.",
    )


def _validate_repository(raw: str) -> Validation:
    ok = bool(REPOSITORY_RE.fullmatch(raw))

    return Validation(
        ok, raw.lower(), "Repository slug accepted." if ok else "Use owner/repository."
    )


def _validate_url(raw: str) -> Validation:
    """Accept an http(s) URL; normalize to scheme://host[/path]."""
    try:
        parsed = urlparse(raw)
    except ValueError:
        return Validation(False, raw, "Invalid URL syntax.")

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return Validation(
            False, raw, "Use a full URL with an http(s) scheme and a host."
        )

    host = parsed.hostname.lower()
    is_ip_literal = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip_literal = False

    if not is_ip_literal and not DOMAIN_RE.fullmatch(host):
        return Validation(False, raw, "URL host is not a valid domain or IP address.")

    netloc = parsed.netloc.lower()
    normalized = f"{parsed.scheme.lower()}://{netloc}{parsed.path}"
    if parsed.query:
        normalized += f"?{parsed.query}"

    return Validation(
        True,
        normalized,
        "Valid URL target; its resolved addresses require explicit probing approval."
        if not is_ip_literal
        else "Valid IP-literal URL.",
    )


_VALIDATORS = {
    "domain": _validate_domain,
    "url": _validate_url,
    "ip": _validate_ip,
    "network": _validate_network,
    "cloud-account": _validate_cloud_account,
    "username": _validate_username,
    "email": _validate_email,
    "person": _validate_person,
    "repository": _validate_repository,
}


def validate_target(
    target: str,
    target_type: str,
    mode: str,
    allow_person_targets: bool = False,
) -> Validation:
    """Validate *target* syntax for *target_type* under engagement *mode*."""
    raw = target.strip()

    if not raw:
        return Validation(False, raw, "Target is empty.")

    if mode not in MODES:
        return Validation(False, raw, f"Unsupported mode: {mode}")

    if target_type not in TARGET_TYPES:
        return Validation(False, raw, f"Unsupported target type: {target_type}")

    if target_type in PERSON_TARGET_TYPES and not allow_person_targets:
        return Validation(
            False,
            raw,
            "Person-oriented targets are disabled. "
            "Enable only for an authorized, appropriate assessment.",
        )

    return _VALIDATORS[target_type](raw)
