"""Local DNS and WHOIS lookups.

These are separate from active port scanning.
"""

from __future__ import annotations

import shutil
from typing import Any

from reconforge.infrastructure.subprocess_tools import run_command

DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


def dns(domain: str) -> dict[str, Any]:
    """Collect common DNS record answers using dig."""
    if not shutil.which("dig"):
        return {"error": "dig not installed; install dnsutils."}

    return {
        record_type: run_command(
            ["dig", "+noall", "+answer", domain, record_type]
        )
        for record_type in DNS_RECORD_TYPES
    }


def whois(domain: str) -> dict[str, Any]:
    """Run a WHOIS lookup for the domain."""
    if not shutil.which("whois"):
        return {"error": "whois not installed; install whois."}

    return run_command(["whois", domain], timeout=25)
