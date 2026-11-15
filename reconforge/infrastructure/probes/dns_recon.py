"""Low-impact DNS record collection using dig."""

from __future__ import annotations

import shutil
from typing import Any

from reconforge.infrastructure.subprocess_tools import run_command

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")


def query(domain: str, record_type: str, timeout: int = 10) -> dict[str, Any]:
    """Query one DNS record type for the domain using dig."""
    if not shutil.which("dig"):
        return {"error": "dig is not installed."}

    result = run_command(
        [
            "dig",
            "+time=3",
            "+tries=1",
            "+noall",
            "+answer",
            domain,
            record_type,
        ],
        timeout=timeout,
        stdout_limit=1_000_000,
    )

    if "error" in result:
        # A missing binary or timeout is reported per record type.
        return {"record_type": record_type, "error": result["error"]}

    stdout = str(result.get("stdout", ""))

    return {
        "record_type": record_type,
        "returncode": result.get("returncode"),
        "answers": [
            line.strip() for line in stdout.splitlines() if line.strip()
        ],
        "error": str(result.get("stderr") or "").strip() or None,
    }


def collect(domain: str) -> dict[str, Any]:
    """Collect all configured DNS record types for the domain."""
    return {
        "source": "dns_recon",
        "domain": domain,
        "records": {
            record_type: query(domain, record_type)
            for record_type in RECORD_TYPES
        },
    }
