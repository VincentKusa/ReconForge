"""Shared subprocess execution for local command-line tools (dig, whois).

All recon tools are invoked with argument lists (never a shell) and a hard
timeout. Output is truncated so a chatty tool cannot exhaust memory.
"""

from __future__ import annotations

import subprocess

STDOUT_LIMIT = 100_000
STDERR_LIMIT = 4_000


def run_command(
    args: list[str],
    timeout: int = 15,
    stdout_limit: int = STDOUT_LIMIT,
    stderr_limit: int = STDERR_LIMIT,
) -> dict[str, object]:
    """Run *args* and return ``{returncode, stdout, stderr}`` or ``{error}``.

    Missing binaries and timeouts are reported as ``{"error": ...}`` so
    callers can treat an unavailable tool as an isolated data gap instead
    of a crash.
    """
    try:
        process = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}

    return {
        "returncode": process.returncode,
        "stdout": process.stdout[:stdout_limit],
        "stderr": process.stderr[:stderr_limit],
    }
