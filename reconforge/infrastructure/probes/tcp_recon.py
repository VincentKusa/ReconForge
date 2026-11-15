"""Small, explicitly approved TCP connection checks.

No SYN scanning, service exploitation, banner grabbing, or broad
port-range scanning.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterable
from typing import Any

DEFAULT_PORTS = (80, 443, 8080, 8443)


def check_port(host: str, port: int, timeout: int = 3) -> dict[str, Any]:
    """Attempt one TCP connection and classify the outcome."""
    started = time.monotonic()

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "host": host,
                "port": port,
                "state": "open",
                "duration_seconds": round(time.monotonic() - started, 3),
            }

    except ConnectionRefusedError:
        return {"host": host, "port": port, "state": "closed"}

    except TimeoutError:
        return {"host": host, "port": port, "state": "filtered_or_timeout"}

    except OSError as exc:
        return {"host": host, "port": port, "state": "error", "error": str(exc)}


def collect(
    host: str,
    ports: Iterable[int] | None = None,
    timeout: int = 3,
    delay_seconds: float = 2,
) -> dict[str, Any]:
    """Check the selected ports; None means the conservative default set.

    An explicitly empty list checks nothing — callers must pass ports
    deliberately rather than falling back to defaults by accident.
    """
    if ports is None:
        ports = DEFAULT_PORTS

    port_list = [int(port) for port in ports]

    results = []
    for index, port in enumerate(port_list):
        results.append(check_port(host, port, timeout))

        # Politeness delay between attempts, not after the last one.
        if delay_seconds and index < len(port_list) - 1:
            time.sleep(max(0, delay_seconds))

    return {
        "host": host,
        "ports_checked": port_list,
        "results": results,
    }
