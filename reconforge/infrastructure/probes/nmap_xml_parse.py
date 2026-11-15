"""Adapter: Nmap XML dict -> domain fingerprint objects.

Wraps reconforge.infrastructure.probes.nmap_inventory.parse_nmap_xml so the
existing scanner module stays unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reconforge.domain.fingerprint import (
    Confidence,
    OsGuess,
    ServiceFingerprint,
)
from reconforge.infrastructure.probes.nmap_recon import parse_nmap_xml


def _iter_open_ports(host: dict[str, Any]):
    for port in host.get("ports", []):
        if port.get("state") == "open":
            yield port


def fingerprints_from_nmap(
    xml_path: str | Path,
) -> tuple[list[ServiceFingerprint], list[OsGuess]]:
    """Return (services, os_guesses) parsed from one Nmap XML file."""
    parsed = parse_nmap_xml(xml_path)

    services: list[ServiceFingerprint] = []
    os_guesses: list[OsGuess] = []

    for host in parsed.get("hosts", []):
        for port in _iter_open_ports(host):
            svc = port.get("service") or {}
            services.append(
                ServiceFingerprint(
                    port=int(port.get("port") or 0),
                    protocol=port.get("protocol") or "tcp",
                    service=svc.get("name"),
                    product=svc.get("product"),
                    version=svc.get("version"),
                    extrainfo=svc.get("extrainfo"),
                    ostype=svc.get("ostype"),
                    cpe=tuple(svc.get("cpe") or ()),
                    confidence=(
                        Confidence.HIGH if svc.get("product") else Confidence.MEDIUM
                    ),
                )
            )

        for match in host.get("os_matches", []):
            classes = match.get("classes") or []
            family = classes[0].get("osfamily") if classes else None
            try:
                accuracy = int(match.get("accuracy")) if match.get("accuracy") else None
            except (TypeError, ValueError):
                accuracy = None
            os_guesses.append(
                OsGuess(
                    name=match.get("name") or "unknown",
                    family=family,
                    accuracy=accuracy,
                    source="nmap",
                    confidence=Confidence.HIGH,
                )
            )

    return services, os_guesses