"""Application service: Nmap XML -> domain fingerprints.

Satisfies application.ports.NmapXmlPort. The infrastructure probe module
stays the only place that touches XML, files or Nmap; this service exists
so the use case depends on the port, not the adapter.

Application *services* are permitted to compose infrastructure adapters
(see tests/test_refactor_regressions.py). Use cases themselves are not.
"""

from __future__ import annotations

from pathlib import Path

from reconforge.domain.fingerprint import OsGuess, ServiceFingerprint
from reconforge.infrastructure.probes.nmap_xml_parse import fingerprints_from_nmap


class NmapXmlFingerprints:
    """Adapter implementing application.ports.NmapXmlPort."""

    def fingerprints(
        self, xml_path: str | Path
    ) -> tuple[list[ServiceFingerprint], list[OsGuess]]:
        return fingerprints_from_nmap(xml_path)