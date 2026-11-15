"""Fingerprint value objects: services, OS, web, WAF, CVE candidates.

Pure domain vocabulary. No I/O, no framework imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ServiceFingerprint:
    """A service banner/version observation. A LEAD, never a finding."""

    port: int
    protocol: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    ostype: str | None = None
    cpe: tuple[str, ...] = ()
    confidence: Confidence = Confidence.MEDIUM


@dataclass(frozen=True)
class OsGuess:
    name: str
    family: str | None = None
    accuracy: int | None = None
    source: str = "nmap"
    confidence: Confidence = Confidence.MEDIUM


@dataclass(frozen=True)
class WebServerInfo:
    url: str
    server_header: str | None = None
    powered_by: str | None = None
    technologies: tuple[str, ...] = ()
    title: str | None = None


@dataclass(frozen=True)
class WafSignal:
    detected: bool
    vendor: str | None = None
    evidence: str | None = None
    confidence: Confidence = Confidence.LOW


@dataclass(frozen=True)
class CveCandidate:
    """A possible CVE for a fingerprinted product/version. LEAD, not finding."""

    product: str
    version: str | None
    cve_id: str
    cvss_score: float | None
    cvss_severity: str | None
    summary: str
    source: str = "nvd"


@dataclass
class HostFingerprintReport:
    """Aggregate per-asset fingerprint, assembled by the discover/analyze steps."""

    asset: str
    services: list[ServiceFingerprint] = field(default_factory=list)
    os_guesses: list[OsGuess] = field(default_factory=list)
    web: list[WebServerInfo] = field(default_factory=list)
    waf: WafSignal | None = None
    cve_candidates: list[CveCandidate] = field(default_factory=list)