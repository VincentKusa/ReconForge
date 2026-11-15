"""Active WAF detection for explicitly approved assets.

Uses wafw00f when present; otherwise a minimal header/behaviour heuristic
(Server, Via, cf-ray). Active fingerprinting may be logged or blocked by the
WAF — the report must state this.
"""

from __future__ import annotations

import shutil
import subprocess
import urllib.request
from reconforge.domain.fingerprint import WafSignal, Confidence

_KNOWN = {
    "cloudflare": "Cloudflare",
    "mod_security": "ModSecurity",
    "akamai": "Akamai",
    "sucuri": "Sucuri",
    "imperva": "Imperva",
    "aws": "AWS WAF",
}


def _from_wafw00f(url: str) -> WafSignal | None:
    if not shutil.which("wafw00f"):
        return None
    try:
        out = subprocess.run(
            ["wafw00f", url, "-f", "json", "-o", "/dev/stdout"],
            capture_output=True, text=True, timeout=60,
        ).stdout
        low = out.lower()
        if '"detected": true' in low or "is behind" in low:
            for key, vendor in _KNOWN.items():
                if key in low:
                    return WafSignal(True, vendor, "wafw00f", Confidence.HIGH)
            return WafSignal(True, "unknown", "wafw00f", Confidence.MEDIUM)
        return WafSignal(
            False, evidence="wafw00f: no WAF detected", confidence=Confidence.MEDIUM
        )
    except Exception:
        return None


def _heuristic(url: str) -> WafSignal:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconForge/0.8"})
        with urllib.request.urlopen(req, timeout=15) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
        for key, vendor in _KNOWN.items():
            if key in hdrs.get("server", "").lower() or key in hdrs.get("via", "").lower():
                return WafSignal(True, vendor, f"header:{key}", Confidence.MEDIUM)
        if "cf-ray" in hdrs:
            return WafSignal(True, "Cloudflare", "cf-ray header", Confidence.HIGH)
        return WafSignal(
            False, evidence="no WAF header signature", confidence=Confidence.LOW
        )
    except Exception as e:
        return WafSignal(False, evidence=f"probe error: {e}", confidence=Confidence.LOW)


def detect_waf(url: str) -> WafSignal:
    return _from_wafw00f(url) or _heuristic(url)