"""Read-only NVD lookup: fingerprinted service -> CVE candidates.

Never touches the engagement target. Results are LEADS for the reviewer,
never auto-promoted to confirmed findings.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

from reconforge.domain.fingerprint import CveCandidate, ServiceFingerprint

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cpe_for(fp: ServiceFingerprint) -> str | None:
    if fp.cpe:
        return fp.cpe[0]
    if fp.product and fp.version:
        prod = fp.product.lower().replace(" ", "_")
        return f"cpe:2.3:a:{prod}:{prod}:{fp.version}:*:*:*:*:*:*:*"
    return None


def lookup_cves(
    service: ServiceFingerprint,
    api_key: str | None = None,
    sleep: float = 6.0,
) -> list[CveCandidate]:
    cpe = _cpe_for(service)
    if not cpe:
        return []

    params = urllib.parse.urlencode({"cpeName": cpe})
    req = urllib.request.Request(f"{NVD}?{params}")
    if api_key:
        req.add_header("apiKey", api_key)

    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except Exception:
        return []
    finally:
        # NVD rate limit: 5/30s without key, 50/30s with.
        time.sleep(sleep)

    out: list[CveCandidate] = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        metrics = cve.get("metrics", {})
        score = sev = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]["cvssData"]
                score, sev = m.get("baseScore"), m.get("baseSeverity")
                break
        out.append(
            CveCandidate(
                product=service.product or "?",
                version=service.version,
                cve_id=cve["id"],
                cvss_score=score,
                cvss_severity=sev,
                summary=(cve.get("descriptions", [{}])[0].get("value", ""))[:300],
            )
        )
    return out