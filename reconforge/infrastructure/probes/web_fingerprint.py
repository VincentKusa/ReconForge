"""Active web/technology fingerprinting for explicitly approved assets.

Uses ProjectDiscovery httpx when present; falls back to a stdlib HEAD
request for the Server / X-Powered-By headers. Caller must have passed the
active-mode and asset-approval gates in ActiveCheckRunner.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from reconforge.domain.fingerprint import WebServerInfo


def _from_httpx(url: str) -> WebServerInfo | None:
    if not shutil.which("httpx"):
        return None
    try:
        out = subprocess.run(
            ["httpx", "-u", url, "-json", "-silent", "-tech-detect"],
            capture_output=True, text=True, timeout=60, check=True,
        ).stdout
        rec = json.loads(out.splitlines()[0])
        return WebServerInfo(
            url=url,
            server_header=rec.get("webserver"),
            technologies=tuple(rec.get("tech", []) or []),
            title=rec.get("title"),
        )
    except Exception:
        return None


def _from_stdlib(url: str) -> WebServerInfo:
    import urllib.request
    req = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": "ReconForge/0.8"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return WebServerInfo(
            url=url,
            server_header=resp.headers.get("Server"),
            powered_by=resp.headers.get("X-Powered-By"),
        )


def fingerprint_web(url: str) -> WebServerInfo:
    return _from_httpx(url) or _from_stdlib(url)