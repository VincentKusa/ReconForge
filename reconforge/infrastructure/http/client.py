"""Standard-library HTTP client with conservative pacing and caching.

Responses are cached on disk keyed by URL, requests are rate-limited, and
provider failures are converted into ``RuntimeError`` so connectors can be
isolated without crashing a whole stage.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from reconforge import __version__

DEFAULT_CACHE_TTL = 3600
MAX_RESPONSE_BYTES = 5_000_000

USER_AGENT = f"ReconForge/{__version__} (authorized security research)"


class HttpClient:
    """A small polite GET client with a file cache."""

    def __init__(
        self,
        cache_dir: str | Path = "output/cache",
        requests_per_minute: int = 6,
        timeout: int = 20,
        user_agent: str = USER_AGENT,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.interval = 60.0 / max(1, int(requests_per_minute))
        self.timeout = timeout
        self.user_agent = user_agent
        self.last_request = 0.0

    def get_json(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
    ) -> Any:
        """GET *url* and return the parsed JSON body."""
        return self.get(url, headers=headers, cache_ttl=cache_ttl, as_json=True)

    def get_text(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
    ) -> str:
        """GET *url* and return the body as text."""
        return self.get(url, headers=headers, cache_ttl=cache_ttl, as_json=False)

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        as_json: bool = False,
    ) -> Any:
        """GET *url*, honoring the cache, rate limit and size cap."""
        key = hashlib.sha256(url.encode()).hexdigest()
        extension = ".json" if as_json else ".txt"
        cache_file = self.cache_dir / (key + extension)

        if (
            cache_file.exists()
            and time.time() - cache_file.stat().st_mtime < cache_ttl
        ):
            raw = cache_file.read_text(encoding="utf-8")
            return json.loads(raw) if as_json else raw

        raw = self._fetch(url, headers)

        if as_json:
            # Parse before caching so a malformed response is not
            # persisted and retried forever.
            data = json.loads(raw)
            cache_file.write_text(raw, encoding="utf-8")
            return data

        cache_file.write_text(raw, encoding="utf-8")
        return raw

    def _fetch(self, url: str, headers: dict[str, str] | None) -> str:
        delay = self.interval - (time.monotonic() - self.last_request)
        if delay > 0:
            time.sleep(delay)

        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }
        request_headers.update(headers or {})

        request = urllib.request.Request(url, headers=request_headers)
        self.last_request = time.monotonic()

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read(MAX_RESPONSE_BYTES).decode(
                    "utf-8", errors="replace"
                )
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"HTTP {exc.code} from {urllib.parse.urlparse(url).netloc}"
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(
                f"Request failed for {urllib.parse.urlparse(url).netloc}: {exc}"
            ) from exc
