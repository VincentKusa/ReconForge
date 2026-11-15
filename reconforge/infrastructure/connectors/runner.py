"""Run selected passive OSINT connectors independently.

Connector failures are isolated so one unavailable provider does not
prevent other connectors from running. Raw results are saved as JSON
evidence; concise leads are derived through :mod:`reconforge.domain.leads`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from reconforge.application.ports import LeadRepository
from reconforge.infrastructure.connectors import (
    archive,
    cert_transparency,
    dns_whois,
    github,
    search_provider,
    wikipedia,
)
from reconforge.infrastructure.http.client import HttpClient

DEFAULT_SOURCES = ("dns", "whois", "crtsh", "archive", "github", "wikipedia")


class OsintRunner:
    """Executes the enabled passive connectors for one target."""

    def __init__(self, leads: LeadRepository):
        self._leads = leads

    def run(
        self,
        target: str,
        target_type: str,
        engagement_id: int,
        enabled: list[str] | None = None,
        search_query: str | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Run every enabled connector; return ``{"results", "errors"}``."""
        enabled_names = set(enabled or DEFAULT_SOURCES)

        results: dict[str, Any] = {}
        errors: dict[str, str] = {}

        client = HttpClient()

        for name, task in self._tasks(
            target, target_type, enabled_names, client, search_query
        ).items():
            try:
                data = task()
                results[name] = data

                evidence_path = self._leads.save_evidence(engagement_id, name, data)
                self._leads.record_connector(engagement_id, name, data, evidence_path)

            except Exception as exc:  # isolate provider failures
                errors[name] = str(exc)

        return {"results": results, "errors": errors}

    def _tasks(
        self,
        target: str,
        target_type: str,
        enabled: set[str],
        client: HttpClient,
        search_query: str | None,
    ) -> dict[str, Callable[[], Any]]:
        """Map connector names to zero-argument callables for this target."""
        tasks: dict[str, Callable[[], Any]] = {}

        if target_type == "domain":
            if "dns" in enabled:
                tasks["dns"] = lambda: dns_whois.dns(target)
            if "whois" in enabled:
                tasks["whois"] = lambda: dns_whois.whois(target)
            if "crtsh" in enabled:
                tasks["crtsh"] = lambda: cert_transparency.collect(target, client)
            if "archive" in enabled:
                tasks["archive"] = lambda: archive.collect(target, client)

        # Repository, encyclopedia and web search lookups make sense for any
        # target type, not only domains.
        if "github" in enabled:
            tasks["github"] = lambda: github.collect(f'"{target}"', client)
        if "wikipedia" in enabled:
            tasks["wikipedia"] = lambda: wikipedia.collect(target, client)
        if "search" in enabled and search_query:
            tasks["search"] = lambda: search_provider.collect(search_query, client)

        return tasks
