"""Discovery step services: passive enrichment and gated active checks.

Passive collection is the default.

Active checks require explicit configuration and command-line approval.
Hostname-level HTTP/TLS checks require an approved hostname. TCP and Nmap
require each resolved IP address to be separately authorized by scope policy.
Exclusions override all allow rules. HTTP/TLS checks use hostname DNS/SNI and
are not represented as IP-authorized TCP/Nmap activity.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from reconforge.application.ports import LeadRepository
from reconforge.domain.scope_policy import (
    is_excluded,
    is_in_scope,
    load_exclusions,
    load_policy,
    normalize,
)
from reconforge.infrastructure.connectors import (
    cert_transparency,
    commoncrawl,
    dns_whois,
    rdap,
    wayback,
)
from reconforge.infrastructure.http.client import HttpClient
from reconforge.infrastructure.probes import dns_recon, http_recon, nmap_recon, tcp_recon


class DiscoveryService:
    """Passive enrichment: run configured connectors against the target."""

    def __init__(self, leads: LeadRepository):
        self._leads = leads

    def enrich(
        self,
        target: str,
        target_type: str,
        engagement_id: int,
        config: dict[str, Any],
        discovery_dir: Path,
    ) -> dict[str, Any]:
        """Run configured passive connectors; failures are stored per connector.

        A URL target is enriched through its hostname, plus a dedicated
        ``url_resolution`` record of every address the URL resolves to.
        """
        results: dict[str, Any] = {}

        if not config.get("passive", {}).get("enabled", True):
            return results

        url_target = target_type == "url"
        if url_target:
            target = normalize(target)
        elif target_type != "domain":
            return results

        client = HttpClient(
            cache_dir=str(discovery_dir / "cache"),
            requests_per_minute=config.get("limits", {}).get("requests_per_minute", 4),
        )

        tasks = self._tasks(target, config, client)

        if url_target:
            tasks["url_resolution"] = lambda: {
                "host": target,
                "addresses": nmap_recon.resolve_addresses(target),
            }

        for name, task in tasks.items():
            try:
                result = task()
                results[name] = result

                evidence_path = self._leads.save_evidence(
                    engagement_id, f"discover-{name}", result
                )
                self._leads.record_connector(engagement_id, name, result, evidence_path)

            except Exception as exc:
                results[name] = {"error": str(exc)}

        return results

    def _tasks(
        self,
        target: str,
        config: dict[str, Any],
        client: HttpClient,
    ) -> dict[str, Any]:
        """Map enabled passive connector names to zero-argument callables."""
        limits = config.get("limits", {})
        sources = config.get("passive", {})

        tasks: dict[str, Any] = {}

        if sources.get("wayback"):
            tasks["wayback"] = lambda: wayback.collect(
                target, client, limits.get("wayback_records", 500)
            )
        if sources.get("crtsh"):
            tasks["crtsh"] = lambda: cert_transparency.collect(target, client)
        if sources.get("rdap"):
            tasks["rdap"] = lambda: rdap.collect(target, client)
        if sources.get("commoncrawl"):
            tasks["commoncrawl"] = lambda: commoncrawl.collect(
                target, client, limits.get("commoncrawl_records", 200)
            )
        if sources.get("dns"):
            tasks["dns"] = lambda: dns_recon.collect(target)
        if sources.get("whois"):
            tasks["whois"] = lambda: dns_whois.whois(target)

        return tasks


class ActiveCheckRunner:
    """Gated active checks: hostname HTTP/TLS plus IP-authorized TCP/Nmap."""

    def resolve_probe_target(
        self,
        target: str,
        policy_path: str,
        exclusions_path: str,
    ) -> dict[str, Any]:
        """Resolve the engagement target and classify its addresses.

        The target itself is the authorization basis for
        ``--probe-resolved``; exclusions still override. Returns the
        provenance record embedded in the discovery artifact.
        """
        probe_host = normalize(target)
        policy = load_policy(policy_path)
        exclusions = load_exclusions(exclusions_path)

        try:
            resolved = nmap_recon.resolve_addresses(probe_host)
            error = None
        except Exception as exc:
            resolved, error = [], str(exc)

        return {
            "host": probe_host,
            "resolved": resolved,
            "approved_for_probing": [
                address
                for address in resolved
                if not is_excluded(address, policy, exclusions)
            ],
            "excluded": [
                address
                for address in resolved
                if is_excluded(address, policy, exclusions)
            ],
            "error": error,
            "authorization_basis": "engagement target (--probe-resolved)",
        }

    def run(
        self,
        inventory: dict[str, Any],
        config: dict[str, Any],
        approved_assets: list[str],
        active_requested: bool,
        policy_path: str,
        exclusions_path: str,
        nmap_requested: bool = False,
        output_dir: Path | None = None,
        probe_host: str | None = None,
        resolved_allow: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        """Run approved hostname checks; TCP/Nmap only on scope-authorized IPs.

        *probe_host* is the engagement target's own hostname (URL/domain
        targets with ``--probe-resolved``): it is always included, and its
        resolved addresses are authorized via *resolved_allow* (exclusions
        still override).
        """
        if not active_requested:
            return {}

        active_config = config.get("active", {})

        if not active_config.get("enabled", False):
            raise PermissionError("Active checks are disabled in discovery.json.")

        if not active_config.get("require_explicit_asset_approval", True):
            raise PermissionError("Explicit asset approval must remain enabled.")

        if (
            nmap_requested
            and not config.get("nmap", {}).get("enabled", False)
        ):
            raise PermissionError("Nmap is disabled in discovery.json.")

        selected = self._select_assets(approved_assets, inventory, probe_host)

        max_assets = active_config.get("max_assets")
        if max_assets not in (None, 0, "all"):
            selected = selected[: int(max_assets)]

        # Load the scope policy once for the whole run.
        policy = load_policy(policy_path)
        exclusions = load_exclusions(exclusions_path)

        timeout = int(active_config.get("http_timeout_seconds", 10))
        ports = active_config.get("tcp_ports", list(tcp_recon.DEFAULT_PORTS))
        delay = float(active_config.get("delay_seconds", 2))
        connect_timeout = int(active_config.get("connect_timeout_seconds", 3))

        results: dict[str, Any] = {}

        for index, host in enumerate(selected):
            allowed, reason = is_in_scope(
                host,
                inventory["target"],
                inventory["target_type"],
                policy=policy,
                exclusions=exclusions,
            )

            if not allowed:
                results[host] = {
                    "status": "skipped",
                    "skipped": True,
                    "reason": reason,
                    "hostname_approval": "rejected_by_scope",
                    "http_tls": {"status": "not_run", "reason": reason},
                    "tcp": [],
                    "nmap": {"status": "not_run", "reason": reason},
                }
                continue

            results[host] = self._check_host(
                host,
                inventory,
                policy,
                exclusions,
                config,
                nmap_requested,
                output_dir,
                timeout,
                ports,
                connect_timeout,
                delay,
                resolved_allow,
            )

            # Politeness delay between assets, not after the last one.
            if delay and index < len(selected) - 1:
                time.sleep(delay)

        return results

    def _select_assets(
        self,
        approved_assets: list[str],
        inventory: dict[str, Any],
        probe_host: str | None = None,
    ) -> list[str]:
        """Intersect approved assets with inventory; the target host itself
        is always included when ``--probe-resolved`` names it."""
        approved = {normalize(item) for item in approved_assets}
        inventory_hosts = {
            normalize(item["hostname"])
            for item in inventory["assets"]
            if item.get("hostname")
        }

        selected = approved.intersection(inventory_hosts)

        if probe_host:
            selected = set(selected) | {normalize(probe_host)}

        return sorted(selected)

    def _classify_addresses(
        self,
        resolved_addresses: list[str],
        inventory: dict[str, Any],
        policy: dict[str, Any],
        exclusions: list[str],
        extra_allow: frozenset[str] | None = None,
    ) -> tuple[list[str], list[dict[str, str]], list[dict[str, str]]]:
        """Split resolved IPs into approved / excluded / unauthorized groups."""
        approved_addresses: list[str] = []
        excluded_addresses: list[dict[str, str]] = []
        unauthorized_addresses: list[dict[str, str]] = []

        for address in resolved_addresses:
            ip_allowed, ip_reason = is_in_scope(
                address,
                inventory["target"],
                inventory["target_type"],
                policy=policy,
                exclusions=exclusions,
                extra_allow=extra_allow,
            )

            if ip_allowed:
                approved_addresses.append(address)
                continue

            item = {"address": address, "reason": ip_reason}

            # Preserve the distinction between an explicit exclusion and an
            # address that simply is not approved.
            if "exclusion" in ip_reason.lower():
                excluded_addresses.append(item)
            else:
                unauthorized_addresses.append(item)

        return approved_addresses, excluded_addresses, unauthorized_addresses

    def _check_host(
        self,
        host: str,
        inventory: dict[str, Any],
        policy: dict[str, Any],
        exclusions: list[str],
        config: dict[str, Any],
        nmap_requested: bool,
        output_dir: Path | None,
        timeout: int,
        ports: list[int],
        connect_timeout: int,
        delay: float,
        extra_allow: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        """Run HTTP/TLS plus optionally TCP/Nmap for one approved hostname."""
        # Hostname approval permits only hostname-level HTTP/TLS checks.
        # These checks do not authorize IP-level TCP probing or Nmap.
        try:
            http_tls_result = http_recon.collect(host, timeout=timeout)
            http_tls_status = "completed"
        except Exception as exc:
            http_tls_result = {"hostname": host, "error": str(exc)}
            http_tls_status = "error"

        # Resolve addresses separately for IP-level authorization.
        try:
            resolved_addresses = nmap_recon.resolve_addresses(host)
            resolution_error = None
        except Exception as exc:
            resolved_addresses = []
            resolution_error = str(exc)

        approved_addresses, excluded_addresses, unauthorized_addresses = (
            self._classify_addresses(
                resolved_addresses, inventory, policy, exclusions, extra_allow
            )
        )

        # TCP checks are performed only against independently authorized IPs.
        tcp_results = []
        for address in approved_addresses:
            try:
                tcp_result = tcp_recon.collect(
                    address,
                    ports=ports,
                    timeout=connect_timeout,
                    delay_seconds=delay,
                )
            except Exception as exc:
                tcp_result = {"error": str(exc)}

            tcp_results.append({"connected_ip": address, "result": tcp_result})

        # Nmap also requires independently authorized IP addresses.
        if not nmap_requested:
            nmap_result: dict[str, Any] = {"status": "not_requested"}
        elif not approved_addresses:
            nmap_result = {
                "status": "skipped",
                "reason": (
                    "No resolved IP address is explicitly "
                    "authorized for Nmap by the engagement "
                    "scope policy."
                ),
            }
        else:
            try:
                nmap_result = nmap_recon.collect(
                    host,
                    output_dir,
                    config.get("nmap", {}),
                    scan_targets=approved_addresses,
                )
                nmap_result["status"] = "completed"
            except Exception as exc:
                nmap_result = {"status": "error", "error": str(exc)}

        return {
            "status": "completed",
            "hostname_approval": "approved",
            "ip_authorization": (
                "approved" if approved_addresses else "no_authorized_addresses"
            ),
            "resolved_addresses": resolved_addresses,
            "resolution_error": resolution_error,
            "approved_addresses": approved_addresses,
            "unauthorized_addresses": unauthorized_addresses,
            "excluded_addresses": excluded_addresses,
            "http_tls": {
                "status": http_tls_status,
                "authorization_basis": "explicit_hostname_approval",
                "result": http_tls_result,
            },
            "tcp": tcp_results,
            "nmap": nmap_result,
        }
