"""Use case: the discover step (inventory, enrichment, gated active checks)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reconforge.application.ports import (
    ArtifactStore,
    Console,
    EngagementRepository,
    MarkdownRenderer,
    PdfRenderer,
)
from reconforge.application.services.asset_inventory import build_inventory
from reconforge.application.services.discovery import (
    ActiveCheckRunner,
    DiscoveryService,
)
from reconforge.application.workspace import WorkspaceLayout
from reconforge.domain.errors import ReconForgeError
from reconforge.domain.exposure_rules import build_assessment


class DiscoveryGateError(ReconForgeError):
    """An active-check request violated a command-line authorization gate."""


def apply_full_port_override(config: dict[str, Any]) -> None:
    """Extend the Nmap sweep to all UDP ports (TCP is already 1-65535).

    Mutates *config* in place: enables the UDP sweep and switches it from
    the top-N default to the full port range.
    """
    nmap_config = config.setdefault("nmap", {})
    udp_config = nmap_config.setdefault("udp", {})
    udp_config["all_ports"] = True
    udp_config["enabled"] = True


@dataclass(frozen=True)
class DiscoveryRequest:
    engagement_id: int
    database: Path
    config_path: Path
    policy: Path
    exclusions: Path
    active: bool = False
    nmap: bool = False
    all_ports: bool = False
    probe_resolved: bool = False


class DiscoverAssets:
    """Build the asset inventory and run controlled technical discovery."""

    def __init__(
        self,
        workspace: WorkspaceLayout,
        artifacts: ArtifactStore,
        engagements: EngagementRepository,
        enrichment: DiscoveryService,
        active_checks: ActiveCheckRunner,
        markdown: MarkdownRenderer,
        pdf: PdfRenderer,
        console: Console,
    ):
        self._workspace = workspace
        self._artifacts = artifacts
        self._engagements = engagements
        self._enrichment = enrichment
        self._active_checks = active_checks
        self._markdown = markdown
        self._pdf = pdf
        self._console = console

    def execute(self, request: DiscoveryRequest) -> dict[str, Any]:
        """Write ``discover.json`` + Markdown/PDF reports; return the result."""
        if request.nmap and not request.active:
            # Reject before any collection work, passive or active.
            raise DiscoveryGateError(
                "--nmap requires --active as well as explicit asset approval."
            )

        if request.probe_resolved and not request.active:
            raise DiscoveryGateError(
                "--probe-resolved requires --active: probing resolved "
                "addresses is active collection."
            )

        layout = self._workspace.engagement(request.engagement_id)
        discovery_dir = layout.discovery

        config = self._artifacts.load(request.config_path)
        if config is None:
            # Unreachable for required loads; keeps the optional type honest.
            raise FileNotFoundError(f"Required input not found: {request.config_path}")
        engagement = self._engagements.require(request.engagement_id)

        if request.probe_resolved and engagement["target_type"] not in (
            "url",
            "domain",
        ):
            raise DiscoveryGateError(
                "--probe-resolved applies to url and domain targets only."
            )

        if request.all_ports:
            # TCP always sweeps the full 1-65535 range; the flag extends
            # the UDP sweep from top-N ports to all ports as well.
            apply_full_port_override(config)
            self._console.info(
                "Full-port sweep requested: TCP 1-65535 plus all UDP ports."
            )

        discovery_dir.mkdir(parents=True, exist_ok=True)

        self._console.info(f"Discovery engagement: {request.engagement_id}")
        self._console.info(f"Target: {engagement['target']}")
        self._console.info("Running passive enrichment...")

        passive = self._enrichment.enrich(
            engagement["target"],
            engagement["target_type"],
            request.engagement_id,
            config,
            discovery_dir,
        )

        inventory = build_inventory(
            str(request.database),
            request.engagement_id,
            str(request.policy),
            str(request.exclusions),
        )

        probe_host: str | None = None
        resolved_allow: frozenset[str] = frozenset()
        resolved_target_ips: dict[str, Any] = {}

        if request.probe_resolved:
            # Probe every address the engagement target resolves to. The
            # target itself is the authorization basis; exclusions still
            # override. Config gates (active/nmap enablement) were already
            # enforced by the ActiveCheckRunner.
            resolved_target_ips = self._active_checks.resolve_probe_target(
                engagement["target"],
                str(request.policy),
                str(request.exclusions),
            )
            probe_host = resolved_target_ips.get("host")
            resolved_allow = frozenset(
                resolved_target_ips.get("approved_for_probing", [])
            )

            self._console.info(
                f"Probe-resolved: {probe_host} resolves to "
                f"{len(resolved_target_ips.get('resolved', []))} address(es); "
                f"{len(resolved_allow)} approved for probing."
            )

        active = self._active_checks.run(
            inventory,
            config,
            config.get("active", {}).get("approved_assets", []),
            request.active,
            str(request.policy),
            str(request.exclusions),
            nmap_requested=request.nmap,
            output_dir=discovery_dir,
            probe_host=probe_host,
            resolved_allow=resolved_allow,
        )

        assessment = build_assessment(
            {
                host: item["nmap"]
                for host, item in active.items()
                if item.get("nmap")
            }
        )

        result = {
            "engagement_id": request.engagement_id,
            **engagement,
            "passive": passive,
            "inventory": inventory,
            "active": active,
            "assessment": assessment,
        }

        if resolved_target_ips:
            result["resolved_target_ips"] = resolved_target_ips

        json_path = self._artifacts.write(layout.discovery_json, result)

        markdown_path = self._markdown.markdown(result, layout.discovery_markdown)
        pdf_path = self._pdf.pdf(result, layout.discovery_pdf)

        self._console.info("Discovery completed.")
        self._console.info(f"JSON: {json_path}")
        self._console.info(f"Report: {markdown_path}")
        self._console.info(f"PDF: {pdf_path}")
        self._console.info(
            f"In-scope hosts: {inventory['summary']['in_scope_hosts']}"
        )
        self._console.info(
            f"Excluded observations: "
            f"{inventory['summary']['excluded_observations']}"
        )
        self._console.info(f"Active checks: {len(active)}")

        return result
