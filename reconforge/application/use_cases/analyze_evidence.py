"""Use case: the analyze step (local evidence analysis and consolidation)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reconforge.application.ports import ArtifactStore, Console, MarkdownRenderer
from reconforge.application.workspace import WorkspaceLayout
from reconforge.domain.evidence_analysis import build_analysis
from reconforge.domain.fingerprint import ServiceFingerprint


@dataclass(frozen=True)
class AnalysisRequest:
    engagement_id: int
    output_root: Path


class AnalyzeEvidence:
    """Consolidate discovery + intel artifacts into the analysis result."""

    def __init__(
        self,
        artifacts: ArtifactStore,
        renderer: MarkdownRenderer,
        console: Console,
        cve_lookup=None,
    ):
        self._artifacts = artifacts
        self._renderer = renderer
        self._console = console
        self._cve_lookup = cve_lookup

    def execute(self, request: AnalysisRequest) -> dict[str, Any]:
        """Write ``analyze.json`` + Markdown report; return the analysis result."""
        layout = WorkspaceLayout(request.output_root).engagement(
            request.engagement_id
        )

        discovery = self._artifacts.load(layout.discovery_json)
        if discovery is None:
            raise FileNotFoundError(f"Required input not found: {layout.discovery_json}")
        intel = self._artifacts.load(layout.intel_json, required=False)

        # Optional CVE enrichment (read-only NVD lookups; never touches the
        # target). Mutates *discovery* in place so ``build_analysis`` sees
        # the candidate list under each asset's fingerprint record.
        if self._cve_lookup is not None:
            self._enrich_with_cve_candidates(discovery)

        result = build_analysis(discovery, intel)

        # Carry the fingerprinted summary forward as its own section so the
        # analysis report and the final assessment can both surface it.
        result["fingerprints"] = discovery.get("fingerprints", [])

        json_path = self._artifacts.write(layout.analysis_json, result)
        markdown_path = self._renderer.markdown(result, layout.analysis_markdown)

        self._console.info("Analysis completed.")
        self._console.info(f"JSON: {json_path}")
        self._console.info(f"Report: {markdown_path}")
        self._console.info(
            "Technical findings: "
            f"{result['summary']['technical_findings_recorded']}"
        )
        self._console.info(
            f"TCP open observations: {result['summary']['tcp_open_observations']}"
        )
        self._console.info(f"Evidence gaps: {result['summary']['evidence_gaps']}")

        cve_total = sum(
            len(fp.get("cve_candidates", []))
            for fp in result.get("fingerprints", [])
        )
        if cve_total:
            self._console.info(
                f"CVE candidates (leads — reviewer validation required): {cve_total}"
            )

        return result

    def _enrich_with_cve_candidates(self, discovery: dict[str, Any]) -> None:
        """Look up CVE candidates for each fingerprinted service.

        Each candidate is appended to its asset's ``cve_candidates`` list.
        Lookups are deduplicated per (product, version, cpe) so an asset
        with the same service on several ports only queries NVD once.
        """
        seen: set[tuple[str, str | None, str]] = set()

        for report in discovery.get("fingerprints", []):
            candidates = report.setdefault("cve_candidates", [])

            for svc in report.get("services", []):
                key = (
                    svc.get("product") or "",
                    svc.get("version"),
                    (svc.get("cpe") or [""])[0] if svc.get("cpe") else "",
                )
                if key in seen:
                    continue
                seen.add(key)

                fingerprint = ServiceFingerprint(
                    port=int(svc.get("port") or 0),
                    protocol=svc.get("protocol") or "tcp",
                    service=svc.get("service"),
                    product=svc.get("product"),
                    version=svc.get("version"),
                    extrainfo=svc.get("extrainfo"),
                    ostype=svc.get("ostype"),
                    cpe=tuple(svc.get("cpe") or ()),
                )

                try:
                    found = self._cve_lookup.lookup(fingerprint)
                except Exception as exc:  # noqa: BLE001
                    self._console.warning(
                        f"CVE lookup failed for "
                        f"{svc.get('product')} {svc.get('version')}: {exc}"
                    )
                    continue

                for cand in found:
                    candidates.append(
                        {
                            "cve_id": cand.cve_id,
                            "product": cand.product,
                            "version": cand.version,
                            "cvss_score": cand.cvss_score,
                            "cvss_severity": cand.cvss_severity,
                            "summary": cand.summary,
                            "source": cand.source,
                            "status": "candidate — reviewer validation required",
                        }
                    )