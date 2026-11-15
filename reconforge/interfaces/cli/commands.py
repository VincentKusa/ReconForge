"""CLI commands: thin adapters between argparse and the use cases.

Each command parses its arguments, resolves paths, invokes one use case
from the container, prints the result, and maps the outcome to an exit
code. No business logic lives here.
"""

from __future__ import annotations

import argparse
import sqlite3
from dataclasses import asdict
from typing import TYPE_CHECKING

from reconforge.application.use_cases.analyze_evidence import AnalysisRequest
from reconforge.application.use_cases.assemble_assessment import AssessmentRequest
from reconforge.application.use_cases.collect_passive import PassiveCollectionRequest
from reconforge.application.use_cases.correlate_intelligence import (
    IntelligenceRequest,
)
from reconforge.application.use_cases.discover_assets import (
    DiscoveryGateError,
    DiscoveryRequest,
)
from reconforge.application.use_cases.register_engagement import (
    RegisterEngagementRequest,
)
from reconforge.application.use_cases.run_pipeline import PipelineRunRequest
from reconforge.application.use_cases.validate_target import ValidateTargetRequest
from reconforge.domain.errors import ReconForgeError
from reconforge.infrastructure.connectors.runner import DEFAULT_SOURCES
from reconforge.shared.paths import (
    DEFAULT_DATABASE,
    DEFAULT_OUTPUT_ROOT,
    PROJECT_ROOT,
    resolve_path,
)

if TYPE_CHECKING:
    from reconforge.interfaces.cli.composition import Container

MODES = ("external", "internal", "cloud", "hybrid")


class Command:
    """Base class: subclasses declare ``name``/``help_text`` and wiring."""

    name: str = ""
    help_text: str = ""

    def configure(self, parser: argparse.ArgumentParser) -> None:
        """Add this command's arguments to its subparser."""

    def run(self, args: argparse.Namespace, container: Container) -> int:
        raise NotImplementedError


class InitCommand(Command):
    name = "init"
    help_text = "Initialize local database"

    def run(self, args: argparse.Namespace, container: Container) -> int:
        path = container.initialize_workspace().execute()
        container.console.info(f"Initialized database: {path}")
        return 0


class ValidateCommand(Command):
    name = "validate"
    help_text = "Validate target syntax and mode"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--target", required=True)
        parser.add_argument("--type", dest="target_type", required=True)
        parser.add_argument("--mode", choices=MODES, required=True)

    def run(self, args: argparse.Namespace, container: Container) -> int:
        validation = container.validate_target().execute(
            ValidateTargetRequest(args.target, args.target_type, args.mode)
        )
        container.console.emit(asdict(validation))
        return 0 if validation.ok else 2


class RegisterCommand(Command):
    name = "register"
    help_text = "Register an authorized engagement"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--target", required=True)
        parser.add_argument("--type", dest="target_type", required=True)
        parser.add_argument("--mode", choices=MODES, required=True)
        parser.add_argument("--authorization", required=True)
        parser.add_argument("--owner", required=True)

    def run(self, args: argparse.Namespace, container: Container) -> int:
        outcome = container.register_engagement().execute(
            RegisterEngagementRequest(
                target=args.target,
                target_type=args.target_type,
                mode=args.mode,
                authorization=args.authorization,
                owner=args.owner,
            )
        )
        container.console.emit(asdict(outcome.validation))

        if outcome.error:
            container.console.warning(outcome.error)
            return 2

        if outcome.engagement_id is None:
            return 2

        container.console.info(
            f"Registered engagement ID: {outcome.engagement_id}"
        )
        return 0


class EngagementsCommand(Command):
    name = "engagements"
    help_text = "List registered engagements"

    def run(self, args: argparse.Namespace, container: Container) -> int:
        container.console.emit(container.list_engagements().execute())
        return 0


class PassiveCommand(Command):
    name = "passive"
    help_text = "Run selected passive OSINT connectors for a registered engagement"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--engagement", type=int, required=True)
        parser.add_argument("--sources", default=",".join(DEFAULT_SOURCES))
        parser.add_argument("--search-query", default=None)

    def run(self, args: argparse.Namespace, container: Container) -> int:
        sources = [item.strip() for item in args.sources.split(",") if item.strip()]

        try:
            result = container.collect_passive().execute(
                PassiveCollectionRequest(
                    engagement_id=args.engagement,
                    sources=sources,
                    search_query=args.search_query,
                )
            )
        except ReconForgeError as exc:
            container.console.warning(str(exc))
            return 2

        container.console.emit(result)
        return 0 if not result["errors"] else 1


class IntelCommand(Command):
    name = "intel"
    help_text = "Intel: correlate, prioritize and report collected intelligence"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--engagement", type=int, required=True)
        parser.add_argument("--database", default=str(DEFAULT_DATABASE))
        parser.add_argument("--policy", default="config/scope.json")
        parser.add_argument("--exclusions", default="config/exclusions.txt")
        parser.add_argument("--output-dir", default=None)

    def run(self, args: argparse.Namespace, container: Container) -> int:
        try:
            summary = container.correlate_intelligence().execute(
                IntelligenceRequest(
                    engagement_id=args.engagement,
                    database=resolve_path(args.database),
                    policy=resolve_path(args.policy),
                    exclusions=resolve_path(args.exclusions),
                    output_dir=(
                        resolve_path(args.output_dir) if args.output_dir else None
                    ),
                )
            )
        except ValueError as exc:
            container.console.warning(f"Intel error: {exc}")
            return 2

        container.console.emit(summary)
        return 0


class DiscoverCommand(Command):
    name = "discover"
    help_text = (
        "Discovery: passive enrichment and selective technical reconnaissance"
    )

    def configure(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--engagement", required=True, type=int)
        parser.add_argument("--database", default=str(DEFAULT_DATABASE))
        parser.add_argument("--config", default="config/discovery.json")
        parser.add_argument("--policy", default="config/scope.json")
        parser.add_argument("--exclusions", default="config/exclusions.txt")
        parser.add_argument(
            "--nmap",
            action="store_true",
            help=(
                "Run full TCP port/service/OS discovery; requires --active, "
                "config enablement and explicit asset approval."
            ),
        )
        parser.add_argument(
            "--active",
            action="store_true",
            help=(
                "Request active checks. "
                "Configuration and explicit asset approval are also required."
            ),
        )
        parser.add_argument(
            "--all-ports",
            action="store_true",
            help=(
                "Sweep all ports: TCP 1-65535 (always on for Nmap) plus "
                "all UDP ports instead of the UDP top-N default."
            ),
        )
        parser.add_argument(
            "--probe-resolved",
            action="store_true",
            help=(
                "Probe every address the engagement target (url/domain) "
                "resolves to: the target's own IPs are treated as approved "
                "for this run. Requires --active; exclusions still apply."
            ),
        )
        # --- fingerprint/WAF additions ---
        parser.add_argument(
            "--fingerprint-web",
            action="store_true",
            help=(
                "Active web/technology fingerprinting (httpx if present, "
                "otherwise a HEAD-request header fallback). "
                "Requires --active and explicit asset approval."
            ),
        )
        parser.add_argument(
            "--waf",
            action="store_true",
            help=(
                "Active WAF detection (wafw00f if present, otherwise a "
                "header heuristic). Requires --active and explicit asset "
                "approval. Active fingerprinting may be logged or blocked."
            ),
        )

    def run(self, args: argparse.Namespace, container: Container) -> int:
        try:
            container.discover_assets(
                fingerprint_web=args.fingerprint_web,
                waf=args.waf,
            ).execute(
                DiscoveryRequest(
                    engagement_id=args.engagement,
                    database=resolve_path(args.database),
                    config_path=resolve_path(args.config),
                    policy=resolve_path(args.policy),
                    exclusions=resolve_path(args.exclusions),
                    active=args.active,
                    nmap=args.nmap,
                    all_ports=args.all_ports,
                    probe_resolved=args.probe_resolved,
                )
            )
        except DiscoveryGateError as exc:
            container.console.warning(str(exc))
            return 2
        except (
            ReconForgeError,
            FileNotFoundError,
            PermissionError,
            ValueError,
            OSError,
        ) as exc:
            container.console.warning(f"Discovery error: {exc}")
            return 2

        return 0


class AnalyzeCommand(Command):
    name = "analyze"
    help_text = "Analysis: local evidence analysis and consolidation"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--engagement", type=int, required=True)
        parser.add_argument(
            "--output-root", default=str(PROJECT_ROOT / DEFAULT_OUTPUT_ROOT)
        )
        # --- CVE candidate additions ---
        parser.add_argument(
            "--cve-lookup",
            action="store_true",
            help=(
                "Query the NVD for CVE candidates from the fingerprinted "
                "services. Read-only external lookups; results are leads "
                "for the reviewer, never confirmed findings."
            ),
        )
        parser.add_argument(
            "--nvd-api-key",
            default=None,
            help=(
                "Optional NVD API key (raises the rate limit from 5/30s "
                "to 50/30s)."
            ),
        )

    def run(self, args: argparse.Namespace, container: Container) -> int:
        try:
            container.analyze_evidence(
                cve_lookup=args.cve_lookup,
                nvd_api_key=args.nvd_api_key,
            ).execute(
                AnalysisRequest(
                    engagement_id=args.engagement,
                    output_root=resolve_path(args.output_root),
                )
            )
        except (FileNotFoundError, ValueError, OSError) as exc:
            container.console.warning(f"Analysis error: {exc}")
            return 2

        return 0


class ReportCommand(Command):
    name = "report"
    help_text = "Report: final assessment assembly and reporting (local-only)"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--engagement", type=int, required=True)
        parser.add_argument(
            "--output-root", default=str(PROJECT_ROOT / DEFAULT_OUTPUT_ROOT)
        )
        parser.add_argument(
            "--database", default=str(PROJECT_ROOT / DEFAULT_DATABASE)
        )
        parser.add_argument(
            "--reviewer",
            default=None,
            help="Optional reviewer label for the review worksheet",
        )

    def run(self, args: argparse.Namespace, container: Container) -> int:
        try:
            container.assemble_assessment().execute(
                AssessmentRequest(
                    engagement_id=args.engagement,
                    output_root=resolve_path(args.output_root),
                    database=resolve_path(args.database),
                    reviewer=args.reviewer,
                )
            )
        except (FileNotFoundError, ValueError, OSError, sqlite3.Error) as exc:
            container.console.warning(f"Assessment error: {exc}")
            return 2

        return 0


class RunCommand(Command):
    name = "run"
    help_text = (
        "Run the whole engagement workflow: register (or reuse) an "
        "engagement, then passive -> intel -> discover -> analyze -> report"
    )

    def configure(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--engagement",
            type=int,
            default=None,
            help="Reuse an existing engagement instead of registering one",
        )
        parser.add_argument("--target", default=None)
        parser.add_argument("--type", dest="target_type", default=None)
        parser.add_argument("--mode", choices=MODES, default=None)
        parser.add_argument("--authorization", default=None)
        parser.add_argument("--owner", default=None)
        parser.add_argument("--sources", default=",".join(DEFAULT_SOURCES))
        parser.add_argument("--search-query", default=None)
        parser.add_argument("--database", default=str(DEFAULT_DATABASE))
        parser.add_argument(
            "--config",
            default=None,
            help="Discovery config JSON (default: config/discovery.json, "
            "falling back to config/discovery.json.example)",
        )
        parser.add_argument("--policy", default="config/scope.json")
        parser.add_argument("--exclusions", default="config/exclusions.txt")
        parser.add_argument(
            "--output-root", default=str(PROJECT_ROOT / DEFAULT_OUTPUT_ROOT)
        )
        parser.add_argument(
            "--nmap",
            action="store_true",
            help="Include full Nmap discovery (requires --active and config gates)",
        )
        parser.add_argument(
            "--active",
            action="store_true",
            help="Include active checks (requires config gates and approval)",
        )
        parser.add_argument(
            "--all-ports",
            action="store_true",
            help=(
                "Sweep all ports during discovery: TCP 1-65535 plus all "
                "UDP ports instead of the UDP top-N default."
            ),
        )
        parser.add_argument(
            "--probe-resolved",
            action="store_true",
            help=(
                "Probe every address the target (url/domain) resolves to "
                "during discovery. Requires --active; exclusions still apply."
            ),
        )
        # --- fingerprint/WAF/CVE additions for the pipeline ---
        parser.add_argument(
            "--fingerprint-web",
            action="store_true",
            help="Include web/technology fingerprinting in discovery",
        )
        parser.add_argument(
            "--waf",
            action="store_true",
            help="Include WAF detection in discovery",
        )
        parser.add_argument(
            "--cve-lookup",
            action="store_true",
            help="Include NVD CVE candidate lookup in analysis",
        )
        parser.add_argument(
            "--nvd-api-key",
            default=None,
            help="Optional NVD API key for the CVE lookup step",
        )
        parser.add_argument(
            "--reviewer",
            default=None,
            help="Optional reviewer label for the review worksheet",
        )

    def run(self, args: argparse.Namespace, container: Container) -> int:
        if args.engagement is None:
            missing = [
                flag
                for flag, value in (
                    ("--target", args.target),
                    ("--type", args.target_type),
                    ("--mode", args.mode),
                    ("--authorization", args.authorization),
                    ("--owner", args.owner),
                )
                if not value
            ]
            if missing:
                container.console.warning(
                    "Without --engagement a new engagement is registered; "
                    "missing options: " + " ".join(missing)
                )
                return 2

        config_path = self._resolve_config(args, container)

        try:
            result = container.run_pipeline(
                fingerprint_web=args.fingerprint_web,
                waf=args.waf,
                cve_lookup=args.cve_lookup,
                nvd_api_key=args.nvd_api_key,
            ).execute(
                PipelineRunRequest(
                    database=resolve_path(args.database),
                    config_path=config_path,
                    policy=resolve_path(args.policy),
                    exclusions=resolve_path(args.exclusions),
                    output_root=resolve_path(args.output_root),
                    engagement_id=args.engagement,
                    target=args.target or "",
                    target_type=args.target_type or "",
                    mode=args.mode or "",
                    authorization=args.authorization or "",
                    owner=args.owner or "",
                    sources=[
                        item.strip()
                        for item in args.sources.split(",")
                        if item.strip()
                    ],
                    search_query=args.search_query,
                    active=args.active,
                    nmap=args.nmap,
                    all_ports=args.all_ports,
                    probe_resolved=args.probe_resolved,
                    reviewer=args.reviewer,
                )
            )
        except ReconForgeError as exc:
            container.console.warning(str(exc))
            return 2

        if not result.ok:
            failed = next(step for step in result.steps if not step.ok)
            container.console.warning(
                f"Pipeline stopped at '{failed.step}': {failed.detail}"
            )
            return 2

        container.console.info(
            f"Pipeline completed for engagement {result.engagement_id}: "
            + ", ".join(step.step for step in result.steps)
        )
        return 0

    def _resolve_config(
        self, args: argparse.Namespace, container: Container
    ) -> object:
        """Discovery config: explicit path, default, then shipped example."""
        if args.config:
            return resolve_path(args.config)

        default = resolve_path("config/discovery.json")
        if default.exists():
            return default

        example = resolve_path("config/discovery.json.example")
        if example.exists():
            container.console.info(
                "Using passive-only discovery defaults "
                "(config/discovery.json.example; no config/discovery.json found)."
            )
            return example

        return default


COMMANDS: tuple[Command, ...] = (
    InitCommand(),
    ValidateCommand(),
    RegisterCommand(),
    EngagementsCommand(),
    PassiveCommand(),
    IntelCommand(),
    DiscoverCommand(),
    AnalyzeCommand(),
    ReportCommand(),
    RunCommand(),
)

COMMANDS_BY_NAME = {command.name: command for command in COMMANDS}