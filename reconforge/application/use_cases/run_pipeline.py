"""Use case: run the whole engagement workflow in one invocation.

Composes the step use cases (register -> passive -> intel -> discover ->
analyze -> report) into a single end-to-end run. Steps stop at the first
failure; passive connector errors are reported but do not stop the
pipeline, matching the passive command's semantics.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reconforge.application.ports import Console, EngagementRepository
from reconforge.application.use_cases.analyze_evidence import (
    AnalysisRequest,
    AnalyzeEvidence,
)
from reconforge.application.use_cases.assemble_assessment import (
    AssembleAssessment,
    AssessmentRequest,
)
from reconforge.application.use_cases.collect_passive import (
    CollectPassiveOsint,
    PassiveCollectionRequest,
)
from reconforge.application.use_cases.correlate_intelligence import (
    CorrelateIntelligence,
    IntelligenceRequest,
)
from reconforge.application.use_cases.discover_assets import (
    DiscoverAssets,
    DiscoveryGateError,
    DiscoveryRequest,
)
from reconforge.application.use_cases.register_engagement import (
    RegisterEngagement,
    RegisterEngagementRequest,
)
from reconforge.domain.errors import ReconForgeError


@dataclass(frozen=True)
class PipelineRunRequest:
    """Everything one end-to-end pipeline run needs.

    Provide either ``engagement_id`` (reuse a registered engagement) or
    the registration fields (register a new engagement first).
    """

    database: Path
    config_path: Path
    policy: Path
    exclusions: Path
    output_root: Path
    engagement_id: int | None = None
    target: str = ""
    target_type: str = ""
    mode: str = ""
    authorization: str = ""
    owner: str = ""
    sources: list[str] = field(default_factory=list)
    search_query: str | None = None
    active: bool = False
    nmap: bool = False
    all_ports: bool = False
    probe_resolved: bool = False
    reviewer: str | None = None


@dataclass(frozen=True)
class StepOutcome:
    """Result of one pipeline step."""

    step: str
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class PipelineRunResult:
    """Aggregate result: per-step outcomes and where the run stopped."""

    engagement_id: int | None
    steps: tuple[StepOutcome, ...]

    @property
    def ok(self) -> bool:
        return all(step.ok for step in self.steps)

    @property
    def stopped_at(self) -> str | None:
        for step in self.steps:
            if not step.ok:
                return step.step
        return None


class RunEngagementPipeline:
    """Orchestrates the full engagement workflow through the step use cases."""

    def __init__(
        self,
        engagements: EngagementRepository,
        register: RegisterEngagement,
        collect: CollectPassiveOsint,
        correlate: CorrelateIntelligence,
        discover: DiscoverAssets,
        analyze: AnalyzeEvidence,
        assemble: AssembleAssessment,
        console: Console,
    ):
        self._engagements = engagements
        self._register = register
        self._collect = collect
        self._correlate = correlate
        self._discover = discover
        self._analyze = analyze
        self._assemble = assemble
        self._console = console

    def execute(self, request: PipelineRunRequest) -> PipelineRunResult:
        """Run every step in order; stop at the first failing step."""
        steps: list[StepOutcome] = []

        engagement_id = request.engagement_id
        if engagement_id is None:
            engagement_id = self._register_engagement(request, steps)
            if engagement_id is None:
                return PipelineRunResult(None, tuple(steps))
        else:
            # Raises EngagementNotFoundError for unknown ids.
            self._engagements.require(engagement_id)

        # Passive collection: connector errors are non-fatal; storage or
        # engagement failures stop the pipeline here.
        ok, outcome = self._guard(
            steps,
            "passive",
            (ReconForgeError, OSError, sqlite3.Error, ValueError),
            lambda: self._collect.execute(
                PassiveCollectionRequest(
                    engagement_id=engagement_id,  # type: ignore[arg-type]
                    sources=request.sources,
                    search_query=request.search_query,
                )
            ),
        )
        if ok:
            for name, error in outcome["errors"].items():
                self._console.warning(f"passive/{name}: {error}")
        else:
            return PipelineRunResult(engagement_id, tuple(steps))

        run = [
            (
                "intel",
                (ValueError,),
                lambda: self._correlate.execute(
                    IntelligenceRequest(
                        engagement_id=engagement_id,  # type: ignore[arg-type]
                        database=request.database,
                        policy=request.policy,
                        exclusions=request.exclusions,
                    )
                ),
            ),
            (
                "discover",
                (
                    DiscoveryGateError,
                    ReconForgeError,
                    FileNotFoundError,
                    PermissionError,
                    ValueError,
                    OSError,
                ),
                lambda: self._discover.execute(
                    DiscoveryRequest(
                        engagement_id=engagement_id,  # type: ignore[arg-type]
                        database=request.database,
                        config_path=request.config_path,
                        policy=request.policy,
                        exclusions=request.exclusions,
                        active=request.active,
                        nmap=request.nmap,
                        all_ports=request.all_ports,
                        probe_resolved=request.probe_resolved,
                    )
                ),
            ),
            (
                "analyze",
                (FileNotFoundError, ValueError, OSError),
                lambda: self._analyze.execute(
                    AnalysisRequest(
                        engagement_id=engagement_id,  # type: ignore[arg-type]
                        output_root=request.output_root,
                    )
                ),
            ),
            (
                "report",
                (FileNotFoundError, ValueError, OSError, sqlite3.Error),
                lambda: self._assemble.execute(
                    AssessmentRequest(
                        engagement_id=engagement_id,  # type: ignore[arg-type]
                        output_root=request.output_root,
                        database=request.database,
                        reviewer=request.reviewer,
                    )
                ),
            ),
        ]

        for name, exceptions, action in run:
            ok, _ = self._guard(steps, name, exceptions, action)
            if not ok:
                return PipelineRunResult(engagement_id, tuple(steps))

        return PipelineRunResult(engagement_id, tuple(steps))

    # -- helpers -----------------------------------------------------------

    def _register_engagement(
        self,
        request: PipelineRunRequest,
        steps: list[StepOutcome],
    ) -> int | None:
        """Register a new engagement; record the outcome and return its id."""
        outcome = self._register.execute(
            RegisterEngagementRequest(
                target=request.target,
                target_type=request.target_type,
                mode=request.mode,
                authorization=request.authorization,
                owner=request.owner,
            )
        )

        if not outcome.validation.ok:
            steps.append(
                StepOutcome("register", False, outcome.validation.message)
            )
            return None

        if outcome.error or outcome.engagement_id is None:
            steps.append(
                StepOutcome("register", False, outcome.error or "registration failed")
            )
            return None

        steps.append(StepOutcome("register", True))
        self._console.info(f"Registered engagement ID: {outcome.engagement_id}")
        return outcome.engagement_id

    def _guard(
        self,
        steps: list[StepOutcome],
        name: str,
        exceptions: tuple[type[BaseException], ...],
        action: Callable[[], Any],
    ) -> tuple[bool, Any]:
        """Run one step, recording success or failure in *steps*."""
        try:
            result = action()
        except exceptions as exc:
            steps.append(StepOutcome(name, False, str(exc)))
            return False, None

        steps.append(StepOutcome(name, True))
        return True, result
