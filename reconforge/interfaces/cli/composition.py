"""Composition root: wire infrastructure adapters into the use cases.

This is the only place that knows which concrete implementations back the
application ports. Every use case is built here and receives its
dependencies through the constructor.
"""

from __future__ import annotations

from reconforge.application.ports import EngagementRepository, LeadRepository
from reconforge.application.services.discovery import (
    ActiveCheckRunner,
    DiscoveryService,
)
from reconforge.application.settings import Settings
from reconforge.application.use_cases.analyze_evidence import AnalyzeEvidence
from reconforge.application.use_cases.assemble_assessment import AssembleAssessment
from reconforge.application.use_cases.collect_passive import CollectPassiveOsint
from reconforge.application.use_cases.correlate_intelligence import (
    CorrelateIntelligence,
)
from reconforge.application.use_cases.discover_assets import DiscoverAssets
from reconforge.application.use_cases.initialize_workspace import InitializeWorkspace
from reconforge.application.use_cases.list_engagements import ListEngagements
from reconforge.application.use_cases.register_engagement import RegisterEngagement
from reconforge.application.use_cases.run_pipeline import RunEngagementPipeline
from reconforge.application.use_cases.validate_target import ValidateTarget
from reconforge.application.workspace import WorkspaceLayout
from reconforge.infrastructure.connectors.runner import OsintRunner
from reconforge.infrastructure.jsonio import JsonArtifactStore
from reconforge.infrastructure.persistence.assessment_context import (
    AssessmentContextReader,
)
from reconforge.infrastructure.persistence.engagement_repository import (
    SqliteEngagementRepository,
)
from reconforge.infrastructure.persistence.evidence_store import EvidenceStore
from reconforge.infrastructure.reporting.renderers import (
    AnalysisReportRenderer,
    AssessmentReportRenderer,
    DiscoveryReportRenderer,
    IntelBriefRenderer,
)
from reconforge.interfaces.cli.console import Console


def _engagements(settings: Settings) -> EngagementRepository:
    return SqliteEngagementRepository(settings.database_path)


def _leads(settings: Settings) -> LeadRepository:
    return EvidenceStore(settings.database_path, settings.output_root)


class Container:
    """Holds the shared adapters; builds one use case per factory method."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.console = Console()
        self.workspace = WorkspaceLayout(settings.output_root)
        self.artifacts = JsonArtifactStore()
        self.engagements: EngagementRepository = _engagements(settings)
        self.leads: LeadRepository = _leads(settings)
        self.assessment_context = AssessmentContextReader()

    # -- engagement setup -------------------------------------------------

    def initialize_workspace(self) -> InitializeWorkspace:
        return InitializeWorkspace(self.engagements)

    def validate_target(self) -> ValidateTarget:
        return ValidateTarget(self.settings.allow_person_targets)

    def register_engagement(self) -> RegisterEngagement:
        return RegisterEngagement(
            self.engagements, self.settings.allow_person_targets
        )

    def list_engagements(self) -> ListEngagements:
        return ListEngagements(self.engagements)

    # -- pipeline ----------------------------------------------------------

    def collect_passive(self) -> CollectPassiveOsint:
        return CollectPassiveOsint(self.engagements, OsintRunner(self.leads))

    def correlate_intelligence(self) -> CorrelateIntelligence:
        return CorrelateIntelligence(
            self.workspace,
            self.artifacts,
            IntelBriefRenderer(),
            self.console,
        )

    def discover_assets(self) -> DiscoverAssets:
        return DiscoverAssets(
            self.workspace,
            self.artifacts,
            self.engagements,
            DiscoveryService(self.leads),
            ActiveCheckRunner(),
            DiscoveryReportRenderer(),
            DiscoveryReportRenderer(),
            self.console,
        )

    def analyze_evidence(self) -> AnalyzeEvidence:
        return AnalyzeEvidence(
            self.artifacts,
            AnalysisReportRenderer(),
            self.console,
        )

    def assemble_assessment(self) -> AssembleAssessment:
        return AssembleAssessment(
            self.artifacts,
            self.assessment_context,
            AssessmentReportRenderer(),
            AssessmentReportRenderer(),
            self.console,
        )

    def run_pipeline(self) -> RunEngagementPipeline:
        """Compose the step use cases into one end-to-end pipeline run."""
        return RunEngagementPipeline(
            engagements=self.engagements,
            register=self.register_engagement(),
            collect=self.collect_passive(),
            correlate=self.correlate_intelligence(),
            discover=self.discover_assets(),
            analyze=self.analyze_evidence(),
            assemble=self.assemble_assessment(),
            console=self.console,
        )
