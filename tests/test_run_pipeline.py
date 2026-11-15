"""Unit tests for the one-command pipeline use case (``recon.py run``).

Uses stub step use cases so the orchestration logic (step order,
stop-at-first-failure, passive error tolerance) is verified without any
I/O.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from reconforge.application.use_cases.register_engagement import (
    RegistrationOutcome,
)
from reconforge.application.use_cases.run_pipeline import (
    PipelineRunRequest,
    RunEngagementPipeline,
)
from reconforge.domain.scope import Validation


class _Console:
    """Test double collecting console output."""

    def __init__(self):
        self.infos: list[str] = []
        self.warnings: list[str] = []

    def info(self, message: str) -> None:
        self.infos.append(message)

    def emit(self, payload: object) -> None:
        pass

    def warning(self, message: str) -> None:
        self.warnings.append(message)


class _StubUseCase:
    """Returns a canned result or raises a canned error."""

    def __init__(self, result=None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.calls: list[object] = []

    def execute(self, request):
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        return self.result


class _StubEngagements:
    def require(self, engagement_id: int) -> dict:
        return {"target": "example.org", "target_type": "domain"}


def _request(**overrides) -> PipelineRunRequest:
    base = dict(
        database=Path("db.sqlite3"),
        config_path=Path("config/discovery.json"),
        policy=Path("config/scope.json"),
        exclusions=Path("config/exclusions.txt"),
        output_root=Path("output"),
        engagement_id=7,
    )
    base.update(overrides)
    return PipelineRunRequest(**base)


def _pipeline(
    console: _Console,
    register: _StubUseCase | None = None,
    collect: _StubUseCase | None = None,
    correlate: _StubUseCase | None = None,
    discover: _StubUseCase | None = None,
    analyze: _StubUseCase | None = None,
    assemble: _StubUseCase | None = None,
) -> RunEngagementPipeline:
    return RunEngagementPipeline(
        engagements=_StubEngagements(),
        register=register or _StubUseCase(),
        collect=collect or _StubUseCase(result={"results": {}, "errors": {}}),
        correlate=correlate or _StubUseCase(result={}),
        discover=discover or _StubUseCase(result={}),
        analyze=analyze or _StubUseCase(result={}),
        assemble=assemble or _StubUseCase(result={}),
        console=console,
    )


class RunPipelineTests(unittest.TestCase):
    """Orchestration behaviour of RunEngagementPipeline."""

    def test_all_steps_run_in_order_and_succeed(self):
        console = _Console()
        pipeline = _pipeline(console)

        result = pipeline.execute(_request())

        self.assertTrue(result.ok)
        self.assertEqual(result.stopped_at, None)
        self.assertEqual(
            [step.step for step in result.steps],
            ["passive", "intel", "discover", "analyze", "report"],
        )
        self.assertEqual(result.engagement_id, 7)

    def test_stops_at_first_failing_step(self):
        console = _Console()
        analyze = _StubUseCase(error=FileNotFoundError("missing analyze input"))

        result = _pipeline(console, analyze=analyze).execute(_request())

        self.assertFalse(result.ok)
        self.assertEqual(result.stopped_at, "analyze")
        self.assertEqual(
            [step.step for step in result.steps],
            ["passive", "intel", "discover", "analyze"],
        )
        self.assertIn("missing analyze input", result.steps[-1].detail)

    def test_passive_connector_errors_do_not_stop_the_pipeline(self):
        console = _Console()
        collect = _StubUseCase(
            result={"results": {}, "errors": {"github": "rate limited"}}
        )

        result = _pipeline(console, collect=collect).execute(_request())

        self.assertTrue(result.ok)
        self.assertIn("passive/github: rate limited", console.warnings)

    def test_passive_failure_stops_the_pipeline(self):
        console = _Console()
        collect = _StubUseCase(error=OSError("database locked"))

        result = _pipeline(console, collect=collect).execute(_request())

        self.assertFalse(result.ok)
        self.assertEqual(result.stopped_at, "passive")

    def test_existing_engagement_is_reused_without_registration(self):
        console = _Console()
        register = _StubUseCase()

        _pipeline(console, register=register).execute(_request(engagement_id=7))

        self.assertEqual(register.calls, [])

    def test_new_engagement_is_registered_first(self):
        console = _Console()
        validation = Validation(True, "example.org", "Valid domain syntax.")
        register = _StubUseCase(
            result=RegistrationOutcome(validation=validation, engagement_id=3)
        )

        result = _pipeline(console, register=register).execute(
            _request(
                engagement_id=None,
                target="example.org",
                target_type="domain",
                mode="external",
                authorization="AUTH-1",
                owner="Owner",
            )
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.engagement_id, 3)
        self.assertEqual([step.step for step in result.steps][0], "register")
        self.assertIn("Registered engagement ID: 3", console.infos)

    def test_invalid_target_stops_before_any_collection(self):
        console = _Console()
        validation = Validation(False, "example.org", "Invalid domain syntax.")
        register = _StubUseCase(result=RegistrationOutcome(validation=validation))
        collect = _StubUseCase(result={"results": {}, "errors": {}})

        result = _pipeline(console, register=register, collect=collect).execute(
            _request(
                engagement_id=None,
                target="not a domain",
                target_type="domain",
                mode="external",
                authorization="AUTH-1",
                owner="Owner",
            )
        )

        self.assertFalse(result.ok)
        self.assertEqual(result.stopped_at, "register")
        self.assertEqual(result.steps[-1].detail, "Invalid domain syntax.")
        self.assertEqual(collect.calls, [])


if __name__ == "__main__":
    unittest.main()
