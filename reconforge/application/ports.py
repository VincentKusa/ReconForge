"""Ports: interfaces the application layer depends on.

Use cases are written against these protocols; the infrastructure package
provides the concrete adapters (SQLite repositories, file stores, console,
renderers). This keeps the application layer independent of any specific
database, filesystem or presentation technology.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from reconforge.domain.scope import Validation


@runtime_checkable
class Console(Protocol):
    """User-facing output channel (stdout/stderr in the CLI delivery)."""

    def info(self, message: str) -> None:
        """Print a progress/status line."""
        ...

    def emit(self, payload: object) -> None:
        """Print a structured JSON payload."""
        ...

    def warning(self, message: str) -> None:
        """Print a warning line to stderr."""
        ...


@runtime_checkable
class EngagementRepository(Protocol):
    """Persistence of engagement records."""

    def ensure_schema(self) -> Path:
        """Create the database/schema if needed; return its path."""
        ...

    def register(
        self,
        normalized_target: str,
        target_type: str,
        mode: str,
        authorization: str,
        owner: str,
    ) -> int:
        """Insert an engagement row and return its id."""
        ...

    def get(self, engagement_id: int) -> dict[str, Any] | None: ...

    def require(self, engagement_id: int) -> dict[str, Any]:
        """Return the engagement or raise EngagementNotFoundError."""
        ...

    def list_all(self) -> list[dict[str, Any]]: ...


@runtime_checkable
class LeadRepository(Protocol):
    """Persistence of collected leads and raw connector evidence."""

    def add(
        self,
        engagement_id: int,
        leads: list[dict[str, Any]],
        evidence_path: str | None = None,
    ) -> None: ...

    def record_connector(
        self,
        engagement_id: int,
        connector: str,
        data: Any,
        evidence_path: str | None = None,
    ) -> int:
        """Derive and persist the leads of one connector payload; return count."""
        ...

    def save_evidence(self, engagement_id: int, source: str, data: Any) -> str:
        """Write raw connector output to the evidence directory; return path."""
        ...


@runtime_checkable
class ArtifactStore(Protocol):
    """Read/write access to JSON artifacts."""

    def load(self, path: Path, required: bool = True) -> dict[str, Any] | None: ...

    def write(
        self, path: Path, data: dict[str, Any], trailing_newline: bool = False
    ) -> Path: ...


@runtime_checkable
class MarkdownRenderer(Protocol):
    """Renders a step result as a Markdown report at *path*."""

    def markdown(self, result: dict[str, Any], path: Path) -> Path: ...


@runtime_checkable
class PdfRenderer(Protocol):
    """Renders a step result as a PDF report at *path*."""

    def pdf(self, result: dict[str, Any], path: Path) -> Path: ...


@runtime_checkable
class AssessmentContext(Protocol):
    """Read-only engagement metadata and input provenance."""

    def database_context(self, database: Path, engagement_id: int) -> dict[str, Any]: ...

    def source_manifest(
        self,
        engagement_dir: Path,
        database: Path,
        input_paths: list[Path],
    ) -> dict[str, Any]: ...


@runtime_checkable
class ValidationPresenter(Protocol):
    """Formats a scope validation result for display."""

    def present(self, validation: Validation) -> dict[str, Any]:
        return asdict(validation)  # pragma: no cover - default convention
