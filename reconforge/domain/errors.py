"""Domain-specific errors with stable, user-facing messages."""

from __future__ import annotations


class ReconForgeError(Exception):
    """Base class for domain/application errors reported without a traceback."""


class EngagementNotFoundError(ReconForgeError):
    """The referenced engagement does not exist in the database."""
