"""Application settings (immutable value object).

Loading from the environment / ``config/settings.env`` file lives in the
CLI delivery layer (``interfaces.cli.config``); the application layer only
sees this frozen record.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Effective runtime configuration for one CLI invocation."""

    database_path: Path
    output_root: Path
    allow_person_targets: bool
    log_level: str

    def with_database(self, database_path: Path) -> Settings:
        """Return a copy pointing at a different database (``--database``)."""
        return Settings(
            database_path=database_path,
            output_root=self.output_root,
            allow_person_targets=self.allow_person_targets,
            log_level=self.log_level,
        )
