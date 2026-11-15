"""Load ReconForge settings from the process environment and settings.env.

``config/settings.env`` entries are applied with ``setdefault`` so real
environment variables always win. Connector credentials (``GITHUB_TOKEN``,
search provider keys, ...) are read by the connectors themselves from
``os.environ``; loading the file here makes them available without shell
exports.
"""

from __future__ import annotations

import os

from reconforge.application.settings import Settings
from reconforge.shared.paths import DEFAULT_DATABASE, PROJECT_ROOT, resolve_path


class SettingsLoader:
    """Build the immutable :class:`Settings` for one CLI invocation."""

    ENV_FILE = PROJECT_ROOT / "config" / "settings.env"

    def load(self) -> Settings:
        if self.ENV_FILE.exists():
            for line in self.ENV_FILE.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

        return Settings(
            database_path=resolve_path(
                os.getenv("DATABASE_PATH", str(PROJECT_ROOT / DEFAULT_DATABASE))
            ),
            output_root=PROJECT_ROOT / "output",
            allow_person_targets=(
                os.getenv("ALLOW_PERSON_TARGETS", "false").lower() == "true"
            ),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )
