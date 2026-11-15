"""ReconForge command-line interface.

The entry point builds the parser from the command registry, loads
settings, wires the container (composition root) and dispatches to one
small command object per invocation. Call it through ``recon.py`` (or the
``recon`` console script after ``pip install``).
"""

from __future__ import annotations

import argparse
import logging
import sys

from reconforge.interfaces.cli.commands import COMMANDS_BY_NAME
from reconforge.interfaces.cli.composition import Container
from reconforge.interfaces.cli.config import SettingsLoader
from reconforge.shared.paths import PROJECT_ROOT, resolve_path


def build_parser() -> argparse.ArgumentParser:
    """Build the recon CLI argument parser from the command registry."""
    parser = argparse.ArgumentParser(
        prog="recon",
        description="ReconForge authorized hybrid reconnaissance framework",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    for command in (
        command
        for name in (
            "init",
            "validate",
            "register",
            "engagements",
            "passive",
            "intel",
            "discover",
            "analyze",
            "report",
            "run",
        )
        for command in [COMMANDS_BY_NAME[name]]
    ):
        sub_parser = sub.add_parser(command.name, help=command.help_text)
        command.configure(sub_parser)

    return parser


def configure_logging(settings: object) -> None:
    """Log to logs/reconforge.log and stderr at the configured level."""
    log_file = PROJECT_ROOT / "logs" / "reconforge.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=getattr(logging, str(settings.log_level), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler(sys.stderr)],
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns a process exit code."""
    settings = SettingsLoader().load()
    configure_logging(settings)

    args = build_parser().parse_args(argv)

    # Commands that define --database override the configured database.
    if getattr(args, "database", None):
        settings = settings.with_database(resolve_path(args.database))

    container = Container(settings)

    return COMMANDS_BY_NAME[args.command].run(args, container)


if __name__ == "__main__":
    raise SystemExit(main())
