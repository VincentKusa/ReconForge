"""Console adapter: the CLI implementation of the Console port."""

from __future__ import annotations

import json
import sys


class Console:
    """Prints progress lines to stdout/stderr and payloads as JSON."""

    def info(self, message: str) -> None:
        print(message)

    def emit(self, payload: object) -> None:
        print(json.dumps(payload, indent=2))

    def warning(self, message: str) -> None:
        print(message, file=sys.stderr)
