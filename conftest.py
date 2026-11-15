"""Pytest/bootstrap configuration.

Ensures the project root is importable regardless of how the test runner
is invoked (``pytest``, ``python -m pytest`` or ``python -m unittest``).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
