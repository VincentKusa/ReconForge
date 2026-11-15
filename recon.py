#!/usr/bin/env python3
"""ReconForge — the single command-line entry point.

All workflow commands are dispatched from here: engagement setup
(init/validate/register/engagements), passive collection (passive), and
the pipeline steps intel/discover/analyze/report.

Usage:
    python3 recon.py <command> [options]
    python3 recon.py --help
"""

from __future__ import annotations

from reconforge.interfaces.cli.app import main

if __name__ == "__main__":
    raise SystemExit(main())
