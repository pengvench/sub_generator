"""Консольная точка входа SubGenerator (для отдельного CLI exe)."""
from __future__ import annotations

import sys

from subgen.encoding import setup_console_encoding
from subgen.pipeline import run
from ui.paths import ensure_sources_file

if __name__ == "__main__":
    setup_console_encoding()
    ensure_sources_file()
    raise SystemExit(run(sys.argv[1:]))

