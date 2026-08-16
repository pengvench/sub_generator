"""Консольная точка входа SubGenerator (для отдельного CLI exe)."""
from __future__ import annotations

import sys

from subgen.encoding import setup_console_encoding
from subgen.pipeline import run

if __name__ == "__main__":
    setup_console_encoding()
    raise SystemExit(run(sys.argv[1:]))

