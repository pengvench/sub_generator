#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Точка входа: всё содержимое вынесено в пакет subgen."""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from subgen.encoding import setup_console_encoding
from subgen.pipeline import main

if __name__ == "__main__":
    setup_console_encoding()
    raise SystemExit(main())

