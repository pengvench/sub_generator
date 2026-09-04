#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Единая точка входа SubGenerator (ПК).

В корне репозитория лежат только соурс и батники на сборку; весь Python-код
находится в python/. Этот файл — тонкая обёртка, которая добавляет python/
в sys.path и выбирает режим:

    python generate.py              # GUI (customtkinter), без аргументов
    python generate.py --cli ...    # консольный конвейер (явно)
    python generate.py --workers 32 # консольный конвейер (есть аргументы)

Ранер scripts/run_sub_generator.ps1 всегда вызывает этот файл с аргументами
конвейера и переменной окружения SUB_GEN_PS_WRAPPER=1 — в этом режиме
включается консоль независимо от аргументов.

Собранные exe (build_release.bat): SubGenerator.exe / SubGenerator-CLI.exe.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_PYTHON_DIR = Path(__file__).resolve().parent / "python"
if str(_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_PYTHON_DIR))


def _console_mode(argv: list[str]) -> bool:
    """Консольный режим: есть аргументы, флаг --cli или обёртка ps1."""
    if os.environ.get("SUB_GEN_PS_WRAPPER"):
        return True
    if argv:
        return True
    return False


def main() -> int:
    argv = list(sys.argv[1:])

    if _console_mode(argv):
        # Явный флаг --cli/-c вырезаем (для единообразия с ui.main).
        if argv and argv[0] in ("--cli", "-c"):
            argv = argv[1:]
        from subgen.encoding import setup_console_encoding
        from subgen.pipeline import main as pipeline_main

        setup_console_encoding()
        return pipeline_main(argv)

    # Без аргументов — графический интерфейс.
    from ui.main import main as gui_main

    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
