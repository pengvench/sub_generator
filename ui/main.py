"""Точка входа SubGenerator.

Без аргументов — запускает графический интерфейс (customtkinter, Material-тема).
С флагом --cli / -c — консольный режим (полный конвейер), как из батника.
"""
from __future__ import annotations

import argparse
import os
import sys


def _run_cli(argv):
    from subgen.encoding import setup_console_encoding
    from subgen.pipeline import run

    setup_console_encoding()
    os.environ["SUB_GEN_PS_WRAPPER"] = "1"
    return run(argv)



def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-c", "--cli", action="store_true", help="Консольный режим (без GUI): полный конвейер.")
    parser.add_argument("-h", "--help", action="store_true", help="Показать справку.")
    try:
        ns, rest = parser.parse_known_args(argv)
    except SystemExit:
        return 2

    if ns.help and not ns.cli:
        parser.print_help()
        print("Без аргументов запускается графический интерфейс (customtkinter).")
        print("С флагом --cli запускается консольный режим (полный конвейер).")
        print("Пример: SubGenerator --cli --workers 32 --dpi-check --dpi-siberian")
        return 0

    if ns.cli:
        if ns.help:
            rest = rest + ["--help"]
        return _run_cli(rest)

    try:
        import customtkinter as ctk  # noqa: F401
    except Exception as exc:
        print(f"[gui] customtkinter недоступен: {exc}")
        print("[gui] Запустите в консольном режиме: SubGenerator --cli")
        return 1

    from ui.app import SubGenApp

    app = SubGenApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
