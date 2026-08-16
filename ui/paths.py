"""Определение путей приложения (работает и из исходников, и из PyInstaller)."""
from __future__ import annotations

import sys
from pathlib import Path


def app_root() -> Path:
    """Корень приложения.

    Из собранного .exe (frozen) — каталог рядом с exe.
    Из исходников — каталог build/ui/../.. (корень проекта sub_generator).
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent


def data_dir() -> Path:
    return app_root() / "data"


def sources_file() -> Path:
    return app_root() / "sources.txt"


def bin_dir() -> Path:
    return app_root() / "bin"


def scripts_dir() -> Path:
    """Каталог вспомогательных скриптов (build_release.bat, run_sub_generator.ps1 и т.п.)."""
    return app_root() / "scripts"



def ui_dir() -> Path:
    if getattr(sys, "frozen", False):
        # Рядом с exe могут лежать страницы — но они вшиты. Возвращаем корень.
        return Path(__file__).resolve().parent
    return Path(__file__).resolve().parent
