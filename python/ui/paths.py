"""Определение путей приложения (работает и из исходников, и из PyInstaller).

Единый соурс: python/ui/paths.py. Корень репозитория — на два уровня выше
(ui -> python -> корень), где лежат generate.py, bin/, data/, scripts/.
"""
from __future__ import annotations

import sys
from pathlib import Path


def app_root() -> Path:
    """Корень приложения.

    Из собранного .exe (frozen) — каталог рядом с exe.
    Из исходников — python/ui/../.. (корень репозитория sub_generator).
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    return app_root() / "data"


def sources_file() -> Path:
    return data_dir() / "sources.txt"


def ensure_sources_file() -> Path:
    """Вернуть путь к sources.txt, создав пустой файл, если его нет."""
    path = sources_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("", encoding="utf-8")
    return path


def bin_dir() -> Path:
    return app_root() / "bin"


def scripts_dir() -> Path:
    """Каталог вспомогательных скриптов (PyInstaller spec'и, ранеры, тесты)."""
    return app_root() / "scripts"


def assets_dir() -> Path:
    """Каталог ресурсов (иконки и т.п.)."""
    return app_root() / "assets"


def ui_dir() -> Path:
    if getattr(sys, "frozen", False):
        # Рядом с exe могут лежать страницы — но они вшиты. Возвращаем корень.
        return Path(__file__).resolve().parent
    return Path(__file__).resolve().parent
