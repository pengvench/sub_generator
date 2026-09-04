"""Определение путей приложения (работает и из исходников, и из PyInstaller).

Единый соурс: python/ui/paths.py. Корень репозитория — на два уровня выше
(ui -> python -> корень), где лежат generate.py, sources.txt, bin/, scripts/.
data/ — только рантайм-артефакты (логи, кеш, отчёты), создаётся автоматически.
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
    """sources.txt — в корне (рядом с exe/в репозитории), НЕ в data/.

    В data/ живут только рантайм-артефакты (логи, кеш, отчёты),
    чтобы пользовательский список подписок не смешивался с мусором.
    """
    return app_root() / "sources.txt"


def ensure_sources_file() -> Path:
    """Вернуть путь к sources.txt, создав пустой файл, если его нет."""
    path = sources_file()
    if not path.exists():
        path.write_text("", encoding="utf-8")
    return path


def scripts_dir() -> Path:
    """Каталог вспомогательных скриптов (PyInstaller spec'и, ранеры, тесты)."""
    return app_root() / "scripts"


def assets_dir() -> Path:
    """Каталог ресурсов (иконки и т.п.)."""
    return app_root() / "assets"
