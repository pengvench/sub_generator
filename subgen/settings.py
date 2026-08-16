"""Пользовательские настройки приложения (data/settings.json).

Хранит настраиваемые параметры, которые пользователь меняет в GUI:
  - description — описание подписки (добавляется в начало как комментарий);
  - prefix      — префикс, добавляемый в начало подписки (по умолчанию "peppo").
"""
from __future__ import annotations

import json
import threading

from pathlib import Path

from subgen.config import DATA_DIR, SUBSCRIPTION_DESCRIPTION

_SETTINGS_PATH = DATA_DIR / "settings.json"
_lock = threading.Lock()

# Значения по умолчанию.
DEFAULT_PREFIX = "peppo"


def _defaults() -> dict[str, str]:
    return {
        "description": SUBSCRIPTION_DESCRIPTION,
        "prefix": DEFAULT_PREFIX,
    }


def load_settings() -> dict[str, str]:
    """Загрузить настройки из data/settings.json (с подстановкой дефолтов)."""
    settings = _defaults()
    try:
        if _SETTINGS_PATH.exists():
            data = json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for key in ("description", "prefix"):
                    value = data.get(key)
                    if isinstance(value, str):
                        settings[key] = value
    except Exception:
        pass
    return settings


def save_settings(settings: dict[str, str]) -> None:
    """Сохранить настройки в data/settings.json."""
    with _lock:
        _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _SETTINGS_PATH.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(settings, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(_SETTINGS_PATH)


def get_description() -> str:
    """Текущее описание подписки."""
    return load_settings().get("description", SUBSCRIPTION_DESCRIPTION)


def get_prefix() -> str:
    """Текущий префикс подписки."""
    return load_settings().get("prefix", DEFAULT_PREFIX)
