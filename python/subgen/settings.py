"""Пользовательские настройки приложения (data/settings.json).

Хранит настраиваемые параметры, которые пользователь меняет в GUI:
  - description — описание подписки (добавляется в начало как комментарий);
  - prefix      — префикс, добавляемый в начало подписки (по умолчанию "peppo");
  - test_options — параметры страницы «Тестирование» (workers, timeout,
    max_ping, min_speed, limit, toggles). Сохраняются между запусками,
    чтобы пользователю не приходилось заново выставлять значения.
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

# Дефолтные параметры страницы «Тестирование». Должны совпадать с
# дефолтами в PipelineOptions (ui/runner.py), чтобы при первом запуске
# (когда settings.json ещё нет) UI показывал те же значения, что и раньше.
DEFAULT_TEST_OPTIONS: dict[str, object] = {
    "workers": 32,
    "timeout": 15.0,
    "max_ping": 1500,
    "min_speed": 3000,
    "limit": 0,
    "no_stress": False,
    "telegram_check": True,
    "dpi_check": False,
    "dpi_siberian": False,
    "dpi_cidr": False,
    "dpi_active": False,
    # v8: Zapret-suite — часть DPI-проверки (ключи zapret_check/ai_check
    # удалены; старые settings.json просто игнорируют лишние ключи).
    # ИИ-гео слепок обязателен; единственная опция — ai_strict.
    "ai_strict": False,
    "ai_timeout": 6.0,
}


def _defaults() -> dict[str, object]:
    return {
        "description": SUBSCRIPTION_DESCRIPTION,
        "prefix": DEFAULT_PREFIX,
        # Копия, чтобы мутирование не затронуло DEFAULT_TEST_OPTIONS.
        "test_options": dict(DEFAULT_TEST_OPTIONS),
    }


def load_settings() -> dict[str, object]:
    """Загрузить настройки из data/settings.json (с подстановкой дефолтов)."""
    settings = _defaults()
    try:
        if _SETTINGS_PATH.exists():
            data = json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                # Строковые поля (description, prefix).
                for key in ("description", "prefix"):
                    value = data.get(key)
                    if isinstance(value, str):
                        settings[key] = value
                # Параметры тестирования (test_options).
                saved_test = data.get("test_options")
                if isinstance(saved_test, dict):
                    test_opts = settings["test_options"]
                    assert isinstance(test_opts, dict)
                    for key, default_val in DEFAULT_TEST_OPTIONS.items():
                        value = saved_test.get(key, default_val)
                        # Сверка типа: если в файле сохранён, например,
                        # строка "32" вместо числа 32 — приводим к дефолту.
                        if isinstance(value, type(default_val)):
                            test_opts[key] = value
    except Exception:
        pass
    return settings


def save_settings(settings: dict[str, object]) -> None:
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
    settings = load_settings()
    value = settings.get("description", SUBSCRIPTION_DESCRIPTION)
    return str(value) if isinstance(value, str) else SUBSCRIPTION_DESCRIPTION


def get_prefix() -> str:
    """Текущий префикс подписки."""
    settings = load_settings()
    value = settings.get("prefix", DEFAULT_PREFIX)
    return str(value) if isinstance(value, str) else DEFAULT_PREFIX


def get_test_options() -> dict[str, object]:
    """Текущие параметры тестирования (с подстановкой дефолтов)."""
    settings = load_settings()
    value = settings.get("test_options")
    if isinstance(value, dict):
        # Дополняем дефолтами — если в файле нет какого-то поля (например,
        # добавили новое в новой версии), оно подставится из DEFAULT_TEST_OPTIONS.
        merged = dict(DEFAULT_TEST_OPTIONS)
        merged.update(value)
        return merged
    return dict(DEFAULT_TEST_OPTIONS)


def save_test_options(test_options: dict[str, object]) -> None:
    """Сохранить только параметры тестирования (не трогая description/prefix)."""
    settings = load_settings()
    settings["test_options"] = dict(test_options)
    save_settings(settings)
