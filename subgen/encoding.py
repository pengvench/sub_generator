"""Инициализация кодировки консоли для корректного вывода русского текста.

На Windows консоль по умолчанию может использовать cp866 (OEM) или cp1251,
а Python-процесс (особенно собранный PyInstaller) определяет кодировку stdout
по кодовой странице консоли. Это приводит к двум проблемам:
  1. UnicodeEncodeError при выводе символов вне кодовой страницы (например, '∞').
  2. "Квадраты" вместо русского текста при несоответствии кодировок.

Решение: принудительно переключаем кодовую страницу консоли на UTF-8 (65001)
и настраиваем sys.stdout/sys.stderr на UTF-8. Вызывается один раз в точке входа.
"""
from __future__ import annotations

import os
import sys


def _set_console_cp_utf8() -> None:
    """Переключить кодовую страницу консоли на UTF-8 (65001) через WinAPI."""
    try:
        import ctypes

        # SetConsoleOutputCP(65001) — кодировка вывода консоли.
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        # SetConsoleCP(65001) — кодировка ввода консоли.
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        # Консоль может быть недоступна (например, запуск из GUI без консоли).
        pass


def setup_console_encoding() -> None:
    """Настроить кодировку консоли и stdout/stderr на UTF-8 (Windows)."""
    if os.name != "nt":
        return

    _set_console_cp_utf8()

    # Принудительно используем UTF-8 для stdout/stderr.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # Для надёжности также выставляем переменную окружения, чтобы дочерние
    # процессы Python наследовали UTF-8.
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

