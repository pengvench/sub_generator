"""Логирование в stdout + файл data/run.log с таймстампом."""
from __future__ import annotations

import atexit
import contextlib
import sys
import threading
import time


from subgen.config import DATA_DIR

_LOG_PATH = DATA_DIR / "run.log"
_log_lock = threading.Lock()
_log_file_handle = None  # type: ignore


def _init_log_file():
    global _log_file_handle
    if _log_file_handle is None:
        _log_file_handle = open(_LOG_PATH, "a", encoding="utf-8")
        atexit.register(_close_log_file)


def _close_log_file() -> None:
    global _log_file_handle
    if _log_file_handle is not None:
        with contextlib.suppress(Exception):
            _log_file_handle.close()
        _log_file_handle = None


def _safe_print(message: str) -> None:
    """Печать в stdout с защитой от ошибок кодировки (cp1251 и т.п.)."""
    try:
        print(message, flush=True)
    except UnicodeEncodeError:
        # Символы, не поддерживаемые кодировкой консоли, заменяем на '?'.
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        safe = message.encode(enc, errors="replace").decode(enc, errors="replace")
        print(safe, flush=True)


def log(message: str) -> None:
    """Печать в stdout + дублирование в data/run.log с таймстампом."""
    _safe_print(message)
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n"
    with _log_lock:
        try:
            _init_log_file()
            _log_file_handle.write(line)
            _log_file_handle.flush()
        except Exception:
            pass

