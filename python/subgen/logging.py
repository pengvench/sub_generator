"""Логирование в stdout + файл data/run.log с таймстампом.

Архитектура: потоки-работники (32+) пишут лог в queue (неблокирующая
операция), а отдельный writer-поток асинхронно сбрасывает queue в файл
и stdout. Это критично для параллельности: раньше log() брал глобальный
_lock_ и делал flush() на каждую строку, что сериализовало 32 потока.
На 5000+ узлов с 5-10 строками лога на узел = 25000+ flush() под локом
= минуты потерянного времени на ожидание I/O.

Теперь: put_nowait в очередь — O(1), без блокировки. Writer-поток
с batching (по 50 мс или 100 строк) делает один flush на пачку.
"""
from __future__ import annotations

import atexit
import contextlib
import logging
import os
import queue
import sys
import threading
import time


from subgen.config import DATA_DIR

_LOG_PATH = DATA_DIR / "run.log"
_log_lock = threading.Lock()  # защищает только _log_file_handle
_log_file_handle = None  # type: ignore

# Асинхронная очередь логов: потоки-работники кладут сюда строки, а
# writer-поток забирает пачками и пишет в файл+stdout без блокировки
# потоков-работников.
_log_queue: "queue.Queue[str | None]" = queue.Queue(maxsize=100_000)
_writer_thread: threading.Thread | None = None
_writer_started = False
_SHUTDOWN_SENTINEL = None  # None в очереди = сигнал остановки writer-потока


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


def _writer_loop() -> None:
    """Фоновый поток: читает _log_queue пачками, пишет в файл+stdout.

    Batching: накапливает до 100 строк или 50 мс, потом делает один flush.
    Это снижает количество I/O-операций в 50-100 раз по сравнению с
    посимвольным flush-ем под локом.
    """
    _init_log_file()
    batch: list[str] = []
    last_flush = time.monotonic()
    while True:
        try:
            item = _log_queue.get(timeout=0.05)
        except queue.Empty:
            # Таймаут — сбрасываем накопленный batch, даже если он маленький.
            if batch and (time.monotonic() - last_flush) >= 0.05:
                _flush_batch(batch)
                batch = []
                last_flush = time.monotonic()
            continue
        if item is _SHUTDOWN_SENTINEL:
            # Останавливаемся — сбрасываем остатки и выходим.
            if batch:
                _flush_batch(batch)
            return
        batch.append(item)
        # Flush по размеру или по времени.
        if len(batch) >= 100 or (time.monotonic() - last_flush) >= 0.05:
            _flush_batch(batch)
            batch = []
            last_flush = time.monotonic()


def _flush_batch(batch: list[str]) -> None:
    """Сбрасывает пачку строк лога в файл и stdout."""
    if not batch:
        return
    # stdout — построчно (print сам буферизует).
    for line in batch:
        _safe_print(line)
    # Файл — одним write + один flush на всю пачку.
    with _log_lock:
        if _log_file_handle is not None:
            try:
                _log_file_handle.write("".join(line + "\n" for line in batch))
                _log_file_handle.flush()
            except Exception as exc:
                # ВАЖНО: только stderr, НЕ через logging — иначе рекурсия
                # (мост stdlib logging -> log() -> очередь -> _flush_batch).
                print(f"[log] запись в run.log не удалась: {type(exc).__name__}: {exc}", file=sys.stderr)


def _ensure_writer_started() -> None:
    """Лениво запускает writer-поток при первом вызове log()."""
    global _writer_thread, _writer_started
    if not _writer_started:
        with _log_lock:
            if not _writer_started:
                _writer_thread = threading.Thread(
                    target=_writer_loop, name="log-writer", daemon=True
                )
                _writer_thread.start()
                _writer_started = True


def log(message: str) -> None:
    """Печать в stdout + дублирование в data/run.log с таймстампом.

    Асинхронная: кладёт строку в _log_queue (O(1), без блокировки) и
    возвращается. Writer-поток асинхронно сбрасывает queue в файл.
    Это снимает contention между 32+ потоками-работниками на I/O.
    """
    _ensure_writer_started()
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    try:
        _log_queue.put_nowait(line)
    except queue.Full:
        # Очередь переполнена (максимум 100k строк) — writer не успевает.
        # В этом случае пишем синхронно, чтобы не потерять лог. Это
        # аварийный режим, в норме не должен случаться.
        _safe_print(line)
        with _log_lock:
            if _log_file_handle is None:
                _init_log_file()
            try:
                _log_file_handle.write(line + "\n")
                _log_file_handle.flush()
            except Exception as exc:
                # Аварийный путь переполнения очереди: только stderr (без
                # logging — защита от рекурсии, см. _flush_batch).
                print(f"[log] аварийная запись в run.log не удалась: {type(exc).__name__}: {exc}", file=sys.stderr)


def shutdown() -> None:
    """Корректно остановить writer-поток (для atexit/тестов)."""
    global _writer_started
    if _writer_started and _writer_thread is not None:
        try:
            _log_queue.put_nowait(_SHUTDOWN_SENTINEL)
        except queue.Full:
            # Очередь переполнена — writer сам заметит остановку по join-таймауту
            # (поток daemon); диагностическую заметку выводим в stderr.
            print("[log] очередь переполнена, writer остановлен по таймауту", file=sys.stderr)
        _writer_thread.join(timeout=2.0)
        _writer_started = False


# ---------------------------------------------------------------------------
# Мост stdlib logging -> асинхронная очередь проекта.
#
# Модули движка (runtime/*) не могут импортировать subgen.logging напрямую
# (цикл: subgen -> xray_runtime -> runtime), поэтому они пишут в стандартный
# logging.getLogger(__name__). Этот мост, установленный на старте приложения,
# перенаправляет записи в очередь log() — они попадают в stdout и data/run.log.
#
# Уровень по умолчанию WARNING (тихие debug-сообщения горячих путей не шумят);
# SUBGEN_DEBUG=1 включает DEBUG (диагностика при разборе проблем).
# ---------------------------------------------------------------------------
_bridge_installed = False


class _StdlibQueueHandler(logging.Handler):
    """Пересылает записи stdlib logging в очередь log() (без блокировки)."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            log(f"[{record.levelname}] {record.name}: {record.getMessage()}")
        except Exception:
            self.handleError(record)


def install_stdlib_bridge(level: int | None = None) -> None:
    """Подключить stdlib logging к stdout + data/run.log (вызывать на старте).

    Идемпотентна: повторные вызовы (GUI + CLI точки входа) не дублируют мост.
    ``level`` по умолчанию: DEBUG если SUBGEN_DEBUG=1, иначе WARNING.
    """
    global _bridge_installed
    if _bridge_installed:
        return
    _bridge_installed = True
    if level is None:
        level = logging.DEBUG if os.environ.get("SUBGEN_DEBUG") else logging.WARNING
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(_StdlibQueueHandler())


atexit.register(shutdown)


# Ранний вызов моста прямо из этого модуля: даже если точка входа не успела
# вызвать install_stdlib_bridge() (например, библиотечное использование
# конвейера), предупреждения stdlib logging не теряются молча.
# Уровень остаётся WARNING, если переменная окружения не задана.
with contextlib.suppress(Exception):
    install_stdlib_bridge()

