"""Фоновый запуск конвейера и агрегация статистики для GUI."""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Optional, TextIO

from . import paths

PROGRESS_MARKER = "[POWERPROGRESS]"


@dataclass
class PipelineOptions:
    workers: int = 32
    timeout: float = 15.0
    limit: int = 0
    max_ping: int = 1500
    min_speed: int = 3000
    plain: bool = False
    no_stress: bool = False
    telegram_check: bool = True
    dpi_check: bool = False

    dpi_siberian: bool = False
    dpi_cidr: bool = False
    dpi_active: bool = False
    dpi_active_timeout: float = 4.0
    video_check: bool = False
    route_check: bool = False
    zapret_check: bool = False

    zapret_targets: int = 8
    zapret_timeout: float = 5.0
    zapret_min_score: float = 0.75
    zapret_no_http: bool = False
    start_stage: str = "ping"
    use_cache: bool = False




@dataclass
class SourceStat:
    url: str
    discovered: int = 0
    ping_passed: int = 0
    working: int = 0
    rejected: int = 0


@dataclass
class RunEvent:
    kind: str  # log | progress | done | error | source_stats
    message: str = ""
    progress: Optional[tuple[int, str]] = None
    stats: list[SourceStat] = field(default_factory=list)


class _StdoutProxy(TextIO):
    """Перенаправляет запись в sys.stdout в перехватчик строк."""

    encoding = "utf-8"

    def __init__(self, sink):
        self._sink = sink
        self._buffer = ""

    def write(self, data: str) -> int:
        self._buffer += data
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self._sink(line.rstrip("\r"))
        return len(data)

    def flush(self) -> None:
        if self._buffer:
            self._sink(self._buffer.rstrip("\r"))
            self._buffer = ""

    def isatty(self) -> bool:
        return False

    def fileno(self):
        return -1

    def readable(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False


def build_pipeline_args(options: PipelineOptions, sources: list[str]) -> list[str]:
    """Собрать аргументы CLI конвейера из настроек UI (для PowerShell-запуска)."""
    args: list[str] = []
    # Всегда передаём workers/timeout явно: дефолты конвейера (4/8) отличаются
    # от дефолтов UI (32/15), поэтому при совпадении с UI-дефолтом аргумент
    # нельзя опускать — иначе конвейер применит свой дефолт.
    args += ["--workers", str(options.workers)]
    args += ["--timeout", str(options.timeout)]
    if options.limit:
        args += ["--limit", str(options.limit)]
    # max_ping/min_speed тоже передаём всегда: дефолты конвейера (1000/5000)
    # отличаются от дефолтов UI (1500/3000), поэтому при совпадении с UI-дефолтом
    # аргумент нельзя опускать — иначе конвейер применит свой дефолт.
    args += ["--max-ping", str(options.max_ping)]
    args += ["--min-speed", str(options.min_speed)]

    if options.plain:
        args.append("--plain")
    if options.no_stress:
        args.append("--no-stress")
    if not options.telegram_check:
        args.append("--no-telegram")
    if options.dpi_check:
        args.append("--dpi-check")
    if options.dpi_siberian:
        args.append("--dpi-siberian")
    if options.dpi_cidr:
        args.append("--dpi-cidr")
    if options.dpi_active:
        args.append("--dpi-active")
        if options.dpi_active_timeout != 4.0:
            args += ["--dpi-active-timeout", str(options.dpi_active_timeout)]
    if options.video_check:
        args.append("--video-check")
    if options.route_check:
        args.append("--route-check")
    if options.zapret_check:
        args += ["--zapret-check"]
        if options.zapret_targets != 8:
            args += ["--zapret-targets", str(options.zapret_targets)]
        if options.zapret_timeout != 5.0:
            args += ["--zapret-timeout", str(options.zapret_timeout)]
        if options.zapret_min_score != 0.75:
            args += ["--zapret-min-score", str(options.zapret_min_score)]
        if options.zapret_no_http:
            args.append("--zapret-no-http")
    if options.start_stage != "ping":
        args += ["--start-stage", options.start_stage]
    if sources:
        args += ["--sources"] + sources
    return args


class PipelineRunner:
    """Запускает subgen.pipeline.run в фоновом потоке, собирает события.


    События логов батчатся: фоновый поток не ставит в очередь каждую строку
    по отдельности, а копит их и флашит пачками не чаще MAX_UI_HZ раз в
    секунду. Это снижает число сигналов до GUI с сотен в секунду до ~5/с.
    """

    MAX_UI_HZ = 5  # не чаще 5 обновлений GUI в секунду (батч 200 мс)
    FLUSH_INTERVAL = 1.0 / MAX_UI_HZ  # ~0.2 сек

    def __init__(self) -> None:
        self._events: "queue.Queue[RunEvent]" = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._cancel_event = threading.Event()
        self._pause_event = threading.Event()
        self._batch_lock = threading.Lock()
        self._batch: list[RunEvent] = []          # не сфлашенные события логов
        self._last_flush = time.monotonic()


    # ------------------------------------------------------------------ API
    def start(self, options: PipelineOptions, sources: list[str]) -> None:
        self._stop_flag.clear()
        self._cancel_event.clear()
        self._pause_event.clear()
        self._thread = threading.Thread(
            target=self._run_worker,
            args=(options, list(sources)),
            daemon=True,
            name="pipeline-run",
        )
        self._thread.start()

    def stop(self) -> None:
        """Останавливает проверки: сигналим отмену и снимаем паузу."""
        self._stop_flag.set()
        self._cancel_event.set()
        self._pause_event.clear()

    def pause(self) -> None:
        self._pause_event.set()

    def resume(self) -> None:
        self._pause_event.clear()

    def is_paused(self) -> bool:
        return self._pause_event.is_set()

    @property
    def cancel_event(self) -> threading.Event:
        return self._cancel_event

    @property
    def pause_event(self) -> threading.Event:
        return self._pause_event

    def poll(self, timeout: float = 0.1) -> list[RunEvent]:
        """Читает события из очереди, предварительно сбрасывая накопленный батч логов.

        Батч логов сбрасывается не чаще MAX_UI_HZ раз в секунду, поэтому GUI
        получает одно событие на пачку строк вместо события на каждую строку.
        """
        self._flush_batch()

        events: list[RunEvent] = []
        try:
            while True:
                events.append(self._events.get(timeout=timeout))
        except queue.Empty:
            pass
        self._flush_batch()
        return events

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------- internals
    def _emit(
        self,
        kind: str,
        message: str = "",
        progress: Optional[tuple[int, str]] = None,
        stats: Optional[list[SourceStat]] = None,
    ) -> None:
        self._events.put(RunEvent(kind=kind, message=message, progress=progress, stats=stats or []))

    def _flush_batch(self, force: bool = False) -> None:
        """Сбрасывает накопленные лог-строки одним событием (не чаще 5 раз/сек)."""
        with self._batch_lock:
            if not self._batch:
                return
            now = time.monotonic()
            if not force and (now - self._last_flush) < self.FLUSH_INTERVAL:
                return
            batch, self._batch = self._batch, []
            self._last_flush = now
        if not batch:
            return
        # Ограничиваем размер пачки, чтобы не вставлять в виджет сразу мегабайты.
        if len(batch) > 400:
            batch = batch[-400:]
        self._events.put(
            RunEvent(kind="log", message="\n".join(batch))
        )

    def _handle_line(self, raw: str) -> None:
        if not raw:
            return
        if raw.startswith(PROGRESS_MARKER):
            if raw == PROGRESS_MARKER + "_END":
                self._flush_batch(force=True)
                self._emit("progress", "Готово", (100, "Готово"))
                return
            try:
                parts = raw.split("|")
                pct = int(parts[1])
                stage = parts[2]
                current = parts[3]
                total = parts[4]
                message = parts[5]
            except Exception:
                return
            clean = f"{stage} · {message}".strip(" ·") or f"{current}/{total}"
            self._emit("progress", clean, (pct, clean))
        else:
            with self._batch_lock:
                self._batch.append(raw)


    def _run_worker(self, options: PipelineOptions, sources: list[str]) -> None:
        from subgen.pipeline import run as pipeline_run

        os.environ["SUB_GEN_PS_WRAPPER"] = "1"
        real_stdout = sys.stdout
        proxy = _StdoutProxy(self._handle_line)
        try:
            sys.stdout = proxy
            args = build_pipeline_args(options, sources)

            self._emit("log", f"[ui] Запуск: {' '.join(args) if args else '(используется sources.txt)'}")
            start = time.perf_counter()
            code = pipeline_run(
                args,
                cancel_event=self._cancel_event,
                pause_event=self._pause_event,
            )
            elapsed = time.perf_counter() - start

            if code != 0:
                self._emit("error", f"Конвейер завершился с кодом {code}")
            else:
                self._emit("log", f"[ui] Конвейер завершён за {elapsed:.1f} сек, код {code}")
            stats = self._collect_source_stats()
            self._emit("source_stats", stats=stats)
        except RuntimeError as exc:
            if "refresh_cancelled" in str(exc):
                self._emit("log", "[ui] Проверки остановлены пользователем.")
            else:
                traceback.print_exc()
                self._emit("error", f"Ошибка: {exc}")
        except Exception as exc:
            traceback.print_exc()
            self._emit("error", f"Ошибка: {exc}")
        finally:
            sys.stdout = real_stdout
            self._cancel_event.clear()
            self._pause_event.clear()
            # Сбрасываем остатки батча, чтобы ни одна строка лога не потерялась.
            self._flush_batch(force=True)
            self._emit("done")




    # ------------------------------------------------------------ статистика

    def _collect_source_stats(self) -> list[SourceStat]:
        cache_dir = paths.data_dir() / ".runtime_cache"
        by_source: dict[str, SourceStat] = {}

        def load(name: str) -> list[dict]:
            path = cache_dir / name
            if not path.exists():
                return []
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return []
            return data if isinstance(data, list) else []

        for node in load("xray_rejected.json"):
            src = node.get("source")
            if not src:
                continue
            st = by_source.setdefault(src, SourceStat(url=src))
            st.discovered += 1
            if node.get("latency_ms") is not None:
                st.ping_passed += 1

        for node in load("xray_working.json"):
            src = node.get("source")
            if not src:
                continue
            st = by_source.setdefault(src, SourceStat(url=src))
            st.discovered += 1
            st.ping_passed += 1
            st.working += 1

        for node in load("xray_rejected.json"):
            src = node.get("source")
            if not src:
                continue
            st = by_source.setdefault(src, SourceStat(url=src))
            st.rejected += 1

        return sorted(by_source.values(), key=lambda s: (-s.working, -s.discovered))


def filter_sources_by_history(
    sources: list[str],
    working_path,
    rejected_path,
) -> tuple[list[str], list[str]]:
    """Отсеивает подписки, не отдавшие живых конфигов в прошлых прогонах."""
    import json as _json

    def load(path) -> list[dict]:
        if not path.exists():
            return []
        try:
            data = _json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        return data if isinstance(data, list) else []

    def norm(url: str) -> str:
        return url.rstrip("/")

    good: set[str] = set()
    for node in load(working_path):
        src = node.get("source")
        if src:
            good.add(norm(src))
    for node in load(rejected_path):
        src = node.get("source")
        if src and node.get("latency_ms") is not None:
            good.add(norm(src))

    good_norm = {norm(s) for s in good}
    kept = [u for u in sources if norm(u) in good_norm]
    removed = [u for u in sources if norm(u) not in good_norm]
    return kept, removed
