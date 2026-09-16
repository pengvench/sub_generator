"""Ядро рантайма: сборка XrayCoreRuntime из примесей + оркестрация refresh().

Бывший god-файл (~5000 строк) мигрирован в пакет runtime/ послойно. Этот
модуль — точка сборки: класс XrayCoreRuntime наследует готовые слои и
добавляет оркестрацию полной проверки (refresh: подписки -> TCP/UDP-префильтр
-> xray-ping -> стресс-тест -> выбор/переключение активного узла), а также
глобальный форс ядра («только sing-box» / «только xray»).

Слои:
  lifecycle.LifecycleMixin — старт/стоп/pid-файлы/Job Objects/_start_node;
  probing.ProbingMixin     — пробы узлов (_probe_node/_probe_node_ping/...);
  sorting.SortingMixin     — быстрая ping-пересортировка quick_sort_by_ping;
  stress.StressMixin       — stress_test/_stress_probe_node/with_node_process;
  collect.CollectMixin     — мёртвые источники подписок (cooldown);
  results.ResultsMixin     — выбор узла/снимок/персистентность.

Совместимость: реэкспортирует имена, которые раньше жилé в монолите (см.
__all__) — ``from runtime.core import ...`` и ``from xray_runtime import ...``
продолжают работать без изменений.
"""
from __future__ import annotations

import atexit
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from .collect import (
    CollectMixin,
    XRAY_SUBSCRIPTION_FETCH_WORKERS,
    _collect_from_source,
    _wait_if_paused,
    collect_subscription_nodes,
)
from .configs import _sing_box_config, _xray_config
from .lifecycle import LifecycleMixin
from .probes_ping import _tcp_udp_ping_node
from .probing import ProbingMixin
from .procs import _create_kill_on_close_job, _resolve_binary
from .results import ResultsMixin, _normalize_selection_strategy, _result_from_row
from .sorting import SortingMixin, _reason_counts, _reason_summary, _xray_result_sort_key
from .stress import StressMixin
from .types import TELEGRAM_XRAY_PROBE_TOTAL, XrayNode, XrayProbeResult, XrayRuntimeConfig

__all__ = [
    "SING_BOX_UTLS_FINGERPRINTS",
    "XRAY_SUBSCRIPTION_FETCH_WORKERS",
    "XrayCoreRuntime",
    "_FORCED_RUNTIME",
    "_collect_from_source",
    "_normalize_core_mode",
    "_normalize_selection_strategy",
    "_reason_counts",
    "_reason_summary",
    "_resolved_core_mode",
    "_result_from_row",
    "_wait_if_paused",
    "_xray_result_sort_key",
    "collect_subscription_nodes",
    "get_default_core_mode",
    "get_forced_runtime",
    "set_default_core_mode",
    "set_forced_runtime",
]


# ---------------------------------------------------------------------------
# v11: глобальный форс ядра («только sing-box» / «только xray»).
# Глобальность нужна потому, что checkers.base.run_with_node создаёт СВОЙ
# XrayCoreRuntime на каждый вызов — передавать флаг через каждый чекер
# не нужно, достаточно один раз выставить форс на старте конвейера.
# (Перенесено из god-файла xray_runtime.py при завершении миграции.)
# ---------------------------------------------------------------------------
_FORCED_RUNTIME: str | None = None


def set_forced_runtime(runtime: str | None) -> None:
    """Установить принудительное ядро для всех узлов (или снять форс)."""
    global _FORCED_RUNTIME
    value = str(runtime or "").strip().lower() or None
    if value not in (None, "xray", "sing-box"):
        value = None
    _FORCED_RUNTIME = value


def get_forced_runtime() -> str | None:
    """Текущий форс ядра (None = выбор по протоколу узла)."""
    return _FORCED_RUNTIME


class XrayCoreRuntime(
    LifecycleMixin,
    ProbingMixin,
    SortingMixin,
    StressMixin,
    CollectMixin,
    ResultsMixin,
):
    """Двухфазный движок проверки узлов (ping -> stress) с selection strategy."""

    def __init__(
        self,
        config: XrayRuntimeConfig,
        *,
        root_dir: Path,
        out_dir: Path,
        log_sink: Callable[[str], None] | None = None,
        event_sink: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.config = config
        self.root_dir = root_dir
        self.out_dir = out_dir
        self.log_sink = log_sink
        self.event_sink = event_sink
        self._lock = threading.RLock()
        self._process: subprocess.Popen | None = None
        self._running_node: XrayNode | None = None
        self._config_path: str = ""
        self._pid_path = self.out_dir / "xray_runtime.pid"
        self._shutdown_requested = False
        self._job_handle: int | None = _create_kill_on_close_job()
        self._cleanup_stale_processes()
        atexit.register(self.stop)
        self.active_result: XrayProbeResult | None = None
        self.last_working: list[XrayProbeResult] = []
        self.last_rejected: list[XrayProbeResult] = []
        self.discovered_nodes: list[XrayNode] = []
        # Кандидаты, прошедшие быстрый пинг (Фаза 1), но ещё не прошедшие
        # стресс-тест/полную проверку (Фаза 2). last_working содержит ТОЛЬКО
        # полностью проверенные (fully_checked=True) узлы.
        self.ping_candidates: list[XrayProbeResult] = []
        self.last_error = ""
        self.last_refresh_finished_at = 0.0
        self.active_download_kbps: float | None = None
        self.active_download_measured_at: float = 0.0
        self._round_robin_cursor = 0
        self._sticky_key: tuple[str, str, int, str] | None = None
        # Защита от реентерабельного refresh: если refresh уже выполняется
        # (например из фонового health-цикла), повторный вызов не должен
        # запускать параллельный полный пересбор подписок.
        self._refresh_running = threading.Event()
        # Счётчики последовательных неудач источника и время до «размораживания»
        # мёртвых подписок (источник не опрашивается в cooldown).
        self._source_failures: dict[str, int] = {}
        self._source_dead_until: dict[str, float] = {}
        self._load_cached_results()

    def refresh(
        self,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
    ) -> None:
        """Полная проверка в две фазы.

        Фаза 1 — быстрый параллельный пинг всех найденных нод (_probe_node_ping):
        глобальный пинг + доступность серверов Telegram (HEAD api.telegram.org
        + MTProto DC). Прошедшие попадают в ping_candidates (отсортированы по
        пингу). Сразу после Фазы 1 лучший по пингу кандидат включается в работу,
        не дожидаясь стресс-теста.

        Фаза 2 — стресс-тест (_stress_probe_node) только по пропинговавшимся
        кандидатам: спид-тест (download/upload) + доступность Telegram в 3 раунда.
        Прошедшие попадают в last_working (fully_checked=True). Отклонённые —
        в last_rejected.
        """
        if self._shutdown_requested:
            raise RuntimeError("runtime_shutdown")
        if self._refresh_running.is_set():
            self._log("[xray] refresh already in progress, skipping duplicate")
            return
        self._refresh_running.set()
        self._log("[xray] fetching subscriptions")
        try:
            previous_working = list(self.last_working)
            previous_active = self.active_result
            nodes = collect_subscription_nodes(
                self._live_subscription_urls(self.config.subscription_urls),
                timeout=float(self.config.probe_timeout_sec or 8.0),
                max_servers=int(self.config.max_servers or 0),
                log_sink=self._log,
                on_source_result=self._note_source_result,
                on_progress=lambda index, total, url: self._emit(
                    "xray_subscription_progress",
                    index=index,
                    total=total,
                    url=str(url or ""),
                ),
                cancel_event=cancel_event,
                pause_event=pause_event,
            )
            _wait_if_paused(pause_event, cancel_event)
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            # Если подписки недоступны (нет сети / все источники упали) —
            # используем кеш пропингованных узлов pinged_subs.txt.
            if not nodes:
                cached = self.load_pinged_subs()
                if cached:
                    self._log(
                        f"[xray] subscriptions unreachable, fallback to {len(cached)} cached pinged nodes"
                    )
                    nodes = cached
                else:
                    self._log("[xray] subscriptions unreachable and no cached pinged nodes")
            self.discovered_nodes = list(nodes)
            if not self.last_working:
                self.last_rejected = [
                    XrayProbeResult(node, False, "pending", None, 0, TELEGRAM_XRAY_PROBE_TOTAL, node.runtime)
                    for node in nodes
                ]
            self.last_error = ""
            self._log(f"[xray] parsed {len(nodes)} nodes")
            if not nodes:
                self.last_working = previous_working
                self.active_result = previous_active
                self.last_refresh_finished_at = time.time()
                self._emit(
                    "xray_refresh_complete",
                    working=len(self.last_working),
                    rejected=len(self.last_rejected),
                    total=0,
                    phase="ping",
                    candidates=0,
                    reason_counts=_reason_counts(self.last_rejected),
                )
                return

            # ---------- Фаза 1: быстрый параллельный пинг всех нод ----------
            # ---------------------------------------------------------------
            # Предварительный TCP-ping: отсеивает мёртвые узлы (закрытые порты,
            # недоступные IP) за секунды, без поднятия ядра. Только узлы с
            # открытым портом идут в дорогой _probe_node_ping ниже.
            # На 10000 узлов: TCP-ping ~30 сек, xray-ping был бы ~5-8 часов.
            # ---------------------------------------------------------------
            # TCP-ping таймаут: 5 сек (а не 2) — это компромисс.
            # 2 сек слишком мало для мобильных сетей с потерями и спутников
            # (RTT 600-1500ms), а также для дальних серверов (Австралия/
            # Сингапур). 5 сек покрывает большинство реальных сценариев
            # и всё ещё в 3 раза быстрее, чем 15-секундный SOCKS-ping.
            # Берём min(5.0, probe_timeout_sec) — если пользователь явно
            # поставил короткий --timeout, уважаем его.
            tcp_timeout_phase1 = min(5.0, float(self.config.probe_timeout_sec or 8.0))
            # TCP/UDP-ping — дешёвый I/O (просто сокеты, без subprocess).
            # Не зависит от RAM/CPU так, как SOCKS-ping с xray.exe.
            # Ставим минимум 256 потоков — это безопасно даже на слабом CPU,
            # т.к. потоки в основном ждут сети (timeout), а не крутят CPU.
            # При workers >= 32 масштабируем до 512 — это ускорит TCP-ping
            # на больших списках без ущерба для системы.
            tcp_workers_phase1 = max(256, int(self.config.probe_workers or 1) * 8)
            self._log(
                f"[xray] TCP/UDP-ping prefilter: {len(nodes)} nodes, "
                f"timeout={tcp_timeout_phase1}s, workers={tcp_workers_phase1} "
                f"(TCP for vless/vmess/trojan/ss, UDP for hysteria/hy2)"
            )
            alive_nodes_phase1: list[XrayNode] = []
            tcp_dead_phase1 = 0
            tcp_started_phase1 = time.monotonic()
            with ThreadPoolExecutor(max_workers=tcp_workers_phase1, thread_name_prefix="tcp-ping") as tcp_exec:
                # Используем _tcp_udp_ping_node: для vless/vmess/trojan/ss
                # это TCP-ping, для hysteria/hy2 — UDP-ping (QUIC-like probe).
                tcp_futures = {tcp_exec.submit(_tcp_udp_ping_node, n, tcp_timeout_phase1): n for n in nodes}
                for tcp_f in as_completed(tcp_futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    n = tcp_futures[tcp_f]
                    if tcp_f.result() is not None:
                        alive_nodes_phase1.append(n)
                    else:
                        tcp_dead_phase1 += 1
            self._log(
                f"[xray] TCP/UDP-ping done in {time.monotonic() - tcp_started_phase1:.1f}s: "
                f"{len(alive_nodes_phase1)} alive, {tcp_dead_phase1} dead (filtered out before xray-ping)"
            )

            # Все TCP-мёртвые узлы сразу попадают в rejected с причиной
            # tcp_ping_failed — они не пойдут в дорогой xray-ping.
            # Используем node.key (хешируемый tuple) для membership-проверки,
            # т.к. XrayNode не реализует __hash__ по умолчанию.
            alive_keys_phase1 = {n.key for n in alive_nodes_phase1}
            tcp_rejected = [
                XrayProbeResult(n, False, "tcp_ping_failed", None, 0, 1, n.runtime)
                for n in nodes if n.key not in alive_keys_phase1
            ]
            # Заменяем nodes на TCP-живые — дальше пингуем только их.
            nodes_for_ping = alive_nodes_phase1

            ping_outcomes: list[XrayProbeResult] = []
            completed = 0
            workers = max(8, int(self.config.probe_workers or 1) * 2)
            if not nodes_for_ping:
                self._log("[xray] WARNING: после TCP-ping не осталось живых узлов для xray-ping")
                with self._lock:
                    self.ping_candidates = []
                    self.last_rejected = list(tcp_rejected)
                    self.last_refresh_finished_at = time.time()
                self._emit(
                    "xray_refresh_complete",
                    working=0,
                    rejected=len(tcp_rejected),
                    total=len(nodes),
                    phase="ping",
                    candidates=0,
                    reason_counts={"tcp_ping_failed": len(tcp_rejected)},
                )
                return
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xray-ping") as executor:
                futures = {executor.submit(self._probe_node_ping, node): node for node in nodes_for_ping}
                for future in as_completed(futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    node = futures[future]
                    completed += 1
                    self._emit("xray_probe_progress", index=completed, total=len(nodes_for_ping), node=node.title(), phase="ping")
                    outcome = future.result()
                    ping_outcomes.append(outcome)
                    status = "ok" if outcome.accepted else outcome.reason
                    latency = f"{outcome.latency_ms:.0f}ms" if outcome.latency_ms is not None else "-"
                    self._log(f"[xray] ping {node.protocol} {node.host}:{node.port} -> {status} {latency}")

            # Объединяем: TCP-мёртвые + xray-ping rejected.
            ping_outcomes.extend(tcp_rejected)
            ping_accepted = sorted(
                (item for item in ping_outcomes if item.accepted),
                key=lambda item: (float("inf") if item.latency_ms is None else float(item.latency_ms)),
            )
            with self._lock:
                self.ping_candidates = ping_accepted
                self.last_rejected = [item for item in ping_outcomes if not item.accepted]

            self._log(f"[xray] phase 1 done: {len(self.ping_candidates)}/{len(nodes)} passed ping (TCP-ping filtered {len(tcp_rejected)} dead)")

            # Сразу включаем конфигурацию с лучшим пингом, пока идёт стресс-тест.
            if self.ping_candidates and not self.is_running():
                best_ping = self.ping_candidates[0]
                self.active_result = best_ping
                self.last_error = ""
                try:
                    self._start_node(best_ping.node, int(self.config.socks_port))
                    self._emit("xray_state", running=True, endpoint=self.config.endpoint)
                    self._log(f"[xray] started best-ping node {best_ping.node.title()} ({best_ping.latency_ms:.0f}ms)")
                except Exception as exc:
                    self.last_error = str(exc)
                    self._log(f"[xray] start failed for best-ping node: {exc}")
                    self._emit("xray_state", running=False, error=str(exc))

            self._emit(
                "xray_refresh_complete",
                working=len(self.ping_candidates),
                rejected=len(self.last_rejected),
                total=len(nodes),
                phase="ping",
                candidates=len(self.ping_candidates),
                reason_counts=_reason_counts(self.last_rejected),
            )

            if not self.ping_candidates:
                self.last_working = previous_working
                self.active_result = previous_active
                self.last_refresh_finished_at = time.time()
                if self.active_result is None:
                    self.last_error = _reason_summary(self.last_rejected) or "No accepted xray/sing-box nodes"
                else:
                    self.last_error = ""
                self._export_results()
                return

            # ---------- Фаза 2: стресс-тест только пропинговавшихся ----------
            stress_outcomes: list[XrayProbeResult] = []
            completed = 0
            stress_nodes = [item.node for item in self.ping_candidates]
            workers = max(1, int(self.config.probe_workers or 1))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xray-stress") as executor:
                futures = {executor.submit(self._stress_probe_node, node): node for node in stress_nodes}
                for future in as_completed(futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    node = futures[future]
                    completed += 1
                    self._emit(
                        "xray_stress_progress",
                        index=completed,
                        total=len(stress_nodes),
                        node=node.title(),
                        accepted=False,
                        reason="stress",
                        latency_ms=None,
                        download_kbps=None,
                        phase="stress",
                    )
                    outcome = future.result()
                    stress_outcomes.append(outcome)
                    status = "ok" if outcome.accepted else outcome.reason
                    latency = f"{outcome.latency_ms:.0f}ms" if outcome.latency_ms is not None else "-"
                    speed = f"{outcome.download_kbps:.0f}K" if outcome.download_kbps is not None else "-"
                    self._log(f"[xray] stress {node.protocol} {node.host}:{node.port} -> {status} {latency} {speed}")

            new_working = sorted(
                (item for item in stress_outcomes if item.accepted),
                key=_xray_result_sort_key,
            )
            stress_rejected = [item for item in stress_outcomes if not item.accepted]
            ping_rejected = [item for item in ping_outcomes if not item.accepted]
            new_rejected = ping_rejected + stress_rejected
            with self._lock:
                if new_working:
                    self.last_working = new_working
                    self.last_rejected = new_rejected
                    self._select_active_result(advance_round_robin=True)
                else:
                    self.last_working = previous_working
                    self.last_rejected = new_rejected
                    # Не выключаем уже запущенную ноду (например, включённую
                    # сразу после Фазы 1 по лучшему пингу), даже если стресс-тест
                    # её отклонил. previous_active сохраняется только если нода
                    # не была выбрана из ping-кандидатов.
                    if self.is_running() and self.active_result is not None:
                        self._log(
                            f"[xray] stress rejected all; keeping running node "
                            f"{self.active_result.node.title()} ({self.active_result.reason})"
                        )
                    else:
                        self.active_result = previous_active
                if not new_working and self.active_result is None:
                    self.last_error = _reason_summary(self.last_rejected) or "No accepted xray/sing-box nodes"
                else:
                    self.last_error = ""
                self.last_refresh_finished_at = time.time()
                self._export_results()
            self._emit(
                "xray_refresh_complete",
                working=len(self.last_working),
                rejected=len(self.last_rejected),
                total=len(nodes),
                phase="stress",
                candidates=len(self.ping_candidates),
                reason_counts=_reason_counts(self.last_rejected),
            )
            # Если после стресса выбранный fully-checked узел отличается от того,
            # что уже запущен (например, был включён ping-кандидат по Фазе 1) —
            # переключаемся на него.
            if new_working and self.active_result is not None:
                if self._shutdown_requested or (cancel_event and cancel_event.is_set()):
                    return
                if self.is_running():
                    running_key = getattr(self._running_node, "key", None)
                    if self.active_result.node.key != running_key:
                        self._log(
                            f"[xray] switching to fully-checked node "
                            f"{self.active_result.node.title()} (latency "
                            f"{self.active_result.latency_ms:.0f}ms)"
                        )
                        self.stop()
                try:
                    self._start_node(self.active_result.node, int(self.config.socks_port))
                    self._emit("xray_state", running=True, endpoint=self.config.endpoint)
                except Exception as exc:
                    self.last_error = str(exc)
                    self._log(f"[xray] start failed after stress: {exc}")
                    self._emit("xray_state", running=False, error=str(exc))
        finally:
            self._refresh_running.clear()

    def _build_config(
        self,
        node: XrayNode,
        port: int,
        *,
        fp: str | None = None,
    ) -> dict[str, Any]:
        # ВНИМАНИЕ (багфикс слияния): через _effective_runtime, а не node.runtime —
        # иначе терялся глобальный форс «только sing-box» (set_forced_runtime).
        if self._effective_runtime(node) == "sing-box":
            return _sing_box_config(node, "127.0.0.1", port, fp=fp)
        return _xray_config(node, "127.0.0.1", port, fp=fp)

    def _binary_for_node(self, node: XrayNode) -> str:
        if self._effective_runtime(node) == "sing-box":
            return _resolve_binary(self.config.sing_box_binary_path, self.root_dir, "sing-box")
        return _resolve_binary(self.config.xray_binary_path, self.root_dir, "xray")

    def _effective_runtime(self, node: XrayNode) -> str:
        """Ядро для узла с учётом глобального форса («только sing-box»)."""
        forced = get_forced_runtime()
        if forced:
            return forced
        return node.runtime

    def _log(self, message: str) -> None:
        if self.log_sink is not None:
            self.log_sink(str(message))

    def _emit(self, event_name: str, **payload: Any) -> None:
        if self.event_sink is not None:
            self.event_sink(event_name, payload)


SING_BOX_UTLS_FINGERPRINTS = frozenset({
    "chrome", "firefox", "edge", "360", "qq", "random",
})


def set_default_core_mode(mode: str | None) -> None:
    """Алиас для set_forced_runtime. Принимает 'auto' = снять форс."""
    if mode is None or str(mode).strip().lower() in ("", "auto"):
        set_forced_runtime(None)
    else:
        set_forced_runtime(str(mode).strip().lower())

def get_default_core_mode() -> str:
    """Алиас для get_forced_runtime. Возвращает 'auto' вместо None."""
    return get_forced_runtime() or "auto"

def _normalize_core_mode(raw: str) -> str:
    """Нормализовать строку режима ядра.

    Аналог старого API: 'sing_box_only'/'sb' → 'sing-box', 'hybrid'/мусор → 'auto'.
    """
    if not raw:
        return ""
    value = str(raw).strip().lower()
    if value in ("sing-box", "singbox", "sing_box_only", "sb"):
        return "sing-box"
    if value == "xray":
        return "xray"
    if value in ("auto", "hybrid"):
        return "auto"
    # Неизвестное значение → auto (не форсируем).
    return "auto"

def _resolved_core_mode(config: Any) -> str:
    """Определить итоговый режим ядра для конфига.

    Если у config есть явное поле core_mode (не 'auto') — оно приоритетнее.
    Иначе — get_default_core_mode().
    """
    core_mode = getattr(config, "core_mode", None) or "auto"
    if core_mode and str(core_mode).strip().lower() not in ("auto", ""):
        return _normalize_core_mode(str(core_mode))
    return get_default_core_mode()
