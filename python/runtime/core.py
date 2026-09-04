"""Ядро рантайма: XrayCoreRuntime (двухфазная проверка ping -> stress,
подъём core-процессов, selection strategy) + сбор узлов из подписок
(collect_subscription_nodes) и восстановление результатов из кеша."""
from __future__ import annotations


import atexit
import contextlib
import hashlib
import json
import subprocess
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from .configs import _sing_box_config, _write_temp_config, _xray_config
from .fetch import _fetch_text
from .netsocks import _socks_https_head_status, _socks_https_latency
from .parse import _subscription_lines, parse_node_link
from .probes_ping import _tcp_udp_ping_node
from .probes_speed import _download_speed_probe, _xray_download_speed, _xray_upload_speed
from .probes_telegram import _socks_mtproto_latency, _tg_media_probe
from .procs import (
    _assign_process_to_job,
    _cleanup_stale_bundle_cores,
    _close_windows_handle,
    _create_kill_on_close_job,
    _find_free_port,
    _resolve_binary,
    _subprocess_no_window,
    _terminate_pid_tree,
    _terminate_process_tree,
)
from .types import (
    CHATGPT_PROBE_TARGETS,
    INSTAGRAM_PROBE_TARGETS,
    PING_HTTPS_TARGETS,
    TELEGRAM_API_HEAD_TARGET,
    TELEGRAM_DCS,
    TELEGRAM_PROBE_TARGETS,
    TELEGRAM_XRAY_PROBE_TOTAL,
    TG_MEDIA_MIN_KBPS,
    XRAY_ACTIVE_SPEED_TEST_BYTES,
    XRAY_ACTIVE_SPEED_TEST_SECONDS,
    XRAY_DEAD_SOURCE_COOLDOWN_SEC,
    XRAY_DEAD_SOURCE_FAILURES,
    XRAY_GOOD_DOWNLOAD_KBPS,
    XRAY_MIN_MEDIA_KBPS,
    XrayNode,
    XrayProbeResult,
    XrayRuntimeConfig,
)


def _wait_if_paused(
    pause_event: threading.Event | None,
    cancel_event: threading.Event | None = None,
) -> None:
    """Блокирующий ожидатель паузы (вызывается из главного потока).

    Пока pause_event установлен — спим короткими интервалами, реагируя при
    этом на cancel_event (остановка должна работать даже во время паузы).
    """
    if pause_event is None or not pause_event.is_set():
        return
    while pause_event.is_set():
        if cancel_event and cancel_event.is_set():
            raise RuntimeError("refresh_cancelled")
        time.sleep(0.2)


class XrayCoreRuntime:
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


    def is_running(self) -> bool:
        proc = self._process
        return bool(proc and proc.poll() is None)

    @property
    def local_tg_url(self) -> str:
        return f"tg://socks?server={self.config.socks_host}&port={int(self.config.socks_port)}"

    @property
    def local_proxy_url(self) -> str:
        return self.local_tg_url

    def start(self) -> bool:
        with self._lock:
            if self._shutdown_requested:
                return False
            if self.is_running():
                return True
            # Если есть кеш рабочих узлов — стартуем сразу, без полной перепроверки.
            if self.active_result is None and self.last_working:
                self._select_active_result(advance_round_robin=True)
            # Кеша полностью проверенных нет — пробуем лучшего кандидата по пингу,
            # чтобы стартовать как можно раньше (стресс-тест идёт фоном).
            if self.active_result is None and self.ping_candidates:
                self.active_result = self.ping_candidates[0]
                self._log(f"[xray] start from best ping candidate {self.active_result.node.title()}")
            if self.active_result is None:
                # Кеша нет — единственный случай, когда блокируем на полной проверке.
                # refresh() сам запустит лучший по пингу узел сразу после Фазы 1.
                self.refresh()
            if self.is_running():
                return True
            if self.active_result is None:
                self.last_error = "No accepted xray/sing-box nodes"
                self._log(f"[xray] start skipped: {self.last_error}")
                return False
            try:
                self._start_node(self.active_result.node, int(self.config.socks_port))
                self._emit("xray_state", running=True, endpoint=self.config.endpoint)
                return True
            except Exception as exc:
                self.last_error = str(exc)
                self._log(f"[xray] start failed: {exc}")
                self._emit("xray_state", running=False, error=str(exc))
                return False

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            proc = self._process
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=timeout)
            elif proc is None:
                stale_pid = self._read_pid_file()
                if stale_pid:
                    _terminate_pid_tree(stale_pid, timeout=timeout)
            self._process = None
            self._running_node = None
            self._unlink_pid_file()
            self._reset_process_job()
            if self._config_path:
                with contextlib.suppress(Exception):
                    Path(self._config_path).unlink(missing_ok=True)
                self._config_path = ""
            self._emit("xray_state", running=False)

    def shutdown(self, timeout: float = 5.0) -> None:
        self._shutdown_requested = True
        self.stop(timeout=timeout)

    def _read_pid_file(self) -> int | None:
        try:
            payload = json.loads(self._pid_path.read_text(encoding="utf-8"))
            pid = int(payload.get("pid") or 0)
            return pid if pid > 0 else None
        except Exception:
            return None

    def _write_pid_file(self, proc: subprocess.Popen, config_path: str, binary: str) -> None:
        with contextlib.suppress(Exception):
            self.out_dir.mkdir(parents=True, exist_ok=True)
            self._pid_path.write_text(
                json.dumps(
                    {
                        "pid": int(proc.pid),
                        "binary": str(binary),
                        "config": str(config_path),
                        "started_at": time.time(),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

    def _unlink_pid_file(self) -> None:
        with contextlib.suppress(Exception):
            self._pid_path.unlink(missing_ok=True)

    def _cleanup_stale_processes(self) -> None:
        stale_pid = self._read_pid_file()
        if stale_pid:
            _terminate_pid_tree(stale_pid, timeout=2.0)
            self._unlink_pid_file()
        _cleanup_stale_bundle_cores(self.root_dir, self.out_dir)

    def _assign_to_process_job(self, proc: subprocess.Popen) -> None:
        if self._shutdown_requested:
            _terminate_process_tree(proc, timeout=1.0)
            return
        if self._job_handle is None:
            self._job_handle = _create_kill_on_close_job()
        _assign_process_to_job(self._job_handle, proc)

    def _reset_process_job(self) -> None:
        if self._job_handle is not None:
            _close_windows_handle(self._job_handle)
        self._job_handle = _create_kill_on_close_job()

    def restart(self) -> bool:
        self.stop()
        return self.start()

    def probe_active_latency(self, timeout: float | None = None) -> float | None:
        if not self.is_running():
            return None
        probe_timeout = float(timeout if timeout is not None else self.config.probe_timeout_sec or 8.0)
        for host, target_port in TELEGRAM_DCS:
            latency = _socks_mtproto_latency(
                self.config.socks_host,
                int(self.config.socks_port),
                host,
                target_port,
                min(5.0, max(2.0, probe_timeout)),
            )
            if latency is not None:
                return latency
        return None

    def probe_active_download_speed(self, timeout: float | None = None) -> float | None:
        if not self.is_running():
            return None
        probe_timeout = float(timeout if timeout is not None else self.config.probe_timeout_sec or 8.0)
        speed = _xray_download_speed(
            self.config.socks_host,
            int(self.config.socks_port),
            min(15.0, max(8.0, probe_timeout)),
            max_bytes=XRAY_ACTIVE_SPEED_TEST_BYTES,
            sample_seconds=XRAY_ACTIVE_SPEED_TEST_SECONDS,
        )
        if speed is not None and speed > 0:
            self.active_download_kbps = float(speed)
            self.active_download_measured_at = time.time()
            if self.active_result is not None:
                self.active_result.download_kbps = max(float(self.active_result.download_kbps or 0.0), float(speed))
            return float(speed)
        return None

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

    def quick_sort_by_ping(
        self,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
    ) -> int:
        if self._shutdown_requested:
            return len(self.last_working)
        if self._refresh_running.is_set():
            self._log("[xray] refresh already in progress, skipping quick sort")
            return len(self.last_working)
        self._refresh_running.set()
        try:
            with self._lock:
                # Проверяем весь найденный пул (discovered_nodes), а не только принятые ноды.
                nodes = list(self.discovered_nodes)
                if not nodes:
                    nodes = [item.node for item in self.last_working]
                    if not nodes:
                        nodes = [item.node for item in self.ping_candidates]
            if not nodes:
                # Пула нет — запускаем полный refresh (guard временно снимаем, чтобы
                # не заблокировать собственный вызов refresh()).
                self._refresh_running.clear()
                try:
                    self.refresh(cancel_event=cancel_event, pause_event=pause_event)
                finally:
                    return len(self.last_working)

            self._log(f"[xray] quick ping sort for {len(nodes)} nodes")
            # ---------------------------------------------------------------
            # Предварительный TCP-ping: быстрый connect к (host, port) без
            # поднятия ядра. Отсеивает 60-70% мёртвых узлов (закрытые порты,
            # таймауты, недоступные IP) за ~30 сек вместо часов xray-ping.
            # Только узлы с открытым портом идут в дорогой xray-ping ниже.
            # ---------------------------------------------------------------
            workers = max(8, int(self.config.probe_workers or 1) * 2)
            # TCP-ping таймаут: 5 сек (см. комментарий в refresh() выше).
            tcp_timeout = min(5.0, float(self.config.probe_timeout_sec or 8.0))
            # TCP/UDP-ping — дешёвый I/O, минимум 256 потоков.
            # (см. комментарий в refresh() — тот же подход.)
            tcp_workers = max(256, int(self.config.probe_workers or 1) * 8)
            self._log(f"[xray] TCP/UDP-ping prefilter: {len(nodes)} nodes, timeout={tcp_timeout}s, workers={tcp_workers} (TCP+UDP)")
            alive_nodes: list[XrayNode] = []
            tcp_dead = 0
            tcp_started = time.monotonic()
            with ThreadPoolExecutor(max_workers=tcp_workers, thread_name_prefix="tcp-ping") as tcp_executor:
                # _tcp_udp_ping_node: TCP для vless/vmess/trojan/ss,
                # UDP для hysteria/hy2 (см. _udp_ping_node).
                tcp_futures = {tcp_executor.submit(_tcp_udp_ping_node, node, tcp_timeout): node for node in nodes}
                for tcp_future in as_completed(tcp_futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    node = tcp_futures[tcp_future]
                    latency = tcp_future.result()
                    if latency is not None:
                        alive_nodes.append(node)
                    else:
                        tcp_dead += 1
            tcp_elapsed = time.monotonic() - tcp_started
            self._log(
                f"[xray] TCP/UDP-ping done in {tcp_elapsed:.1f}s: "
                f"{len(alive_nodes)} alive, {tcp_dead} dead (filtered out before xray-ping)"
            )

            # Если после TCP-ping ничего не осталось — выходим без xray-ping.
            if not alive_nodes:
                self._log("[xray] WARNING: после TCP-ping не осталось живых узлов")
                with self._lock:
                    self.ping_candidates = []
                    self.last_rejected = [
                        XrayProbeResult(node, False, "tcp_ping_failed", None, 0, 1, node.runtime)
                        for node in nodes
                    ]
                    self.last_refresh_finished_at = time.time()
                self._emit(
                    "xray_refresh_complete",
                    working=0,
                    rejected=len(nodes),
                    total=len(nodes),
                    phase="ping",
                    candidates=0,
                    reason_counts={"tcp_ping_failed": len(nodes)},
                )
                return 0

            # Заменяем nodes на TCP-живые — дальше пингуем только их.
            nodes = alive_nodes

            previous_working = list(self.last_working)
            previous_active = self.active_result
            outcomes: list[XrayProbeResult] = []
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xray-ping") as executor:

                futures = {executor.submit(self._probe_node_ping, node): node for node in nodes}
                completed = 0
                for future in as_completed(futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    node = futures[future]
                    completed += 1
                    self._emit("xray_probe_progress", index=completed, total=len(nodes), node=node.title(), phase="ping")
                    outcome = future.result()
                    outcomes.append(outcome)
                    status = "ok" if outcome.accepted else outcome.reason
                    latency = f"{outcome.latency_ms:.0f}ms" if outcome.latency_ms is not None else "-"
                    self._log(f"[xray] quick {node.protocol} {node.host}:{node.port} -> {status} {latency}")

            with self._lock:
                # Быстрая ping-сортировка НЕ трогает last_working (там только
                # полностью проверенные). Она обновляет ping_candidates и при
                # необходимости переключает активную ноду на лучший пинг.
                old_rejected = [item for item in self.last_rejected if item.reason != "quick_ping_failed"]
                new_candidates = sorted(
                    (item for item in outcomes if item.accepted),
                    key=lambda item: (float("inf") if item.latency_ms is None else float(item.latency_ms)),
                )
                self.ping_candidates = new_candidates
                self.last_rejected = old_rejected + [item for item in outcomes if not item.accepted]
                if new_candidates:
                    best = new_candidates[0]
                    if self.active_result is None or (
                        best.latency_ms is not None
                        and (self.active_result.latency_ms is None or best.latency_ms < float(self.active_result.latency_ms))
                        and best.node.key != self.active_result.node.key
                    ):
                        self.active_result = best
                        if self.is_running():
                            if self._shutdown_requested or (cancel_event and cancel_event.is_set()):
                                return len(self.last_working)
                            self.stop()
                            self._start_node(best.node, int(self.config.socks_port))
                            self._emit("xray_state", running=True, endpoint=self.config.endpoint)
                            self._log(f"[xray] switched to best-ping node {best.node.title()} ({best.latency_ms:.0f}ms)")
                else:
                    self.active_result = previous_active
                    self.last_error = _reason_summary([item for item in outcomes if not item.accepted]) or self.last_error
                self.last_refresh_finished_at = time.time()
            self._emit(
                "xray_refresh_complete",
                working=len(self.last_working),
                rejected=len(self.last_rejected),
                total=len(nodes),
                phase="ping",
                candidates=len(self.ping_candidates),
                reason_counts=_reason_counts(self.last_rejected),
            )
            return len(self.last_working)
        finally:
            self._refresh_running.clear()

    def stress_test(
        self,
        *,
        limit: int = 24,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Стресс-тест vless/vmess/trojan/ss узлов (xray/sing-box).

        Для каждого кандидата поднимает временный локальный core на свободном
        порту и прогоняет несколько раундов проверки: доступность Telegram
        (HEAD api.telegram.org + MTProto DC) и спид-тест (M-Lab NDT7 с fallback
        на speed.cloudflare.com). Узел считается стабильным, если минимум
        (rounds - 1) раундов успешны. Медиа-проверка (загрузка/выгрузка в
        Telegram) выполняется на уровне AppRuntime через with_node_process.

        Эмитит события xray_stress_started / xray_stress_progress; финальное
        xray_stress_finished эмитит AppRuntime (добавляет счётчик media_probed).
        """
        if self._shutdown_requested:
            raise RuntimeError("runtime_shutdown")
        if self._refresh_running.is_set():
            self._log("[xray] refresh in progress, skipping stress test")
            return {"total": 0, "stable": [], "rejected": 0, "error": "refresh_in_progress"}
        with self._lock:
            nodes = list(self.discovered_nodes)
            if not nodes:
                nodes = [item.node for item in self.last_working]
        if not nodes:
            return {"total": 0, "stable": [], "rejected": 0}

        nodes = nodes[: max(1, min(int(limit or 24), len(nodes)))]
        self._emit("xray_stress_started", total=len(nodes))
        self._log(f"[xray] stress test for {len(nodes)} nodes")
        outcomes: list[XrayProbeResult] = []
        completed = 0
        workers = max(1, int(self.config.probe_workers or 1))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xray-stress") as executor:
            futures = {executor.submit(self._stress_probe_node, node): node for node in nodes}
            for future in as_completed(futures):
                _wait_if_paused(pause_event, cancel_event)
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                node = futures[future]
                outcome = future.result()
                outcomes.append(outcome)
                completed += 1
                self._emit(
                    "xray_stress_progress",
                    index=completed,
                    total=len(nodes),
                    node=node.title(),
                    accepted=outcome.accepted,
                    reason=outcome.reason,
                    latency_ms=outcome.latency_ms,
                    download_kbps=outcome.download_kbps,
                )
                status = "ok" if outcome.accepted else outcome.reason
                latency = f"{outcome.latency_ms:.0f}ms" if outcome.latency_ms is not None else "-"
                self._log(f"[xray-stress] {node.protocol} {node.host}:{node.port} -> {status} {latency}")

        with self._lock:
            stable = sorted((item for item in outcomes if item.accepted), key=_xray_result_sort_key)
            rejected = [item for item in outcomes if not item.accepted]
            if stable:
                self.last_working = stable
                self.last_rejected = rejected
                self._select_active_result(advance_round_robin=True)
            else:
                self.last_rejected = rejected
                self.last_error = _reason_summary(rejected) or self.last_error
            self._export_results()
        return {"total": len(nodes), "stable": stable, "rejected": len(rejected)}

    def _stress_probe_node(self, node: XrayNode) -> XrayProbeResult:
        if self._shutdown_requested:
            return XrayProbeResult(node, False, "runtime_shutdown", None, 0, 0, node.runtime)
        binary = self._binary_for_node(node)
        if not binary:
            return XrayProbeResult(node, False, f"{node.runtime} binary not found", None, 0, 0, node.runtime)
        port = _find_free_port()
        config_path = ""
        proc: subprocess.Popen | None = None
        started_at = time.monotonic()
        rounds = 3
        try:
            config_path = _write_temp_config(self._build_config(node, port))
            proc = subprocess.Popen(
                [binary, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_subprocess_no_window(),
            )
            self._assign_to_process_job(proc)
            time.sleep(0.8)
            if proc.poll() is not None:
                return XrayProbeResult(node, False, "core exited", None, 0, rounds, node.runtime)
            timeout = float(self.config.probe_timeout_sec or 8.0)
            # Медиа-проверка Telegram (загрузка/выгрузка: HEAD api.telegram.org +
            # MTProto DC) — обязательная часть стресс-теста, если включена.
            # При telegram_media_check=False узлы принимаются только по
            # спид-тесту (download/upload), без требования доступности Telegram.
            telegram_check = bool(getattr(self.config, "telegram_media_check", True))
            round_ok = 0
            latencies: list[float] = []
            speeds: list[float] = []
            upload_speeds: list[float] = []
            for _ in range(rounds):
                if telegram_check:
                    head_result = _socks_https_head_status("127.0.0.1", port, *TELEGRAM_API_HEAD_TARGET, timeout)
                    if head_result is None or head_result[0] not in (200, 302):
                        continue
                    dc_latency: float | None = None
                    for host, target_port in TELEGRAM_DCS:
                        latency = _socks_mtproto_latency("127.0.0.1", port, host, target_port, timeout)
                        if latency is not None:
                            dc_latency = latency
                            break
                    if dc_latency is None:
                        continue
                else:
                    dc_latency = None
                speed = _download_speed_probe("127.0.0.1", port, timeout)
                if speed is not None and speed > 0:
                    speeds.append(speed)

                up = _xray_upload_speed("127.0.0.1", port, timeout)
                if up is not None and up > 0:
                    upload_speeds.append(up)
                if telegram_check:
                    latencies.append(dc_latency)
                round_ok += 1
                time.sleep(0.2)
            accepted = round_ok >= (rounds - 1)
            download_kbps = sorted(speeds)[len(speeds) // 2] if speeds else None
            upload_kbps = sorted(upload_speeds)[len(upload_speeds) // 2] if upload_speeds else None
            min_latency = min(latencies) if latencies else None
            # Проверка скорости: download — главный критерий, upload — второстепенный.
            # Раньше оба проверялись по одному порогу min_speed — узел с хорошим
            # download (3 МБ/с) и плохим upload (500 КБ/с) отбраковывался как
            # slow_upload, хотя для просмотра видео/серфинга он нормально работает.
            # Теперь: download >= min_speed (главный), upload >= min_speed * 0.1
            # (10% от порога — достаточно для базовых задач).
            # v1.3: оба порога могут быть адаптированы под реальную сеть
            # (config.upload_min_kbps/tg_media_min_kbps от базового замера
            # subgen/baseline.py) — мобильная сеть 46/5 Мбит не должна
            # браковать узлы по порогу, который сама не выдаёт.
            min_speed = float(getattr(self.config, "min_speed_kbps", XRAY_MIN_MEDIA_KBPS) or XRAY_MIN_MEDIA_KBPS)
            upload_min_cfg = getattr(self.config, "upload_min_kbps", None)
            min_upload_speed = float(upload_min_cfg) if upload_min_cfg else min_speed * 0.1
            tg_media_min_kbps = float(getattr(self.config, "tg_media_min_kbps", 0.0) or TG_MEDIA_MIN_KBPS) or TG_MEDIA_MIN_KBPS
            if accepted and download_kbps is not None and download_kbps < min_speed:
                accepted = False
                reason = f"slow_download ({download_kbps:.0f} < {min_speed:.0f})"
            elif accepted and upload_kbps is not None and upload_kbps < min_upload_speed:
                accepted = False
                reason = f"slow_upload ({upload_kbps:.0f} < {min_upload_speed:.0f})"
            else:
                reason = "ready" if accepted else ("stress_unstable" if round_ok > 0 else "stress_failed")

            # --- Telegram-медиа фильтр (t.me/s/peppe_poppo) — ОБЯЗАТЕЛЬНЫЙ ---
            # Раньше это было «спасение»: проба запускалась только для узлов,
            # проваливших спид-тест, и прошедшие 512 КБ/с принимались с особым
            # reason и обходили фильтр min-speed и финальный recheck. Теперь
            # проба выполняется для КАЖДОГО узла, прошедшего
            # раунды (прокси жив): не качает видео из Telegram — отбраковка
            # (reason="tg_media_failed"), даже если спид-тест пройден.
            # Обратного перекрытия нет: slow_download/slow_upload медиа-пробой
            # НЕ «спасается» — узел должен проходить оба фильтра.
            # Метка в имени подписки не ставится: категорий больше нет.
            tg_media_kbps: float | None = None
            if telegram_check and round_ok > 0:
                try:
                    tg_media_kbps = _tg_media_probe("127.0.0.1", port, timeout)
                except Exception:
                    tg_media_kbps = None
                if tg_media_kbps is None or tg_media_kbps < tg_media_min_kbps:
                    failed_detail = (
                        f"{tg_media_kbps:.0f} < {tg_media_min_kbps:.0f} Kbps"
                        if tg_media_kbps is not None
                        else f"видео из t.me не скачалось (порог {tg_media_min_kbps:.0f} Kbps)"
                    )
                    tg_media_kbps = None
                    if accepted:
                        accepted = False
                        reason = f"tg_media_failed ({failed_detail})"
                # Иначе: tg_media_kbps зафиксирован как данные строки (row/кеш);
                # вердикт спид-теста не меняется.
            return XrayProbeResult(
                node,
                accepted,
                reason,
                min_latency,
                round_ok,
                rounds,
                node.runtime,
                dc_latency_ms=min_latency,
                download_kbps=download_kbps,
                upload_kbps=upload_kbps,
                tg_media_kbps=tg_media_kbps,
                fully_checked=True,
            )
        except Exception as exc:
            return XrayProbeResult(node, False, str(exc), None, 0, rounds, node.runtime)
        finally:
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=max(0.2, 2.0 - (time.monotonic() - started_at)))
            if config_path:
                with contextlib.suppress(Exception):
                    Path(config_path).unlink(missing_ok=True)

    def with_node_process(
        self,
        node: XrayNode,
        fn: Callable[[str, int], Any],
        *,
        fp: str | None = None,
    ) -> Any:
        """Поднимает временный core-процесс ноды на свободном порту, вызывает
        fn(host, port), затем убивает процесс. Используется для медиа-проверки
        (upload/download в Telegram) через локальный SOCKS5 во время стресс-теста.

        ``fp`` — принудительный TLS-фингерпринт uTLS ("chrome"/"firefox"/"random",
        "none" = без uTLS/system TLS). None = использовать fp из ссылки узла.
        """
        binary = self._binary_for_node(node)
        if not binary:
            raise RuntimeError(f"{node.runtime} binary not found")
        port = _find_free_port()
        config_path = ""
        proc: subprocess.Popen | None = None
        started_at = time.monotonic()
        try:
            config_path = _write_temp_config(self._build_config(node, port, fp=fp))
            proc = subprocess.Popen(
                [binary, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_subprocess_no_window(),
            )
            self._assign_to_process_job(proc)
            time.sleep(0.8)
            if proc.poll() is not None:
                raise RuntimeError(f"{node.runtime} exited during startup")
            return fn("127.0.0.1", port)
        finally:
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=max(0.2, 2.0 - (time.monotonic() - started_at)))
            if config_path:
                with contextlib.suppress(Exception):
                    Path(config_path).unlink(missing_ok=True)

    def snapshot(self) -> dict[str, Any]:
        rows = [item.row() for item in self.last_working]
        rejected_rows = [item.row() for item in self.last_rejected]
        pool_rows = rows + rejected_rows
        active = self.active_result.row() if self.active_result else None
        running = self.is_running()
        if active:
            latency_value = active.get("latency_ms")
            latency = ""
            if latency_value is not None:
                latency_number = float(latency_value)
                latency = f" · {'<1' if latency_number < 1 else str(int(round(latency_number)))} ms"
            active_text = (
                f"{active.get('protocol')} via {active.get('runtime')} · "
                f"{active.get('host')}:{active.get('port')} · {active.get('name')}{latency}"
            )
        else:
            active_text = ""
        return {
            "mode": "xray_core",
            "running": running,
            "local_running": running,
            "local_tg_url": self.local_tg_url,
            "local_url": self.local_proxy_url,
            "endpoint": self.config.endpoint,
            "status_text": "sing-box активен" if running else (self.last_error or ("sing-box ожидает перезапуск" if self.active_result else "sing-box остановлен")),
            "best_proxy": active_text,

            "active_node": active,
            "pool_rows": pool_rows,
            "xray_rejected_rows": rejected_rows,
            "ping_candidate_rows": [item.row() for item in self.ping_candidates],
            "working_count": len(rows),
            "ping_candidate_count": len(self.ping_candidates),
            "discovered_count": len(self.discovered_nodes),
            "rejected_count": len(rejected_rows),
            "unique_count": len(pool_rows),
            "balancer_strategy": _normalize_selection_strategy(self.config.selection_strategy),
            "manual_upstream_url": self.config.manual_upstream_url,
            "last_refresh_finished_at": self.last_refresh_finished_at,
            "active_download_kbps": self.active_download_kbps,
            "active_download_measured_at": self.active_download_measured_at,
            "reason_counts": _reason_counts(self.last_rejected),
            "xray_binary_found": bool(_resolve_binary(self.config.xray_binary_path, self.root_dir, "xray")),
            "sing_box_binary_found": bool(_resolve_binary(self.config.sing_box_binary_path, self.root_dir, "sing-box")),
        }

    def update_selection(self, selection_strategy: str, manual_upstream_url: str = "", *, restart: bool = True) -> None:
        with self._lock:
            self.config.selection_strategy = _normalize_selection_strategy(selection_strategy)
            self.config.manual_upstream_url = str(manual_upstream_url or "").strip()
            if self.config.manual_upstream_url and self.last_working and self._find_working_by_url(self.config.manual_upstream_url) is None:
                raise ValueError("xray node not found in accepted list")
            previous = self.active_result.node.key if self.active_result else None
            self._select_active_result(advance_round_robin=True)
            current = self.active_result.node.key if self.active_result else None
            if restart and previous != current and self.is_running():
                self.stop()
                if self.active_result is not None:
                    self._start_node(self.active_result.node, int(self.config.socks_port))
                    self._emit("xray_state", running=True, endpoint=self.config.endpoint)

    def _find_working_by_url(self, raw_url: str) -> XrayProbeResult | None:
        raw_url = str(raw_url or "").strip()
        return next((item for item in self.last_working if item.node.raw_url == raw_url), None)

    def _best_working_result(self) -> XrayProbeResult | None:
        return min(self.last_working, key=_xray_result_sort_key) if self.last_working else None

    def _select_active_result(self, *, advance_round_robin: bool) -> XrayProbeResult | None:
        ordered = sorted(self.last_working, key=_xray_result_sort_key)
        if not ordered:
            self.active_result = None
            return None

        manual = self._find_working_by_url(self.config.manual_upstream_url)
        if manual is not None:
            self.active_result = manual
            return manual

        strategy = _normalize_selection_strategy(self.config.selection_strategy)
        if strategy == "round_robin":
            index = self._round_robin_cursor % len(ordered)
            chosen = ordered[index]
            if advance_round_robin:
                self._round_robin_cursor = (self._round_robin_cursor + 1) % max(1, len(ordered))
        elif strategy == "consistent_hash":
            session_key = f"{self.config.socks_host}:{int(self.config.socks_port)}"
            digest = hashlib.blake2b(session_key.encode("utf-8", errors="ignore"), digest_size=8).digest()
            chosen = ordered[int.from_bytes(digest, "big") % len(ordered)]
        else:
            chosen = next((item for item in ordered if item.node.key == self._sticky_key), None)
            if chosen is None:
                chosen = ordered[0]
                self._sticky_key = chosen.node.key
        self.active_result = chosen
        return chosen

    def _probe_node(self, node: XrayNode) -> XrayProbeResult:
        if self._shutdown_requested:
            return XrayProbeResult(node, False, "runtime_shutdown", None, 0, 0, node.runtime)
        binary = self._binary_for_node(node)
        if not binary:
            return XrayProbeResult(node, False, f"{node.runtime} binary not found", None, 0, 0, node.runtime)
        port = _find_free_port()
        config_path = ""
        proc: subprocess.Popen | None = None
        started_at = time.monotonic()
        try:
            config_path = _write_temp_config(self._build_config(node, port))
            proc = subprocess.Popen(
                [binary, "run", "-c", config_path] if node.runtime == "xray" else [binary, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_subprocess_no_window(),
            )
            self._assign_to_process_job(proc)
            time.sleep(0.8)
            if proc.poll() is not None:
                return XrayProbeResult(node, False, "core exited", None, 0, TELEGRAM_XRAY_PROBE_TOTAL, node.runtime)
            api_latencies: list[float] = []
            api_status_ok = False
            for host, target_port, server_name in TELEGRAM_PROBE_TARGETS[:1]:
                latency = _socks_https_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    server_name,
                    float(self.config.probe_timeout_sec or 8.0),
                )
                if latency is not None:
                    api_latencies.append(latency)
                    api_status_ok = True
            total_probes = TELEGRAM_XRAY_PROBE_TOTAL
            if not api_latencies:
                return XrayProbeResult(node, False, "telegram_api_unreachable", None, 0, total_probes, node.runtime)

            # Медиа-проверка Bot API: HEAD https://api.telegram.org, ожидаем HTTP/2 200/302.
            head_result = _socks_https_head_status(
                "127.0.0.1",
                port,
                *TELEGRAM_API_HEAD_TARGET,
                float(self.config.probe_timeout_sec or 8.0),
            )
            if head_result is None or head_result[0] not in (200, 302):
                return XrayProbeResult(node, False, "telegram_api_bad_status", None, len(api_latencies), total_probes, node.runtime)

            dc_latencies: list[float] = []
            dc_ok = False
            for host, target_port in TELEGRAM_DCS:
                latency = _socks_mtproto_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    float(self.config.probe_timeout_sec or 8.0),
                )
                if latency is not None:
                    dc_latencies.append(latency)
                    dc_ok = True
                    break
            if not dc_latencies:
                return XrayProbeResult(node, False, "telegram_dc_unreachable", None, len(api_latencies), total_probes, node.runtime)
            if not dc_ok:
                return XrayProbeResult(node, False, "telegram_data_unreachable", None, len(api_latencies), total_probes, node.runtime)
            api_latency = min(api_latencies)
            dc_latency = min(dc_latencies)
            accepted = dc_latency < 5000

            # Дополнительные запрещённые в РФ цели: ChatGPT и Instagram.
            # Эти проверки не влияют на accepted — узел считается рабочим, если
            # Telegram и спид-тест прошли. Но мы фиксируем доступность, чтобы
            # отличать полностью пригодный узел от частично заблокированного.
            chatgpt_latencies: list[float] = []
            for host, target_port, server_name in CHATGPT_PROBE_TARGETS:
                latency = _socks_https_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    server_name,
                    min(float(self.config.probe_timeout_sec or 8.0), 3.0),
                )
                if latency is not None:
                    chatgpt_latencies.append(latency)
            chatgpt_latency = min(chatgpt_latencies) if chatgpt_latencies else None
            chatgpt_blocked = chatgpt_latency is None

            instagram_latencies: list[float] = []
            for host, target_port, server_name in INSTAGRAM_PROBE_TARGETS:
                latency = _socks_https_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    server_name,
                    min(float(self.config.probe_timeout_sec or 8.0), 3.0),
                )
                if latency is not None:
                    instagram_latencies.append(latency)
            instagram_latency = min(instagram_latencies) if instagram_latencies else None
            instagram_blocked = instagram_latency is None

            download_kbps = None
            upload_kbps = None
            if accepted:
                # Единый спид-тест (NDT7 → CF → proof.ovh.net → tele2, 16MB/8s).
                download_kbps = _download_speed_probe("127.0.0.1", port, float(self.config.probe_timeout_sec or 8.0))
                # Upload-тест для отбрасывания конфигов с медленной выгрузкой.
                upload_kbps = _xray_upload_speed("127.0.0.1", port, float(self.config.probe_timeout_sec or 8.0))
                # Отбрасываем конфиги, у которых скорость загрузки ИЛИ выгрузки
                # ниже единого минимального порога (min_speed_kbps из конфига).
                min_speed = float(getattr(self.config, "min_speed_kbps", XRAY_MIN_MEDIA_KBPS) or XRAY_MIN_MEDIA_KBPS)
                if download_kbps is not None and download_kbps < min_speed:
                    accepted = False
                    reason = "slow_download"
                elif upload_kbps is not None and upload_kbps < min_speed:
                    accepted = False
                    reason = "slow_upload"
                else:
                    reason = "ready" if accepted else "slow"
            return XrayProbeResult(
                node,
                accepted,
                reason,
                dc_latency,
                len(api_latencies) + len(dc_latencies),
                total_probes,
                node.runtime,
                api_latency_ms=api_latency,
                dc_latency_ms=dc_latency,
                chatgpt_latency_ms=chatgpt_latency,
                instagram_latency_ms=instagram_latency,
                chatgpt_blocked=chatgpt_blocked,
                instagram_blocked=instagram_blocked,
                download_kbps=download_kbps,
                upload_kbps=upload_kbps,
                fully_checked=True,
            )
        except Exception as exc:
            return XrayProbeResult(node, False, str(exc), None, 0, TELEGRAM_XRAY_PROBE_TOTAL, node.runtime)
        finally:
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=max(0.2, 2.0 - (time.monotonic() - started_at)))
            if config_path:
                with contextlib.suppress(Exception):
                    Path(config_path).unlink(missing_ok=True)

    def _probe_node_ping(self, node: XrayNode) -> XrayProbeResult:
        """Быстрый пинг узла через SOCKS-прокси.

        Ключевое отличие от старой версии: пинг НЕ отбраковывает узел, если
        Telegram недоступен. Раньше узел, который работает, но не пингует
        api.telegram.org, отбраковывался целиком (`telegram_api_bad_status`).
        В Karing-стиле: узел остаётся в списке с пометкой telegram_blocked=True,
        Telegram-проверка выполняется отдельно на этапе stress/telegram_pro.

        Перебор HTTPS-целей: GSTATIC → IP-SB → Cloudflare → Google → Microsoft
        → Apple. Успешный ответ ЛЮБОЙ из них = узел жив. Это критично для
        заблокированных сетей, где часть CDN недоступна.

        time.sleep(0.5) после старта ядра — даём xray/sing-box время поднять
        SOCKS-сервер (раньше было 0.2 — слишком мало, первый запрос падал).
        """
        if self._shutdown_requested:
            return XrayProbeResult(node, False, "runtime_shutdown", None, 0, 0, node.runtime)
        binary = self._binary_for_node(node)
        if not binary:
            return XrayProbeResult(node, False, f"{node.runtime} binary not found", None, 0, 0, node.runtime)
        port = _find_free_port()
        config_path = ""
        proc: subprocess.Popen | None = None
        started_at = time.monotonic()
        try:
            config_path = _write_temp_config(self._build_config(node, port))
            # stderr=PIPE: при core exited читаем последние строки, чтобы
            # понять причину (битый конфиг, неподдерживаемый шифр, кривой
            # Reality pbk и т.д.). Без этого мы видели только «core exited»
            # без объяснения, и не могли понять, почему 7-10% узлов падают.
            proc = subprocess.Popen(
                [binary, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                creationflags=_subprocess_no_window(),
            )
            self._assign_to_process_job(proc)
            # 0.5 сек — xray/sing-box не успевает поднять SOCKS быстрее,
            # особенно с DNS-секцией. Раньше было 0.2 → первый запрос падал.
            time.sleep(0.5)
            if proc.poll() is not None:
                # Ядро упало при старте — читаем stderr и логируем.
                stderr_tail = ""
                try:
                    stderr_bytes, _ = proc.communicate(timeout=2.0)
                    stderr_text = (stderr_bytes or b"").decode("utf-8", errors="replace").strip()
                    if stderr_text:
                        stderr_tail = "\n".join(stderr_text.splitlines()[-3:])
                except Exception:
                    pass
                if stderr_tail:
                    self._log(f"[xray] {node.protocol} {node.host}:{node.port} core exited — {stderr_tail}")
                return XrayProbeResult(node, False, "core exited", None, 0, len(PING_HTTPS_TARGETS), node.runtime)

            # Перебор HTTPS-целей: берём первую успешную, остальные не ждём.
            # Таймаут на цель — половина probe_timeout_sec, чтобы успеть
            # попробовать несколько целей.
            per_target_timeout = min(4.0, float(self.config.probe_timeout_sec or 8.0))
            ping_latencies: list[float] = []
            for host, target_port, server_name, path in PING_HTTPS_TARGETS:
                latency = _socks_https_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    server_name,
                    per_target_timeout,
                    path=path,
                )
                if latency is not None:
                    ping_latencies.append(latency)
                    # Первой успешной достаточно — узел жив.
                    break
            if not ping_latencies:
                return XrayProbeResult(node, False, "quick_ping_failed", None, 0, len(PING_HTTPS_TARGETS), node.runtime)
            ping_latency = min(ping_latencies)
            accepted = ping_latency < 5000

            # Telegram-проверка — НЕ блокирующая. Если недоступен, помечаем
            # telegram_blocked=True, но узел остаётся в ping_candidates.
            # Полная Telegram-проверка (MTProto DC + upload) выполняется
            # отдельно на этапе telegram_pro.
            head_result = _socks_https_head_status(
                "127.0.0.1",
                port,
                *TELEGRAM_API_HEAD_TARGET,
                per_target_timeout,
            )
            telegram_ok = head_result is not None and head_result[0] in (200, 302)
            dc_latency: float | None = None
            if telegram_ok:
                for tg_host, tg_port in TELEGRAM_DCS:
                    latency = _socks_mtproto_latency(
                        "127.0.0.1",
                        port,
                        tg_host,
                        tg_port,
                        per_target_timeout,
                    )
                    if latency is not None:
                        dc_latency = latency
                        break

            return XrayProbeResult(
                node,
                accepted,
                "ready" if accepted else "slow",
                ping_latency,
                len(ping_latencies) + (1 if telegram_ok else 0) + (1 if dc_latency is not None else 0),
                len(PING_HTTPS_TARGETS) + 1 + len(TELEGRAM_DCS),
                node.runtime,
                dc_latency_ms=dc_latency,
                download_kbps=None,
            )
        except Exception as exc:
            return XrayProbeResult(node, False, str(exc), None, 0, len(PING_HTTPS_TARGETS), node.runtime)

        finally:
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=max(0.2, 2.0 - (time.monotonic() - started_at)))
            # Закрываем stderr-PIPE, чтобы не оставлять открытый файловый
            # дескриптор. communicate() уже вызван выше в случае падения,
            # здесь — для нормального пути (когда proc.poll() is None).
            if proc is not None and proc.stderr is not None:
                with contextlib.suppress(Exception):
                    proc.stderr.close()
            if config_path:
                with contextlib.suppress(Exception):
                    Path(config_path).unlink(missing_ok=True)

    def _build_config(
        self,
        node: XrayNode,
        port: int,
        *,
        fp: str | None = None,
    ) -> dict[str, Any]:
        if node.runtime == "sing-box":
            return _sing_box_config(node, "127.0.0.1", port, fp=fp)
        return _xray_config(node, "127.0.0.1", port, fp=fp)

    def _binary_for_node(self, node: XrayNode) -> str:
        if node.runtime == "sing-box":
            return _resolve_binary(self.config.sing_box_binary_path, self.root_dir, "sing-box")
        return _resolve_binary(self.config.xray_binary_path, self.root_dir, "xray")

    def _export_results(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "xray_working.json").write_text(
            json.dumps([item.row() for item in self.last_working], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (self.out_dir / "xray_rejected.json").write_text(
            json.dumps([item.row() for item in self.last_rejected], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        # Кеш пропингованных подписок в txt (для тестов на заблокированной сети,
        # где подписки не импортируются). Содержит raw_url всех узлов, прошедших
        # быстрый пинг (ping_candidates) и полностью проверенных (last_working),
        # отсортированных по пингу.
        pinged = list(self.ping_candidates)
        for item in self.last_working:
            if not any(p.node.raw_url == item.node.raw_url for p in pinged):
                pinged.append(item)
        pinged_sorted = sorted(
            pinged,
            key=lambda r: (float("inf") if r.latency_ms is None else float(r.latency_ms)),
        )
        (self.out_dir / "pinged_subs.txt").write_text(
            "\n".join(item.node.raw_url for item in pinged_sorted) + ("\n" if pinged_sorted else ""),
            encoding="utf-8",
        )

    def load_pinged_subs(self) -> list[XrayNode]:
        """Загрузить пропингованные узлы из txt-кеша (pinged_subs.txt).

        Используется на заблокированной сети, где подписки не импортируются:
        берём сохранённые ранее пропингованные узлы и прогоняем по ним проверки.
        """
        path = self.out_dir / "pinged_subs.txt"
        if not path.exists():
            return []
        nodes: list[XrayNode] = []
        seen: set[str] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = str(line).strip()
            if not raw or raw in seen:
                continue
            seen.add(raw)
            node = parse_node_link(raw, source_url="pinged_cache")
            if node is not None:
                nodes.append(node)
        return nodes


    def _load_cached_results(self) -> None:
        working_path = self.out_dir / "xray_working.json"
        rejected_path = self.out_dir / "xray_rejected.json"
        # Старые кеши (созданные до введения двухфазной проверки) в
        # xray_working.json содержат все принятые записи без поля fully_checked.
        # Такие записи — только «пропингованные» кандидаты, а не полностью
        # проверенные рабочие. Раскладываем их по соответствующим спискам, иначе
        # GUI после обновления поверх покажет всех старых «рабочих».
        loaded = self._load_result_file(working_path, accepted=True)
        self.last_working = [item for item in loaded if item.fully_checked]
        self.ping_candidates = [item for item in loaded if not item.fully_checked]
        self.last_rejected = self._load_result_file(rejected_path, accepted=False)
        if self.last_working:
            self.last_refresh_finished_at = working_path.stat().st_mtime
            self._select_active_result(advance_round_robin=False)
            self._log(
                f"[xray] loaded {len(self.last_working)} cached fully-checked nodes, "
                f"{len(self.ping_candidates)} ping candidates"
            )

    def _load_result_file(self, path: Path, *, accepted: bool) -> list[XrayProbeResult]:
        if not path.exists():
            return []
        try:
            rows = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        results: list[XrayProbeResult] = []
        if not isinstance(rows, list):
            return results
        for row in rows:
            if not isinstance(row, dict):
                continue
            # Пропускаем заведомо мусорные записи: падение NDT7 (UnboundLocalError
            # в _mlab_fetch_target, исправлено) ловилось except и писало reason с
            # текстом исключения, а не причину отклонения узла.
            reason = str(row.get("reason") or "")
            if reason.startswith("cannot access local variable") or "is not associated with a value" in reason:
                continue
            result = _result_from_row(row, accepted=accepted)
            if result is not None:
                results.append(result)
        return sorted(results, key=_xray_result_sort_key)

    def _log(self, message: str) -> None:
        if self.log_sink is not None:
            self.log_sink(str(message))

    def _emit(self, event_name: str, **payload: Any) -> None:
        if self.event_sink is not None:
            self.event_sink(event_name, payload)

    def _live_subscription_urls(self, urls: list[str]) -> list[str]:
        """Возвращает подписки без тех, что сейчас в cooldown как «мёртвые»."""
        now = time.time()
        live: list[str] = []
        for url in urls:
            clean = str(url or "").strip()
            if not clean:
                continue
            dead_until = self._source_dead_until.get(clean, 0.0)
            if dead_until > now:
                self._log(
                    f"[xray] subscription {clean} marked dead, skipped "
                    f"({max(0.0, dead_until - now):.0f}s remaining)"
                )
                continue
            live.append(clean)
        return live

    def _note_source_result(self, source_url: str, *, ok: bool) -> None:
        """Ведёт счёт последовательных неудач источника; после N подряд — cooldown."""
        clean = str(source_url or "").strip()
        if not clean:
            return
        now = time.time()
        if ok:
            if clean in self._source_failures:
                del self._source_failures[clean]
            if clean in self._source_dead_until:
                del self._source_dead_until[clean]
            return
        failures = self._source_failures.get(clean, 0) + 1
        self._source_failures[clean] = failures
        if failures >= XRAY_DEAD_SOURCE_FAILURES:
            self._source_dead_until[clean] = now + XRAY_DEAD_SOURCE_COOLDOWN_SEC
            self._log(
                f"[xray] subscription {clean} marked dead after {failures} consecutive failures, "
                f"cooldown {XRAY_DEAD_SOURCE_COOLDOWN_SEC:.0f}s"
            )


XRAY_SUBSCRIPTION_FETCH_WORKERS = 8
def _collect_from_source(
    source_url: str,
    *,
    timeout: float,
    per_source_limit: int,
    log_sink: Callable[[str], None] | None,
    on_source_result: Callable[[str, bool], None] | None,
) -> list[XrayNode]:
    try:
        text = _fetch_text(source_url, timeout=timeout, log_sink=log_sink)
    except Exception as exc:
        if log_sink is not None:
            log_sink(f"[xray] subscription {source_url} failed: {type(exc).__name__}: {exc}")
        if on_source_result is not None:
            on_source_result(source_url, ok=False)
        return []

    source_nodes: list[XrayNode] = []
    source_added = 0

    # _subscription_lines выполняет сложный разбор тела (base64/JSON/URL-декод)
    # и на битом теле одной подписки может бросить исключение. В многопоточном
    # режиме collect_subscription_nodes такое исключение упадёт через
    # future.result() и оборвёт ВЕСЬ конвейер. Логируем и пропускаем источник.
    try:
        lines = _subscription_lines(text)
    except Exception as exc:
        if log_sink is not None:
            log_sink(f"[xray] bad subscription body from {source_url}: {type(exc).__name__}: {exc}")
        if on_source_result is not None:
            on_source_result(source_url, ok=False)
        return []

    for raw in lines:
        try:
            node = parse_node_link(raw, source_url=source_url)

        except Exception as exc:
            if log_sink is not None:
                log_sink(
                    f"[xray] bad node skipped from {source_url}: "
                    f"{type(exc).__name__}: {exc}"
                )
            continue

        if node is None:
            continue

        source_nodes.append(node)
        source_added += 1

        if per_source_limit > 0 and source_added >= per_source_limit:
            break

    if on_source_result is not None:
        on_source_result(source_url, ok=True)

    return source_nodes

def collect_subscription_nodes(
    urls: list[str],
    *,
    timeout: float,
    max_servers: int,
    log_sink: Callable[[str], None] | None = None,
    on_source_result: Callable[[str, bool], None] | None = None,
    on_progress: Callable[[int, int, str], None] | None = None,
    cancel_event: threading.Event | None = None,
    pause_event: threading.Event | None = None,
) -> list[XrayNode]:
    """Скачать все подписки и собрать уникальные узлы.

    on_progress(index, total, url) вызывается после завершения каждого
    источника (из главного потока), чтобы сквозной прогресс «загрузка
    подписок» двигался: 1/24, 2/24, ... 24/24.
    """
    nodes: dict[tuple[str, str, int, str], XrayNode] = {}
    source_urls = [str(url).strip() for url in urls if str(url).strip()]
    if not source_urls:
        return []
    per_source_limit = 0
    if max_servers > 0:
        # Не режем жёстко по источнику: при обновлении важно получить ВСЕ
        # актуальные ноды из подписок. Лимит нужен только как страховка от
        # одного гигантского источника.
        per_source_limit = max(1, int(max_servers) * 4)
    workers = max(1, min(XRAY_SUBSCRIPTION_FETCH_WORKERS, len(source_urls)))
    fetched: list[list[XrayNode]] = []
    completed = 0
    total = len(source_urls)
    if workers <= 1:
        for source_url in source_urls:
            _wait_if_paused(pause_event, cancel_event)
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            fetched.append(
                _collect_from_source(
                    source_url,
                    timeout=timeout,
                    per_source_limit=per_source_limit,
                    log_sink=log_sink,
                    on_source_result=on_source_result,
                )
            )
            completed += 1
            if on_progress is not None:
                on_progress(completed, total, source_url)
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sub-fetch") as executor:
            futures = {
                executor.submit(
                    _collect_from_source,
                    source_url,
                    timeout=timeout,
                    per_source_limit=per_source_limit,
                    log_sink=log_sink,
                    on_source_result=on_source_result,
                ): source_url
                for source_url in source_urls
            }
            for future in as_completed(futures):
                _wait_if_paused(pause_event, cancel_event)
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                url = futures[future]
                try:
                    source_nodes = future.result()
                except Exception as exc:
                    # Одна битая подписка НЕ должна ронять весь refresh:
                    # исключение из потока иначе пробрасывается сюда и
                    # обрывает конвейер на первой строке traceback.
                    if log_sink is not None:
                        log_sink(
                            f"[xray] subscription {url} crashed: "
                            f"{type(exc).__name__}: {exc}"
                        )
                    if on_source_result is not None:
                        on_source_result(url, ok=False)
                    source_nodes = []
                fetched.append(source_nodes)
                completed += 1
                if on_progress is not None:
                    on_progress(completed, total, url)

    # Дедупликация: собираем все узлы из всех подписок в dict по node.key.
    # Первый выигрывает (если два узла имеют одинаковый key — protocol/host/port/
    # sha256(normalized-url) — остаётся тот, что из более ранней подписки).
    # Логируем количество дубликатов, чтобы было видно эффективность дедупликации.
    total_before_dedup = sum(len(source_nodes) for source_nodes in fetched)
    duplicates_removed = 0
    for source_nodes in fetched:
        for node in source_nodes:
            if node.key in nodes:
                duplicates_removed += 1
            else:
                nodes[node.key] = node
    result = list(nodes.values())
    total_after_dedup = len(result)
    if log_sink is not None and duplicates_removed > 0:
        log_sink(
            f"[xray] dedup: {total_before_dedup} → {total_after_dedup} "
            f"({duplicates_removed} duplicates removed)"
        )
    return result[:max_servers] if max_servers > 0 else result


def _reason_counts(results: list[XrayProbeResult]) -> dict[str, int]:
    return dict(Counter(str(item.reason or "unknown") for item in results))


def _xray_result_sort_key(item: XrayProbeResult) -> tuple[int, float, float, float, str]:
    latency = item.dc_latency_ms if item.dc_latency_ms is not None else item.latency_ms
    speed = float(item.download_kbps or 0.0)
    upload = float(item.upload_kbps or 0.0)
    speed_bucket = 0 if speed >= XRAY_GOOD_DOWNLOAD_KBPS else 1 if speed > 0 else 2
    return (
        speed_bucket,
        latency if latency is not None else 10_000_000.0,
        -speed,
        -upload,
        item.node.raw_url,
    )


def _normalize_selection_strategy(strategy: str) -> str:
    normalized = str(strategy or "").strip()
    if normalized not in {"round_robin", "consistent_hash", "sticky_session"}:
        return "sticky_session"
    return normalized
def _reason_summary(results: list[XrayProbeResult], *, limit: int = 3) -> str:
    counts = Counter(str(item.reason or "unknown") for item in results)
    if not counts:
        return ""
    parts = [f"{reason}: {count}" for reason, count in counts.most_common(limit)]
    return "No accepted nodes. " + ", ".join(parts)


def _result_from_row(row: dict[str, Any], *, accepted: bool) -> XrayProbeResult | None:
    node = parse_node_link(str(row.get("url") or ""), source_url=str(row.get("source") or "cache"))
    if node is None:
        return None
    try:
        latency = row.get("latency_ms")
        api_latency = row.get("api_latency_ms")
        dc_latency = row.get("dc_latency_ms")
        download = row.get("download_kbps")
        upload = row.get("upload_kbps")
        tg_media = row.get("tg_media_kbps")
        ai_country = str(row.get("ai_geo_country") or "").strip().upper()
        # Обратная совместимость: старые xray_working.json (созданные до введения
        # двухфазной проверки) не содержали поля fully_checked. Считать их
        # полностью проверенными НЕЛЬЗЯ — они прошли только быструю проверку,
        # а не полный стресс-тест. Поэтому без явного ключа fully_checked=True
        # запись считается лишь «пропингованной» (accepted, not fully_checked).
        fully_checked = bool(row.get("fully_checked", False))
        return XrayProbeResult(
            node=node,
            accepted=bool(row.get("accepted", accepted)),
            reason=str(row.get("reason") or ("ready" if accepted else "cached")),
            latency_ms=float(latency) if latency is not None else None,
            successes=int(row.get("successes") or (TELEGRAM_XRAY_PROBE_TOTAL if accepted else 0)),
            attempts=int(row.get("attempts") or TELEGRAM_XRAY_PROBE_TOTAL),
            runtime=str(row.get("runtime") or node.runtime),
            api_latency_ms=float(api_latency) if api_latency is not None else None,
            dc_latency_ms=float(dc_latency) if dc_latency is not None else None,
            download_kbps=float(download) if download is not None else None,
            upload_kbps=float(upload) if upload is not None else None,
            tg_media_kbps=float(tg_media) if tg_media is not None else None,
            ai_geo_country=ai_country if len(ai_country) == 2 else "",
            fully_checked=fully_checked,
        )
    except (TypeError, ValueError):
        return None
