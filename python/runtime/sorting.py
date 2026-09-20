"""Сортировка узлов и ключи порядка (перенесено из runtime/core.py).

Модульные функции:
  _xray_result_sort_key — композитный ключ (скорость-бакет -> латентность ->
                          download -> upload -> raw_url);
  _reason_counts/_reason_summary — статистика причин отклонения.

SortingMixin.quick_sort_by_ping — быстрая пересортировка найденного пула:
TCP/UDP-префильтр -> параллельный xray-ping -> переключение на лучший пинг
без полного стресс-теста. Входит в XrayCoreRuntime.
"""
from __future__ import annotations

import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from .collect import _wait_if_paused
from .probes_ping import _tcp_udp_ping_node
from .types import XRAY_GOOD_DOWNLOAD_KBPS, XrayNode, XrayProbeResult

__all__ = [
    "SortingMixin",
    "_reason_counts",
    "_reason_summary",
    "_xray_result_sort_key",
]


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


def _reason_summary(results: list[XrayProbeResult], *, limit: int = 3) -> str:
    counts = Counter(str(item.reason or "unknown") for item in results)
    if not counts:
        return ""
    parts = [f"{reason}: {count}" for reason, count in counts.most_common(limit)]
    return "No accepted nodes. " + ", ".join(parts)


class SortingMixin:
    """Быстрая ping-пересортировка пула узлов (без стресс-теста)."""

    # Атрибуты экземпляра (config/_lock/_process/...) создаются в
    # XrayCoreRuntime.__init__ (runtime/core.py) — примесь не имеет __init__.

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
                # Багфикс (P1): раньше здесь был «finally: return ...» — return
                # из finally глотал ЛЮБЫЕ исключения refresh(), включая
                # RuntimeError("refresh_cancelled") (протокол отмены конвейера:
                # ловится только наверху — ui/runner.py / ui/app.py) и
                # KeyboardInterrupt. Отмена молча игнорировалась, конвейер
                # продолжал работать. Теперь исключения пробрасываются;
                # _refresh_running чистится самим refresh() (его finally)
                # и внешним finally quick_sort_by_ping.
                self.refresh(cancel_event=cancel_event, pause_event=pause_event)
                return len(self.last_working)

            self._log(f"[xray] quick ping sort for {len(nodes)} nodes")
            # ---------------------------------------------------------------
            # Предварительный TCP-ping: быстрый connect к (host, port) без
            # поднятия ядра. Отсеивает 60-70% мёртвых узлов (закрытые порты,
            # таймауты, недоступные IP) за ~30 сек вместо часов xray-ping.
            # Только узлы с открытым портом идут в дорогой xray-ping ниже.
            # ---------------------------------------------------------------
            # v11: увеличили workers с 64 до 128 — xray.exe лёгкий (~50MB RAM),
            # 128 параллельных инстансов = ~6GB RAM, на 16GB машине норм.
            # Это даёт ~2× ускорение xray-ping.
            workers = max(16, int(self.config.probe_workers or 1) * 4)
            # TCP-ping таймаут: 3 сек (было 5) — мёртвые порты отваливаются быстрее.
            tcp_timeout = min(3.0, float(self.config.probe_timeout_sec or 8.0))
            # TCP/UDP-ping — дешёвый I/O, минимум 256 потоков.
            tcp_workers = max(256, int(self.config.probe_workers or 1) * 8)
            self._log(f"[xray] TCP/UDP-ping prefilter: {len(nodes)} nodes, timeout={tcp_timeout}s, workers={tcp_workers} (TCP+UDP)")
            alive_nodes: list[XrayNode] = []
            tcp_dead = 0
            tcp_started = time.monotonic()
            # v16: узлы, убитые TCP/UDP-предфильтром, — с причиной. Раньше они
            # не попадали в last_rejected и в трассировке значились «—» на
            # стадии quick (в лог2 юзера: 16537 узлов «потерялись хрен пойми
            # где» — а это просто закрытые порты). Теперь у каждого причина:
            # tcp_prefilter_dead (порт закрыт/таймаут) или tcp_prefilter_slow
            # (connect дольше 3с).
            prefilter_dead: list[XrayProbeResult] = []
            # v11: сохраняем TCP latency для ранней отбраковки медленных нод.
            tcp_latencies: dict = {}  # node.key -> latency_ms
            with ThreadPoolExecutor(max_workers=tcp_workers, thread_name_prefix="tcp-ping") as tcp_executor:
                tcp_futures = {tcp_executor.submit(_tcp_udp_ping_node, node, tcp_timeout): node for node in nodes}
                for tcp_future in as_completed(tcp_futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    node = tcp_futures[tcp_future]
                    latency = tcp_future.result()
                    if latency is not None:
                        # v11: ранняя отбраковка — если TCP-ping > 3000мс, нода
                        # слишком медленная для туннеля. Пропускаем xray-ping.
                        if latency > 3000.0:
                            tcp_dead += 1
                            prefilter_dead.append(
                                XrayProbeResult(
                                    node, False,
                                    f"tcp_prefilter_slow ({latency:.0f}мс > 3000мс)",
                                    None, 0, 1, node.runtime,
                                )
                            )
                            continue
                        alive_nodes.append(node)
                        tcp_latencies[node.key] = latency
                    else:
                        tcp_dead += 1
                        prefilter_dead.append(
                            XrayProbeResult(node, False, "tcp_prefilter_dead", None, 0, 1, node.runtime)
                        )
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

            # v16: предфильтр-мёртвые попадают в last_rejected — трассировка
            # видит их причину, а не «—». Сюда же — «все мертвы» случай выше
            # (он отдельно сохраняет совместимость причины tcp_ping_failed).

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
                old_rejected = [
                    item
                    for item in self.last_rejected
                    if item.reason != "quick_ping_failed"
                    and not str(item.reason or "").startswith("tcp_prefilter_")
                ]
                new_candidates = sorted(
                    (item for item in outcomes if item.accepted),
                    key=lambda item: (float("inf") if item.latency_ms is None else float(item.latency_ms)),
                )
                self.ping_candidates = new_candidates
                # v16: предфильтр-мёртвые идут в rejected ПЕРВЫМИ (хронология:
                # они умерли до xray-ping) — их причины попадают в трассировку.
                self.last_rejected = (
                    old_rejected
                    + prefilter_dead
                    + [item for item in outcomes if not item.accepted]
                )
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
