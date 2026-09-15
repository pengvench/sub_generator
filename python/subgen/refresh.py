"""Сборка узлов из подписок и быстрая распинговка через XrayCoreRuntime.

Архитектура v9: run_refresh выполняет ТОЛЬКО быструю распинговку
(collect_subscription_nodes + quick_sort_by_ping с TCP/UDP-префильтром).
Промежуточная стресс-фаза (спид-тест + tg-медиа на сотни узлов) УДАЛЕНА:
- tg-медиа живёт в этапе telegram_pro (checkers/telegram_pro.py);
- скорость измеряется финальным информативным спидтестом ПОСЛЕ
  переименования (конец конвейера).

Средняя стресс-фаза runtime.refresh() (Фаза 2) больше не используется
конвейером: главный критерий — загрузка заблокированных сервисов, а не
абстрактная скорость до CDN.
"""
from __future__ import annotations

import contextlib
import threading

from collections.abc import Callable

from subgen.config import DATA_DIR, ROOT
from xray_runtime import (
    XrayCoreRuntime,
    XrayNode,
    XrayProbeResult,
    XrayRuntimeConfig,
    collect_subscription_nodes,
)


def run_refresh(
    sources: list[str],
    *,
    timeout: float,
    workers: int,
    max_servers: int,
    stress: bool,
    log_sink: Callable[[str], None],
    progress=None,
    min_speed_kbps: float = 2048.0,
    telegram_media_check: bool = True,
    cancel_event: threading.Event | None = None,
    pause_event: threading.Event | None = None,
) -> tuple[list[XrayProbeResult], list[XrayProbeResult], list[XrayNode]]:
    """Собрать узлы из подписок и прогнать быструю распинговку.

    Возвращает (working, rejected, discovered):
    - working — узлы, прошедшие быстрый пинг через туннель (ping_candidates);
    - rejected — отбракованные (tcp_ping_failed / quick_ping_failed / core);
    - discovered — все распарсенные узлы.

    Параметр ``stress`` сохранён для совместимости сигнатуры (GUI передаёт
    его), но больше не включает среднюю стресс-фазу: скорость измеряется
    финальным спидтестом в конце конвейера, tg-медиа — в этапе telegram_pro.
    ``min_speed_kbps`` аналогично не применяется здесь (порог задаёт
    финальный информативный спидтест).
    """
    config = XrayRuntimeConfig(
        subscription_urls=list(sources),
        probe_workers=max(1, workers),
        probe_timeout_sec=max(2.0, timeout),
        max_servers=max_servers,
        min_speed_kbps=min_speed_kbps,
        telegram_media_check=telegram_media_check,
    )
    temp_out = DATA_DIR / ".runtime_cache"

    ping_idx = progress.stage_index("ping") if progress else -1
    load_idx = progress.stage_index("load") if progress else -1

    def on_event(event_name: str, payload: dict) -> None:
        total = int(payload.get("total") or 0)
        if event_name == "xray_subscription_progress":
            if progress is not None and load_idx >= 0:
                if progress.active_stage != load_idx:
                    progress.start_stage(load_idx, "загрузка подписок")
                progress.set_total(load_idx, total)
                url = str(payload.get("url") or "")
                short = url.split("/")[-1][:48] if url else ""
                progress.update(int(payload.get("index") or 0), f"загрузка подписок {short}")
        elif event_name == "xray_probe_progress":
            if progress is not None and ping_idx >= 0:
                if progress.active_stage != ping_idx:
                    progress.start_stage(ping_idx, "ping-проверка узлов")
                progress.set_total(ping_idx, total)
                progress.update(int(payload.get("index") or 0), str(payload.get("node") or ""))
        elif event_name == "xray_refresh_complete":
            phase = str(payload.get("phase") or "")
            if progress is not None and phase == "ping" and ping_idx >= 0:
                accepted = int(payload.get("working") or 0)
                rejected = int(payload.get("rejected") or 0)
                total = int(payload.get("total") or 0)
                progress.finish_stage(
                    ping_idx,
                    f"[ping] done: {accepted} accepted, {rejected} rejected (total {total})",
                )

    def wrapped_log(message: str) -> None:
        log_sink(message)

    runtime = XrayCoreRuntime(
        config,
        root_dir=ROOT,
        out_dir=temp_out,
        log_sink=wrapped_log,
        event_sink=on_event,
    )
    try:
        # Быстрая распинговка: сбор узлов + TCP/UDP-префильтр + пинг через
        # туннель. Средняя стресс-фаза удалена (см. докстринг модуля).
        def _sub_progress(index: int, total: int, url: str) -> None:
            if progress is not None and load_idx >= 0:
                if progress.active_stage != load_idx:
                    progress.start_stage(load_idx, "загрузка подписок")
                progress.set_total(load_idx, total)
                short = url.split("/")[-1][:48] if url else ""
                progress.update(index, f"загрузка подписок {short}")

        discovered = collect_subscription_nodes(
            list(sources),
            timeout=float(config.probe_timeout_sec),
            max_servers=int(config.max_servers),
            log_sink=log_sink,
            on_progress=_sub_progress,
            cancel_event=cancel_event,
            pause_event=pause_event,
        )
        runtime.discovered_nodes = list(discovered)
        runtime.quick_sort_by_ping(cancel_event=cancel_event, pause_event=pause_event)
        working = list(runtime.ping_candidates)
        rejected = list(runtime.last_rejected)
    finally:
        with contextlib.suppress(Exception):
            runtime.stop()
    return working, rejected, list(runtime.discovered_nodes)
