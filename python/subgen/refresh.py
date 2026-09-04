"""Сборка узлов из подписок и полная проверка через XrayCoreRuntime.

Использует XrayCoreRuntime.refresh() (двухфазный: ping -> stress) с временным
out_dir в data/.runtime_cache, чтобы переиспользовать ровно ту же логику,
что работает в GUI.
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
    """Собрать узлы из подписок и прогнать полную проверку.

    Возвращает (working, rejected, discovered).
    Через event_sink подключаем единый progressbar к событиям фаз ping/stress.

    min_speed_kbps — единый порог скорости (КБ/с), который применяется и в
    стресс-тесте (Фаза 2), и в финальном recheck. Передаётся в XrayRuntimeConfig,
    чтобы оба замера использовали один и тот же порог.
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
    stress_idx = progress.stage_index("stress") if progress else -1
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
        elif event_name == "xray_stress_progress":
            if progress is not None and stress_idx >= 0:
                if progress.active_stage != stress_idx:
                    progress.start_stage(stress_idx, "стресс-тест узлов")
                progress.set_total(stress_idx, total)
                progress.update(int(payload.get("index") or 0), str(payload.get("node") or ""))
        elif event_name == "xray_refresh_complete":
            phase = str(payload.get("phase") or "")
            accepted = int(payload.get("working") or 0)
            rejected = int(payload.get("rejected") or 0)
            total = int(payload.get("total") or 0)
            if progress is not None:
                if phase == "ping" and ping_idx >= 0:
                    progress.finish_stage(
                        ping_idx,
                        f"[ping] done: {accepted} accepted, {rejected} rejected (total {total})",
                    )
                elif phase == "stress" and stress_idx >= 0:
                    progress.finish_stage(
                        stress_idx,
                        f"[stress] done: {accepted} accepted, {rejected} rejected (total {total})",
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
        if stress:
            runtime.refresh(cancel_event=cancel_event, pause_event=pause_event)
            working = list(runtime.last_working)
            rejected = list(runtime.last_rejected)
        else:
            # Режим без стресс-теста: только быстрый пинг (Фаза 1).
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
