"""Сбор узлов из подписок (перенесено из runtime/core.py).

Модульные функции:
  _wait_if_paused            — блокирующий ожидатель паузы/отмены конвейера;
  XRAY_SUBSCRIPTION_FETCH_WORKERS — параллелизм загрузки подписок;
  _collect_from_source       — один источник: fetch -> parse -> лимит (в т.ч.
                               прямые конфиги vless://... прямо в sources.txt);
  collect_subscription_nodes — параллельная загрузка всех подписок + дедуп.

Примесь CollectMixin (состояние мёртвых источников) входит в XrayCoreRuntime.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from .fetch import _fetch_text
from .parse import _subscription_lines, parse_node_link
from .types import XRAY_DEAD_SOURCE_COOLDOWN_SEC, XRAY_DEAD_SOURCE_FAILURES, XrayNode

__all__ = [
    "XRAY_SUBSCRIPTION_FETCH_WORKERS",
    "CollectMixin",
    "_collect_from_source",
    "_wait_if_paused",
    "collect_subscription_nodes",
]


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


class CollectMixin:
    """Счётчики неудач источников подписок и cooldown «мёртвых» URL."""

    # Атрибуты экземпляра (config/_lock/_process/...) создаются в
    # XrayCoreRuntime.__init__ (runtime/core.py) — примесь не имеет __init__.

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
    # HARD FIX: If source_url is a direct config (vless://, vmess://, etc),
    # parse it directly via parse_node_link instead of fetching as HTTP URL.
    # This protects against bad sources.txt with inline configs even when
    # the upstream _load_sources filter missed them (e.g. old .exe).
    _DIRECT_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "hysteria://")
    if source_url.lower().startswith(_DIRECT_SCHEMES):
        try:
            node = parse_node_link(source_url)
            if node is not None:
                if log_sink is not None:
                    log_sink(f"[xray] direct config parsed: {source_url[:80]}")
                if on_source_result is not None:
                    on_source_result(source_url, ok=True)
                return [node]
        except Exception as exc:
            if log_sink is not None:
                log_sink(f"[xray] direct config parse failed {source_url[:80]}: {exc}")
        if on_source_result is not None:
            on_source_result(source_url, ok=False)
        return []

    # Skip comment lines that leaked through (defensive)
    if source_url.lstrip().startswith("#"):
        if log_sink is not None:
            log_sink(f"[xray] skipping comment as source: {source_url[:60]}")
        return []

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
