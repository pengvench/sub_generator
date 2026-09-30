#!/usr/bin/env python3
"""GHA-совместимый лёгкий CLI для обновления списков подписок.

Запускается на GitHub Actions (Linux) БЕЗ xray.exe / sing-box.exe —
использует только Python-стек runtime:
  fetch (urllib + curl + (PowerShell-транспорт на Linux = no-op))
  → parse (_subscription_lines: plain / base64 / JSON / Clash-YAML)
  → parse_node_link → XrayNode
  → TCP-ping (опционально, --with-ping; без аргументов — без проверки)
  → dedup по node.key
  → запись в preload.txt (или --output).

Запуск локально:
  python scripts/refresh_subs.py \\
      --sources-file data/sources.txt \\
      --output data/preload.txt \\
      --with-ping \\
      --ping-timeout 3.0

Запуск в GitHub Actions (см. .github/workflows/refresh-subs.yml):
  python scripts/refresh_subs.py \\
      --sources-file data/sources.txt \\
      --output data/preload.txt \\
      --with-ping \\
      --ping-timeout 3.0 \\
      --ping-workers 16

Артефакты:
  data/preload.txt         — итоговый список vless:// / vmess:// / ...
  data/preload_report.json — короткий отчёт (источник/узлов/ошибки).

Возвращает:
  0 — успех (узлы записаны);
  1 — фатальная ошибка (нет источников, все упали, файл не записан);
  2 — partial success (часть источников упала, но что-то записано).
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

# Добавляем python/ в sys.path — скрипт запускается из корня репо.
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from runtime.fetch import _fetch_text  # noqa: E402
from runtime.parse import _subscription_lines, parse_node_link  # noqa: E402
from runtime.types import XrayNode  # noqa: E402
from runtime.collect import collect_subscription_nodes  # noqa: E402


# ---------------------------------------------------------------------- helpers
def _read_sources(sources_file: Path, extra: list[str],
                  *, saved_subs_dir: Path | None = None,
                  use_saved_subs: bool = True) -> list[str]:
    """Прочитать URL'ы подписок из файла + доп. аргументы CLI + saved_subs/.

    Поведение зеркалит локальное приложение (sources_page.get_sources):
    когда use_saved_subs=True (по умолчанию, как в GUI), сканируем
    data/saved_subs/ на *.txt и *.json — добавляем их как локальные пути.
    runtime.fetch._fetch_text понимает локальные пути (Path.exists →
    читает файл напрямую).

    saved_subs/ — это каталог, куда ImportPage (вкладка «Импорт») сохраняет
    файлы с конфигами при ручном импорте. В GHA юзер клал туда файлы через
    git push (GHA не имеет доступа к локальному C:\\... на машине юзера).

    Файл README.txt в saved_subs/ игнорируется (как и в локальном app).
    """
    sources: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        value = (value or "").strip()
        if not value or value.startswith("#"):
            return
        # На GHA хотим поддержать и прямые vless:// в sources.txt — runtime
        # _collect_from_source их понимает, мы просто передаём как есть.
        if value not in seen:
            seen.add(value)
            sources.append(value)

    if sources_file.exists():
        for line in sources_file.read_text(encoding="utf-8").splitlines():
            add(line)
    for value in extra or []:
        add(value)

    # Авто-мёрдж data/saved_subs/*.txt + *.json — как в локальном app
    # (sources_page._use_saved_subs = True по умолчанию). Файлы в saved_subs
    # могут содержать либо прямые vless:// (по строке), либо JSON-массив
    # объектов Xray/Hiddify — оба формата _subscription_lines понимает.
    if use_saved_subs and saved_subs_dir is not None and saved_subs_dir.is_dir():
        for f in sorted(saved_subs_dir.glob("*.txt")) + sorted(saved_subs_dir.glob("*.json")):
            if f.name == "README.txt":
                continue
            # Передаём абсолютный путь — _fetch_text проверит Path.exists()
            # и прочитает файл напрямую (без HTTP-запроса).
            add(str(f.resolve()))
    return sources


def _tcp_ping(node: XrayNode, timeout: float) -> tuple[bool, float]:
    """Быстрый TCP-ping. True если удалось подключиться за timeout сек.

    НЕ запускает xray — это просто socket.connect() с таймаутом. Дешёвый
    фильтр мёртвых узлов (TCP RST / timeout / DNS-fail). Реальная проверка
    работы узла требует xray.exe (только Windows), её тут нет.
    """
    host = node.host
    port = int(node.port or 0)
    if not host or port <= 0:
        return False, 0.0
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.monotonic() - t0)
    except (OSError, socket.gaierror, TimeoutError):
        return False, 0.0


def _ping_filter(nodes: list[XrayNode], *, timeout: float, workers: int,
                 log_sink) -> list[XrayNode]:
    """Пропинговать узлы параллельно, оставить только живые."""
    alive: list[XrayNode] = []
    lock = threading.Lock()
    done = 0
    total = len(nodes)

    def probe(node: XrayNode) -> tuple[XrayNode, bool]:
        return node, _tcp_ping(node, timeout)[0]

    with ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="ping") as ex:
        futures = {ex.submit(probe, n): n for n in nodes}
        for fut in as_completed(futures):
            nonlocal_done = done
            done = nonlocal_done + 1
            node, ok = fut.result()
            with lock:
                if ok:
                    alive.append(node)
            if done % 25 == 0 or done == total:
                log_sink(f"[gha] ping progress {done}/{total} ({len(alive)} alive)")

    return alive


# ---------------------------------------------------------------------- main
def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="GHA-совместимый CLI для обновления списков подписок (без xray).",
    )
    p.add_argument("--sources-file", type=Path,
                   default=REPO / "data" / "sources.txt",
                   help="Файл со списком URL'ов подписок (по строке на URL). "
                        "Поддерживает прямые vless:// в файле. "
                        "По умолчанию: data/sources.txt.")
    p.add_argument("--sources", nargs="*", default=[],
                   help="Доп. URL'ы (добавляются к --sources-file).")
    p.add_argument("--output", type=Path,
                   default=REPO / "data" / "preload.txt",
                   help="Куда писать итоговый список vless://... (по умолчанию: data/preload.txt).")
    p.add_argument("--report", type=Path,
                   default=REPO / "data" / "preload_report.json",
                   help="Куда писать короткий JSON-отчёт (по умолчанию: data/preload_report.json).")
    p.add_argument("--with-ping", action="store_true",
                   help="Включить TCP-ping (socket connect, без xray). Оставит только TCP-доступные узлы.")
    p.add_argument("--ping-timeout", type=float, default=3.0,
                   help="Таймаут TCP-ping, сек (по умолчанию: 3.0).")
    p.add_argument("--ping-workers", type=int, default=16,
                   help="Параллелизм TCP-ping (по умолчанию: 16).")
    p.add_argument("--fetch-timeout", type=float, default=20.0,
                   help="Таймаут загрузки одной подписки, сек (по умолчанию: 20.0).")
    p.add_argument("--max-servers", type=int, default=0,
                   help="Лимит итоговых узлов (0 = без лимита).")
    p.add_argument("--strict", action="store_true",
                   help="Строгий режим: если ХОТЯ БЫ ОДИН источник упал — exit code 2.")
    p.add_argument("--sort-by-sni", action="store_true",
                   help="Сортировать узлы по SNI-категории (БС → серый → фейк → "
                        "none → ЧС). На ограниченной сети РФ работает только БС "
                        "(белый список SNI: sberbank.ru, vk.com, gosuslugi.ru, ...). "
                        "См. checkers/sni_category.py.")
    p.add_argument("--bs-only", action="store_true",
                   help="Оставить только «БС»-узлы (белый список SNI) — для "
                        "ограниченных сетей РФ (мобильные операторы). Отсекает "
                        "ЧС (instagram.com, chatgpt.com ...), серые, фейки. "
                        "По умолчанию выключено: даже на ограниченной сети серые "
                        "SNI часто работают — '--bs-only' для жёсткого режима.")
    p.add_argument("--bs-allow-grey", action="store_true", default=True,
                   help="(только с --bs-only) Включать в финал «серые» SNI — "
                        "реальные домены не из списков. По умолчанию ON: "
                        "серые SNI часто проходят DPI как обычный TLS.")
    p.add_argument("--bs-allow-fake", action="store_true",
                   help="(только с --bs-only) Включать в финал «фейк» SNI — "
                        "короткие строки без точки (abc12345). НЕ рекомендуется: "
                        "ТСПУ быстро учится их блокировать.")
    # v23: saved_subs/ — авто-мёрдж (как в локальном GUI по умолчанию).
    # Юзер кладёт свои файлы в data/saved_subs/*.txt через git push,
    # GHA автоматически их подхватывает. --no-saved-subs чтобы выключить.
    p.add_argument("--saved-subs-dir", type=Path,
                   default=REPO / "data" / "saved_subs",
                   help="Каталог с локально-сохранёнными конфигами (data/saved_subs "
                        "по умолчанию). Все *.txt и *.json (кроме README.txt) "
                        "авто-добавляются к списку источников. Зеркалит локальный "
                        "GUI (sources_page._use_saved_subs = True).")
    p.add_argument("--no-saved-subs", action="store_true",
                   help="Не мёрджить saved_subs/ в источники. По умолчанию ON — "
                        "повторяет поведение GUI (тумблер «Использовать импортированные "
                        "подписки (data/saved_subs/)» ON по умолчанию).")
    args = p.parse_args(argv)

    def log(msg: str) -> None:
        print(msg, flush=True)

    # 1) Читаем источники.
    # v23: авто-мёрджим saved_subs/*.txt + *.json — как в локальном GUI
    # (sources_page.get_sources с тумблером _use_saved_subs=True по умолчанию).
    # Юзер push'ит свои файлы в репо, GHA их автоматически подхватывает.
    saved_subs_dir = args.saved_subs_dir if not args.no_saved_subs else None
    sources = _read_sources(args.sources_file, args.sources,
                            saved_subs_dir=saved_subs_dir,
                            use_saved_subs=not args.no_saved_subs)
    if not sources:
        log("[gha] FATAL: sources list is empty")
        return 1
    log(f"[gha] sources: {len(sources)} (from {args.sources_file} + CLI"
        + (f" + {args.saved_subs_dir}" if not args.no_saved_subs
           and args.saved_subs_dir.is_dir() else "")
        + ")")
    # Логируем сколько saved_subs-файлов подхвачено (для отладки).
    if not args.no_saved_subs and args.saved_subs_dir.is_dir():
        saved_files = [f.name for f in
                       sorted(args.saved_subs_dir.glob("*.txt"))
                       + sorted(args.saved_subs_dir.glob("*.json"))
                       if f.name != "README.txt"]
        if saved_files:
            log(f"[gha] saved_subs merged: {len(saved_files)} file(s) — "
                f"{', '.join(saved_files[:5])}"
                + (" ..." if len(saved_files) > 5 else ""))

    # 2) collect_subscription_nodes делает всё: fetch + parse + dedup.
    #    Внутри _collect_from_source для каждого URL: _fetch_text →
    #    _subscription_lines → parse_node_link → XrayNode. Дедуп по node.key.
    #    on_source_result считает «мёртвые» источники (для отчёта).
    failed_sources: list[str] = []
    def on_result(url: str, ok: bool) -> None:
        if not ok:
            failed_sources.append(url)

    try:
        nodes = collect_subscription_nodes(
            sources,
            timeout=args.fetch_timeout,
            max_servers=0,  # режем лимит сами (после ping, чтобы не выкинуть живых)
            log_sink=log,
            on_source_result=on_result,
        )
    except Exception as exc:
        log(f"[gha] FATAL: collect_subscription_nodes crashed: {type(exc).__name__}: {exc}")
        return 1

    log(f"[gha] collected {len(nodes)} unique nodes (failed sources: {len(failed_sources)})")

    # 3) Опциональный TCP-ping (дешёвый фильтр мёртвых).
    if args.with_ping and nodes:
        log(f"[gha] TCP-ping {len(nodes)} nodes (workers={args.ping_workers}, timeout={args.ping_timeout}s)")
        alive = _ping_filter(nodes, timeout=args.ping_timeout,
                             workers=args.ping_workers, log_sink=log)
        log(f"[gha] ping: {len(alive)}/{len(nodes)} alive")
        nodes = alive

    # 3b) SNI-категоризация (БС/ЧС/серый/фейк/none) и опциональная фильтрация.
    #     Кейс юзера 2026-09-29: на ограниченных сетях РФ мобильные операторы
    #     пропускают только узлы с SNI из БЕЛОГО списка (sberbank.ru, vk.com,
    #     gosuslugi.ru ...). ЧС (instagram.com, chatgpt.com ...) блокируется.
    if args.bs_only or args.sort_by_sni:
        from checkers.sni_category import (  # lazy — модуль тянет только runtime.types
            category_summary,
            passes_filter as _bs_passes,
            sort_by_sni as _sort_by_sni,
            sni_category as _sni_cat,
        )
        summary = category_summary(nodes)
        log(f"[gha] SNI breakdown: БС={summary.get('white', 0)} "
            f"серый={summary.get('grey', 0)} фейк={summary.get('fake', 0)} "
            f"none={summary.get('none', 0)} ЧС={summary.get('black', 0)}")
        if args.bs_only:
            before = len(nodes)
            nodes = [n for n in nodes if _bs_passes(
                n, allow_grey=args.bs_allow_grey, allow_fake=args.bs_allow_fake)]
            log(f"[gha] --bs-only filter: {before} → {len(nodes)} "
                f"(allow_grey={args.bs_allow_grey}, allow_fake={args.bs_allow_fake})")
            if not nodes:
                log("[gha] WARNING: 0 BS-nodes after filter — preload.txt NOT written")
                return 1
        if args.sort_by_sni and nodes:
            # Сортируем так, что БС-узлы идут первыми в итоговом списке.
            nodes = _sort_by_sni(nodes, white_first=True)
            cats = [_sni_cat(n) for n in nodes[:3]]
            log(f"[gha] --sort-by-sni: first 3 categories = {cats}")

    # 4) Лимит.
    if args.max_servers > 0 and len(nodes) > args.max_servers:
        nodes = nodes[:args.max_servers]
        log(f"[gha] truncated to {len(nodes)} (--max-servers {args.max_servers})")

    if not nodes:
        log("[gha] WARNING: 0 nodes after filter — preload.txt NOT written (existing file kept)")
        return 1

    # 5) Записываем preload.txt (по строке на узел — то, что sub_generator уже
    #    умеет читать как «рабочие конфиги» через _extract_configs в ImportPage).
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')} | {len(nodes)} nodes | "
                f"sources: {len(sources)} | failed: {len(failed_sources)}\n")
        for n in nodes:
            f.write(n.raw_url + "\n")
    log(f"[gha] wrote {len(nodes)} nodes to {args.output}")

    # 6) Короткий JSON-отчёт для отладки и пуша в коммит-сообщение.
    report = {
        "timestamp": int(time.time()),
        "total_sources": len(sources),
        "failed_sources": failed_sources,
        "nodes_collected": len(nodes),
        "ping_filter_applied": bool(args.with_ping),
        "output": str(args.output),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"[gha] wrote report to {args.report}")

    # 7) Exit code.
    if failed_sources and args.strict:
        log(f"[gha] STRICT mode: {len(failed_sources)} source(s) failed — exit 2")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
