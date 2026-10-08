#!/usr/bin/env python3
"""geo_stage.py — geo-этап пайплайна в ОТДЕЛЬНОМ GHA job'е (v11).

Вынесен из refresh_subs.py по требованию владельца: гео внутри refresh
съедало пол-job'а и убивало его целиком (инцидент 45м). Теперь:
  refresh (fetch+ping+split) → GEO (этот скрипт) → alive-bs ∥ alive-chs → publish.

Что делает:
  1. Читает пулы (--pool, можно несколько: preload_bs/preload_chs/preload).
  2. Грузит персистентный кеш гео (--geo-cache; хиты не ходят в сеть,
     записи-неудачи «🌐/??» не пишутся — их перерешат в следующий ран).
  3. Переименовывает узлы «🇩🇪 DE peppo» (цепочка ip.sb→ip-api→ipwho).
     IP-хосты, захваченные при пинге, берёт из --known-ips (json
     host→ip, пишет refresh_subs.py --ping-ips-out) — DNS повторно
     НЕ делается.
  4. Дропает неопределившиеся «🌐 peppo» (поведение drop-geo-fallback
     из refresh_subs.py; опция --keep-unknown оставляет их).
  5. Перезаписывает пулы (header-строка сохраняется), flush кеша.

Пустые пулы (0 узлов) не трогаются — файл остаётся как есть.
Выход: 0 — ок; 1 — ни одного читаемого пула.

Только stdlib (как alive_test.py): pip install не нужен.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))
sys.path.insert(0, str(REPO / "scripts"))

import refresh_subs as rs  # noqa: E402  (geo-механика v10 переиспользуется)
from runtime.parse import parse_node_link, _node_links_from_text  # noqa: E402


def log(msg: str) -> None:
    print(f"[geo] {msg}", flush=True)


def read_pool(path: Path) -> tuple[str, list]:
    """(header, nodes). Header — первая #-строка файла (сохраняем при записи)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    header = ""
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            header = line
            break
        break  # первый же узел без header — ок
    nodes = []
    for url in _node_links_from_text(text):
        try:
            n = parse_node_link(url)
        except Exception:
            continue
        if n is not None:
            nodes.append(n)
    return header, nodes


def write_pool(path: Path, header: str, nodes: list) -> None:
    body = "\n".join(n.raw_url for n in nodes)
    text = (header + "\n" if header else "") + (body + "\n" if body else "")
    path.write_text(text, encoding="utf-8")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Geo-этап: rename «flag ISO peppo» + drop unknown")
    p.add_argument("--pool", type=Path, action="append", required=True,
                   help="Пул для переименования (можно несколько: "
                        "data/preload_bs.txt data/preload_chs.txt data/preload.txt)")
    p.add_argument("--geo-cache", type=Path, default=None,
                   help="Персистентный кеш {ip: [код, флаг]} (v10-механика).")
    p.add_argument("--known-ips", type=Path, default=None,
                   help="json host→ipv4 с пинга (refresh_subs.py --ping-ips-out). "
                        "Для этих хостов DNS-resolve не делается.")
    p.add_argument("--workers", type=int, default=32)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--keep-unknown", action="store_true",
                   help="НЕ дропать «🌐 peppo» (узлы без гео после всей цепочки).")
    args = p.parse_args(argv)

    # --- known IPs с пинга (без повторного DNS) ---
    known_ips: dict[str, str] = {}
    if args.known_ips and args.known_ips.is_file():
        try:
            raw = json.loads(args.known_ips.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                known_ips = {str(k): str(v) for k, v in raw.items() if v}
        except Exception as exc:
            log(f"known-ips: не читается ({exc}) — DNS-resolve будет полный")
    if known_ips:
        log(f"known-ips: {len(known_ips)} host→ip с пинга (без DNS)")

    # --- читаем пулы ---
    pools: list[tuple[Path, str, list]] = []
    for path in args.pool:
        if not path.is_file():
            log(f"ОШИБКА: пул {path} не найден")
            return 1
        header, nodes = read_pool(path)
        if not nodes:
            log(f"пул {path}: 0 узлов — НЕ трогаю (файл остаётся)")
            continue
        log(f"пул {path}: {len(nodes)} узлов")
        pools.append((path, header, nodes))
    if not pools:
        log("ОШИБКА: ни одного читаемого пула")
        return 1

    # --- персистентный кеш: seed ДО rename ---
    loaded = 0
    if args.geo_cache:
        loaded = rs._geo_cache_seed_and_load(args.geo_cache, log)
        if loaded:
            log(f"geo-cache: {loaded} entries preloaded")

    # --- rename (все пулы одним вызовом — общий кеш IP) ---
    all_nodes = [n for _, _, ns in pools for n in ns]
    rs._geo_rename_nodes(
        all_nodes,
        workers=args.workers,
        timeout=args.timeout,
        log_sink=log,
        known_ips=known_ips,
    )

    # --- drop «🌐 peppo» ---
    if not args.keep_unknown:
        before = sum(len(ns) for _, _, ns in pools)
        pools = [(pth, hdr, [n for n in ns if n.name != "🌐 peppo"])
                 for pth, hdr, ns in pools]
        after = sum(len(ns) for _, _, ns in pools)
        log(f"drop-unknown: «🌐 peppo» выброшено {before - after} "
            f"(было {before}, осталось {after})")

    # --- пишем ---
    for pth, hdr, ns in pools:
        write_pool(pth, hdr, ns)
        log(f"written {pth}: {len(ns)} узлов (после geo)")

    # --- flush кеша ---
    if args.geo_cache:
        rs._geo_cache_flush(args.geo_cache, loaded, log)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
