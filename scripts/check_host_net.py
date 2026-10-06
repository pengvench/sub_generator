#!/usr/bin/env python3
"""Проверка узлов через check-host.net API (бесплатно, РФ-локации).

Запускается ПОСЛЕ refresh_subs.py в GHA workflow. Берёт топ-N узлов из
preload.txt, для каждого делает TCP-check через check-host.net API с узлов
в Москве/СПб/других РФ-локациях. Оставляет только confirmed-узлы.

Преимущество перед GHA TCP-ping:
- GHA runner на Azure US → TCP-ping с US-IP (гео-блок РФ-серверов)
- check-host.net → TCP-ping с РФ-узлов (Москва, СПб) → реальные данные
  для РФ-мобилки

API: https://check-host.net/check-tcp?host=HOST:PORT&max_nodes=10
- Возвращает request_id
- GET https://check-host.net/check-tcp/{request_id} → результаты через ~10 сек
- Бесплатно, rate limit ~10 запросов/мин

Запуск:
  python scripts/check_host_net.py \\
      --input data/preload_bs.txt \\
      --output data/preload_confirmed.txt \\
      --max-nodes 50 \\
      --timeout 60

Артефакты:
  data/preload_confirmed.txt — только confirmed узлы (рабочие в РФ).
  data/check_host_report.json — JSON-отчёт.

Возвращает:
  0 — успех (минимум 1 узел confirmed).
  1 — фатальная ошибка.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

# check-host.net API требует User-Agent (иначе отдаёт HTML вместо JSON).
_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36"
_HEADERS = {
    "User-Agent": _UA,
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
}


def _api_get(url: str, timeout: float = 30.0) -> dict | None:
    """GET-запрос к check-host.net API. Возвращает JSON dict или None при ошибке.

    v54: urllib НЕ работает с check-host.net (отдаёт 404 на /check-tcp/{id}).
    Видимо, они проверяют User-Agent/Cookie. Используем subprocess wget —
    он работает (проверено).
    """
    import subprocess
    try:
        result = subprocess.run(
            ["wget", "-qO-", "--header=Accept: application/json",
             f"--header=User-Agent: {_UA}",
             "--timeout", str(int(timeout)),
             url],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        if result.returncode != 0 or not result.stdout:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, Exception) as exc:
        print(f"[check-host] API fail (wget): {url[:80]}: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
        return None


def _check_tcp(host: str, port: int, max_nodes: int = 5,
               timeout: float = 30.0) -> tuple[bool, list[dict]]:
    """Проверить host:port через check-host.net/check-tcp.

    Возвращает (confirmed, results).
    confirmed = True если хотя бы 1 узел (особенно РФ) смог подключиться.
    results = список результатов по узлам.
    """
    host_port = f"{host}:{port}"
    url = (f"https://check-host.net/check-tcp?host={quote(host_port)}"
           f"&max_nodes={max_nodes}")
    init = _api_get(url, timeout=timeout)
    if not init or not init.get("ok"):
        return False, []

    request_id = init.get("request_id")
    if not request_id:
        return False, []

    # Ждём ~10 секунд, потом запрашиваем результаты.
    time.sleep(min(10.0, timeout / 2))

    result_url = f"https://check-host.net/check-tcp/{request_id}"
    result = _api_get(result_url, timeout=timeout)
    if not result:
        return False, []

    nodes_results = result.get("nodes", {}) or {}
    if not nodes_results:
        return False, []

    # Анализируем результаты по узлам.
    # Формат: {"node_name": ["country_code", "country", "city", "ip", "asn", [time, is_ok]]}
    confirmed_nodes: list[dict] = []
    for node_name, node_data in nodes_results.items():
        if not isinstance(node_data, list) or len(node_data) < 6:
            continue
        # node_data[5] — это список [time_seconds, "OK"/"FAIL"] или null
        check_result = node_data[5] if len(node_data) > 5 else None
        if not check_result:
            continue
        if isinstance(check_result, list) and len(check_result) >= 2:
            time_sec = check_result[0]
            status = check_result[1]
            if status == "OK" and time_sec is not None:
                confirmed_nodes.append({
                    "node": node_name,
                    "country": node_data[1] if len(node_data) > 1 else "?",
                    "city": node_data[2] if len(node_data) > 2 else "?",
                    "ip": node_data[3] if len(node_data) > 3 else "?",
                    "latency_ms": time_sec * 1000.0 if isinstance(time_sec, (int, float)) else None,
                })

    # confirmed = хотя бы 1 узел ответил OK.
    return bool(confirmed_nodes), confirmed_nodes


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Проверка узлов через check-host.net API (бесплатно, РФ-локации).",
    )
    p.add_argument("--input", type=Path,
                   default=REPO / "data" / "preload_bs.txt",
                   help="Файл с vless:// / vmess:// ... конфигами (default: data/preload_bs.txt).")
    p.add_argument("--output", type=Path,
                   default=REPO / "data" / "preload_confirmed.txt",
                   help="Куда писать confirmed узлы (default: data/preload_confirmed.txt).")
    p.add_argument("--report", type=Path,
                   default=REPO / "data" / "check_host_report.json",
                   help="JSON-отчёт (default: data/check_host_report.json).")
    p.add_argument("--max-nodes", type=int, default=50,
                   help="Лимит числа узлов для проверки (default: 50). "
                        "check-host.net rate limit ~10 req/min → 50 узлов = 5 мин.")
    p.add_argument("--check-nodes", type=int, default=5,
                   help="Сколько check-host.net узлов использовать на 1 хост (default: 5).")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="Таймаут HTTP-запроса, сек (default: 30).")
    args = p.parse_args(argv)

    def log(msg: str) -> None:
        print(msg, flush=True)

    # 1) Парсим конфиги из preload_bs.txt.
    if not args.input.exists():
        log(f"[check-host] FATAL: input file not found: {args.input}")
        return 1
    from runtime.parse import _node_links_from_text, parse_node_link
    text = args.input.read_text(encoding="utf-8")
    raw_urls = _node_links_from_text(text)
    log(f"[check-host] parsed {len(raw_urls)} configs from {args.input}")

    nodes = []
    for url in raw_urls:
        try:
            n = parse_node_link(url)
            if n:
                nodes.append((n, url))
        except Exception:
            continue

    if not nodes:
        log("[check-host] FATAL: 0 valid nodes")
        return 1

    if len(nodes) > args.max_nodes:
        log(f"[check-host] truncating to {args.max_nodes} nodes (--max-nodes)")
        nodes = nodes[:args.max_nodes]

    # 2) Для каждого узла — check-host.net/check-tcp.
    log(f"[check-host] checking {len(nodes)} nodes via check-host.net "
        f"({args.check_nodes} locations per node, timeout={args.timeout}s)")

    confirmed: list[tuple[str, dict]] = []
    failed: list[tuple[str, str]] = []
    done = 0
    for node, url in nodes:
        done += 1
        host = node.host
        port = int(node.port or 0)
        if not host or port <= 0:
            failed.append((url, "no host/port"))
            continue

        ok, results = _check_tcp(host, port, max_nodes=args.check_nodes,
                                 timeout=args.timeout)
        if ok:
            # РФ-узлы — приоритет.
            ru_nodes = [r for r in results if r.get("country") == "Russia"]
            other_nodes = [r for r in results if r.get("country") != "Russia"]
            confirmed.append((url, {
                "host": host,
                "port": port,
                "confirmed_count": len(results),
                "ru_count": len(ru_nodes),
                "nodes": results[:5],  # топ-5 для отчёта
            }))
            log(f"[check-host] {done}/{len(nodes)}: {host}:{port} = "
                f"✅ {len(results)} confirmed ({len(ru_nodes)} РФ, "
                f"{len(other_nodes)} other)")
        else:
            failed.append((url, "no check-host.net confirmation"))
            log(f"[check-host] {done}/{len(nodes)}: {host}:{port} = ❌ no answer")

        # Rate limit: 10 req/min → 6 sec между запросами.
        if done < len(nodes):
            time.sleep(6.0)

    log(f"[check-host] done: {len(confirmed)} confirmed, {len(failed)} failed")

    # 3) Сортируем: сначала РФ-confirmed, потом другие.
    confirmed.sort(key=lambda x: -x[1].get("ru_count", 0))

    # 4) Записываем preload_confirmed.txt (только confirmed узлы).
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{len(confirmed)} confirmed nodes (check-host.net) | "
                f"checked: {len(nodes)}\n")
        for url, info in confirmed:
            f.write(url + "\n")
    log(f"[check-host] wrote {len(confirmed)} confirmed nodes to {args.output}")

    # 5) JSON-отчёт.
    report = {
        "timestamp": int(time.time()),
        "total_checked": len(nodes),
        "confirmed": len(confirmed),
        "failed": len(failed),
        "results": [
            {"url": url, **info} for url, info in confirmed
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    log(f"[check-host] wrote report to {args.report}")

    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
