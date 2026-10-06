#!/usr/bin/env python3
"""Быстрый alive-test: sing-box SOCKS5 + HTTP HEAD к gstatic.com/generate_204.

Для каждого узла:
  1. Запускаем sing-box с конфигом узла (SOCKS5 на 127.0.0.1:<port>).
  2. curl --socks5 → HTTP HEAD к https://www.gstatic.com/generate_204
  3. Если HTTP 204 → узел ЖИВОЙ (прокси работает).
  4. Если 403/429/TLS failure/timeout → МЁРТВЫЙ (отбрасываем).

Это ИМБА — отличает реальные VPN-сервера от CDN/хостинг/фейк:
  - CDN (Cloudflare/Fastly) → 403 Forbidden (CDN не прокси)
  - Railway.app/Vercel → TLS handshake failure (не VPN)
  - Реальные VPN → HTTP 204 (прокси работает)

Скорость: ~2-5 сек на узел (HTTP HEAD = 0 bytes download).
200 узлов × 3с / 8 workers ≈ 75 секунд.

Запуск:
  python scripts/alive_test.py \\
      --input data/preload_bs.txt \\
      --output data/preload_alive.txt \\
      --singbox-bin bin/sing-box \\
      --max-nodes 200 \\
      --workers 8

Артефакты:
  data/preload_alive.txt — только confirmed-alive узлы.
  data/alive_test_report.json — JSON-отчёт со статусами.
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from runtime.parse import parse_node_link, _node_links_from_text
from runtime.types import XrayNode
from singbox_convert import sing_box_full_config

# gstatic.com/generate_204 — Google's connectivity check endpoint.
# Возвращает HTTP 204 (No Content) — минимальный payload, быстро.
_TEST_URL = "https://www.gstatic.com/generate_204"

_PORT_POOL = list(range(11001, 11201))
_PORT_INDEX = 0
_PORT_LOCK = threading.Lock()


def _find_free_port() -> int:
    global _PORT_INDEX
    with _PORT_LOCK:
        port = _PORT_POOL[_PORT_INDEX % len(_PORT_POOL)]
        _PORT_INDEX += 1
        return port


def _wait_for_socks5(port: int, timeout: float) -> bool:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _test_node(node: XrayNode, singbox_bin: Path, *,
               head_timeout: float = 5.0, startup_timeout: float = 5.0) -> dict:
    """Протестировать узел: sing-box SOCKS5 + HTTP HEAD к gstatic.com.

    Возвращает dict:
      {host, port, protocol, status: "alive"|"dead", http_code: int|None,
       error: str|None, latency_ms: float|None}
    """
    result = {
        "host": node.host,
        "port": node.port,
        "protocol": node.protocol,
        "name": node.name,
        "status": "unknown",
        "http_code": None,
        "error": None,
        "latency_ms": None,
    }

    listen_port = _find_free_port()
    config, reason = sing_box_full_config(node, "127.0.0.1", listen_port)
    if config is None:
        result["status"] = "dead"
        result["error"] = f"sing-box config: {reason}"
        return result

    config_path = Path(tempfile.mkstemp(suffix=".json")[1])
    try:
        config_path.write_text(json.dumps(config), encoding="utf-8")
    except OSError as exc:
        result["status"] = "dead"
        result["error"] = f"config write: {exc}"
        return result

    sb_proc = None
    try:
        sb_proc = subprocess.Popen(
            [str(singbox_bin), "run", "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        result["status"] = "dead"
        result["error"] = f"sing-box start: {exc}"
        config_path.unlink(missing_ok=True)
        return result

    try:
        if not _wait_for_socks5(listen_port, startup_timeout):
            result["status"] = "dead"
            result["error"] = f"sing-box did not start in {startup_timeout}s"
            return result

        t0 = time.monotonic()
        try:
            curl = subprocess.run(
                ["curl", "-sS", "--socks5", f"127.0.0.1:{listen_port}",
                 "--max-time", str(head_timeout),
                 "-o", "/dev/null",
                 "-w", "%{http_code}\t%{time_total}",
                 _TEST_URL],
                capture_output=True, text=True, timeout=head_timeout + 5,
            )
        except subprocess.TimeoutExpired:
            result["status"] = "dead"
            result["error"] = f"curl timeout after {head_timeout}s"
            return result

        latency = (time.monotonic() - t0) * 1000.0
        result["latency_ms"] = latency

        if curl.returncode != 0:
            result["status"] = "dead"
            result["error"] = curl.stderr.strip()[:200] or f"curl exit {curl.returncode}"
            return result

        try:
            http_code_str, time_total = curl.stdout.strip().split("\t")
            http_code = int(http_code_str)
        except (ValueError, IndexError):
            result["status"] = "dead"
            result["error"] = f"curl output: {curl.stdout[:200]}"
            return result

        result["http_code"] = http_code
        if http_code in (200, 204):
            result["status"] = "alive"
            return result
        else:
            result["status"] = "dead"
            result["error"] = f"HTTP {http_code}"
            return result
    finally:
        if sb_proc is not None and sb_proc.poll() is None:
            sb_proc.terminate()
            try:
                sb_proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                sb_proc.kill()
                sb_proc.wait(timeout=1.0)
        config_path.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Быстрый alive-test через sing-box + HTTP HEAD.",
    )
    p.add_argument("--input", type=Path, required=True,
                   help="Файл с конфигами (vless://, vmess://, ...).")
    p.add_argument("--output", type=Path, required=True,
                   help="Куда писать alive узлы.")
    p.add_argument("--report", type=Path, default=Path("data/alive_test_report.json"),
                   help="JSON-отчёт (default: data/alive_test_report.json).")
    p.add_argument("--singbox-bin", type=Path, required=True,
                   help="Путь к sing-box binary.")
    p.add_argument("--max-nodes", type=int, default=200,
                   help="Лимит числа узлов для тестирования (default: 200).")
    p.add_argument("--workers", type=int, default=8,
                   help="Параллелизм (default: 8).")
    p.add_argument("--head-timeout", type=float, default=5.0,
                   help="Таймаут HTTP HEAD, сек (default: 5.0).")
    p.add_argument("--startup-timeout", type=float, default=5.0,
                   help="Таймаут запуска sing-box, сек (default: 5.0).")
    # v65: --final-limit — обрез ПОСЛЕ alive-test (не ДО!).
    # Раньше refresh_subs обрезал до 200 ДО alive-test → из 200 выживало 11.
    # Теперь: refresh_subs даёт 1000, alive-test проверяет 1000,
    # --final-limit 200 берёт топ-200 из alive.
    p.add_argument("--final-limit", type=int, default=0,
                   help="ФИНАЛЬНЫЙ обрез ПОСЛЕ alive-test. 200 = топ-200 alive "
                        "(по latency). 0 = без лимита (все alive). Default: 0.")
    args = p.parse_args(argv)

    def log(msg: str) -> None:
        print(msg, flush=True)

    if not args.singbox_bin.exists():
        log(f"[alive] FATAL: sing-box not found at {args.singbox_bin}")
        return 1

    if not args.input.exists():
        log(f"[alive] FATAL: input not found: {args.input}")
        return 1

    text = args.input.read_text(encoding="utf-8")
    raw_urls = _node_links_from_text(text)
    log(f"[alive] parsed {len(raw_urls)} configs from {args.input}")

    nodes: list[tuple[XrayNode, str]] = []
    for url in raw_urls:
        try:
            n = parse_node_link(url)
            if n:
                nodes.append((n, url))
        except Exception:
            continue

    if not nodes:
        log("[alive] FATAL: 0 valid nodes")
        return 1

    if args.max_nodes > 0 and len(nodes) > args.max_nodes:
        log(f"[alive] truncating to {args.max_nodes} (--max-nodes)")
        nodes = nodes[:args.max_nodes]
    elif args.max_nodes == 0:
        log(f"[alive] --max-nodes 0 = NO LIMIT, testing ALL {len(nodes)} nodes")

    log(f"[alive] testing {len(nodes)} nodes with {args.workers} workers "
        f"(head_timeout={args.head_timeout}s, startup={args.startup_timeout}s)")

    results: list[dict] = []
    alive_urls: list[str] = []
    done = 0
    alive_count = 0
    dead_count = 0
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="sb") as ex:
        futures = {ex.submit(_test_node, n, args.singbox_bin,
                             head_timeout=args.head_timeout,
                             startup_timeout=args.startup_timeout): (n, url)
                   for n, url in nodes}
        for fut in as_completed(futures):
            node, url = futures[fut]
            done += 1
            try:
                r = fut.result()
            except Exception as exc:
                r = {"host": node.host, "port": node.port, "protocol": node.protocol,
                     "status": "dead", "error": str(exc)}

            with lock:
                results.append(r)
                if r["status"] == "alive":
                    alive_count += 1
                    alive_urls.append(url)
                else:
                    dead_count += 1

            latency_str = f"{r.get('latency_ms', 0):.0f}ms" if r.get("latency_ms") else "—"
            log(f"[alive] {done}/{len(nodes)}: {r['host']}:{r['port']} "
                f"({r['protocol']}) = {r['status']} "
                f"[HTTP {r.get('http_code', '?')}] {latency_str}"
                + (f" {r.get('error', '')[:80]}" if r.get("error") else ""))

    log(f"[alive] done: {alive_count} alive, {dead_count} dead")

    # v65: --final-limit — обрез ПОСЛЕ alive-test, по latency (быстрые первыми).
    # Сортируем alive по latency, берём топ-N.
    if args.final_limit > 0 and len(alive_urls) > args.final_limit:
        # Нужно отсортировать alive по latency. Перестроим alive_urls по latency.
        alive_results = [(url, r) for url, r in zip(alive_urls, results)
                         if r["status"] == "alive"]
        alive_results.sort(key=lambda x: x[1].get("latency_ms") or 9999)
        before = len(alive_urls)
        alive_urls = [url for url, _ in alive_results[:args.final_limit]]
        log(f"[alive] FINAL --final-limit: {before} → {args.final_limit} "
            f"(по latency, быстрые первыми)")

    # Записываем alive узлы.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{alive_count} alive nodes | tested: {len(nodes)}\n")
        for url in alive_urls:
            f.write(url + "\n")
    log(f"[alive] wrote {alive_count} alive nodes to {args.output}")

    # JSON-отчёт.
    report = {
        "timestamp": int(time.time()),
        "total_tested": len(nodes),
        "alive": alive_count,
        "dead": dead_count,
        "results": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    log(f"[alive] wrote report to {args.report}")

    return 0 if alive_count > 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
