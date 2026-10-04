#!/usr/bin/env python3
"""Тест пропускной способности VPN-узлов через sing-box + Cloudflare download.

Запускается в GitHub Actions (Linux) — нужен sing-box Linux binary
(качается в .github/workflows/refresh-subs.yml при full_test=true).
Без sing-box файл просто не запускается (см. --require-binary).

Алгоритм на один узел:
  1. Генерируем sing-box JSON-конфиг из vless:// / vmess:// / trojan:// /
     ss:// / hysteria2:// URL узла (через runtime.singbox_convert).
  2. Запускаем sing-box с этим конфигом (HTTP-прокси на 127.0.0.1:<port>).
  3. Через curl --proxy http://127.0.0.1:<port> скачиваем
     https://speed.cloudflare.com/__down?bytes=10485760 (10 MB).
  4. Замеряем throughput = 10MB / download_time_sec → MB/s.
  5. Убиваем sing-box, переходим к следующему узлу.

Параллелизм: 4 узла одновременно (методом round-robin портов 10801..10899).
Sing-box процесс не падает между тестами (1 процесс на узел), порты
никогда не пересекаются (используем atomic counter).

Что отсекаем:
  - Узлы с throughput < --min-speed-mbs (default: 1.0 MB/s).
    1 MB/s = 8 Mbit/s — минимально приемлемо для просмотра 720p YouTube.
  - Узлы, где sing-box не стартовал (некорректный конфиг, неподдерживаемый
    протокол — например, hy2 без obfs).
  - Узлы, где download не завершился за --download-timeout (default: 15s).
  - Узлы, где HTTP-статус != 200 (прокси работает, но Cloudflare недоступен
    через этот узел — гео-блок, rate-limit).

Артефакты:
  JSON-отчёт (по умолчанию data/speedtest_report.json) с массивом записей:
    [{host, port, protocol, mbps, latency_ms, error, ...}, ...]

Возвращает:
  0 — успех (минимум 1 узел протестирован, файл записан).
  1 — фатальная ошибка (нет sing-box, нет узлов, все упали).
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from runtime.parse import parse_node_link  # noqa: E402
from runtime.types import XrayNode  # noqa: E402
from singbox_convert import sing_box_full_config  # noqa: E402


# Cloudflare speed-test endpoint — отдаёт N байт пустого payload.
# 10 MB достаточно для замера (5-10 сек download), не слишком долго.
# Альтернативно: https://speed.hetzner.de/10MB.bin (файл, не endpoint).
# Cloudflare лучше: geo-distributed CDN, низкая задержка, редко режут.
CLOUDFLARE_DOWN_URL = "https://speed.cloudflare.com/__down?bytes=10485760"
CLOUDFLARE_DOWN_BYTES = 10 * 1024 * 1024  # 10 MB

# Минимальный throughput (MB/s) для прохождения фильтра.
# 1.0 MB/s = 8 Mbit/s — минимально приемлемо для просмотра 720p YouTube.
DEFAULT_MIN_SPEED_MBS = 1.0

# Таймаут на download (сек). 10 MB / 1 MB/s = 10 сек, плюс 5 сек на handshake.
DEFAULT_DOWNLOAD_TIMEOUT = 20.0

# Таймаут на запуск sing-box (сек). Если процесс не поднял прокси за это
# время — конфиг некорректный или протокол не поддерживается.
DEFAULT_STARTUP_TIMEOUT = 5.0

# Параллелизм. 4 узла одновременно — баланс между скоростью и стабильностью
# (больше процессов = больше трафика = GHA может throttling'нуть).
DEFAULT_WORKERS = 4

# Пул портов для sing-box HTTP-прокси. 100 портов хватит на 100 узлов
# одновременно (вряд ли будем тестировать больше 100).
_PORT_POOL = list(range(10801, 10901))
_PORT_INDEX = 0
_PORT_LOCK = threading.Lock()


def _next_port() -> int:
    """Выдать следующий свободный порт из пула (round-robin)."""
    global _PORT_INDEX
    with _PORT_LOCK:
        port = _PORT_POOL[_PORT_INDEX % len(_PORT_POOL)]
        _PORT_INDEX += 1
        return port


def _is_port_free(port: int) -> bool:
    """Проверить, что порт свободен (никто не слушает)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))
            return True
    except OSError:
        return False


def _find_free_port() -> int:
    """Найти свободный порт — round-robin из пула, с fallback на OS-assigned."""
    for _ in range(len(_PORT_POOL)):
        port = _next_port()
        if _is_port_free(port):
            return port
    # Fallback: попросим OS выделить порт (ephemeral range 49152-65535).
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------- sing-box config
def _node_to_singbox_config(node: XrayNode, listen_port: int) -> dict | None:
    """Сгенерировать sing-box JSON-конфиг с SOCKS5 inbound + outbound узла.

    Использует singbox_convert.sing_box_full_config — это готовая функция,
    которая строит корректный конфиг для всех поддерживаемых протоколов
    (vless/vmess/trojan/ss/hysteria2). Возвращает None если протокол не
    поддерживается (например, hy2 с неподдерживаемым obfs).
    """
    config, reason = sing_box_full_config(node, "127.0.0.1", listen_port)
    if config is None:
        return None
    # sing_box_full_config создаёт SOCKS5 inbound — мы используем curl --socks5.
    return config


def _wait_for_proxy(port: int, timeout: float) -> bool:
    """Подождать, пока sing-box поднимет HTTP-прокси на порту.

    Делаем TCP-connect каждые 100мс. Если за timeout не поднялся — False.
    """
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


# --------------------------------------------------------------------- test one node
def _test_node(node: XrayNode, singbox_bin: Path, *,
              download_timeout: float, startup_timeout: float,
              download_bytes: int = CLOUDFLARE_DOWN_BYTES) -> dict:
    """Протестировать один узел: запустить sing-box, скачать 10MB, вернуть метрики.

    Возвращает dict:
      {host, port, protocol, mbps: float|None, latency_ms: float|None,
       status: "ok"|"sb_failed"|"download_failed"|"slow", error: str|None}
    """
    result = {
        "host": node.host,
        "port": node.port,
        "protocol": node.protocol,
        "name": node.name,
        "mbps": None,
        "latency_ms": None,
        "status": "unknown",
        "error": None,
    }

    listen_port = _find_free_port()
    config = _node_to_singbox_config(node, listen_port)
    if config is None:
        result["status"] = "sb_config_failed"
        result["error"] = "sing-box outbound generation failed"
        return result

    # Пишем конфиг во временный файл.
    import tempfile
    config_path = Path(tempfile.mkstemp(suffix=".json")[1])
    try:
        config_path.write_text(json.dumps(config), encoding="utf-8")
    except OSError as exc:
        result["status"] = "sb_config_failed"
        result["error"] = f"config write: {exc}"
        return result

    # Запускаем sing-box. На Linux он требует --config <path>.
    # stderr подавляем (лог не нужен), stdout — подавляем.
    sb_proc = None
    try:
        sb_proc = subprocess.Popen(
            [str(singbox_bin), "run", "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        result["status"] = "sb_start_failed"
        result["error"] = f"sing-box start: {exc}"
        config_path.unlink(missing_ok=True)
        return result

    try:
        # Ждём поднятия прокси.
        if not _wait_for_proxy(listen_port, startup_timeout):
            result["status"] = "sb_startup_timeout"
            result["error"] = f"sing-box did not start in {startup_timeout}s"
            return result

        # Делаем HTTP-download через SOCKS5. curl с --socks5.
        # -sS: silent + show errors. --max-time: жёсткий таймаут.
        # -o /dev/null: не пишем файл (нам нужен только throughput).
        # -w '%{speed_download} %{time_total} %{http_code}': метрики.
        t0 = time.monotonic()
        try:
            curl = subprocess.run(
                ["curl", "-sS", "--socks5", f"127.0.0.1:{listen_port}",
                 "--max-time", str(download_timeout),
                 "-o", "/dev/null",
                 "-w", "%{speed_download}\t%{time_total}\t%{http_code}",
                 f"https://speed.cloudflare.com/__down?bytes={download_bytes}"],
                capture_output=True, text=True, timeout=download_timeout + 5,
            )
        except subprocess.TimeoutExpired:
            result["status"] = "download_timeout"
            result["error"] = f"curl timed out after {download_timeout}s"
            return result

        elapsed = time.monotonic() - t0
        result["latency_ms"] = elapsed * 1000.0

        if curl.returncode != 0:
            result["status"] = "download_failed"
            result["error"] = curl.stderr.strip()[:200] or f"curl exit {curl.returncode}"
            return result

        # Парсим вывод curl: "speed_download\ttime_total\thttp_code".
        try:
            speed_bps_str, time_total_str, http_code_str = curl.stdout.strip().split("\t")
            speed_bps = float(speed_bps_str)  # bytes/sec
            time_total = float(time_total_str)
            http_code = int(http_code_str)
        except (ValueError, IndexError):
            result["status"] = "download_parse_failed"
            result["error"] = f"curl output: {curl.stdout[:200]}"
            return result

        if http_code != 200:
            result["status"] = "download_http_error"
            result["error"] = f"HTTP {http_code}"
            return result

        # Throughput в MB/s (1 MB = 1024*1024 bytes, не SI).
        mbps = speed_bps / (1024 * 1024)
        result["mbps"] = mbps
        result["status"] = "ok"
        return result
    finally:
        # Убиваем sing-box. SIGTERM, ждём 1 сек, SIGKILL если не умер.
        if sb_proc is not None and sb_proc.poll() is None:
            sb_proc.terminate()
            try:
                sb_proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                sb_proc.kill()
                sb_proc.wait(timeout=1.0)
        config_path.unlink(missing_ok=True)


# --------------------------------------------------------------------- main
def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Тест пропускной способности VPN-узлов через sing-box + Cloudflare.",
    )
    p.add_argument("--input", type=Path,
                   default=REPO / "data" / "preload.txt",
                   help="Файл с vless:// / vmess:// / ... конфигами (один на строку). "
                        "По умолчанию: data/preload.txt (выход refresh_subs.py).")
    p.add_argument("--output", type=Path,
                   default=REPO / "data" / "preload_speed.txt",
                   help="Куда писать отфильтрованные узлы (только быстрые). "
                        "По умолчанию: data/preload_speed.txt.")
    p.add_argument("--report", type=Path,
                   default=REPO / "data" / "speedtest_report.json",
                   help="JSON-отчёт со всеми метриками. По умолчанию: "
                        "data/speedtest_report.json.")
    p.add_argument("--singbox-bin", type=Path,
                   default=REPO / "bin" / "sing-box",
                   help="Путь к sing-box Linux binary. По умолчанию: bin/sing-box "
                        "(качается в GHA при full_test=true).")
    p.add_argument("--min-speed-mbs", type=float, default=DEFAULT_MIN_SPEED_MBS,
                   help="Минимальный throughput, MB/s (default: 1.0 = 8 Mbit/s). "
                        "Узлы с меньшей скоростью отбраковываются.")
    p.add_argument("--max-nodes", type=int, default=20,
                   help="Лимит числа узлов для тестирования (default: 20). "
                        "Больше = дольше (20 узлов × ~10с = ~3 мин с workers=4).")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                   help="Параллелизм (default: 4). Больше = быстрее, но "
                        "больше трафика. Sing-box процессы не пересекаются "
                        "(каждый свой порт из пула 10801..10899).")
    p.add_argument("--download-timeout", type=float, default=DEFAULT_DOWNLOAD_TIMEOUT,
                   help="Таймаут на download 10MB (default: 20s). "
                        "10MB / 1MB/s = 10s, плюс 10s запас на handshake.")
    p.add_argument("--startup-timeout", type=float, default=DEFAULT_STARTUP_TIMEOUT,
                   help="Таймаут на запуск sing-box (default: 5s). "
                        "Если sing-box не поднял прокси за это время — конфиг "
                        "некорректный или протокол не поддерживается.")
    p.add_argument("--require-binary", action="store_true", default=True,
                   help="Требовать sing-box binary (default: ON). Если OFF — "
                        "упадёт мягко (exit 0) при отсутствии.")
    # v41: режим работы speedtest. Раньше был только "filter" — отбраковывал
    # всё что не fast. Теперь есть "ranker" — узлы НЕ отбрасываются, а просто
    # сортируются (быстрые первыми, failed — в конце).
    # Режим "ranker" по умолчанию — потому что на GHA Azure US многие узлы
    # гео-блокированы (отклоняют US IP), но реально работают на РФ-мобиле.
    # Их нельзя отбрасывать — просто пускаем в финал последними.
    p.add_argument("--mode", choices=["filter", "ranker"], default="ranker",
                   help="Режим работы: "
                        "filter — оставить только быстрые (отбросить failed); "
                        "ranker — оставить все, отсортировать (быстрые первыми, "
                        "failed canonical-stack — в конце). Default: ranker. "
                        "v41: для курируемых списков (AetrisVPN/Pizduk) ranker "
                        "правильнее — не убивает узлы, которые не ответили Azure.")
    p.add_argument("--keep-canonical-failed", action="store_true", default=True,
                   help="(только с --mode ranker) Оставлять canonical-stack узлы, "
                        "у которых speedtest failed (connection refused / timeout). "
                        "Причина: на GHA Azure US многие узлы гео-блокированы — "
                        "не отвечают, но реально работают на РФ-мобиле. "
                        "Default: ON.")
    args = p.parse_args(argv)

    def log(msg: str) -> None:
        print(msg, flush=True)

    # 1) Проверяем sing-box.
    if not args.singbox_bin.exists():
        if args.require_binary:
            log(f"[speedtest] FATAL: sing-box binary not found at {args.singbox_bin}")
            log("[speedtest] Качается в GHA при full_test=true. "
                "Локально: скачайте с https://github.com/SagerNet/sing-box/releases "
                "и положите в bin/sing-box")
            return 1
        log(f"[speedtest] sing-box not found, skipping speedtest (require_binary=False)")
        return 0

    # 2) Парсим узлы из preload.txt.
    if not args.input.exists():
        log(f"[speedtest] FATAL: input file not found: {args.input}")
        return 1
    from runtime.parse import _node_links_from_text
    text = args.input.read_text(encoding="utf-8")
    raw_urls = _node_links_from_text(text)
    log(f"[speedtest] parsed {len(raw_urls)} configs from {args.input}")

    nodes: list[XrayNode] = []
    for url in raw_urls:
        try:
            n = parse_node_link(url)
            if n:
                nodes.append(n)
        except Exception:
            continue
    log(f"[speedtest] parsed {len(nodes)} valid XrayNodes")

    if not nodes:
        log("[speedtest] FATAL: 0 valid nodes to test")
        return 1

    # 3) Ограничиваем до max_nodes (берём первые N — они уже отсортированы
    #    pattern-score в refresh_subs.py).
    if len(nodes) > args.max_nodes:
        log(f"[speedtest] truncating to {args.max_nodes} nodes (--max-nodes)")
        nodes = nodes[:args.max_nodes]

    # 4) Тестируем параллельно.
    log(f"[speedtest] testing {len(nodes)} nodes with {args.workers} workers "
        f"(min_speed={args.min_speed_mbs} MB/s, download_timeout={args.download_timeout}s, "
        f"mode={args.mode})")

    results: list[dict] = []
    done = 0
    passed = 0
    failed = 0
    lock = threading.Lock()

    # Ленивый импорт — нужен только в mode=ranker для определения canonical-stack.
    # Импортируем ВНЕ цикла, чтобы не тратить время на повторный import.
    if args.mode == "ranker" and args.keep_canonical_failed:
        # _matches_canonical_stack определена в refresh_subs.py. Чтобы не
        # делать циклический импорт, определим минимальную версию тут.
        def _is_canonical(node: XrayNode) -> bool:
            proto = (node.protocol or "").lower()
            security = (node.query.get("security") or "").lower()
            transport = (node.query.get("type") or "").lower()
            if proto == "vless" and security == "reality":
                return True
            if proto == "vless" and security == "tls" and transport == "ws":
                return True
            if proto == "vless" and security == "tls" and transport in ("http", "xhttp"):
                return True
            if proto == "trojan" and security == "tls" and transport == "ws":
                return True
            if proto == "vmess" and security == "tls" and transport == "ws":
                return True
            if proto in ("hysteria2", "hy2"):
                return True
            # v43: tuic — UDP-over-QUIC, DPI не видит
            if proto == "tuic":
                return True
            return False
    else:
        def _is_canonical(_n: XrayNode) -> bool:
            return False

    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="sb") as ex:
        futures = {ex.submit(_test_node, n, args.singbox_bin,
                            download_timeout=args.download_timeout,
                            startup_timeout=args.startup_timeout): n for n in nodes}
        for fut in as_completed(futures):
            done += 1
            node = futures[fut]
            try:
                r = fut.result()
            except Exception as exc:
                r = {"host": node.host, "port": node.port, "protocol": node.protocol,
                     "status": "exception", "error": str(exc), "mbps": None}
            # v41: Сохраняем canonical-stack флаг для ranker-режима.
            r["canonical_stack"] = _is_canonical(node)
            with lock:
                results.append(r)
                if r["status"] == "ok" and r.get("mbps", 0) >= args.min_speed_mbs:
                    passed += 1
                else:
                    failed += 1
            # Прогресс.
            mbps_str = f"{r.get('mbps', 0):.2f} MB/s" if r.get("mbps") else "—"
            log(f"[speedtest] {done}/{len(nodes)}: {r['host']}:{r['port']} "
                f"({r['protocol']}) = {mbps_str} [{r['status']}]")

    # 5) Сортируем по throughput (быстрые первыми).
    results.sort(key=lambda x: -(x.get("mbps") or 0))

    # v41: В mode=ranker — НЕ отбрасываем failed canonical-stack узлы.
    # Они попадают в финал после быстрых (в порядке original).
    fast_results = [r for r in results if r["status"] == "ok"
                   and (r.get("mbps") or 0) >= args.min_speed_mbs]
    slow_results = [r for r in results if r["status"] == "ok"
                   and (r.get("mbps") or 0) < args.min_speed_mbs]

    if args.mode == "ranker" and args.keep_canonical_failed:
        # Сохраняем canonical-stack failed узлы (гео-блок на Azure, но рабочие на РФ-мобиле).
        # v43: sb_config_failed ТОЖЕ сохраняем — это узлы, протокол которых
        # sing-box не поддерживает (например, tuic). Сам конфиг валидный,
        # просто sing-box не может его протестировать. Клиенты (Hiddify,
        # Karing) их поддерживают — оставляем.
        canonical_failed = [r for r in results
                           if r["status"] != "ok"
                           and r.get("canonical_stack", False)
                           and r["status"] not in ("sb_start_failed",
                                                   "exception")]
        # Совсем отбрасываем только sb_start_failed (sing-box не стартовал —
        # это обычно значит, что конфиг сломанный, или что-то с системой).
        hard_failed = [r for r in results
                      if r not in fast_results
                      and r not in slow_results
                      and r not in canonical_failed]
        log(f"[speedtest] {args.mode} mode: "
            f"{len(fast_results)} fast, {len(slow_results)} slow (below {args.min_speed_mbs} MB/s), "
            f"{len(canonical_failed)} canonical-failed (kept — geo-blocked on Azure), "
            f"{len(hard_failed)} hard-failed (broken configs)")
        # Финальный список: fast → slow → canonical-failed → (hard_failed отбрасываем).
        final_results = fast_results + slow_results + canonical_failed
    else:
        # filter mode: только fast.
        final_results = fast_results
        log(f"[speedtest] {args.mode} mode: "
            f"{len(fast_results)} fast (kept), {len(results) - len(fast_results)} discarded")

    if fast_results:
        # Топ-5 по скорости.
        for r in fast_results[:5]:
            log(f"[speedtest]   fastest: {r.get('mbps', 0):.2f} MB/s "
                f"@ {r['host']}:{r['port']} ({r['protocol']})")
        # p50/p95 latency.
        lats = sorted(r.get("latency_ms", 0) for r in fast_results if r.get("latency_ms"))
        if lats:
            p50 = lats[len(lats) // 2]
            p95 = lats[int(len(lats) * 0.95)] if len(lats) > 1 else lats[0]
            log(f"[speedtest] latency: p50={p50:.0f}ms p95={p95:.0f}ms "
                f"({len(lats)} successful downloads)")

    # 6) Пишем preload_speed.txt (final_results, в порядке скорости).
    # Находим исходный URL узла по (host, port, protocol). Это медленно
    # для больших списков, но max_nodes обычно ≤ 100.
    url_map: dict[tuple[str, str, str], str] = {}
    for url in raw_urls:
        try:
            n = parse_node_link(url)
            if n:
                url_map[(n.host, str(n.port), n.protocol)] = url
        except Exception:
            continue

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{len(final_results)} nodes "
                f"({len(fast_results)} fast + {len(slow_results)} slow + "
                f"{len(final_results) - len(fast_results) - len(slow_results)} canonical-failed-kept) | "
                f"tested: {len(nodes)} | mode={args.mode}\n")
        for r in final_results:
            url = url_map.get((r["host"], str(r["port"]), r["protocol"]))
            if url:
                f.write(url + "\n")
    log(f"[speedtest] wrote {len(final_results)} nodes to {args.output} "
        f"(fast: {len(fast_results)}, slow: {len(slow_results)}, "
        f"canonical-failed-kept: {len(final_results) - len(fast_results) - len(slow_results)})")

    # 7) JSON-отчёт.
    report = {
        "timestamp": int(time.time()),
        "total_tested": len(nodes),
        "fast_passed": len(fast_results),
        "slow_passed": len(slow_results),
        "canonical_failed_kept": (len(final_results) - len(fast_results) - len(slow_results))
                                  if args.mode == "ranker" else 0,
        "hard_failed": len(results) - len(final_results),
        "min_speed_mbs": args.min_speed_mbs,
        "workers": args.workers,
        "mode": args.mode,
        "results": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    log(f"[speedtest] wrote report to {args.report}")

    # v41: в mode=ranker возвращаем 0 всегда (если хоть 1 узел в final_results).
    # В mode=filter — 0 только если есть fast_results.
    if args.mode == "ranker":
        return 0 if final_results else 1
    return 0 if fast_results else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
