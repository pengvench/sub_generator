#!/usr/bin/env python3
"""Alive-test: sing-box/xray SOCKS5 + HTTP-пробы через прокси.

Порядок проверки узла:
  1. Стартуем ядро (sing-box, для raw/xhttp — xray) с SOCKS5 на 127.0.0.1:<port>.
  2. Через прокси: GET https://api.ipify.org — проверка смены exit-IP.
     exit_ip == runner_ip → прокси не работает, узел отбраковывается.
  3. Через прокси: GET заблокированных в РФ сервисов (см. _TEST_URLS).
     Узел alive, если хотя бы --min-services из них ответили HTTP 2xx/3xx.

Замеры latency (curl -w, миллисекунды, по каждой пробе отдельно):
  connect — TCP connect до сервера (через SOCKS);
  tls     — TLS/Reality handshake (time_appconnect);
  ttfb    — время до первого байта ответа (time_starttransfer);
  total   — полное время запроса (time_total).

Фильтр --max-latency-ms применяется к ОДНОЙ величине для всех узлов —
TTFB пробы exit-IP. В лог/отчёт пишутся все четыре фазы каждой пробы,
итоговая latency_ms = ttfb пробы exit-IP (ровно то, с чем сравнивается порог).

User-Agent (v6): все HTTP-пробы идут с UA обычного Chrome (_PROBE_UA) —
антиботы (Instagram/Cloudflare и др.) режут не-браузерные UA (curl/8.x):
часть серверов отдаёт curl'у другой ответ, чем браузеру, и живой узел
ловил ложный DEAD. Феч подписок, наоборот, представляется клиентом
v2rayNG/1.10.8 (runtime/types.py: SUBSCRIPTION_USER_AGENT) — подписочные
серверы гейтят unknown-клиентов по UA.

Запуск:
  python scripts/alive_test.py \\
      --input data/preload_bs.txt \\
      --output data/preload_alive.txt \\
      --singbox-bin bin/sing-box \\
      --workers 16

Артефакты:
  <output> — только alive-узлы (исходные URL, порядок входа сохранён
             при сортировке по latency);
  <report> — JSON-отчёт со статусами и фазами всех проб. ТЕЛА ОТВЕТОВ
             В ОТЧЁТЕ НЕ ХРАНЯТСЯ (v8): exit-IP извлекается из тела
             ipify-пробы на лету и возвращается из _curl_probe ОТДЕЛЬНО
             от dict'а пробы; HTML-страницы instagram/youtube в отчёт
             не пишутся вообще — только http-коды и фазы. Отчёт на ~5k
             узлов = единицы МБ, живёт в CI-artifacts.
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

# Пробы через прокси: сначала exit-IP, затем заблокированные в РФ сервисы.
# Лёгкие generate_204-эндпоинты проходят даже на перегруженных серверах,
# реальные сайты требуют полный TLS + HTTP-ответ.
_TEST_URLS = [
    ("ipify", "https://api.ipify.org"),
    ("instagram", "https://www.instagram.com/"),
    ("youtube", "https://www.youtube.com/"),
    ("telegram", "https://api.telegram.org/"),
]

# Формат curl -w: http_code + фазы запроса (в секундах), отделяется переводом строки.
_CURL_WRITE_OUT = "\\n%{http_code} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}"

# UA HTTP-проб (все запросы через прокси к api.ipify.org/instagram/
# youtube/telegram): обычный десктопный Chrome. Без -A curl шлёт
# «curl/8.x» — часть серверов и CDN (антиботы Instagram, Cloudflare)
# отдаёт не-браузерным клиентам другой ответ или режет соединение:
# живой узел получает ложный DEAD. Проба должна видеть то же, что
# увидит браузер юзера через этот прокси.
_PROBE_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

# v8: тела HTTP-проб в отчёте НЕ хранятся вовсе (ни префиксом). Тело
# нужно ровно в одном месте — извлечь exit-IP из ответа api.ipify.org —
# и _curl_probe возвращает его ОТДЕЛЬНО от dict'а пробы. История: до v7
# хранились полные тела (931 МБ отчёт, push отклонён лимитом GitHub
# 100 МБ/файл), v7 — префикс 80 символов, v8 — ничего: http-коды и фазы
# дают всю диагностику, HTML-страницы — балласт под лимиты платформ.
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
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _geo_lookup_code(ip: str) -> tuple[str, str]:
    """Страна exit-IP через цепочку subgen.geo (ip.sb → ip-api.com → ipwho.is).

    Метаданные для отчёта: {country, geo_status}. Никак не влияет на вердикт
    alive/dead. При полной недоступности цепочки — ("??", "").
    """
    try:
        from subgen.geo import geoip_lookup
        return geoip_lookup(ip, timeout=6.0)
    except Exception:
        return ("??", "")


def _curl_probe(listen_port: int, url: str, timeout: float) -> tuple[dict, str]:
    """Один GET через SOCKS5-прокси с замером фаз.

    Возвращает (result, body):
      result — ok, http_code, error,
               connect_ms, tls_ms, ttfb_ms, total_ms (None, если curl
               не дошёл). Тела ответа в dict'е НЕТ (v8);
      body   — тело ответа целиком; нужно ТОЛЬКО вызывающему коду для
               извлечения exit-IP (ipify), в отчёт не попадает.
    """
    result: dict = {
        "ok": False, "http_code": 0, "error": None,
        "connect_ms": None, "tls_ms": None, "ttfb_ms": None, "total_ms": None,
    }
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--socks5-hostname", f"127.0.0.1:{listen_port}",
             "--max-time", str(timeout),
             "-A", _PROBE_UA,
             "-w", _CURL_WRITE_OUT, url],
            capture_output=True, text=True, timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
        return result, ""
    if proc.returncode != 0:
        result["error"] = (proc.stderr.strip() or f"curl exit {proc.returncode}")[:120]
        return result, ""
    # stdout = тело ответа + "\n" + строка статистики "code connect tls ttfb total".
    body, _, stats_line = proc.stdout.rpartition("\n")
    parts = stats_line.split()
    if len(parts) == 5:
        try:
            code, connect_s, tls_s, ttfb_s, total_s = parts
            result["http_code"] = int(code)
            result["connect_ms"] = round(float(connect_s) * 1000, 1)
            result["tls_ms"] = round(float(tls_s) * 1000, 1) if float(tls_s) > 0 else None
            result["ttfb_ms"] = round(float(ttfb_s) * 1000, 1)
            result["total_ms"] = round(float(total_s) * 1000, 1)
        except ValueError:
            pass
    else:
        # Нет строки статистики (пустое тело у 204 и т.п.) — пробуем как тело.
        body = proc.stdout
    # Тело НЕ кладём в result (v8) — возвращаем отдельно (см. докстринг).
    result["ok"] = True
    return result, body


def _build_xray_config(node: XrayNode, listen_port: int) -> tuple[dict | None, str | None]:
    """Минимальный xray-конфиг для raw/xhttp (sing-box их не поддерживает)."""
    proto = (node.protocol or "").lower()
    q = node.query
    host = node.host
    port = int(node.port)
    cred = node.credential or ""

    outbound: dict = {"protocol": proto, "settings": {}}
    ss: dict = {}  # streamSettings

    if proto == "vless":
        user = {"id": cred, "encryption": q.get("encryption", "none")}
        flow = q.get("flow", "")
        if flow:
            user["flow"] = flow
        outbound["settings"]["vnext"] = [{"address": host, "port": port, "users": [user]}]
    elif proto == "trojan":
        outbound["settings"]["servers"] = [{"address": host, "port": port, "password": cred}]
    elif proto == "vmess":
        outbound["settings"]["vnext"] = [{"address": host, "port": port,
                                          "users": [{"id": cred, "alterId": 0}]}]
    elif proto == "shadowsocks":
        outbound["settings"]["servers"] = [{"address": host, "port": port,
                                            "method": q.get("method", "aes-256-gcm"),
                                            "password": cred}]
    else:
        return None, f"xray: protocol {proto} not supported"

    network = q.get("type", "tcp").lower()
    security = q.get("security", "").lower()

    ss["network"] = network
    ss["security"] = security or "none"

    if security == "reality":
        ss["realitySettings"] = {
            "serverName": q.get("sni", ""),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "fingerprint": q.get("fp", "chrome"),
        }
    elif security == "tls":
        ss["tlsSettings"] = {
            "serverName": q.get("sni", ""),
            "fingerprint": q.get("fp", "chrome"),
        }
        if q.get("alpn"):
            ss["tlsSettings"]["alpn"] = q.get("alpn").split(",")

    if network == "ws":
        ss["wsSettings"] = {"path": q.get("path", "/"), "host": q.get("host", "")}
    elif network in ("raw",):
        ss["rawSettings"] = {}
    elif network in ("xhttp", "http", "splithttp"):
        ss["xhttpSettings"] = {"path": q.get("path", "/"), "host": q.get("host", "")}
    elif network == "grpc":
        ss["grpcSettings"] = {"serviceName": q.get("serviceName", "")}

    outbound["streamSettings"] = ss

    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": listen_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        }],
        "outbounds": [outbound],
    }
    return config, None


def _test_node(node: XrayNode, singbox_bin: Path,
               xray_bin: Path | None = None, *,
               head_timeout: float = 8.0, startup_timeout: float = 5.0,
               max_latency_ms: float = 2000,
               min_services: int = 1,
               runner_ip: str = "") -> dict:
    """Полная проверка узла. latency-порог применяется к TTFB пробы exit-IP."""
    result: dict = {
        "host": node.host, "port": node.port, "protocol": node.protocol,
        "name": node.name, "status": "unknown",
        "http_code": None, "error": None,
        "latency_ms": None,           # TTFB пробы exit-IP (та же величина, что в пороге)
        "exit_ip": None, "ip_changed": None,
        "country": None, "geo_status": "unknown",   # гео exit-IP — метаданные, не критерий жизни
        "instagram": None, "youtube": None, "telegram": None,
        "timings": {},                # все фазы всех проб
    }

    listen_port = _find_free_port()

    config, reason = sing_box_full_config(node, "127.0.0.1", listen_port)
    binary = singbox_bin
    binary_name = "sing-box"

    if config is None and xray_bin is not None and xray_bin.exists():
        xray_config, _xray_reason = _build_xray_config(node, listen_port)
        if xray_config is not None:
            config = xray_config
            binary = xray_bin
            binary_name = "xray"
            reason = None

    if config is None:
        result["status"] = "dead"
        result["error"] = f"config failed (sing-box: {reason})"
        return result

    config_path = Path(tempfile.mkstemp(suffix=".json")[1])
    try:
        config_path.write_text(json.dumps(config), encoding="utf-8")
    except OSError as exc:
        result["status"] = "dead"
        result["error"] = f"config write: {exc}"
        return result

    core_proc = None
    try:
        run_arg = "-c" if binary_name == "xray" else "--config"
        try:
            core_proc = subprocess.Popen(
                [str(binary), "run", run_arg, str(config_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            result["status"] = "dead"
            result["error"] = f"{binary_name} start: {exc}"
            config_path.unlink(missing_ok=True)
            return result

        if not _wait_for_socks5(listen_port, startup_timeout):
            result["status"] = "dead"
            result["error"] = f"{binary_name} did not start in {startup_timeout}s"
            return result

        # Проба 1: exit-IP. Один запрос: тело (IP) + фазы = профиль узла.
        ip_probe, ip_body = _curl_probe(listen_port, _TEST_URLS[0][1], head_timeout)
        result["timings"]["exit_ip"] = ip_probe
        if not ip_probe["ok"]:
            result["status"] = "dead"
            result["error"] = f"exit-ip probe: {ip_probe['error']}"
            return result

        exit_ip = ip_body.strip()
        if not exit_ip:
            result["status"] = "dead"
            result["error"] = "exit-ip probe: empty body"
            return result
        result["exit_ip"] = exit_ip

        # Гео exit-IP — метаданные для отчёта (модель {alive, exit_ip, country,
        # geo_status}). На вердикт alive/dead НЕ влияет никак.
        geo_code, _geo_flag = _geo_lookup_code(exit_ip)
        if geo_code not in ("", "??", "🌐"):
            result["country"] = geo_code
            result["geo_status"] = "ok"

        if runner_ip and exit_ip and exit_ip == runner_ip:
            result["status"] = "dead"
            result["ip_changed"] = False
            result["error"] = f"IP leaked: exit={exit_ip} == runner={runner_ip}"
            return result
        result["ip_changed"] = True

        # Порог latency: TTFB пробы exit-IP. Одна величина для всех узлов.
        ttfb = ip_probe.get("ttfb_ms")
        if ttfb is None:
            ttfb = ip_probe.get("total_ms") or 0.0
        result["latency_ms"] = ttfb
        if max_latency_ms > 0 and ttfb > max_latency_ms:
            result["status"] = "dead"
            result["error"] = (f"ttfb {ttfb:.0f}ms (>{max_latency_ms:.0f}ms); "
                               f"connect={ip_probe.get('connect_ms')} "
                               f"tls={ip_probe.get('tls_ms')} "
                               f"total={ip_probe.get('total_ms')}")
            return result

        # Пробы 2..N: заблокированные сервисы, каждый со своими фазами.
        service_ok = 0
        first_ok_code: int | None = None
        for svc_name, svc_url in _TEST_URLS[1:]:
            probe, _svc_body = _curl_probe(listen_port, svc_url, head_timeout)
            result["timings"][svc_name] = probe
            code = probe.get("http_code") or 0
            if probe["ok"] and code in (200, 204, 301, 302, 303, 307, 308):
                service_ok += 1
                if first_ok_code is None:
                    first_ok_code = code
                result[svc_name] = code
            else:
                result[svc_name] = "timeout" if not probe["ok"] else f"HTTP {code}"

        result["http_code"] = first_ok_code
        if service_ok >= min_services:
            result["status"] = "alive"
        else:
            result["status"] = "dead"
            result["error"] = (f"ip_changed={exit_ip[:20]} but only "
                               f"{service_ok}/{len(_TEST_URLS) - 1} services ok "
                               f"(min {min_services})")
        return result

    finally:
        if core_proc is not None and core_proc.poll() is None:
            core_proc.terminate()
            try:
                core_proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                core_proc.kill()
                core_proc.wait(timeout=1.0)
        config_path.unlink(missing_ok=True)


def _fmt_ms(value) -> str:
    if value is None:
        return "—"
    return f"{value:.0f}"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Alive-test через sing-box/xray + HTTP-пробы с фазовыми замерами.",
    )
    p.add_argument("--input", type=Path, required=True,
                   help="Файл с конфигами (vless://, vmess://, ...).")
    p.add_argument("--output", type=Path, required=True,
                   help="Куда писать alive узлы.")
    p.add_argument("--report", type=Path, default=Path("data/alive_test_report.json"),
                   help="JSON-отчёт (default: data/alive_test_report.json).")
    p.add_argument("--singbox-bin", type=Path, required=True,
                   help="Путь к sing-box binary.")
    p.add_argument("--xray-bin", type=Path, default=None,
                   help="Путь к xray binary (для raw/xhttp транспорта).")
    p.add_argument("--source-map", type=Path, default=None,
                   help="JSON маппинг URL → source (статистика alive/dead по источникам).")
    p.add_argument("--max-nodes", type=int, default=200,
                   help="Лимит числа узлов для тестирования (default: 200). 0 = без лимита.")
    p.add_argument("--workers", type=int, default=8,
                   help="Параллелизм (default: 8).")
    p.add_argument("--head-timeout", type=float, default=8.0,
                   help="Таймаут одной HTTP-пробы, сек (default: 8.0).")
    p.add_argument("--startup-timeout", type=float, default=5.0,
                   help="Таймаут запуска ядра, сек (default: 5.0).")
    p.add_argument("--max-latency-ms", type=float, default=2000,
                   help="Порог на TTFB пробы exit-IP, мс (default: 2000). "
                        "0 = без лимита. Применяется к одной и той же величине "
                        "для всех узлов.")
    p.add_argument("--min-services", type=int, default=1,
                   help="Сколько из 3 сервисов должны ответить 2xx/3xx, "
                        "чтобы узел считался alive (default: 1).")
    p.add_argument("--final-limit", type=int, default=0,
                   help="Обрез ПОСЛЕ alive-test: топ-N alive по TTFB. 0 = без лимита.")
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

    source_map: dict[str, str] = {}
    if args.source_map and args.source_map.exists():
        try:
            source_map = json.loads(args.source_map.read_text(encoding="utf-8"))
            log(f"[alive] loaded source_map: {len(source_map)} entries")
        except Exception as exc:
            log(f"[alive] source_map load failed: {exc}")

    if args.max_nodes > 0 and len(nodes) > args.max_nodes:
        log(f"[alive] truncating to {args.max_nodes} (--max-nodes)")
        nodes = nodes[:args.max_nodes]

    # IP раннера для проверки утечки (прокси не сменил IP → не работает).
    runner_ip = ""
    try:
        ip_result = subprocess.run(
            ["curl", "-sS", "--max-time", "5", "https://api.ipify.org"],
            capture_output=True, text=True, timeout=10,
        )
        if ip_result.returncode == 0:
            runner_ip = ip_result.stdout.strip()
            log(f"[alive] runner IP: {runner_ip}")
    except Exception:
        log("[alive] WARNING: could not get runner IP")

    log(f"[alive] testing {len(nodes)} nodes with {args.workers} workers "
        f"(probe_timeout={args.head_timeout}s, startup={args.startup_timeout}s, "
        f"max_ttfb={args.max_latency_ms}ms, min_services={args.min_services}, "
        f"runner_ip={runner_ip or 'unknown'})")

    results: dict[str, dict] = {}   # url -> result
    node_by_url = {url: n for n, url in nodes}
    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="sb") as ex:
        futures = {ex.submit(_test_node, n, args.singbox_bin,
                             args.xray_bin if args.xray_bin else None,
                             head_timeout=args.head_timeout,
                             startup_timeout=args.startup_timeout,
                             max_latency_ms=args.max_latency_ms,
                             min_services=args.min_services,
                             runner_ip=runner_ip): url
                   for n, url in nodes}
        done = 0
        for fut in as_completed(futures):
            url = futures[fut]
            node = node_by_url[url]
            done += 1
            try:
                r = fut.result()
            except Exception as exc:
                r = {"host": node.host, "port": node.port, "protocol": node.protocol,
                     "status": "dead", "error": str(exc)}
            results[url] = r

            lat = r.get("latency_ms")
            t = r.get("timings", {}).get("exit_ip", {})
            lat_str = (f"ttfb={lat:.0f}ms c={_fmt_ms(t.get('connect_ms'))} "
                       f"tls={_fmt_ms(t.get('tls_ms'))} tot={_fmt_ms(t.get('total_ms'))}"
                       if lat is not None else "—")
            ip_str = f"ip={r.get('exit_ip', '?')[:15]}" if r.get("exit_ip") else ""
            svc_str = (f"ig={r.get('instagram', '?')} yt={r.get('youtube', '?')} "
                       f"tg={r.get('telegram', '?')}")
            log(f"[alive] {done}/{len(nodes)}: {r['host']}:{r['port']} "
                f"({r['protocol']}) = {r['status']} {lat_str} {ip_str} {svc_str}"
                + (f" {r.get('error', '')[:60]}" if r.get("error") else ""))

    # nodes = [(XrayNode, url), ...] — НОДА ПЕРВОЙ (см. сборку выше).
    # Регрессия v5: раньше здесь было `for url, _ in nodes` — порядок был
    # перепутан, results[<XrayNode>] кидал TypeError: unhashable type
    # 'XrayNode' ПОСЛЕ полного прогона (весь прогон впустую). Фикс: `for _, url`.
    alive_urls = [url for _, url in nodes if results[url]["status"] == "alive"]
    alive_count = len(alive_urls)
    dead_count = len(nodes) - alive_count
    log(f"[alive] done: {alive_count} alive, {dead_count} dead")

    if source_map:
        src_total: dict[str, int] = {}
        src_alive: dict[str, int] = {}
        for n, url in nodes:
            src = source_map.get(url, source_map.get(url.split("#")[0], "?"))
            src_total[src] = src_total.get(src, 0) + 1
            if results[url]["status"] == "alive":
                src_alive[src] = src_alive.get(src, 0) + 1
        log("[alive] source stats (alive/dead/total):")
        for src in sorted(src_total, key=lambda s: -src_alive.get(s, 0)):
            a = src_alive.get(src, 0)
            t = src_total[src]
            log(f"[alive]   {a:4d}/{t:4d} ({a / t * 100:5.1f}%) alive  ← {src}")

    # Топ-N alive по TTFB (latency_ms уже = TTFB exit-IP пробы).
    if args.final_limit > 0 and alive_count > args.final_limit:
        alive_urls.sort(key=lambda u: results[u].get("latency_ms") or 9_999_999)
        alive_urls = alive_urls[:args.final_limit]
        log(f"[alive] FINAL --final-limit: {alive_count} → {args.final_limit} (по TTFB)")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{alive_count} alive nodes | tested: {len(nodes)}\n")
        for url in alive_urls:
            f.write(url + "\n")
    log(f"[alive] wrote {alive_count} alive nodes to {args.output}")

    report = {
        "timestamp": int(time.time()),
        "total_tested": len(nodes),
        "alive": alive_count,
        "dead": dead_count,
        "results": [results[url] for _, url in nodes],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    log(f"[alive] wrote report to {args.report}")

    return 0 if alive_count > 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
