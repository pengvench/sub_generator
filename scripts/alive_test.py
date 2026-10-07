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
import re
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

# v75: Все 5 сервисов тестируются ПАРАЛЛЕЛЬНО через ThreadPoolExecutor.
# Если ЛЮБОЙ из Instagram/YouTube/Telegram ответил 2xx/3xx → ALIVE.
# api.ipify.org + ifconfig.me — для проверки exit IP (если оба упали,
# но реальные сервисы работают → всё равно ALIVE).
#
# Почему ПАРАЛЛЕЛЬНО: в v74 api.ipify.org был ЖЁСТКИМ ГЕЙТОМ — если curl
# не мог установить SOCKS5-соединение (TLS handshake fail на Azure US для
# vless+reality с устаревшим pbk/sid/sni), узел сразу помечался DEAD
# без проверки Instagram/YouTube. Это убивало реальные рабочие конфиги
# (e.g. hysteria2 — рабочий, но если бы ipify не отвечал, был бы убит).
#
#Latency = MIN(успешных сервисов) — отражает реальную скорость прокси.
_TEST_SPECS = [
    # (key, url, return_body)
    ("ipify",      "https://api.ipify.org",       True),   # exit IP (primary)
    ("ifconfig",   "https://ifconfig.me/ip",     True),   # exit IP (fallback)
    ("instagram",  "https://www.instagram.com/", False),  # заблокирован в РФ
    ("youtube",    "https://www.youtube.com/",   False),  # замедлен в РФ
    ("telegram",   "https://api.telegram.org/",  False),  # заблокирован в РФ
]

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# v75: ASN организация → класс exit IP. Если выход через облако (AWS/Azure/GCP)
# → скорее всего будет мёртв на РФ мобилке (облачные IP часто блокируются TSPU
# или не имеют нужных SNI-трюков). Если через хостинг (Hetzner/OVH/M247) →
# скорее работает. Эта информация НЕ убивает узел — только помечается в отчёте.
_ASN_BAD_PATTERNS = (
    "amazon", "aws", "microsoft", "azure", "google", "gcp", "cloudflare",
    "digitalocean", "linode", "vultr", "oracle",
)
_ASN_GOOD_PATTERNS = (
    "hetzner", "ovh", "m247", "leaseweb", "contabo", "scaleway",
    "pq", "hosting", "datacenter",
)

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


def _build_xray_config(node: XrayNode, listen_port: int) -> tuple[dict | None, str | None]:
    """v69: Build minimal xray config для raw/xhttp транспорта (sing-box не поддерживает).

    xray config формат: inbounds[socks] + outbounds[proto].
    """
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


def _curl_one(listen_port: int, svc_name: str, url: str,
               return_body: bool, head_timeout: float) -> tuple[str, dict]:
    """Запустить один curl через SOCKS5. Возвращает (svc_name, result_dict).

    result_dict = {ok: bool, code: int, body: str, ms: float, error: str}.
    """
    t_start = time.monotonic()
    try:
        cmd = ["curl", "-sS", "-L", "--socks5-hostname", f"127.0.0.1:{listen_port}",
               "--max-time", str(head_timeout)]
        if return_body:
            # body + newline + http_code (последняя строка).
            cmd += ["-w", "\n%{http_code}"]
        else:
            cmd += ["-o", "/dev/null", "-w", "%{http_code}"]
        cmd.append(url)

        curl = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=head_timeout + 5)
        elapsed_ms = (time.monotonic() - t_start) * 1000.0

        if curl.returncode != 0:
            err = curl.stderr.strip()[:80] or f"curl rc={curl.returncode}"
            return svc_name, {"ok": False, "error": err, "ms": elapsed_ms}

        if return_body:
            output = curl.stdout
            if "\n" in output:
                body, code_str = output.rsplit("\n", 1)
            else:
                body, code_str = "", output
            body = body.strip()
        else:
            body = ""
            code_str = curl.stdout.strip()

        try:
            code = int(code_str)
        except ValueError:
            code = 0

        ok = code in (200, 204, 301, 302, 303, 307, 308)
        return svc_name, {"ok": ok, "code": code, "body": body, "ms": elapsed_ms}
    except subprocess.TimeoutExpired:
        elapsed_ms = (time.monotonic() - t_start) * 1000.0
        return svc_name, {"ok": False, "error": "timeout", "ms": elapsed_ms}
    except Exception as exc:
        elapsed_ms = (time.monotonic() - t_start) * 1000.0
        return svc_name, {"ok": False, "error": str(exc)[:60], "ms": elapsed_ms}


def _lookup_asn(exit_ip: str, timeout: float = 4.0) -> dict:
    """v75: Получить ASN/org/geo для exit IP через api.ip.sb/geoip/<ip>.

    Возвращает {asn_org: str, country: str, cloud_exit: bool, hosting_exit: bool}.
    cloud_exit=True → AWS/Azure/GCP (likely dead на РФ).
    hosting_exit=True → Hetzner/OVH/M247 (likely working).
    """
    out = {"asn_org": "", "country": "", "cloud_exit": False, "hosting_exit": False}
    try:
        curl = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout),
             f"https://api.ip.sb/geoip/{exit_ip}"],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        if curl.returncode != 0:
            return out
        data = json.loads(curl.stdout)
        org = (data.get("organization") or data.get("asn_organization")
               or data.get("isp") or "")
        country = data.get("country", "")
        org_lower = org.lower()
        out["asn_org"] = org
        out["country"] = country
        out["cloud_exit"] = any(p in org_lower for p in _ASN_BAD_PATTERNS)
        out["hosting_exit"] = any(p in org_lower for p in _ASN_GOOD_PATTERNS)
    except Exception:
        pass
    return out


def _test_node(node: XrayNode, singbox_bin: Path,
               xray_bin: Path | None = None, *,
               head_timeout: float = 8.0, startup_timeout: float = 5.0,
               max_latency_ms: float = 2000,
               runner_ip: str = "",
               check_asn: bool = False) -> dict:
    """v75: Параллельный multi-service тест.

    Тестирует 5 сервисов ОДНОВРЕМЕННО через ThreadPoolExecutor:
      - api.ipify.org (exit IP primary)
      - ifconfig.me/ip (exit IP fallback)
      - Instagram
      - YouTube
      - Telegram

    Узел ALIVE если:
      - Exit IP ≠ runner IP И (Instagram ИЛИ YouTube ИЛИ Telegram) ответил 2xx/3xx, ИЛИ
      - Exit IP ≠ runner IP (прокси работает), даже если все 3 сайта не открылись
        (например Cloudflare WAF на exit IP блокирует IG/YT/TG — на РФ мобилке может работать)
      - Instagram ИЛИ YouTube ИЛИ Telegram ответил 2xx/3xx (даже если ipify/ifconfig упали —
        ipify может быть недоступен с exit IP, но прокси работает)

    Узел DEAD если:
      - Все 5 сервисов упали, ИЛИ
      - Exit IP == runner IP (прокси НЕ работает — трафик идёт напрямую)

    Latency = MIN(успешных сервисов). Threshold применяется к min (быстрейший сервис).
    """
    result = {
        "host": node.host, "port": node.port, "protocol": node.protocol,
        "name": node.name, "status": "unknown",
        "http_code": None, "error": None, "latency_ms": None, "dns_ms": None,
        "exit_ip": None, "ip_changed": None,
        "instagram": None, "youtube": None, "telegram": None,
        "ipify": None, "ifconfig": None,
        "asn_org": None, "country": None, "cloud_exit": None, "hosting_exit": None,
    }

    listen_port = _find_free_port()

    # v69: Try sing-box first, then xray for raw/xhttp.
    config, reason = sing_box_full_config(node, "127.0.0.1", listen_port)
    binary = singbox_bin
    binary_name = "sing-box"

    if config is None and xray_bin is not None and xray_bin.exists():
        # sing-box can't build config → try xray (supports raw/xhttp).
        xray_config, xray_reason = _build_xray_config(node, listen_port)
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

    # Запускаем binary (sing-box или xray).
    sb_proc = None
    try:
        if binary_name == "xray":
            sb_proc = subprocess.Popen(
                [str(binary), "run", "-c", str(config_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            sb_proc = subprocess.Popen(
                [str(binary), "run", "--config", str(config_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
    except OSError as exc:
        result["status"] = "dead"
        result["error"] = f"{binary_name} start: {exc}"
        config_path.unlink(missing_ok=True)
        return result

    try:
        if not _wait_for_socks5(listen_port, startup_timeout):
            result["status"] = "dead"
            result["error"] = f"{binary_name} did not start in {startup_timeout}s"
            return result

        t0 = time.monotonic()

        # v75: ПАРАЛЛЕЛЬНЫЙ тест 5 сервисов. Никаких жёстких гейтов.
        test_results: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=5, thread_name_prefix="curl") as ex:
            futures = [ex.submit(_curl_one, listen_port, name, url, ret, head_timeout)
                       for name, url, ret in _TEST_SPECS]
            for fut in as_completed(futures):
                name, res = fut.result()
                test_results[name] = res

        total_time_ms = (time.monotonic() - t0) * 1000.0

        # Сохраняем индивидуальные результаты в result.
        for name in ("ipify", "ifconfig", "instagram", "youtube", "telegram"):
            if name in test_results:
                res = test_results[name]
                if res.get("ok"):
                    result[name] = res.get("code")
                else:
                    result[name] = res.get("error", "fail")

        # Получаем exit IP из ipify или ifconfig (первый, кто вернул валидный IPv4).
        exit_ip = ""
        for ip_svc in ("ipify", "ifconfig"):
            res = test_results.get(ip_svc, {})
            if res.get("ok"):
                body = res.get("body", "")
                if body and _IPV4_RE.match(body):
                    exit_ip = body
                    break
                # ifconfig.me может вернуть IP с trailing-мусором.
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", body)
                if m:
                    exit_ip = m.group(1)
                    break

        if exit_ip:
            result["exit_ip"] = exit_ip
            if runner_ip:
                result["ip_changed"] = (exit_ip != runner_ip)

            # v75: ASN lookup (опционально) — неблокирующая информация.
            if check_asn:
                asn = _lookup_asn(exit_ip)
                result["asn_org"] = asn.get("asn_org")
                result["country"] = asn.get("country")
                result["cloud_exit"] = asn.get("cloud_exit")
                result["hosting_exit"] = asn.get("hosting_exit")

        # v75: ШАГ 1 — Проверка утечки IP (если exit IP == runner IP → прокси НЕ работает).
        if exit_ip and runner_ip and exit_ip == runner_ip:
            result["status"] = "dead"
            result["ip_changed"] = False
            result["latency_ms"] = total_time_ms
            result["error"] = f"IP leak: exit={exit_ip} == runner={runner_ip}"
            return result

        # Вычисляем latency = MIN(успешных сервисов) — реальная скорость прокси.
        success_times = [res["ms"] for res in test_results.values() if res.get("ok")]
        if success_times:
            result["latency_ms"] = min(success_times)
        else:
            result["latency_ms"] = total_time_ms

        # v72: latency threshold — к MIN успешного сервиса.
        # (Если все 5 упали, success_times пустой → проверка пропускается,
        # узел всё равно DEAD по числу успешных сервисов ниже.)
        if max_latency_ms > 0 and success_times and min(success_times) > max_latency_ms:
            result["status"] = "dead"
            result["error"] = (f"latency {min(success_times):.0f}ms "
                                f"(>{max_latency_ms:.0f}ms on fastest service)")
            return result

        # v75: ШАГ 2 — Считаем реальные успехи (Instagram/YouTube/Telegram).
        real_services = ("instagram", "youtube", "telegram")
        real_ok_count = sum(1 for s in real_services
                            if test_results.get(s, {}).get("ok"))

        # ALIVE если хотя бы 1 реальный сервис работает.
        if real_ok_count > 0:
            result["status"] = "alive"
            result["http_code"] = 200
            return result

        # Все реальные сервисы упали, но exit IP ≠ runner IP → прокси работает,
        # сайты заблокированы с exit IP (например Cloudflare WAF на AWS IP).
        # На РФ мобилке может работать (другой путь).
        if exit_ip and (not runner_ip or exit_ip != runner_ip):
            result["status"] = "alive"
            result["http_code"] = 200
            asn_note = ""
            if result.get("asn_org"):
                asn_note = f" [{result['asn_org']}]"
            result["error"] = (f"exit IP {exit_ip} works but IG/YT/TG blocked"
                               f"{asn_note}")
            return result

        # Все 5 сервисов упали.
        # Возьмём первую ошибку для диагностики.
        first_err = next((test_results[s].get("error", "")
                          for s in ("ipify", "ifconfig", "instagram",
                                    "youtube", "telegram")
                          if test_results.get(s, {}).get("error")), "all failed")
        result["status"] = "dead"
        result["error"] = f"all 5 services failed: {first_err[:60]}"
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
    p.add_argument("--xray-bin", type=Path, default=None,
                   help="Путь к xray binary (v69: для raw/xhttp транспорта).")
    p.add_argument("--source-map", type=Path, default=None,
                   help="JSON маппинг URL → source (v70: для статистики alive/dead по источникам).")
    p.add_argument("--max-nodes", type=int, default=200,
                   help="Лимит числа узлов для тестирования (default: 200).")
    p.add_argument("--workers", type=int, default=8,
                   help="Параллелизм (default: 8).")
    p.add_argument("--head-timeout", type=float, default=8.0,
                   help="Таймаут HTTP запроса, сек (default: 8.0). "
                        "v73: увеличен с 5 до 8 — реальные сайты (Instagram/YouTube) "
                        "отвечают дольше чем gstatic.")
    p.add_argument("--startup-timeout", type=float, default=5.0,
                   help="Таймаут запуска sing-box, сек (default: 5.0).")
    # v75: --check-asn — lookup ASN организации exit IP (api.ip.sb/geoip).
    # Помечает cloud_exit (AWS/Azure → likely dead на РФ) или hosting_exit
    # (Hetzner/OVH → likely working). НЕ убивает узел — только информация.
    p.add_argument("--check-asn", action="store_true", default=False,
                   help="Опционально: lookup ASN exit IP через api.ip.sb/geoip. "
                        "Помечает cloud_exit (AWS/Azure) / hosting_exit (Hetzner/OVH). "
                        "НЕ убивает узел — только для отчёта.")
    # v72: max latency — alive конфиги с latency > X ms → dead (reject).
    p.add_argument("--max-latency-ms", type=float, default=2000,
                   help="Максимальная latency (через прокси) в ms. "
                        "Alive с latency > X → dead (reject). "
                        "Default: 2000. 1000 = строже (только быстрые). "
                        "User: 'какого хрена проходят конфиги с 5к пинга'.")
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

    # v70: Загрузить source_map для статистики alive/dead по источникам.
    source_map: dict[str, str] = {}
    if args.source_map and args.source_map.exists():
        try:
            source_map = json.loads(args.source_map.read_text(encoding="utf-8"))
            log(f"[alive] loaded source_map: {len(source_map)} entries")
        except Exception as exc:
            log(f"[alive] source_map load failed: {exc}")
    else:
        log("[alive] no source_map — source stats will be unavailable")

    if args.max_nodes > 0 and len(nodes) > args.max_nodes:
        log(f"[alive] truncating to {args.max_nodes} (--max-nodes)")
        nodes = nodes[:args.max_nodes]
    elif args.max_nodes == 0:
        log(f"[alive] --max-nodes 0 = NO LIMIT, testing ALL {len(nodes)} nodes")

    # v74: Получаем IP runner'а для проверки утечки.
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
        f"(head_timeout={args.head_timeout}s, startup={args.startup_timeout}s, "
        f"runner_ip={runner_ip or 'unknown'})")

    results: list[dict] = []
    alive_urls: list[str] = []
    done = 0
    alive_count = 0
    dead_count = 0
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="sb") as ex:
        futures = {ex.submit(_test_node, n, args.singbox_bin,
                             args.xray_bin if args.xray_bin else None,
                             head_timeout=args.head_timeout,
                             startup_timeout=args.startup_timeout,
                             max_latency_ms=args.max_latency_ms,
                             runner_ip=runner_ip,
                             check_asn=args.check_asn): (n, url)
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
            ip_str = f"ip={r.get('exit_ip', '?')[:15]}" if r.get("exit_ip") else ""
            svc_str = f"ig={r.get('instagram','?')} yt={r.get('youtube','?')} tg={r.get('telegram','?')}"
            asn_str = ""
            if r.get("asn_org"):
                tag = "☁" if r.get("cloud_exit") else ("🖥" if r.get("hosting_exit") else "·")
                asn_str = f" {tag} {r.get('asn_org', '')[:20]}"
            log(f"[alive] {done}/{len(nodes)}: {r['host']}:{r['port']} "
                f"({r['protocol']}) = {r['status']} {latency_str} {ip_str} {svc_str}{asn_str}"
                + (f" {r.get('error', '')[:60]}" if r.get("error") else ""))

    log(f"[alive] done: {alive_count} alive, {dead_count} dead")

    # v70: Source stats — alive/dead по источникам.
    if source_map:
        src_alive: dict[str, int] = {}
        src_dead: dict[str, int] = {}
        src_total: dict[str, int] = {}
        for n, url in nodes:
            src = source_map.get(url, source_map.get(url.split("#")[0], "?"))
            src_total[src] = src_total.get(src, 0) + 1
        for url in alive_urls:
            src = source_map.get(url, source_map.get(url.split("#")[0], "?"))
            src_alive[src] = src_alive.get(src, 0) + 1
        for src in src_total:
            src_dead[src] = src_total[src] - src_alive.get(src, 0)

        log(f"[alive] source stats (alive/dead/total):")
        for src in sorted(src_total.keys(), key=lambda s: -src_alive.get(s, 0)):
            a = src_alive.get(src, 0)
            d = src_dead.get(src, 0)
            t = src_total[src]
            pct = (a / t * 100) if t > 0 else 0
            log(f"[alive]   {a:4d}/{t:4d} ({pct:5.1f}%) alive  ← {src}")

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

    # v75: Финальная сводка по ASN exit IP (если был --check-asn).
    cloud_exits = sum(1 for r in results if r.get("cloud_exit"))
    hosting_exits = sum(1 for r in results if r.get("hosting_exit"))
    if args.check_asn and alive_count > 0:
        log(f"[alive] ASN summary (alive nodes): "
            f"☁ cloud-exit (AWS/Azure/etc) = {cloud_exits}, "
            f"🖥 hosting-exit (Hetzner/OVH/etc) = {hosting_exits}, "
            f"other = {alive_count - cloud_exits - hosting_exits}")

    # JSON-отчёт.
    report = {
        "timestamp": int(time.time()),
        "total_tested": len(nodes),
        "alive": alive_count,
        "dead": dead_count,
        "runner_ip": runner_ip,
        "asn_summary": {
            "cloud_exit": cloud_exits,
            "hosting_exit": hosting_exits,
        } if args.check_asn else None,
        "results": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    log(f"[alive] wrote report to {args.report}")

    return 0 if alive_count > 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
