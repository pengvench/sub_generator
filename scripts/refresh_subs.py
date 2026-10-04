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
import re
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


# RFC 1035: метка DNS-имени — 1..63 символа, всё имя — 1..253 символа.
# На практике в подписках встречается мусор: метки > 63 символов, пустые
# метки (a..b.com), недопустимые символы (подчёркивание в hostname). Такие
# имена вызывают UnicodeError ВНУТРИ socket.create_connection → getaddrinfo
# → encodings.idna.ToASCII — это ValueError, не OSError, поэтому обычный
# except (OSError, ...) его НЕ ловит. См. инцидент 2026-09-29 в GHA:
# 25853 узлов, 12825 пропинговано, потом падение на невалидном hostname.
_DNS_LABEL_MAX_LEN = 63
_DNS_NAME_MAX_LEN = 253

# Метка DNS: буквы/цифры/дефис, не начинается и не заканчивается дефисом.
# Регистронезависимо (RFC 1035). Допускаем underscore для редких паблик-узлов
# (это не по RFC, но встречается) — пинг всё равно их разрезолвит через
# не-IDNA путь.
_DNS_LABEL_RE = re.compile(r"^[a-zA-Z0-9_](?:[a-zA-Z0-9_-]*[a-zA-Z0-9_])?$")

# IPv4: четыре октета 0..255 через точку.
_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$")


def _is_valid_hostname(host: str) -> bool:
    """Проверка, что host — валидное DNS-имя или IP.

    Отсекает мусор, который вызывает UnicodeError в IDNA-кодировании внутри
    socket.create_connection: метки длиннее 63 символов, пустые метки
    (последовательные точки), недопустимые символы.

    Возвращает True для: IPv4 (4 октета), IPv6 (содержит ':'), валидное
    DNS-имя (≤253 символа, метки 1..63 из [a-zA-Z0-9_-]).
    """
    if not host or not isinstance(host, str):
        return False
    host = host.strip().rstrip(".")
    if not host:
        return False
    # IPv4 — без IDNA, валидируем регуляркой.
    if _IPV4_RE.match(host):
        return True
    # IPv6 — содержит ':', валидируем как есть (с или без скобок).
    if ":" in host:
        return True
    # DNS-имя: лимит длины.
    if len(host) > _DNS_NAME_MAX_LEN:
        return False
    labels = host.split(".")
    if not labels:
        return False
    for label in labels:
        if not label or len(label) > _DNS_LABEL_MAX_LEN:
            return False
        if not _DNS_LABEL_RE.match(label):
            return False
    return True


def _tcp_ping(node: XrayNode, timeout: float) -> tuple[bool, float]:
    """Быстрый TCP-ping. True если удалось подключиться за timeout сек.

    НЕ запускает xray — это просто socket.connect() с таймаутом. Дешёвый
    фильтр мёртвых узлов (TCP RST / timeout / DNS-fail / IDNA-fail).
    Реальная проверка работы узла требует xray.exe (только Windows), её тут нет.
    """
    host = (node.host or "").strip()
    port = int(node.port or 0)
    if not host or port <= 0:
        return False, 0.0
    # Санитизация host ДО DNS-запроса: IDNA-некорректные имена (метка > 63,
    # пустые метки a..b.com, недопустимые символы) вызывают UnicodeError из
    # encodings.idna ВНУТРИ socket.create_connection. Это ValueError, не
    # OSError — except (OSError, ...) не ловит. Отбраковываем на старте.
    if not _is_valid_hostname(host):
        return False, 0.0
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.monotonic() - t0)
    except Exception:
        # Любая ошибка (OSError, TimeoutError, gaierror, herror, UnicodeError
        # от IDNA, ValueError, ConnectionRefusedError, ...) — узел недоступен.
        # Широкое except OK для ping-фильтра: мы НЕ логируем каждую ошибку
        # (их будут тысячи), только возвращаем «не прошёл».
        return False, 0.0


def _ping_filter(nodes: list[XrayNode], *, timeout: float, workers: int,
                 log_sink, max_nodes: int = 0,
                 max_ping_ms: float = 0) -> list[XrayNode]:
    """Пропинговать узлы параллельно, оставить только живые + быстрые.

    max_nodes > 0: пингуем только первые max_nodes (после BS-sort'а).
        v44: НЕЛЬЗЯ использовать — отбрасывает 198k узлов из 200k!
        По умолчанию 0 = без лимита, пингуем ВСЕ узлы.
    max_ping_ms > 0: отбраковываем узлы с latency > max_ping_ms (FakeDNS/медленные).
    Возвращает список, отсортированный по latency (быстрые первыми).
    """
    # v44: --max-ping-nodes ОПАСЕН — обрезает список ДО пинга, непингованные
    # узлы просто теряются. Если юзер явно не передал лимит — пингуем ВСЕ.
    # При огромных списках (200k узлов × 1.5с / 64 workers = ~78 мин) это ОК.
    if max_nodes > 0 and len(nodes) > max_nodes:
        log_sink(f"[gha] WARNING: --max-ping-nodes truncating ping list: "
                 f"{len(nodes)} → {max_nodes}. Неотпингованные {len(nodes) - max_nodes} "
                 f"узлов БУДУТ ПОТЕРЯНЫ. Уберите --max-ping-nodes или поставьте 0.")
        nodes = nodes[:max_nodes]
    # tuple (node, latency_ms or None if dead)
    pinged: list[tuple[XrayNode, float | None]] = []
    lock = threading.Lock()
    done = 0
    total = len(nodes)
    skipped_bad_host = 0
    slow_filtered = 0

    def probe(node: XrayNode) -> tuple[XrayNode, float | None]:
        ok, latency = _tcp_ping(node, timeout)
        return node, latency if ok else None

    with ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="ping") as ex:
        futures = {ex.submit(probe, n): n for n in nodes}
        for fut in as_completed(futures):
            done += 1
            node, latency = fut.result()
            with lock:
                if latency is not None:
                    if max_ping_ms > 0 and latency > max_ping_ms:
                        slow_filtered += 1
                    else:
                        pinged.append((node, latency))
                else:
                    if not _is_valid_hostname((node.host or "").strip()):
                        skipped_bad_host += 1
            if done % 25 == 0 or done == total:
                alive_count = len(pinged)
                log_sink(f"[gha] ping progress {done}/{total} ({alive_count} alive"
                         + (f", {slow_filtered} slow (>{max_ping_ms}ms)" if max_ping_ms > 0 else "")
                         + (f", {skipped_bad_host} bad-host" if skipped_bad_host else "")
                         + ")")

    # Сортируем по latency (быстрые первыми).
    pinged.sort(key=lambda x: x[1] if x[1] is not None else float('inf'))

    # Логируем статистику latency.
    if pinged:
        latencies = [l for _, l in pinged if l is not None]
        if latencies:
            lat_sorted = sorted(latencies)
            p50 = lat_sorted[len(lat_sorted) // 2]
            p95 = lat_sorted[int(len(lat_sorted) * 0.95)] if len(lat_sorted) > 1 else lat_sorted[0]
            p100 = lat_sorted[-1]
            log_sink(f"[gha] ping stats: p50={p50:.0f}ms p95={p95:.0f}ms max={p100:.0f}ms "
                     f"({len(pinged)} alive"
                     + (f", {slow_filtered} slow filtered (>{max_ping_ms}ms)" if max_ping_ms > 0 and slow_filtered > 0 else "")
                     + ")")
            # Топ-5 самых быстрых.
            for n, l in pinged[:3]:
                log_sink(f"[gha]   fastest: {l:.0f}ms  {n.host}:{n.port}  sni={n.query.get('sni', '')}")

    return [n for n, _ in pinged]


# ---------------------------------------------------------------------- geo

# Кеш IP → (country_code, flag) для geo-переименования.
# Сильная дедупликация: 10000 узлов на ~5 уникальных CDN-IP = 5 запросов вместо 10k.
_geo_cache: dict[str, tuple[str, str]] = {}
_geo_cache_lock = threading.Lock()

# fallback если api.ip.sb недоступен / rate-limit / невалидный IP.
_GEO_FALLBACK_CODE = "??"
_GEO_FALLBACK_FLAG = "🏳"


# v48b: Региональные indicator-символы для emoji-флагов.
# U+1F1E6 = 'A' (regional indicator A), U+1F1FF = 'Z'.
# Emoji-флаг = 2 таких символа → "🇩🇪" → "DE".
_REGIONAL_INDICATOR_A = 0x1F1E6


def _extract_flag_from_name(name: str) -> tuple[str, str] | None:
    """Извлечь emoji-флаг из имени узла, вернуть (flag, iso_code) или None.

    Emoji-флаг = 2 региональных indicator-символа (U+1F1E6..U+1F1FF).
    Например "🇩🇪" = U+1F1E9 + U+1F1EA = 'D' + 'E' → "DE".

    Используется когда api.ip.sb НЕ смог определить страну (DNS-resolve
    fail для РФ-доменов на Azure US). Берём флаг из оригинального имени
    (например "Литва 🇱🇹" → 🇱🇹 → "LT") → итоговое имя "🇱🇹 LT peppo".
    """
    if not name:
        return None
    # Ищем первый regional indicator символ в имени.
    for i, ch in enumerate(name):
        if _REGIONAL_INDICATOR_A <= ord(ch) <= _REGIONAL_INDICATOR_A + 25:
            # Это 'A'-'Z' regional indicator.
            # Проверим что следующий символ тоже regional indicator.
            if i + 1 < len(name):
                next_ch = name[i + 1]
                if _REGIONAL_INDICATOR_A <= ord(next_ch) <= _REGIONAL_INDICATOR_A + 25:
                    # Нашли emoji-флаг! Переводим в ISO код.
                    iso = (chr(ord(ch) - _REGIONAL_INDICATOR_A + ord('A'))
                           + chr(ord(next_ch) - _REGIONAL_INDICATOR_A + ord('A')))
                    return (ch + next_ch, iso)
    return None


def _resolve_host_to_ip(host: str, timeout: float = 3.0) -> str:
    """Разрезолвить hostname в IPv4. Если уже IP — вернуть как есть.

    Используется для geo-lookup'а: api.ip.sb/geoip/<IP> принимает только IP,
    не домен. Для доменов делаем DNS-resolve через socket.getaddrinfo.
    """
    host = (host or "").strip()
    if not host:
        return ""
    # Если уже IPv4 — возвращаем как есть.
    try:
        import ipaddress
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass
    # Домен — резолвим в IPv4.
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        for family, _type, _proto, _canon, sockaddr in results:
            if family == socket.AF_INET:
                return sockaddr[0]
    except Exception:
        pass
    return ""


def _geoip_lookup_ip(ip: str, timeout: float = 8.0) -> tuple[str, str]:
    """Гео IP через https://api.ip.sb/geoip/<IP>. Возвращает (code, flag).

    Кеш — словарь _geo_cache (см. выше), без TTL (однократный запуск).
    На unreachable/rate-limit — fallback (??, 🏳).
    """
    ip = (ip or "").strip()
    if not ip:
        return _GEO_FALLBACK_CODE, _GEO_FALLBACK_FLAG
    with _geo_cache_lock:
        cached = _geo_cache.get(ip)
    if cached is not None:
        return cached
    # Импортируем здесь, чтоб subgen.geo не тащился при выключенном --geo-rename.
    try:
        from subgen.geo import geoip_lookup, GEOIP_FALLBACK_CODE, GEOIP_FALLBACK_FLAG
    except ImportError:
        return _GEO_FALLBACK_CODE, _GEO_FALLBACK_FLAG
    try:
        code, flag = geoip_lookup(ip, timeout=timeout)
    except Exception:
        code, flag = GEOIP_FALLBACK_CODE, GEOIP_FALLBACK_FLAG
    with _geo_cache_lock:
        _geo_cache[ip] = (code, flag)
    return code, flag


def _geo_rename_nodes(nodes: list[XrayNode], *, workers: int, timeout: float,
                      log_sink) -> None:
    """Переименовать узлы как основное приложение: «<флаг> <ISO> peppo».

    ВХОД: список XrayNode (mutates node.name + node.raw_url).
    Гео берётся через api.ip.sb/geoip/<IP> для host узла (IP берётся напрямую,
    для домена — DNS-resolve). Кеш по IP — до 10000 узлов делают ~5000 запросов
    (IP дублируются у CDN-узлов).

    Имя формата: «🇩🇪 DE peppo» (с пробелом перед peppo, как в serialize_working).
    На fallback (geo недоступно): «🏳 ?? peppo».
    """
    if not nodes:
        return
    # Ленивый импорт set_node_name — не тащим subgen.geo при выключенном --geo-rename.
    try:
        from subgen.geo import set_node_name
    except ImportError as exc:
        log_sink(f"[gha] --geo-rename: FAILED to import set_node_name: {exc}")
        return
    log_sink(f"[gha] --geo-rename: looking up geo for {len(nodes)} nodes "
             f"(workers={workers}, timeout={timeout}s)")

    # Собираем уникальные хосты → IP (для кеширования DNS-resolve).
    host_to_ip: dict[str, str] = {}
    unique_hosts = {n.host for n in nodes if n.host}
    log_sink(f"[gha] --geo-rename: {len(unique_hosts)} unique hosts to resolve")

    # Резолвим домены параллельно (IP-хосты проходят instantly).
    def _resolve_one(host: str) -> tuple[str, str]:
        return host, _resolve_host_to_ip(host, timeout=min(3.0, timeout))

    resolved_count = 0
    failed_resolve = 0
    with ThreadPoolExecutor(max_workers=max(4, workers), thread_name_prefix="dns") as ex:
        futures = {ex.submit(_resolve_one, h): h for h in unique_hosts}
        for fut in as_completed(futures):
            host, ip = fut.result()
            host_to_ip[host] = ip
            resolved_count += 1
            if not ip:
                failed_resolve += 1
            if resolved_count % 50 == 0 or resolved_count == len(unique_hosts):
                log_sink(f"[gha] --geo-rename: DNS-resolve progress "
                         f"{resolved_count}/{len(unique_hosts)} ({failed_resolve} failed)")
    log_sink(f"[gha] --geo-rename: DNS done, {len(unique_hosts) - failed_resolve} resolved, "
             f"{failed_resolve} failed")

    # Уникальные IP → geo lookup (кеш api.ip.sb).
    unique_ips = {ip for ip in host_to_ip.values() if ip}
    log_sink(f"[gha] --geo-rename: looking up {len(unique_ips)} unique IPs")

    # Для каждого IP делаем запрос к api.ip.sb/geoip/<IP>.
    # Лимит параллелизма — 8 (api.ip.sb может rate-limit'ить).
    # Кеш внутри geoip_lookup() — повторные IP берутся из кеша мгновенно.
    geo_done = 0
    geo_failed = 0
    with ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="geoip") as ex:
        futures = {ex.submit(_geoip_lookup_ip, ip, timeout): ip for ip in unique_ips}
        for fut in as_completed(futures):
            try:
                _code, _flag = fut.result()
                geo_done += 1
            except Exception:
                geo_failed += 1
            if geo_done % 25 == 0 or geo_done == len(unique_ips):
                log_sink(f"[gha] --geo-rename: geoip progress {geo_done}/{len(unique_ips)} "
                         f"({geo_failed} failed)")
    log_sink(f"[gha] --geo-rename: geoip done, {geo_done} ok, {geo_failed} failed")

    # Переименовываем узлы.
    # v48b: ВСЕ узлы получают "peppo" формат. Если api.ip.sb определил страну —
    # "🇩🇪 DE peppo". Если НЕ определил (DNS-resolve fail для РФ-доменов на Azure
    # US, или api.ip.sb rate-limit) — извлекаем emoji-флаг из оригинального имени
    # (например "Литва 🇱🇹" → 🇱🇹 → "LT") → итоговое имя "🇱🇹 LT peppo".
    # Если в имени флага нет → настоящий fallback "🏳 ?? peppo".
    renamed_count = 0
    fallback_count = 0
    flag_from_name_count = 0
    real_fallback_count = 0
    for node in nodes:
        host = (node.host or "").strip()
        ip = host_to_ip.get(host, "") if host else ""
        code, flag = _GEO_FALLBACK_CODE, _GEO_FALLBACK_FLAG

        if host and ip:
            code, flag = _geoip_lookup_ip(ip, timeout=timeout)

        if code != _GEO_FALLBACK_CODE and code != "??":
            # api.ip.sb определил страну → "🇩🇪 DE peppo".
            new_name = f"{flag} {code} peppo"
            renamed_count += 1
        else:
            # v48b: api.ip.sb fail. Пытаемся извлечь флаг из оригинального
            # имени узла (например "Литва 🇱🇹" → 🇱🇹 → "LT").
            extracted = _extract_flag_from_name(node.name)
            if extracted:
                flag_extracted, iso_extracted = extracted
                new_name = f"{flag_extracted} {iso_extracted} peppo"
                flag_from_name_count += 1
            else:
                # Даже в имени нет флага → настоящий fallback.
                new_name = f"{_GEO_FALLBACK_FLAG} {_GEO_FALLBACK_CODE} peppo"
                real_fallback_count += 1
            fallback_count += 1
        # set_node_name перестраивает raw_url: для vless/trojan/ss — фрагмент #,
        # для vmess — поле ps в JSON. Тот же код, что в основном приложении.
        set_node_name(node, new_name)

    log_sink(f"[gha] --geo-rename: {renamed_count} renamed (api.ip.sb), "
             f"{flag_from_name_count} from name (flag extracted), "
             f"{real_fallback_count} real fallback (no flag)")


# ---------------------------------------------------------------------- known-good

# Кеш known-good паттернов: SNI set + IP /N subnets set.
# Строится ОДИН раз из data/known_good.txt, потом переиспользуется.
_KNOWN_GOOD_SNI: set[str] | None = None
_KNOWN_GOOD_IPS: set[str] | None = None  # network strings like "1.2.3.0/24"
_KNOWN_GOOD_NODES: list[XrayNode] | None = None  # parsed configs from known_good.txt


def _load_known_good(path: Path) -> tuple[set[str], set[str], list[XrayNode]]:
    """Загрузить known_good.txt, извлечь SNI set + IP /24 set + список узлов.

    Возвращает (sni_set, ip_subnet_set, known_good_nodes).
    Если файла нет — возвращает (set(), set(), []).
    """
    global _KNOWN_GOOD_SNI, _KNOWN_GOOD_IPS, _KNOWN_GOOD_NODES
    if _KNOWN_GOOD_SNI is not None and _KNOWN_GOOD_IPS is not None and _KNOWN_GOOD_NODES is not None:
        return _KNOWN_GOOD_SNI, _KNOWN_GOOD_IPS, _KNOWN_GOOD_NODES

    sni_set: set[str] = set()
    ip_subnet_set: set[str] = set()
    nodes: list[XrayNode] = []

    if not path or not path.is_file():
        _KNOWN_GOOD_SNI, _KNOWN_GOOD_IPS, _KNOWN_GOOD_NODES = sni_set, ip_subnet_set, nodes
        return sni_set, ip_subnet_set, nodes

    # Ленивый импорт — refresh_subs.py не должен тянуть runtime на старте.
    sys.path.insert(0, str(REPO / "python"))
    from runtime.parse import parse_node_link, _node_links_from_text

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        _logger.warning("[gha] known_good.txt read failed: %s", exc)
        _KNOWN_GOOD_SNI, _KNOWN_GOOD_IPS, _KNOWN_GOOD_NODES = sni_set, ip_subnet_set, nodes
        return sni_set, ip_subnet_set, nodes

    # Извлекаем URL из known_good.txt (plain text, как preload.txt).
    raw_urls = _node_links_from_text(text)
    for url in raw_urls:
        try:
            node = parse_node_link(url)
        except Exception:
            continue
        if node is None:
            continue
        nodes.append(node)
        # SNI: query.sni или query.host (как в sni_category.node_sni).
        sni = (node.query.get("sni") or node.query.get("host") or "").strip().lower()
        if sni:
            sni_set.add(sni)
        # IP-подсеть: host это IPv4 → берём /24 (или /N по known_good_ip_prefix).
        host = (node.host or "").strip()
        try:
            import ipaddress
            ip = ipaddress.IPv4Address(host)
            # /24 по умолчанию — но cached без prefix, prefix applied at filter time.
            ip_subnet_set.add(str(ip))
        except (ValueError, TypeError):
            pass  # domain — не можем извлечь IP без DNS-resolve

    _KNOWN_GOOD_SNI, _KNOWN_GOOD_IPS, _KNOWN_GOOD_NODES = sni_set, ip_subnet_set, nodes
    return sni_set, ip_subnet_set, nodes


def _node_matches_known_good(node: XrayNode, sni_set: set[str], ip_set: set[str],
                             *, ip_prefix: int = 24,
                             mode: str = "sni_or_ip") -> bool:
    """Проверить, похож ли узел на known-good (по SNI и/или IP).

    mode:
      "sni"        — SNI узла в sni_set → True.
      "ip"         — IP узла в той же /24 (или /N) что и known-good → True.
      "sni_or_ip"  — ИЛИ (default).
      "sni_and_ip" — И (строгий).
      "none"       — всегда True (фильтр выключен, только append known_good).
    """
    if mode == "none":
        return True

    sni_match = False
    ip_match = False

    if mode in ("sni", "sni_or_ip", "sni_and_ip"):
        sni = (node.query.get("sni") or node.query.get("host") or "").strip().lower()
        if sni and sni in sni_set:
            sni_match = True

    if mode in ("ip", "sni_or_ip", "sni_and_ip"):
        host = (node.host or "").strip()
        try:
            import ipaddress
            ip = ipaddress.IPv4Address(host)
            # Сравниваем подсеть host'а с known-good IP в той же /prefix.
            host_net = ipaddress.IPv4Network(f"{host}/{ip_prefix}", strict=False)
            for known_ip_str in ip_set:
                known_net = ipaddress.IPv4Network(f"{known_ip_str}/{ip_prefix}", strict=False)
                if host_net == known_net:
                    ip_match = True
                    break
        except (ValueError, TypeError):
            pass  # host — домен, не IP

    if mode == "sni":
        return sni_match
    if mode == "ip":
        return ip_match
    if mode == "sni_or_ip":
        return sni_match or ip_match
    if mode == "sni_and_ip":
        return sni_match and ip_match
    return True


def _apply_known_good_filter(nodes: list[XrayNode], path: Path, *,
                             mode: str, ip_prefix: int,
                             log_sink) -> tuple[list[XrayNode], list[XrayNode]]:
    """Применить known-good фильтр + извлечь known_good узлы для APPEND.

    Возвращает (filtered_nodes, known_good_nodes_to_append).
    filtered_nodes — узлы из входа, прошедшие фильтр.
    known_good_nodes_to_append — узлы из known_good.txt (для append в preload).
    """
    sni_set, ip_set, kg_nodes = _load_known_good(path)

    if not kg_nodes:
        log_sink(f"[gha] --known-good: {path} not found or empty — skipping filter")
        return nodes, []

    log_sink(f"[gha] --known-good: loaded {len(kg_nodes)} verified configs, "
             f"{len(sni_set)} unique SNIs, {len(ip_set)} unique IPs (mode={mode}, "
             f"ip_prefix=/{ip_prefix})")
    log_sink(f"[gha] --known-good: top 5 SNIs: {sorted(sni_set)[:5]}")
    log_sink(f"[gha] --known-good: top 5 IPs: {sorted(ip_set)[:5]}")

    if mode == "none":
        log_sink(f"[gha] --known-good: mode=none, filter disabled, "
                 f"{len(kg_nodes)} known-good configs will be appended")
        return nodes, kg_nodes

    before = len(nodes)
    filtered = [n for n in nodes if _node_matches_known_good(
        n, sni_set, ip_set, ip_prefix=ip_prefix, mode=mode)]
    log_sink(f"[gha] --known-good filter: {before} → {len(filtered)} (mode={mode})")
    return filtered, kg_nodes


# ---------------------------------------------------------------------- pattern scoring

# v37: Pattern-based scoring — замена xray-ping для GHA.
# Вместо тестирования "работает ли отсюда" (бесполезно — GHA не на мобильной сети),
# оцениваем "насколько конфиг похож на known_good" (проверенные на мобилке).
# Score 0-100+, threshold 40 по умолчанию.

# Кеш паттернов из known_good.txt.
_KG_PATTERNS: dict | None = None


def _load_known_good_patterns(path: Path) -> dict:
    """Извлечь pattern features из known_good.txt для scoring'а.

    Возвращает dict с:
      sni_set: set[str] — все уникальные SNI
      sni_tld_set: set[str] — second-level domains (promokod.com → {promokod.com})
      ip_subnets: set[str] — IP строки для /24 сравнения
      host_suffixes: set[str] — суффиксы доменов (test-cdn-kkk.com)
      proto_security: set[str] — "{protocol}+{security}" combos
      transports: set[str] — type values
      flows: set[str] — flow values
      fingerprints: set[str] — fp values
      nodes: list[XrayNode] — сами known_good узлы
    """
    global _KG_PATTERNS
    if _KG_PATTERNS is not None:
        return _KG_PATTERNS

    patterns: dict = {
        "sni_set": set(),
        "sni_tld_set": set(),
        "ip_subnets": set(),
        "host_suffixes": set(),
        "proto_security": set(),
        "transports": set(),
        "flows": set(),
        "fingerprints": set(),
        "nodes": [],
    }

    if not path or not path.is_file():
        _KG_PATTERNS = patterns
        return patterns

    sys.path.insert(0, str(REPO / "python"))
    from runtime.parse import parse_node_link, _node_links_from_text

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        _KG_PATTERNS = patterns
        return patterns

    for url in _node_links_from_text(text):
        try:
            node = parse_node_link(url)
        except Exception:
            continue
        if not node:
            continue
        patterns["nodes"].append(node)

        # SNI
        sni = (node.query.get("sni") or node.query.get("host") or "").strip().lower()
        if sni:
            patterns["sni_set"].add(sni)
            # Extract second-level domain: promokod.com from sub.promokod.com
            parts = sni.split(".")
            if len(parts) >= 2:
                tld_plus1 = ".".join(parts[-2:])
                patterns["sni_tld_set"].add(tld_plus1)

        # Host → IP (for /24 match)
        host = (node.host or "").strip()
        try:
            import ipaddress
            ipaddress.IPv4Address(host)
            patterns["ip_subnets"].add(host)
        except (ValueError, TypeError):
            pass

        # Host suffix: test.grey-lance.test-cdn-kkk.com → test-cdn-kkk.com
        host_parts = host.split(".")
        if len(host_parts) >= 2:
            suffix = ".".join(host_parts[-2:])
            patterns["host_suffixes"].add(suffix)

        # Protocol + security combo
        proto = (node.protocol or "").lower()
        security = (node.query.get("security") or "").lower()
        if proto and security:
            patterns["proto_security"].add(f"{proto}+{security}")

        # Transport
        transport = (node.query.get("type") or "").lower()
        if transport:
            patterns["transports"].add(transport)

        # Flow
        flow = (node.query.get("flow") or "").lower()
        if flow:
            patterns["flows"].add(flow)

        # Fingerprint
        fp = (node.query.get("fp") or "").lower()
        if fp:
            patterns["fingerprints"].add(fp)

    _KG_PATTERNS = patterns
    return patterns


def _pattern_score(node: XrayNode, patterns: dict) -> int:
    """Оценить узел по сходству с known_good patterns. Возвращает 0-100+.

    Scoring:
      SNI exact match         +40   SNI в known_good SNI set
      SNI same TLD+1         +20   SNI делит second-level domain (promokod.com)
      Host /24 match          +30   IP в той же /24 что и known-good IP
      Host domain suffix      +25   Host делит суффикс (test-cdn-kkk.com)
      Protocol+security       +10   Комбо совпадает (vless+reality)
      Transport               +5    type совпадает
      Flow                    +5    flow совпадает
      Fingerprint             +5    fp совпадает
      SNI real domain         +5    Не фейк/пустой
    """
    if not patterns or not patterns.get("nodes"):
        return 0

    score = 0
    sni_set = patterns.get("sni_set", set())
    sni_tld_set = patterns.get("sni_tld_set", set())
    ip_subnets = patterns.get("ip_subnets", set())
    host_suffixes = patterns.get("host_suffixes", set())
    proto_security = patterns.get("proto_security", set())
    transports = patterns.get("transports", set())
    flows = patterns.get("flows", set())
    fingerprints = patterns.get("fingerprints", set())

    # SNI
    sni = (node.query.get("sni") or node.query.get("host") or "").strip().lower()
    if sni:
        if sni in sni_set:
            score += 40
        else:
            # Check TLD+1 match
            parts = sni.split(".")
            if len(parts) >= 2:
                tld_plus1 = ".".join(parts[-2:])
                if tld_plus1 in sni_tld_set:
                    score += 20
            # SNI is a real domain (not fake/empty)
            if "." in sni and len(sni) > 5:
                score += 5

    # Host /24 or domain suffix
    host = (node.host or "").strip()
    try:
        import ipaddress
        ipaddress.IPv4Address(host)
        # It's an IP → check /24
        for known_ip in ip_subnets:
            try:
                host_net = ipaddress.IPv4Network(f"{host}/24", strict=False)
                known_net = ipaddress.IPv4Network(f"{known_ip}/24", strict=False)
                if host_net == known_net:
                    score += 30
                    break
            except Exception:
                pass
    except (ValueError, TypeError):
        # It's a domain → check suffix
        host_parts = host.split(".")
        if len(host_parts) >= 2:
            suffix = ".".join(host_parts[-2:])
            if suffix in host_suffixes:
                score += 25

    # Protocol + security
    proto = (node.protocol or "").lower()
    security = (node.query.get("security") or "").lower()
    if proto and security and f"{proto}+{security}" in proto_security:
        score += 10

    # Transport
    transport = (node.query.get("type") or "").lower()
    if transport and transport in transports:
        score += 5

    # Flow
    flow = (node.query.get("flow") or "").lower()
    if flow and flow in flows:
        score += 5

    # Fingerprint
    fp = (node.query.get("fp") or "").lower()
    if fp and fp in fingerprints:
        score += 5

    # v37b: Бонус за ПОЛНОЕ совпадение стека протокола.
    # Если ВСЕ 4 компонента (proto+security, transport, flow, fp) совпали —
    # конфиг структурно идентичен known_good, добавляем +15.
    # Это даёт: 10+5+5+5+5+15 = 45 → проходит даже без SNI/host match.
    # Юзер: "если стакается стек а остальное нет — конфиг может быть нормальным".
    proto_sec_match = bool(proto and security and f"{proto}+{security}" in proto_security)
    transport_match = bool(transport and transport in transports)
    flow_match = bool(flow and flow in flows)
    fp_match = bool(fp and fp in fingerprints)
    if proto_sec_match and transport_match and flow_match and fp_match:
        score += 15  # bonus: full protocol stack match

    return score


# v40: Canonical stack — multi-track filter.
# Конфиги с каноническим стеком протокола проходят ДАЖЕ БЕЗ known_good match.
# Причина: known_good у каждого юзера свой (21 конфиг у Pizduk, 50 у нашего юзера),
# но в полях есть ТЫСЯЧИ валидных конфигов (vless+tls+ws от AetrisVPN, trojan+tls+ws,
# hy2). Если требовать score>=40 по known_good — мы отбрасываем 90% рабочего.
# Multi-track: проходит если (score >= min_score) ИЛИ (stack canonical).
def _matches_canonical_stack(node: XrayNode) -> bool:
    """Проверить, что у узла «канонический» стек протокола.

    Канонические стеки — это связки, которые РЕАЛЬНО работают на мобильных
    сетях РФ (по статистике AetrisVPN / Pizduk / mifa.world):

      vless + reality + tcp (+ vision flow)    — TSPU-resistance
      vless + tls + ws                          — websocket over TLS (AetrisVPN main)
      vless + tls + http (xhttp)                — новый транспорт (v2.10+)
      trojan + tls + ws                         — классика
      vmess + tls + ws                          — классика
      hysteria2 / hy2                           — UDP, DPI не видит (Pizduk lite)

    НЕ канонические (отсекаются):
      ss (shadowsocks) — часто мёртвый, DPI режет
      vless + tls + tcp (без ws/http) — редкий, обычно мусор
      vless + none — незашифрованный, мгновенно режется
      trojan + tls + tcp — обычно работает, но SNI часто фейк
    """
    proto = (node.protocol or "").lower()
    security = (node.query.get("security") or "").lower()
    transport = (node.query.get("type") or "").lower()

    # vless + reality (transport не важен — reality работает с tcp/grpc/xhttp)
    if proto == "vless" and security == "reality":
        return True
    # vless + tls + ws (доминирующий стек AetrisVPN main, ~13% от 550)
    if proto == "vless" and security == "tls" and transport == "ws":
        return True
    # vless + tls + http (xhttp — новый транспорт, всё чаще встречается)
    if proto == "vless" and security == "tls" and transport in ("http", "xhttp"):
        return True
    # trojan + tls + ws (классический websocket-over-TLS)
    if proto == "trojan" and security == "tls" and transport == "ws":
        return True
    # vmess + tls + ws
    if proto == "vmess" and security == "tls" and transport == "ws":
        return True
    # hysteria2 / hy2 — UDP-протокол, DPI не видит (Pizduk/Test включает 2 hy2)
    if proto in ("hysteria2", "hy2"):
        return True
    # v43: tuic — UDP-over-QUIC, DPI не видит (в allproxy.txt 22k hy2+tuic)
    if proto == "tuic":
        return True
    # vless + reality + grpc — alternative transport for reality
    if proto == "vless" and security == "reality":
        return True  # already covered above, but explicit
    return False


def _apply_pattern_scoring(nodes: list[XrayNode], known_good_path: Path, *,
                           min_score: int = 25,
                           allow_canonical_stack: bool = True,
                           log_sink) -> list[XrayNode]:
    """Оценить узлы по pattern score и отфильтровать по порогу.

    Возвращает отсортированный список (по score убыванию).
    Если known_good.txt нет — возвращает nodes как есть.

    v37b: порог 25 (было 40). С бонусом за полный стек протокола (+15),
    конфиг с vless+reality+tcp+vision+qq но другим SNI/host получает
    10+5+5+5+5+15=45 → проходит. Без бонуса было 30 → не прошло.

    v40: Multi-track — если allow_canonical_stack=True (default),
    конфиг проходит ДАЖЕ если score < min_score, но его стек протокола
    «канонический» (vless+reality / vless+tls+ws / trojan+tls+ws /
    vmess+tls+ws / hysteria2). Это пропускает AetrisVPN-конфиги
    (vless+tls+ws = 13% от 550) БЕЗ требования совпадения с known_good.
    Сортировка: сначала known_good-matched (по score desc), потом
    canonical-stack (по protocol alphabetical).

    v40b: ЕСЛИ known_good.txt пустой И allow_canonical_stack=True —
    known_good-track полностью пропускается, но canonical-track ВСЁ
    равно работает. Раньше возвращали nodes как есть (без фильтра),
    теперь — применяем ТОЛЬКО canonical-stack фильтр. Это даёт
    отсев мусора (ss без обфускации, vless+none) даже без known_good.
    """
    global _KG_PATTERNS
    _KG_PATTERNS = None  # force reload
    patterns = _load_known_good_patterns(known_good_path)

    has_known_good = bool(patterns.get("nodes"))
    if not has_known_good:
        log_sink(f"[gha] --pattern-score: {known_good_path} empty/not found")
        if not allow_canonical_stack:
            log_sink("[gha] --pattern-score: known_good empty AND canonical-stack OFF "
                     "— skipping all scoring (filter disabled)")
            return nodes
        # v40b: known_good пустой, но canonical-stack ON — фильтруем только по стеку.
        log_sink("[gha] --pattern-score: known_good empty, applying canonical-stack ONLY filter")
        canonical_pass: list[XrayNode] = []
        rejected: list[XrayNode] = []
        for n in nodes:
            if _matches_canonical_stack(n):
                canonical_pass.append(n)
            else:
                rejected.append(n)
        log_sink(f"[gha] --pattern-score: {len(nodes)} nodes → "
                 f"{len(canonical_pass)} canonical-stack pass, "
                 f"{len(rejected)} rejected (non-canonical stack)")
        if canonical_pass:
            protos = sorted({(n.protocol or "?").lower() for n in canonical_pass})
            log_sink(f"[gha] --pattern-score: passed protocols: {protos}")
        return canonical_pass if canonical_pass else nodes  # не убиваем пайплайн

    log_sink(f"[gha] --pattern-score: loaded {len(patterns['nodes'])} verified configs")
    log_sink(f"[gha] --pattern-score: {len(patterns['sni_set'])} SNIs, "
             f"{len(patterns['ip_subnets'])} IPs, {len(patterns['host_suffixes'])} host suffixes, "
             f"{len(patterns['proto_security'])} proto+security combos")
    log_sink(f"[gha] --pattern-score: top 5 SNIs: {sorted(patterns['sni_set'])[:5]}")
    log_sink(f"[gha] --pattern-score: top 5 host suffixes: {sorted(patterns['host_suffixes'])[:5]}")

    # Score each node
    scored = [(n, _pattern_score(n, patterns)) for n in nodes]
    scored.sort(key=lambda x: -x[1])  # sort by score descending

    # Multi-track: known_good-matched (score >= min_score) OR canonical stack.
    above: list[tuple[XrayNode, int]] = []
    canonical_pass: list[tuple[XrayNode, int]] = []
    below: list[tuple[XrayNode, int]] = []
    for n, s in scored:
        if s >= min_score:
            above.append((n, s))
        elif allow_canonical_stack and _matches_canonical_stack(n):
            canonical_pass.append((n, s))
        else:
            below.append((n, s))

    log_sink(f"[gha] --pattern-score: {len(nodes)} scored, "
             f"{len(above)} known_good-match (≥{min_score}), "
             f"{len(canonical_pass)} canonical-stack pass, "
             f"{len(below)} below (filtered out)")

    if above:
        top_scores = [s for _, s in above[:5]]
        log_sink(f"[gha] --pattern-score: top 5 known_good scores: {top_scores}")
    if canonical_pass:
        # Покажем топ-5 протоколов среди canonical-pass (для аудита).
        protos = sorted({(n.protocol or "?").lower() for n, _ in canonical_pass})
        log_sink(f"[gha] --pattern-score: canonical-pass protocols: {protos}")

    # Финальный список: known_good-matched first (по score desc), потом
    # canonical (в порядке появления в scored — они уже отсортированы по score).
    return [n for n, _ in above] + [n for n, _ in canonical_pass]


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
    # v39: --extra-sources-file — мёрджит доп. файл (например data/tg_subs.txt,
    # который генерирует scripts/fetch_tg_subs.py: парсит t.me/s/happvpn на
    # happ://crypt5/... ссылки + парсит mifa.world главную на категории).
    # Файл перезаписывается каждый запуск fetch_tg_subs.py — динамические
    # подписки (меняются каждый день) попадают в пайплайн автоматически.
    p.add_argument("--extra-sources-file", type=Path, default=None,
                   help="Доп. файл с URL'ами (мёрджится к --sources-file). "
                        "Используется для динамических подписок: например "
                        "data/tg_subs.txt, который генерирует "
                        "scripts/fetch_tg_subs.py (парсит Telegram-каналы и "
                        "mifa.world). Строки '#' = комментарий, пустые = skip. "
                        "Если файл не существует — молча skip.")
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
    p.add_argument("--max-ping-nodes", type=int, default=0,
                   help="Лимит числа узлов для TCP-ping (после BS-sort'а). 0 = без лимита. "
                        "Нужно для огромных подписок (25k+ узлов): полный ping "
                        "сжигает GHA-минуты. Рекомендуемое: 500-1000 (БС-узлов "
                        "достаточно для финальной выборки).")
    p.add_argument("--max-ping-ms", type=float, default=1000,
                   help="Максимальный TCP-ping (latency), мс. Узлы с ping выше этого "
                        "значения отбраковываются (FakeDNS/медленные серверы). "
                        "По умолчанию 1000 (1 сек). 500 = строже. 0 = без лимита. "
                        "v37c: фильтрует конфиги с пингом 800-4000мс (FakeDNS).")
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
    p.add_argument("--tspu-sim", action="store_true",
                   help="TSPU-эмулятор (строгий): SNI в BS-whitelist AND IP в BS-CIDR. "
                        "TSPU на мобильной сети РФ проверяет ОБА условия: даже при "
                        "идеальном SNI (sberbank.ru) узел блокируется, если IP сервера "
                        "не в BS-CIDR. Этот флаг включает оба фильтра одновременно — "
                        "максимально близкая к реальности статическая эмуляция TSPU "
                        "(без поднятия сети). Требует data/cidr_whitelist.txt (30k CIDR'ов) "
                        "— качается scripts/sync_sni_whitelist.py --with-cidr. "
                        "Без cidr_whitelist.txt — фильтр НЕ работает, узлы с SNI в BS "
                        "проходят по умолчанию.")
    p.add_argument("--tspu-sim-allow-grey", action="store_true", default=True,
                   help="(с --tspu-sim) Смягчить SNI-проверку: включить серые SNI "
                        "(реальные домены не из BS/ЧС списков). По умолчанию ON — "
                        "TSPU на мобильных сетях РФ НЕ имеет фиксированного whitelist'а, "
                        "блокирует только конкретные ЧС (instagram/chatgpt/...). "
                        "Серые SNI (promokod.com, realhost.com ...) РЕАЛЬНО работают.")
    p.add_argument("--tspu-sim-allow-fake", action="store_true",
                   help="(с --tspu-sim) Смягчить SNI-проверку: включить фейки. "
                        "НЕ рекомендуется — TSPU быстро блокирует фейки.")
    p.add_argument("--tspu-sim-no-cidr", action="store_true",
                   help="(УСТАРЕЛО в v36: cidr_check по умолчанию False) "
                        "Алиас для дефолтного поведения — не проверять IP-CIDR. "
                        "Оставлен для обратной совместимости.")
    p.add_argument("--tspu-sim-strict-cidr", action="store_true",
                   help="(с --tspu-sim) ВКЛЮЧИТЬ IP-CIDR проверку (по умолчанию OFF). "
                        "Только для полного blackout'а (когда TSPU whitelist'ит весь интернет). "
                        "v36: по умолчанию OFF — убивает все зарубежные VPN-серверы "
                        "потому что их IP не в BS-CIDR. SNI blacklist достаточно "
                        "для обычного ограниченного режима.")
    p.add_argument("--geo-rename", action="store_true",
                   help="Переименовать узлы как основное приложение: "
                        "«<флаг> <ISO-код> peppo» (например, «🇩🇪 DE peppo»). "
                        "Гео берётся через https://api.ip.sb/geoip/<IP> — "
                        "запрос ИДЁТ ИЗ GHA, не через прокси узла (GHA на Azure US/EU, "
                        "гео IP совпадает с тем, что видит api.ip.sb). "
                        "Для доменных host'ов делается DNS-resolve. "
                        "Кеш по IP (10000 узлов = ~10000 запросов, но IP дублируются → ~5000). "
                        "Без --geo-rename узлы пишутся как есть.")
    p.add_argument("--geo-rename-workers", type=int, default=8,
                   help="Параллелизм geo-lookup (по умолчанию: 8). "
                        "Больше — быстрее, но api.ip.sb может rate-limit'ить.")
    p.add_argument("--geo-rename-timeout", type=float, default=8.0,
                   help="Таймаут одного geo-запроса, сек (по умолчанию: 8.0).")
    # v33: known-good patterns — фильтр по проверенным на мобилке конфигам.
    # Юзер кладёт свой test.txt в data/known_good.txt — это конфиги, которые
    # РЕАЛЬНО работают на его мобильной сети (TSPU). Workflow:
    #   1. Извлекает из known_good.txt паттерны: set of SNIs + set of /24 IP-subnets.
    #   2. После TSPU-sim фильтра — применяет known-good фильтр: оставляет только
    #      узлы, чей SNI совпадает с known-good SNI ИЛИ чей IP в known-good IP-подсети.
    #   3. APPEND known_good.txt configs в финал preload.txt (как verified-baseline).
    # Это даёт: всегда есть verified configs + новые похожие на них.
    p.add_argument("--known-good", type=Path,
                   default=REPO / "data" / "known_good.txt",
                   help="Файл с проверенными на мобилке конфигами (vless://...). "
                        "Если существует — workflow извлекает SNI+IP паттерны и "
                        "оставляет только узлы, совпадающие с ними. "
                        "По умолчанию: data/known_good.txt.")
    p.add_argument("--known-good-mode", default="sni_or_ip",
                   choices=["sni", "ip", "sni_or_ip", "sni_and_ip", "none"],
                   help="Режим фильтра known-good: "
                        "sni (SNI в known-good), "
                        "ip (IP в /24 known-good), "
                        "sni_or_ip (ИЛИ, default), "
                        "sni_and_ip (И, strict), "
                        "none (не фильтровать, только append known_good).")
    p.add_argument("--known-good-ip-prefix", type=int, default=24,
                   help="Длина IP-префикса для known-good IP match (/16, /24, /32). "
                        "По умолчанию 24 — та же /24 подсеть что и known-good IP.")
    # v37: Pattern scoring — замена xray-ping для GHA.
    p.add_argument("--pattern-score", action="store_true", default=True,
                   help="Включить pattern-based scoring (v37). Каждый узел оценивается "
                        "по сходству с known_good.txt (SNI +40, TLD+20, IP/24 +30, "
                        "host suffix +25, proto+security +10, transport +5, flow +5, fp +5). "
                        "Узлы с score < --pattern-score-min отбраковываются. "
                        "По умолчанию ON если known_good.txt существует. "
                        "Это ЗАМЕНА xray-ping — не нужен xray, не нужны GHA-минуты.")
    p.add_argument("--pattern-score-min", type=int, default=25,
                   help="Минимальный score для попадания в финал (default: 25). "
                        "0 = пропустить все (фильтр выключен). "
                        "25 = SNI TLD+1 match ИЛИ полный стек протокола (vless+reality+tcp+vision+qq). "
                        "40 = нужно SNI match ИЛИ host+IP match. "
                        "0 = пропустить фильтр (все проходят).")
    # v40: Multi-track canonical stack — конфиг проходит даже без known_good match,
    # если его стек протокола «канонический» (vless+reality / vless+tls+ws /
    # trojan+tls+ws / vmess+tls+ws / hysteria2). По умолчанию ON — это даёт
    # AetrisVPN-конфиги (vless+tls+ws = 13% от 550) и Pizduk hy2 в финал.
    p.add_argument("--allow-canonical-stack", action="store_true", default=True,
                   help="Multi-track: пропускать конфиги с каноническим стеком "
                        "(vless+reality / vless+tls+ws / trojan+tls+ws / "
                        "vmess+tls+ws / hy2) ДАЖЕ БЕЗ known_good match. "
                        "По умолчанию ON — это даёт AetrisVPN/Pizduk-конфиги в финал.")
    p.add_argument("--no-canonical-stack", dest="allow_canonical_stack",
                   action="store_false",
                   help="Выключить multi-track. Только known_good match "
                        "(score >= --pattern-score-min). Строго — отсечёт "
                        "AetrisVPN WS+TLS конфиги.")
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
    # v39: extra_sources — URL'ы из доп. файла (--extra-sources-file).
    # Используется для динамических подписок: scripts/fetch_tg_subs.py
    # парсит t.me/s/happvpn (happ://crypt5/...) и mifa.world (категории),
    # пишет всё в data/tg_subs.txt. Workflow запускает fetch_tg_subs.py
    # ПЕРЕД refresh_subs.py, к моменту чтения файл готов.
    extra_sources: list[str] = []
    if args.extra_sources_file is not None and args.extra_sources_file.exists():
        try:
            for line in args.extra_sources_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                extra_sources.append(line)
            if extra_sources:
                log(f"[gha] extra-sources-file {args.extra_sources_file}: "
                    f"merged {len(extra_sources)} URL(s)")
        except OSError as exc:
            log(f"[gha] extra-sources-file read failed: {exc}")
    sources = _read_sources(args.sources_file, args.sources + extra_sources,
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

    # 3) SNI-категоризация (БС/ЧС/серый/фейк/none) И опциональная фильтрация.
    #    ВАЖНО: SNI-фильтр/сорт идёт ДО TCP-ping, чтобы:
    #    а) не пинговать узлы, которые всё равно будут отбракованы (ЧС на
    #       ограниченной сети РФ — нет смысла их пинговать, экономия минут GHA);
    #    б) --max-ping-nodes срезал уже отсортированный список (пингует ТОП-N
    #       БС-узлов, а не случайные).
    #    Кейс юзера 2026-09-29: на ограниченных сетях РФ мобильные операторы
    #    пропускают только узлы с SNI из БЕЛОГО списка (sberbank.ru, vk.com,
    #    gosuslugi.ru ...). ЧС (instagram.com, chatgpt.com ...) блокируется.
    if args.bs_only or args.sort_by_sni or args.tspu_sim:
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

        # 3a) TSPU-эмулятор — строгий фильтр: SNI в BS-whitelist AND IP в BS-CIDR.
        #     Идёт ПЕРВЫМ (строже --bs-only, который проверяет только SNI).
        #     Кейс юзера: "рабочих конфигов дохрена, на мобиле реально работает
        #     меньше". Причина: --bs-only проверяет только SNI, но TSPU на мобильной
        #     сети РФ проверяет ОБА условия (SNI в BS AND IP в BS-CIDR). --tspu-sim
        #     включает вторую проверку — реально отсекает узлы, чьи IP не в whitelist.
        if args.tspu_sim:
            from checkers.cidr_whitelist import (
                load_cidr_whitelist as _load_cidr,
                reset_cache as _reset_cidr_cache,
                tspu_strict_passes as _tspu_passes,
                tspu_summary as _tspu_summary,
            )
            _reset_cidr_cache()  # на случай, если синкнулся cidr_whitelist.txt
            cidr_count = len(_load_cidr())
            log(f"[gha] --tspu-sim: cidr_whitelist loaded ({cidr_count} CIDRs)")
            # v36: cidr_check по умолчанию OFF. Включается только через --tspu-sim-strict-cidr.
            # Причина: GHA на Azure US/EU, IP-CIDR проверка убивает все зарубежные VPN.
            use_cidr = bool(getattr(args, 'tspu_sim_strict_cidr', False))
            if cidr_count == 0 and use_cidr:
                log("[gha] WARNING: data/cidr_whitelist.txt пуст — TSPU-sim strict-cidr "
                    "не работает. Запустите scripts/sync_sni_whitelist.py --with-cidr.")
            tspu_summary_dict = _tspu_summary(nodes)
            log(f"[gha] --tspu-sim breakdown: {tspu_summary_dict}")
            before = len(nodes)
            # Фильтруем: reject только ЧС-SNI (instagram/chatgpt) + fake + empty.
            # Серые/белые SNI + ЛЮБОЙ IP → PASS (v36: cidr_check=False по умолчанию).
            filtered = []
            for n in nodes:
                ok, _reason = _tspu_passes(
                    n,
                    sni_check=True,
                    cidr_check=use_cidr,
                    allow_grey=args.tspu_sim_allow_grey,
                    allow_fake=args.tspu_sim_allow_fake,
                )
                if ok:
                    filtered.append(n)
            nodes = filtered
            log(f"[gha] --tspu-sim filter: {before} → {len(nodes)} "
                f"(allow_grey={args.tspu_sim_allow_grey}, allow_fake={args.tspu_sim_allow_fake}, "
                f"cidr_check={use_cidr})")
            if not nodes:
                log("[gha] WARNING: 0 TSPU-passed nodes — preload.txt NOT written")
                return 1

        # 3b) --bs-only — мягкий SNI-only фильтр (если не включён --tspu-sim,
        #     который строже). Логируем даже при --tspu-sim (для сравнения).
        if args.bs_only and not args.tspu_sim:
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

    # 4) Опциональный TCP-ping (дешёвый фильтр мёртвых). Идёт ПОСЛЕ SNI-фильтра
    #    — пингуем только нужные узлы (БС + опц. серые). --max-ping-nodes
    #    обрезает уже отсортированный список, если их слишком много.
    if args.with_ping and nodes:
        log(f"[gha] TCP-ping {len(nodes)} nodes (workers={args.ping_workers}, "
            f"timeout={args.ping_timeout}s"
            + (f", max_nodes={args.max_ping_nodes}" if args.max_ping_nodes > 0 else "")
            + (f", max_ping={args.max_ping_ms}ms" if args.max_ping_ms > 0 else "")
            + ")")
        alive = _ping_filter(nodes, timeout=args.ping_timeout,
                             workers=args.ping_workers, log_sink=log,
                             max_nodes=args.max_ping_nodes,
                             max_ping_ms=args.max_ping_ms)
        log(f"[gha] ping: {len(alive)}/{len(nodes)} alive")
        nodes = alive

    # 5) v44: --max-servers ПЕРЕНЕСЁН В КОНЕЦ пайплайна (после pattern-score + geo-rename).
    #     Раньше стоял ПЕРЕД known_good filter — обрезал alive-список до known_good,
    #     теряя рабочий материал. Теперь: known_good → pattern-score → geo-rename → max-servers.
    #     ВАЖНО: max-servers здесь НЕ применяем — он в самом конце (после geo-rename).

    # 5b) known-good фильтр: оставить только узлы, похожие на ПРОВЕРЕННЫЕ
    #     на мобилке конфиги (data/known_good.txt). Если файла нет — skip.
    #     ВСЕГДА append known_good configs в финал (как verified-baseline) —
    #     если они прошли TSPU на мобилке, должны быть в финальной подписке.
    #     Юзер: "10 конфигов от GHA не работают, test.txt работают на мобиле" —
    #     это фикс: GHA-найдённые фильтруются по паттернам из test.txt,
    #     + сам test.txt append'ится в финал.
    kg_nodes_to_append: list[XrayNode] = []
    if args.known_good:
        nodes, kg_nodes_to_append = _apply_known_good_filter(
            nodes, args.known_good,
            mode=args.known_good_mode,
            ip_prefix=args.known_good_ip_prefix,
            log_sink=log,
        )
        # Append known_good configs (verified на мобилке) в финал preload.txt.
        # Дедуп: не добавляем если уже в nodes (по node.key).
        existing_keys = {n.key for n in nodes}
        for kg in kg_nodes_to_append:
            if kg.key not in existing_keys:
                nodes.append(kg)
                existing_keys.add(kg.key)
        if kg_nodes_to_append:
            log(f"[gha] --known-good: appended {len(kg_nodes_to_append)} verified configs "
                f"to final list (total now: {len(nodes)})")

    # 5c) v37: Pattern-based scoring — замена xray-ping для GHA.
    #     Оцениваем каждый узел по сходству с known_good patterns.
    #     Score >= threshold → попадает в финал. Сортировка по score desc.
    #     НЕ требует xray — быстро (30 сек на 25k узлов).
    if args.pattern_score and args.pattern_score_min > 0 and nodes:
        nodes = _apply_pattern_scoring(
            nodes,
            args.known_good,
            min_score=args.pattern_score_min,
            allow_canonical_stack=args.allow_canonical_stack,
            log_sink=log,
        )
        if not nodes:
            log("[gha] WARNING: 0 nodes after pattern scoring — preload.txt NOT written")
            return 1

    if not nodes:
        log("[gha] WARNING: 0 nodes after filter — preload.txt NOT written (existing file kept)")
        return 1

    # 6) Опциональное geo-переименование: «<флаг> <ISO-код> peppo» как в основном
    #    приложении (subgen.geo.serialize_working). Гео берётся через
    #    https://api.ip.sb/geoip/<IP> — публичный JSON API. Запрос идёт ИЗ GHA
    #    (не через прокси узла), для доменных host'ов делается DNS-resolve.
    #    Совпадает с тем, что видит api.ip.sb: «🇩🇪 DE peppo» / «🇺🇸 US peppo» ...
    if args.geo_rename and nodes:
        _geo_rename_nodes(
            nodes,
            workers=args.geo_rename_workers,
            timeout=args.geo_rename_timeout,
            log_sink=log,
        )

    # 7) v44: ЛИМИТ ИТОГОВЫХ УЗЛОВ — в самом конце, ПОСЛЕ всех фильтров.
    #    Раньше стоял ПЕРЕД known_good + pattern-score → обрезал alive-список
    #    до known_good, теряя рабочий материал. Теперь обрезает только финал:
    #    топ-N по pattern-score (после known_good-match first, потом canonical).
    if args.max_servers > 0 and len(nodes) > args.max_servers:
        log(f"[gha] FINAL truncate: {len(nodes)} → {args.max_servers} (--max-servers)")
        nodes = nodes[:args.max_servers]
    else:
        log(f"[gha] FINAL list: {len(nodes)} nodes (no --max-servers limit)")

    # 7) Записываем preload.txt (по строке на узел — то, что sub_generator уже
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
