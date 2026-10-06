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
                  use_saved_subs: bool = True) -> tuple[list[str], dict[str, str]]:
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

    v60: Возвращает (sources, source_tags) где source_tags — dict[url] = "bs"|"chs"|"mixed".
    Источники РАЗДЕЛЕНЫ на 3 секции в sources.txt:
      # === БС === — БС-списки (мобилка РФ)
      # === ЧС === — ЧС-списки (WiFi / не-RU)
      # === MIXED === — без явного маркера (по умолчанию БС)
    Каждый URL помечается по секции, в которой он находится.
    """
    sources: list[str] = []
    source_tags: dict[str, str] = {}  # url → "bs" / "chs" / "mixed"
    seen: set[str] = set()
    current_section = "mixed"  # default — MIXED секция (БС по умолчанию)

    def add(value: str, tag: str = "mixed") -> None:
        value = (value or "").strip()
        if not value or value.startswith("#"):
            return
        # На GHA хотим поддержать и прямые vless:// в sources.txt — runtime
        # _collect_from_source их понимает, мы просто передаём как есть.
        if value not in seen:
            seen.add(value)
            sources.append(value)
            source_tags[value] = tag

    if sources_file.exists():
        for line in sources_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            # v60: Парсер секций. Когда видим "# === БС ===" — переключаемся.
            if stripped.startswith("# ==="):
                upper = stripped.upper()
                if "БС" in upper or "БЕЛЫЙ" in upper or "BS" in upper or "WHITE" in upper:
                    current_section = "bs"
                elif "ЧС" in upper or "ЧЁРНЫЙ" in upper or "CHS" in upper or "BLACK" in upper:
                    current_section = "chs"
                elif "MIXED" in upper:
                    current_section = "mixed"
                # Строку-разделитель пропускаем (не URL).
                continue
            # v62: Также проверяем сам URL на ключевые слова wl/bl/alive_bs.
            # Это для источников, которые попали в MIXED секцию, но по названию
            # файла явно БС (wl.txt, alive_bs.txt, whitelist.txt) или ЧС (bl.txt).
            url_lower = stripped.lower()
            if not current_section or current_section == "mixed":
                # Проверяем filename в URL на WL/BL маркеры.
                # "wl" / "bl" — проверяем как отдельное слово (не подстрока owl/cable).
                import re as _re_mod
                # /wl. /wl_ /wl/ /wl# → БС
                if _re_mod.search(r'[/_.]wl[/_.#]|[/_.]wl$', url_lower) or \
                   "alive_bs" in url_lower or "whitelist" in url_lower or \
                   "white" in url_lower or "бс" in url_lower:
                    current_section_override = "bs"
                    add(stripped, current_section_override)
                    continue
                # /bl. /bl_ /bl/ /bl# → ЧС
                if _re_mod.search(r'[/_.]bl[/_.#]|[/_.]bl$', url_lower) or \
                   "blacklist" in url_lower or "black" in url_lower or "чс" in url_lower:
                    current_section_override = "chs"
                    add(stripped, current_section_override)
                    continue
            add(stripped, current_section)
    for value in extra or []:
        add(value, "mixed")  # CLI args — без секции (mixed = БС по умолчанию).

    # Авто-мёрдж data/saved_subs/*.txt + *.json — как в локальном app.
    if use_saved_subs and saved_subs_dir is not None and saved_subs_dir.is_dir():
        for f in sorted(saved_subs_dir.glob("*.txt")) + sorted(saved_subs_dir.glob("*.json")):
            if f.name == "README.txt":
                continue
            add(str(f.resolve()), "mixed")  # saved_subs — mixed (БС по умолчанию).
    return sources, source_tags


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


# v53: Чёрный список IP-диапазонов DNS, которые часто встречаются в фейковых
# подписках (mifa.world, Epodonios, AetrisVPN-заглушки). Это НЕ VPN-сервера,
# но порты 443 открыты — TCP-ping говорит "alive", и они попадают в финал
# как мёртвые. Отбрасываем на этапе _is_valid_hostname.
#
# v53: Убрал Cloudflare/Fastly CDN IP-диапазоны — на них МОГУТ быть VPN
# (Reality с SNI=cloudflare.com/fastly.com — сервер стоит в CDN сети).
# Оставил только явные DNS IP (100% не VPN).
#
# v63: ВЕРНУЛ Cloudflare/Fastly/Akamai CDN IP-диапазоны. Юзер доказал ошибками
# v2rayN (403, reality verification failed, tls handshake failure) — 99% CDN IP
# в публичных подписках это ФЕЙК, не VPN. Cloudflare Spectrum (через который
# мог бы работать VPN) дорогой и НЕ используется в бесплатных подписках.
import ipaddress as _ipaddr_module
import ipaddress  # v52: используем в нескольких функциях (раньше был в функции)
_CDN_DNS_BLACKLIST: list[_ipaddr_module.IPv4Network] = [
    # Google DNS (AS15169) — 100% не VPN
    _ipaddr_module.ip_network("8.8.8.8/32"),
    _ipaddr_module.ip_network("8.8.4.4/32"),
    # Cloudflare DNS — 100% не VPN
    _ipaddr_module.ip_network("1.1.1.1/32"),
    _ipaddr_module.ip_network("1.0.0.1/32"),
    # Quad9 DNS — 100% не VPN
    _ipaddr_module.ip_network("9.9.9.9/32"),
    _ipaddr_module.ip_network("149.112.112.112/32"),
    # OpenDNS (Cisco) — 100% не VPN
    _ipaddr_module.ip_network("208.67.222.222/32"),
    _ipaddr_module.ip_network("208.67.220.220/32"),
    # Control D — 100% не VPN
    _ipaddr_module.ip_network("76.76.2.0/24"),
    _ipaddr_module.ip_network("76.76.10.0/24"),
    # AdGuard DNS — 100% не VPN
    _ipaddr_module.ip_network("94.140.14.14/32"),
    _ipaddr_module.ip_network("94.140.15.15/32"),
    # v63: Loopback / unspecified / private
    _ipaddr_module.ip_network("0.0.0.0/8"),
    _ipaddr_module.ip_network("127.0.0.0/8"),
    _ipaddr_module.ip_network("10.0.0.0/8"),
    _ipaddr_module.ip_network("172.16.0.0/12"),
    _ipaddr_module.ip_network("192.168.0.0/16"),
    _ipaddr_module.ip_network("169.254.0.0/16"),

    # v63: Cloudflare CDN (AS13335) — 99% фейк в публичных подписках.
    # Ошибки v2rayN: 403, connection reset, tls handshake failure.
    # Cloudflare Spectrum (VPN через CDN) — платный, НЕ используется в бесплатных подписках.
    _ipaddr_module.ip_network("104.16.0.0/13"),   # 104.16-23.x.x
    _ipaddr_module.ip_network("104.24.0.0/14"),   # 104.24-27.x.x
    _ipaddr_module.ip_network("172.64.0.0/13"),   # 172.64-71.x.x
    _ipaddr_module.ip_network("188.114.96.0/20"), # 188.114.96-111.x
    _ipaddr_module.ip_network("190.93.240.0/20"), # 190.93.240-255.x
    _ipaddr_module.ip_network("197.234.240.0/22"),# 197.234.240-243.x

    # v63: Fastly CDN (AS54113) — 99% фейк. Ошибки: 403, EOF, connection reset.
    _ipaddr_module.ip_network("151.101.0.0/16"),  # Fastly
    _ipaddr_module.ip_network("167.82.0.0/16"),   # Fastly
    _ipaddr_module.ip_network("199.232.0.0/16"), # Fastly

    # v63: Akamai CDN —偶尔 встречается в фейк-подписках
    _ipaddr_module.ip_network("23.0.0.0/8"),       # Akamai (большой диапазон)
    _ipaddr_module.ip_network("95.100.0.0/15"),    # Akamai

    # v63: Amazon CloudFront CDN
    _ipaddr_module.ip_network("13.224.0.0/14"),    # CloudFront
    _ipaddr_module.ip_network("52.84.0.0/15"),     # CloudFront
]


# v53: Чёрный список доменов, которые явно НЕ VPN (gov.ua, speedtest.net, ...).
# Эти домены часто встречаются в фейк-подписках как SNI/host — фейк-конфиги.
# Отбрасываем в _is_valid_hostname.
_NON_VPN_DOMAINS: frozenset[str] = frozenset({
    # Государственные домены — точно не VPN
    "www.gov.ua", "gov.ua", "www.gov.ru", "gov.ru",
    "www.kremlin.ru", "kremlin.ru", "www.cbr.ru", "cbr.ru",
    "www.nalog.ru", "nalog.ru", "www.gosuslugi.ru", "gosuslugi.ru",
    # Тестовые / метрические домены
    "www.speedtest.net", "speedtest.net",
    "www.fast.com", "fast.com",
    "speed.cloudflare.com",
    # Игровые / медиа-домены (не VPN)
    "log.bpminecraft.com", "bpminecraft.com",
    # Китайские публичные домены (часто в фейк-подписках)
    "www.baipiao.eu.org", "baipiao.eu.org",
    # Поисковики (SNI=google.com — это фейк, не VPN)
    "www.google.com",  # SNI для маскировки ОК, но host=www.google.com = фейк
    "www.bing.com",
    "www.yahoo.com",
    "www.yandex.ru", "yandex.ru", "ya.ru",
    # Соцсети (host=instagram.com = фейк, SNI=instagram.com = маскировка ОК)
    "www.instagram.com", "instagram.com",
    "www.facebook.com", "facebook.com",
    "www.twitter.com", "twitter.com",
    "www.youtube.com", "youtube.com",
    # Streaming
    "www.netflix.com", "netflix.com",
    # Cloudflare/Fastly как host (НЕ SNI!) — фейк
    "www.cloudflare.com",  # но IP 1.1.1.1 в blacklist
    # AdGuard
    "adguard.com",
})


def _is_cdn_dns_ip(host: str) -> bool:
    """Проверить, является ли host DNS IP (8.8.8.8, 1.1.1.1, etc.).

    Возвращает True если host — это IP из чёрного списка DNS.
    v53: Убрал Cloudflare/Fastly CDN IP-диапазоны — на них могут быть VPN.
    """
    try:
        ip = _ipaddr_module.IPv4Address(host)
    except (ValueError, TypeError):
        return False
    for net in _CDN_DNS_BLACKLIST:
        if ip in net:
            return True
    return False


def _is_non_vpn_domain(host: str) -> bool:
    """Проверить, является ли host не-VPN доменом (gov.ua, speedtest.net, ...).

    v53: Эти домены часто встречаются в фейк-подписках. Если host (НЕ SNI!)
    равен одному из них — это фейк-конфиг, отбрасываем.
    """
    if not host:
        return False
    host_lower = host.strip().lower().rstrip(".")
    if host_lower in _NON_VPN_DOMAINS:
        return True
    # Также проверим домен второго уровня (например, gov.ua для sub.gov.ua)
    parts = host_lower.split(".")
    if len(parts) >= 2:
        domain2 = ".".join(parts[-2:])
        if domain2 in _NON_VPN_DOMAINS:
            return True
    return False


def _is_valid_hostname(host: str) -> bool:
    """Проверка, что host — валидное DNS-имя или IP.

    Отсекает мусор, который вызывает UnicodeError в IDNA-кодировании внутри
    socket.create_connection: метки длиннее 63 символов, пустые метки
    (последовательные точки), недопустимые символы.

    Возвращает True для: IPv4 (4 октета), IPv6 (содержит ':'), валидное
    DNS-имя (≤253 символа, метки 1..63 из [a-zA-Z0-9_-]).

    v51: ОТсекает loopback / private / link-local IP — они НЕ валидные VPN-сервера,
    но проходят IPv4 regex и вызывают TCP-ping = 0ms (мгновенный connect/refuse).
    Также это убирает "ping stats: p50=0ms" баг — реальная latency никогда не 0ms.
    """
    if not host or not isinstance(host, str):
        return False
    host = host.strip().rstrip(".")
    if not host:
        return False
    # IPv4 — без IDNA, валидируем регуляркой.
    if _IPV4_RE.match(host):
        # v51: отбрасываем loopback / private / link-local IP.
        # Это фиктивные хосты из подписок-заглушек (mifa.world и т.д.) —
        # 127.0.0.1:443 мгновенно проходит TCP-handshake на localhost, давая
        # latency=0ms и фейковые "alive" в ping stats.
        try:
            ip = ipaddress.IPv4Address(host)
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                return False
            # Private IP (10.0/8, 192.168/16, 172.16/12) — на GHArunner тоже
            # не валидные VPN-сервера (локальная сеть runner'а).
            if ip.is_private:
                return False
        except (ValueError, TypeError):
            return False
        # v52: отбрасываем CDN/DNS IP (Cloudflare, Fastly, Google DNS, ...).
        # Эти IP часто встречаются в фейк-подписках — порты 443 открыты (CDN!),
        # но vless+reality там не работает.
        if _is_cdn_dns_ip(host):
            return False
        return True
    # IPv6 — содержит ':', валидируем как есть (с или без скобок).
    if ":" in host:
        # v51: отбрасываем IPv6 loopback (::1) и link-local (fe80::/10).
        try:

            ip = ipaddress.IPv6Address(host.strip("[]"))
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                return False
        except (ValueError, TypeError):
            pass
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
    # v51: отбрасываем localhost-домены (не валидный VPN-сервер).
    if host.lower() in ("localhost", "ip6-localhost", "ip6-loopback"):
        return False
    # v53: отбрасываем "не VPN" домены (gov.ua, speedtest.net, google.com, ...).
    # Эти домены часто в фейк-подписках как host — gov.ua / speedtest.net /
    # baipiao.eu.org / bpminecraft.com — точно не VPN-сервера.
    if _is_non_vpn_domain(host):
        return False
    return True


def _tcp_ping(node: XrayNode, timeout: float) -> tuple[bool, float]:
    """Быстрый TCP-ping. True если удалось подключиться за timeout сек.

    НЕ запускает xray — это просто socket.connect() с таймаутом. Дешёвый
    фильтр мёртвых узлов (TCP RST / timeout / DNS-fail / IDNA-fail).
    Реальная проверка работы узла требует xray.exe (только Windows), её тут нет.

    v51: Если latency < 0.5ms — считаем подозрительно быстрой (вероятно
    loopback или CDN-кешированный TCP-handshake). Помечаем как dead (False).
    Реальная сетевая latency никогда не < 0.5ms даже для localhost в Docker.
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
    t0 = time.perf_counter()  # v53: high-resolution timer (наносекунды на Linux)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = time.perf_counter() - t0
            # v64b: ПОРОГ 80ms (ЮЗЕР ПРОСИЛ 80-100, Я САМОВОЛЬНО ПОМЕНЯЛ НА 10 В v57).
            # Замеры на known_good.txt: 185-320ms (реальные РФ-сервера).
            # Railway.app/Vercel/CDN-cache: 10-50ms (НЕ VPN — отбрасываем!).
            # EU VPN: 80-150ms (проходит).
            # РФ VPN: 150-300ms (проходит).
            if latency < 0.080:  # < 80ms — НЕ VPN (CDN/Railway/Vercel/hosting)
                return False, 0.0
            return True, latency
    except Exception:
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
            log_sink(f"[gha] ping stats: p50={p50*1000:.0f}ms p95={p95*1000:.0f}ms max={p100*1000:.0f}ms "
                     f"({len(pinged)} alive"
                     + (f", {slow_filtered} slow filtered (>{max_ping_ms}ms)" if max_ping_ms > 0 and slow_filtered > 0 else "")
                     + ")")
            # Топ-5 самых быстрых.
            for n, l in pinged[:3]:
                log_sink(f"[gha]   fastest: {l*1000:.0f}ms  {n.host}:{n.port}  sni={n.query.get('sni', '')}")

    return [n for n, _ in pinged]


# ---------------------------------------------------------------------- geo

# Кеш IP → (country_code, flag) для geo-переименования.
# Сильная дедупликация: 10000 узлов на ~5 уникальных CDN-IP = 5 запросов вместо 10k.
_geo_cache: dict[str, tuple[str, str]] = {}
_geo_cache_lock = threading.Lock()

# fallback если api.ip.sb недоступен / rate-limit / невалидный IP.
# v49b: Если страна не определена (api.ip.sb fail и в имени нет флага) —
# ставим "🌐 peppo" (земной шар). Не "🏳 ?? peppo" — юзер сказал так не делать.
_GEO_FALLBACK_CODE = "🌐"   # Земной шар вместо "??" + "🏳"
_GEO_FALLBACK_FLAG = "🌐"


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
    На fallback (geo недоступно): «🌐 peppo» (v49b: земля вместо "??").
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
    # Если в имени флага нет → настоящий fallback "🌐 peppo" (v49b).
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
                # Даже в имени нет флага → настоящий fallback "🌐 peppo".
                new_name = "🌐 peppo"
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
    # v49: --no-pattern-score — выключить pattern-score (как у Pizduk/Aetris/Mifa).
    # Pattern-score отсекал рабочие конфиги, оставляя только похожие на known_good
    # (которые могли умереть за пару дней). Без pattern-score проходит ВСЁ canonical-stack.
    p.add_argument("--no-pattern-score", dest="pattern_score",
                   action="store_false",
                   help="Выключить pattern-score. Просто canonical-stack фильтр "
                        "(как у Pizduk/Aetris/Mifa — берут все публичные конфиги без "
                        "сужения по known_good). Рекомендуется v49.")
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
    # v49: Разделение финала на БС (мобилка РФ) и ЧС (WiFi / не-RU).
    # На мобильной сети РФ ТСПУ блокирует ЧС-SNI (instagram, chatgpt, ...).
    # На WiFi / вне РФ — ЧС-SNI работает (нет ТСПУ). Поэтому делим финал:
    #   preload_bs.txt  — БС + серый + фейк + none (НЕ ЧС) → для мобилки РФ
    #   preload_chs.txt — ТОЛЬКО ЧС-SNI → для WiFi / не-RU
    # subs.txt (в GHA workflow) = preload_bs.txt (base64).
    p.add_argument("--split-bs-chs", action="store_true", default=True,
                   help="Разделить финал на 2 файла: preload_bs.txt (БС+серый+фейк+none, "
                        "для мобилки РФ) и preload_chs.txt (только ЧС-SNI, для WiFi/не-RU). "
                        "Default: ON. Позволяет юзеру выбрать подписку под сеть.")
    p.add_argument("--no-split-bs-chs", dest="split_bs_chs",
                   action="store_false",
                   help="НЕ разделять на БС/ЧС. Только preload.txt (как в v48).")
    # v59: --drop-geo-fallback — отбрасывать узлы с именем "🌐 peppo"
    # (geo-rename не смог определить страну — часто это мёртвые узлы).
    p.add_argument("--drop-geo-fallback", action="store_true", default=True,
                   help="Отбрасывать узлы с именем '🌐 peppo' (geo-rename не "
                        "смог определить страну). Юзер: 'большая часть 🌐 peppo "
                        "— мертвые'. Default: ON. v59.")
    p.add_argument("--no-drop-geo-fallback", dest="drop_geo_fallback",
                   action="store_false",
                   help="НЕ отбрасывать '🌐 peppo' узлы (оставить в финале).")
    # v60: --vless-only — собирать ТОЛЬКО vless:// конфиги (отсев trojan/ss/vmess/hy2/tuic).
    p.add_argument("--vless-only", action="store_true", default=False,
                   help="Собирать ТОЛЬКО vless:// конфиги. Все trojan/ss/vmess/"
                        "hysteria2/tuic отбрасываются. Default: OFF (все протоколы).")
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
    sources, source_tags = _read_sources(args.sources_file, args.sources + extra_sources,
                                          saved_subs_dir=saved_subs_dir,
                                          use_saved_subs=not args.no_saved_subs)
    if not sources:
        log("[gha] FATAL: sources list is empty")
        return 1
    # v60: Логируем классификацию источников по секциям.
    bs_count = sum(1 for t in source_tags.values() if t == "bs")
    chs_count = sum(1 for t in source_tags.values() if t == "chs")
    mixed_count = sum(1 for t in source_tags.values() if t == "mixed")
    log(f"[gha] sources: {len(sources)} (BS={bs_count}, ChS={chs_count}, MIXED={mixed_count})")
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
        # v61: on_source_body callback — проверяем ТЕЛО подписки на БС/ЧС.
        # Часто первая строка "#profile-title: AetrisVPN White list" указывает
        # тип списка, даже если в URL нет "white"/"black".
        body_tags: dict[str, str] = {}  # url → "bs"/"chs" (from body keywords)
        def _on_body(url: str, body: str) -> None:
            # Проверяем первые ~20 строк тела на ключевые слова БС/ЧС.
            head = body[:5000].lower()  # первые 5KB — обычно хватает
            has_white = any(w in head for w in (
                "white", "бс", "белый", "белые", "whitelist", "беловой",
                "wl list", "white list", "белые списки", "бс список"
            ))
            has_black = any(w in head for w in (
                "black", "чс", "чёрный", "чёрные", "blacklist",
                "bl list", "black list", "чёрные списки", "чс список"
            ))
            if has_white and not has_black:
                body_tags[url] = "bs"
            elif has_black and not has_white:
                body_tags[url] = "chs"

        nodes = collect_subscription_nodes(
            sources,
            timeout=args.fetch_timeout,
            max_servers=0,
            log_sink=log,
            on_source_result=on_result,
            on_source_body=_on_body,
        )
    except Exception as exc:
        log(f"[gha] FATAL: collect_subscription_nodes crashed: {type(exc).__name__}: {exc}")
        return 1

    # v61: Обновить source_tags на основе body-анализа (override URL-based tag).
    body_overrides = 0
    for url, body_tag in body_tags.items():
        url_tag = source_tags.get(url, "mixed")
        if url_tag != body_tag and body_tag != "mixed":
            source_tags[url] = body_tag
            body_overrides += 1
    if body_overrides:
        log(f"[gha] body-analysis: {body_overrides} sources reclassified "
            f"(БС/ЧС по содержимому подписки, не по URL)")

    # v61: Присваиваем каждому узлу его tag (bs/chs/mixed) из source_tags.
    tagged_count = 0
    for n in nodes:
        src_url = n.source_url or ""
        tag = source_tags.get(src_url, "mixed")
        if tag == "mixed" and src_url:
            for s, t in source_tags.items():
                if s == src_url or src_url.startswith(s.split("#")[0]):
                    tag = t
                    break
        if not n.extra:
            n.extra = {}
        n.extra["bs_chs"] = tag
        tagged_count += 1
    log(f"[gha] tagged {tagged_count} nodes with bs/chs/mixed from sources.txt + body")

    log(f"[gha] collected {len(nodes)} unique nodes (failed sources: {len(failed_sources)})")

    # v61: Debug stats — сколько конфигов дал каждый источник (топ-10).
    source_node_counts: dict[str, int] = {}
    for n in nodes:
        src = n.source_url or "?"
        # Сокращаем URL для читаемости.
        short = src.split("/")[-1] if "/" in src else src[:40]
        source_node_counts[short] = source_node_counts.get(short, 0) + 1
    if source_node_counts:
        top_sources = sorted(source_node_counts.items(),
                             key=lambda x: -x[1])[:10]
        log(f"[gha] source stats (top 10 by node count):")
        for name, count in top_sources:
            log(f"[gha]   {count:6d} configs  ← {name}")

    # v60: --vless-only — отсев НЕ-vless конфигов (trojan/ss/vmess/hy2/tuic).
    # Применяется ПОСЛЕ collect, ДО ping (чтобы не пинговать то, что всё равно отбросим).
    if args.vless_only:
        before_vless = len(nodes)
        nodes = [n for n in nodes if (n.protocol or "").lower() == "vless"]
        dropped_vless = before_vless - len(nodes)
        log(f"[gha] --vless-only: dropped {dropped_vless} non-vless nodes "
            f"(trojan/ss/vmess/hy2/tuic). Before: {before_vless}, after: {len(nodes)}")
        if not nodes:
            log("[gha] WARNING: 0 vless nodes after filter — preload.txt NOT written")
            return 1

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

    # v59: drop-geo-fallback — отбрасываем узлы с именем "🌐 peppo"
    # (geo-rename не смог определить страну). Юзер: "большая часть 🌐 peppo
    # — мертвые". Это происходит ПОСЛЕ geo-rename, но ДО --max-servers.
    if args.drop_geo_fallback and nodes:
        before_count = len(nodes)
        nodes = [n for n in nodes if n.name != "🌐 peppo"]
        dropped = before_count - len(nodes)
        log(f"[gha] --drop-geo-fallback: dropped {dropped} '🌐 peppo' nodes "
            f"(geo-rename не нашёл страну). Before: {before_count}, after: {len(nodes)}")

    # v60: SPLIT БС/ЧС СРАЗУ (до --max-servers!). Каждый список обрезается
    # независимо. Юзер: "сначала обрезал до 200 и только потом ЧС — это
    # не последовательно". Теперь: сначала разделили БС/ЧС, потом обрезали.
    bs_nodes: list[XrayNode] = []
    chs_nodes: list[XrayNode] = []
    if args.split_bs_chs:
        for n in nodes:
            tag = (n.extra or {}).get("bs_chs", "mixed")
            if tag == "chs":
                chs_nodes.append(n)
            else:  # "bs" или "mixed" → БС (по умолчанию)
                bs_nodes.append(n)
        log(f"[gha] SPLIT (before max-servers): BS={len(bs_nodes)}, "
            f"ChS={len(chs_nodes)}, total={len(nodes)}")
        # v62: --max-servers применяется к ОБАМ спискам (БС и ЧС) независимо.
        # Раньше ЧС не обрезался → в финале 387 ЧС узлов при 200 БС.
        if args.max_servers > 0 and len(bs_nodes) > args.max_servers:
            log(f"[gha] BS truncate: {len(bs_nodes)} → {args.max_servers} (--max-servers)")
            bs_nodes = bs_nodes[:args.max_servers]
        else:
            log(f"[gha] BS list: {len(bs_nodes)} nodes")
        if args.max_servers > 0 and len(chs_nodes) > args.max_servers:
            log(f"[gha] ChS truncate: {len(chs_nodes)} → {args.max_servers} (--max-servers)")
            chs_nodes = chs_nodes[:args.max_servers]
        else:
            log(f"[gha] ChS list: {len(chs_nodes)} nodes")
        # Финальный nodes = bs + chs (для preload.txt = общий список).
        nodes = bs_nodes + chs_nodes
    else:
        # Без split — как раньше, --max-servers к общему списку.
        if args.max_servers > 0 and len(nodes) > args.max_servers:
            log(f"[gha] FINAL truncate: {len(nodes)} → {args.max_servers} (--max-servers)")
            nodes = nodes[:args.max_servers]
        else:
            log(f"[gha] FINAL list: {len(nodes)} nodes (no --max-servers limit)")

    # Записываем preload.txt (общий список = bs + chs).
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')} | {len(nodes)} nodes | "
                f"sources: {len(sources)} | failed: {len(failed_sources)}\n")
        for n in nodes:
            f.write(n.raw_url + "\n")
    log(f"[gha] wrote {len(nodes)} nodes to {args.output}")

    # v60: Записываем preload_bs.txt + preload_chs.txt (раздельные списки).
    if args.split_bs_chs:
        bs_path = args.output.parent / "preload_bs.txt"
        with open(bs_path, "w", encoding="utf-8") as f:
            f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')} | BS list "
                    f"(mobile RF) | {len(bs_nodes)} nodes | "
                    f"sources: {len(sources)}\n")
            for n in bs_nodes:
                f.write(n.raw_url + "\n")
        chs_path = args.output.parent / "preload_chs.txt"
        if chs_nodes:
            with open(chs_path, "w", encoding="utf-8") as f:
                f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')} | ChS list "
                        f"(WiFi / non-RU) | {len(chs_nodes)} nodes | "
                        f"sources: {len(sources)}\n")
                for n in chs_nodes:
                    f.write(n.raw_url + "\n")
        else:
            chs_path.write_text("", encoding="utf-8")  # ПУСТОЙ — fix v2rayN
        log(f"[gha] SPLIT files: BS={len(bs_nodes)} ({bs_path.name}) + "
            f"ChS={len(chs_nodes)} ({chs_path.name})")

        # v62: ФИНАЛЬНЫЕ source stats — кто дожил до финала (после всех фильтров).
        # Это показывает, какие источники реально вкладывают рабочие конфиги.
        final_bs_counts: dict[str, int] = {}
        final_chs_counts: dict[str, int] = {}
        for n in bs_nodes:
            src = n.source_url or "?"
            short = src.split("/")[-1] if "/" in src else src[:40]
            final_bs_counts[short] = final_bs_counts.get(short, 0) + 1
        for n in chs_nodes:
            src = n.source_url or "?"
            short = src.split("/")[-1] if "/" in src else src[:40]
            final_chs_counts[short] = final_chs_counts.get(short, 0) + 1
        log(f"[gha] FINAL source stats (BS, top 10):")
        for name, count in sorted(final_bs_counts.items(), key=lambda x: -x[1])[:10]:
            log(f"[gha]   {count:6d} configs  ← {name}")
        if final_chs_counts:
            log(f"[gha] FINAL source stats (ChS, top 10):")
            for name, count in sorted(final_chs_counts.items(), key=lambda x: -x[1])[:10]:
                log(f"[gha]   {count:6d} configs  ← {name}")

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
