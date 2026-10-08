#!/usr/bin/env python3
"""GHA-совместимый CLI для обновления списков подписок.

Пайплайн (Linux, без ядер xray/sing-box):
  fetch (urllib/curl/local files) -> parse -> dedup по node.key
  -> [optional] дедуп по серверу с выбором fp=chrome/firefox
     (--dedup-by-server, default ON — ДО пинга и гео: fp-варианты одного
     сервера живут на одном host:port, TCP-результат идентичен)
  -> [optional] SNI-сортировка БС-первыми (--sort-by-sni)
  -> [optional] TCP-ping фильтр мёртвых (--with-ping; пингует УНИКАЛЬНЫЕ
     host:port — endpoint-dedup; захваченные через getpeername IP
     переиспользуются в geo-rename), порядок входа сохраняется
  -> append known_good (--known-good, фильтр через --known-good-mode)
  -> [optional] geo-переименование (--geo-rename; DNS-resolve только для
     хостов без захваченного при пинге IP — known_good и т.п.)
  -> split БС/ЧС по секциям sources.txt + протоколу (--split-bs-chs)
  -> запись preload.txt / preload_bs.txt / preload_chs.txt.

Антифейк-фильтры (ON по умолчанию; калиброваны на known_good и ручных
проверках v2rayN):
  --min-ping-ms (80) — TCP-connect < 80ms = CDN/PaaS-фейк
                       (замеры: рабочие узлы 185-320ms, CDN/Railway 10-50ms);
  --drop-cdn-ips     — IPv4-host в CDN-диапазонах = фейк
                       (403 / reality verify fail / TLS fail);
  --drop-geo-fallback — узел без гео после цепочки api.ip.sb → ip-api.com
                       → ipwho.is и без флага в имени — отбрасывается:
                       не даёт предсказуемой страны выхода (бесполезен для
                       GEO-обхода) и занимает слот в финальной подписке;
  --guess-source-type — угадывание БС/ЧС по ключевым словам в URL/теле
                       (wl/bl/white/black) для источников без явной секции.
                       Возвращено по вердикту владельца: распределение
                       соответствует реальности (e2e: BS=62/ChS=23).
                       Opt-out: --no-guess-source-type.

Недоказанные эвристики выключены по умолчанию и включаются флагами:
  --cross-dedup      — удаление из ЧС узлов с тем же host:port:proto, что в БС.

Артефакты:
  data/preload.txt         — общий итоговый список;
  data/preload_bs.txt      — БС-список (мобилка РФ) — основа subs.txt;
  data/preload_chs.txt     — ЧС-список (WiFi / не-РФ);
  data/preload_report.json — короткий отчёт;
  data/source_map.json     — URL -> источник (для статистики alive-test).

Exit codes: 0 — успех; 1 — фатальная ошибка; 2 — часть источников упала.
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
                  use_saved_subs: bool = True,
                  guess_source_type: bool = True) -> tuple[list[str], dict[str, str]]:
    """Прочитать URL'ы подписок из файла + доп. аргументы CLI + saved_subs/.

    Поведение зеркалит локальное приложение (sources_page.get_sources):
    когда use_saved_subs=True (по умолчанию, как в GUI), сканируем
    data/saved_subs/ на *.txt и *.json — добавляем их как локальные пути.
    runtime.fetch._fetch_text понимает локальные пути (Path.exists →
    читает файл напрямую).

    saved_subs/ — это каталог, куда ImportPage (вкладка «Импорт») сохраняет
    файлы с конфигами при ручном импорте. Файлы попадают туда через
    git push (GHA не имеет доступа к локальному диску).

    Файл README.txt в saved_subs/ игнорируется (как и в локальном app).

    Возвращает (sources, source_tags), где source_tags — dict[url] = "bs"|"chs"|"mixed".
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
            # Парсер секций. Когда видим "# === БС ===" — переключаемся.
            if stripped.startswith("# ==="):
                upper = stripped.upper()
                # Проверяем MIXED ПЕРВЫМ — заголовок MIXED содержит "БС"
                # в описании "по умолчанию БС", что ломает проверку.
                if "MIXED" in upper:
                    current_section = "mixed"
                elif "БС" in upper or "БЕЛЫЙ" in upper or "BS" in upper or "WHITE" in upper:
                    current_section = "bs"
                elif "ЧС" in upper or "ЧЁРНЫЙ" in upper or "CHS" in upper or "BLACK" in upper:
                    current_section = "chs"
                # Строку-разделитель пропускаем (не URL).
                continue
            # Также проверяем сам URL на ключевые слова wl/bl/alive_bs.
            # Это для источников, которые попали в MIXED секцию, но по названию
            # файла явно БС (wl.txt, alive_bs.txt, whitelist.txt) или ЧС (bl.txt).
            # Эвристика «wl/bl/white/black в имени файла = БС/ЧС» включена
            # по умолчанию (default ON, opt-out --no-guess-source-type):
            # по вердикту владельца распределение БС/ЧС соответствует
            # реальности. Явные секции (# === БС ===) работают всегда.
            if guess_source_type and (not current_section or current_section == "mixed"):
                import re as _re_mod
                url_lower = stripped.lower()
                if (_re_mod.search(r'[/_.]wl[/_.#]|[/_.]wl$', url_lower)
                        or "alive_bs" in url_lower or "whitelist" in url_lower
                        or "white" in url_lower or "бс" in url_lower):
                    add(stripped, "bs")
                    continue
                if (_re_mod.search(r'[/_.]bl[/_.#]|[/_.]bl$', url_lower)
                        or "blacklist" in url_lower or "black" in url_lower
                        or "чс" in url_lower):
                    add(stripped, "chs")
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

# Объективно не-VPN IPv4: публичные DNS-резолверы и приватные/служебные
# диапазоны. Такие host'ы в подписках — заглушки/мусор, отбрасываются всегда.
import ipaddress as _ipaddr_module
import ipaddress
_BLOCKED_IP_NETWORKS: list[_ipaddr_module.IPv4Network] = [
    # Публичные DNS-резолверы
    _ipaddr_module.ip_network("8.8.8.8/32"),
    _ipaddr_module.ip_network("8.8.4.4/32"),
    _ipaddr_module.ip_network("1.1.1.1/32"),
    _ipaddr_module.ip_network("1.0.0.1/32"),
    _ipaddr_module.ip_network("9.9.9.9/32"),
    _ipaddr_module.ip_network("149.112.112.112/32"),
    _ipaddr_module.ip_network("208.67.222.222/32"),
    _ipaddr_module.ip_network("208.67.220.220/32"),
    _ipaddr_module.ip_network("76.76.2.0/24"),
    _ipaddr_module.ip_network("76.76.10.0/24"),
    _ipaddr_module.ip_network("94.140.14.14/32"),
    _ipaddr_module.ip_network("94.140.15.15/32"),
    # Loopback / unspecified / private / link-local
    _ipaddr_module.ip_network("0.0.0.0/8"),
    _ipaddr_module.ip_network("127.0.0.0/8"),
    _ipaddr_module.ip_network("10.0.0.0/8"),
    _ipaddr_module.ip_network("172.16.0.0/12"),
    _ipaddr_module.ip_network("192.168.0.0/16"),
    _ipaddr_module.ip_network("169.254.0.0/16"),
]

# CDN-диапазоны (Cloudflare/Fastly/Akamai/CloudFront). Проверено вручную
# (v2rayN на CDN-узлах: 403, reality verification failed, TLS handshake
# failure): в публичных подписках CDN IP = фейк — TCP/TLS принимают,
# трафик не проксируют. Cloudflare Spectrum (настоящий VPN за CF) платный
# и в бесплатных подписках не встречается. Default ON
# (--no-drop-cdn-ips — отключить).
_CDN_IP_NETWORKS: list[_ipaddr_module.IPv4Network] = [
    # Cloudflare (AS13335)
    _ipaddr_module.ip_network("104.16.0.0/13"),
    _ipaddr_module.ip_network("104.24.0.0/14"),
    _ipaddr_module.ip_network("172.64.0.0/13"),
    _ipaddr_module.ip_network("188.114.96.0/20"),
    _ipaddr_module.ip_network("190.93.240.0/20"),
    _ipaddr_module.ip_network("197.234.240.0/22"),
    # Fastly (AS54113)
    _ipaddr_module.ip_network("151.101.0.0/16"),
    _ipaddr_module.ip_network("167.82.0.0/16"),
    _ipaddr_module.ip_network("199.232.0.0/16"),
    # Akamai
    _ipaddr_module.ip_network("23.0.0.0/8"),
    _ipaddr_module.ip_network("95.100.0.0/15"),
    # Amazon CloudFront
    _ipaddr_module.ip_network("13.224.0.0/14"),
    _ipaddr_module.ip_network("52.84.0.0/15"),
]

# Чёрный список доменов, которые явно НЕ VPN (gov.ua, speedtest.net, ...).
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
    # Хостинг-платформы (workers.dev/vercel/railway/render) — НЕ VPN!
    # 85 конфигов с этими доменами в BS — все мёртвые в v2rayN.
    "workers.dev",  # Cloudflare Workers
    "vercel.app",   # Vercel
    "up.railway.app",  # Railway.app
    "railway.app",
    "render.com",   # Render.com
    "onrender.com",
    "fly.dev",      # Fly.io
    "deno.dev",     # Deno Deploy
    "netlify.app",  # Netlify
    "herokuapp.com", # Heroku
    "glitch.me",    # Glitch
    "repl.co",      # Replit
})

def _is_blocked_ip(host: str, *, drop_cdn_ips: bool = False) -> bool:
    """host — IPv4 из объективно не-VPN диапазонов (DNS, private, loopback).

    drop_cdn_ips=True дополнительно проверяет CDN-диапазоны:
    CDN IP в публичных подписках = фейк (см. _CDN_IP_NETWORKS).
    """
    try:
        ip = _ipaddr_module.IPv4Address(host)
    except (ValueError, TypeError):
        return False
    for net in _BLOCKED_IP_NETWORKS:
        if ip in net:
            return True
    if drop_cdn_ips:
        for net in _CDN_IP_NETWORKS:
            if ip in net:
                return True
    return False

def _is_non_vpn_domain(host: str) -> bool:
    """host — заведомо не VPN-сервер (gov.ua, speedtest.net, ...).

    Такие домены встречаются в фейк-подписках как host (НЕ SNI — SNI может
    быть маскировкой). Проверяем точное совпадение и домен второго уровня.
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

def _is_valid_hostname(host: str, *, drop_cdn_ips: bool = False) -> bool:
    """Проверка, что host — валидное DNS-имя или IP.

    Отсекает мусор, который вызывает UnicodeError в IDNA-кодировании внутри
    socket.create_connection: метки длиннее 63 символов, пустые метки
    (последовательные точки), недопустимые символы.

    Также отбрасывает loopback/private/link-local IP из подписок-заглушек
    (мгновенный connect → фейковые "alive" в ping stats).
    """
    if not host or not isinstance(host, str):
        return False
    host = host.strip().rstrip(".")
    if not host:
        return False
    # IPv4 — без IDNA, валидируем регуляркой.
    if _IPV4_RE.match(host):
        # отбрасываем loopback / private / link-local IP.
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
        # отбрасываем CDN/DNS IP (Cloudflare, Fastly, Google DNS, ...).
        # Эти IP часто встречаются в фейк-подписках — порты 443 открыты (CDN!),
        # но vless+reality там не работает.
        if _is_blocked_ip(host, drop_cdn_ips=drop_cdn_ips):
            return False
        return True
    # IPv6 — содержит ':', валидируем как есть (с или без скобок).
    if ":" in host:
        # отбрасываем IPv6 loopback (::1) и link-local (fe80::/10).
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
    # отбрасываем localhost-домены (не валидный VPN-сервер).
    if host.lower() in ("localhost", "ip6-localhost", "ip6-loopback"):
        return False
    # отбрасываем "не VPN" домены (gov.ua, speedtest.net, google.com, ...).
    # Эти домены часто в фейк-подписках как host — gov.ua / speedtest.net /
    # baipiao.eu.org / bpminecraft.com — точно не VPN-сервера.
    if _is_non_vpn_domain(host):
        return False
    return True

def _tcp_ping_endpoint(host: str, port: int, timeout: float,
                       min_ping_ms: float = 80.0,
                       drop_cdn_ips: bool = True) -> tuple[bool, float, str]:
    """Быстрый TCP-ping одного endpoint'а (host, port).

    Просто socket.connect() с таймаутом — дешёвый фильтр мёртвых узлов
    (TCP RST / timeout / DNS-fail / IDNA-fail). Реальная проверка узла —
    alive_test.py.

    Возвращает (ok, latency_sec, resolved_ipv4). resolved_ipv4 — IP, к
    которому РЕАЛЬНО подключились (getpeername), либо "". Пинг и так
    делает DNS-resolve внутри create_connection — захватываем результат
    бесплатно и переиспользуем в --geo-rename (без повторного DNS).

    min_ping_ms > 0 — отбраковка подозрительно быстрых connect'ов:
    замеры на known_good — рабочие узлы 185-320ms; Railway/Vercel/CDN —
    10-50ms (TCP принимают, трафик не проксируют). Побочный эффект:
    US-хостинг рядом с раннером GHA тоже даёт < 80ms — принятый обмен
    для РФ-подписки.
    """
    host = (host or "").strip()
    port = int(port or 0)
    if not host or port <= 0:
        return False, 0.0, ""
    # Санитизация host ДО DNS-запроса: IDNA-некорректные имена (метка > 63,
    # пустые метки, недопустимые символы) вызывают UnicodeError из
    # encodings.idna ВНУТРИ socket.create_connection. Это ValueError, не
    # OSError — except (OSError, ...) не ловит. Отбраковываем на старте.
    if not _is_valid_hostname(host, drop_cdn_ips=drop_cdn_ips):
        return False, 0.0, ""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            latency = time.perf_counter() - t0
            if min_ping_ms > 0 and latency < min_ping_ms / 1000.0:
                return False, 0.0, ""
            # Захватываем IP подключенного сокета (для --geo-rename без
            # повторного DNS). Держим только IPv4 — гео-цепочка консистентна
            # с _resolve_host_to_ip (AF_INET).
            ip = ""
            try:
                peer = sock.getpeername()[0]
                ipaddress.IPv4Address(peer)  # валидация: IPv4 или исключение
                ip = peer
            except (OSError, ValueError, IndexError):
                pass
            return True, latency, ip
    except Exception:
        return False, 0.0, ""

def _tcp_ping(node: XrayNode, timeout: float,
              min_ping_ms: float = 80.0,
              drop_cdn_ips: bool = True) -> tuple[bool, float]:
    """Обёртка над _tcp_ping_endpoint для одиночного узла (совместимость)."""
    ok, latency, _ip = _tcp_ping_endpoint(
        (node.host or "").strip(), int(node.port or 0), timeout,
        min_ping_ms=min_ping_ms, drop_cdn_ips=drop_cdn_ips)
    return ok, latency

def _ping_filter(nodes: list[XrayNode], *, timeout: float, workers: int,
                 log_sink, max_nodes: int = 0,
                 max_ping_ms: float = 0, min_ping_ms: float = 80.0,
                 drop_cdn_ips: bool = True,
                 host_ips_out: dict[str, str] | None = None) -> list[XrayNode]:
    """Пропинговать узлы параллельно, оставить только TCP-доступные.

    ENDPOINT-DEDUP: все конфиги на одном host:port имеют ИДЕНТИЧНЫЙ
    TCP-результат (fp/sni/uuid не меняют TCP-connect) — пингуем каждый
    уникальный endpoint ОДИН раз и мапим результат на все его конфиги.
    Замер GHA 2026-10-09: 197694 конфигов → ~90k уникальных серверов —
    вдвое меньше сокетов при том же вердикте для каждого конфига.

    Порядок входного списка СОХРАНЯЕТСЯ (стабильный фильтр) — SNI-сортировка
    и порядок known_good не ломаются. Latency логируется в статистику,
    но НЕ используется для сортировки: пинг идёт с раннера GitHub (США),
    для пользователя в РФ этот порядок — шум.

    host_ips_out: если передан dict — заполняется host → IPv4 (getpeername
    успешных подключений). Используется --geo-rename'ом, чтобы НЕ делать
    повторный DNS-resolve тех же хостов (см. _geo_rename_nodes).

    max_nodes > 0: пингуем только первые max_nodes (с предупреждением —
    остальное будет ПОТЕРЯНО).
    max_ping_ms > 0: отбраковка медленных connect'ов.
    min_ping_ms > 0: отбраковка CDN/PaaS-фейков по быстрому connect (default 80).
    """
    if max_nodes > 0 and len(nodes) > max_nodes:
        log_sink(f"[gha] WARNING: --max-ping-nodes truncating ping list: "
                 f"{len(nodes)} → {max_nodes}. Неотпингованные {len(nodes) - max_nodes} "
                 f"узлов БУДУТ ПОТЕРЯНЫ. Уберите --max-ping-nodes или поставьте 0.")
        nodes = nodes[:max_nodes]

    # Группируем конфиги по уникальным endpoint'ам (host, port).
    endpoint_nodes: dict[tuple[str, int], list[XrayNode]] = {}
    for n in nodes:
        host = (n.host or "").strip()
        try:
            port = int(n.port or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or port <= 0:
            continue  # невалидный узел — до сокетов не дойдёт, будет отброшен
        endpoint_nodes.setdefault((host, port), []).append(n)
    endpoints = list(endpoint_nodes.keys())
    log_sink(f"[gha] ping: {len(nodes)} configs → {len(endpoints)} unique "
             f"host:port endpoints (endpoint-dedup, результат мапится на все конфиги)")

    alive_eps: dict[tuple[str, int], float] = {}  # endpoint -> latency
    lock = threading.Lock()
    done = 0
    total = len(endpoints)
    skipped_bad_host = 0
    slow_filtered = 0

    def probe(ep: tuple[str, int]) -> tuple[tuple[str, int], bool, float, str]:
        host, port = ep
        ok, latency, ip = _tcp_ping_endpoint(host, port, timeout,
                                             min_ping_ms=min_ping_ms,
                                             drop_cdn_ips=drop_cdn_ips)
        return ep, ok, latency, ip

    with ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="ping") as ex:
        futures = {ex.submit(probe, ep): ep for ep in endpoints}
        for fut in as_completed(futures):
            ep, ok, latency, ip = fut.result()
            done += 1
            with lock:
                if ok:
                    if max_ping_ms > 0 and latency > max_ping_ms / 1000.0:
                        slow_filtered += 1
                    else:
                        alive_eps[ep] = latency
                        if host_ips_out is not None and ip and ep[0] not in host_ips_out:
                            host_ips_out[ep[0]] = ip
                else:
                    if not _is_valid_hostname(ep[0], drop_cdn_ips=drop_cdn_ips):
                        skipped_bad_host += 1
            # Лог не чаще каждых 500 endpoint'ов (90k/25 = 3600 строк —
            # старый прогресс-спам раздувал логи GHA).
            if done % 500 == 0 or done == total:
                alive_count = len(alive_eps)
                log_sink(f"[gha] ping progress {done}/{total} endpoints ({alive_count} alive"
                         + (f", {slow_filtered} slow (>{max_ping_ms:g}ms)" if max_ping_ms > 0 else "")
                         + (f", {skipped_bad_host} bad-host" if skipped_bad_host else "")
                         + ")")

    # Мапим результат endpoint'а обратно на конфиги (в исходном порядке).
    def _ep_of(n: XrayNode) -> tuple[str, int] | None:
        host = (n.host or "").strip()
        try:
            port = int(n.port or 0)
        except (TypeError, ValueError):
            return None
        if not host or port <= 0:
            return None
        return (host, port)

    alive_ep_set = set(alive_eps)
    result = [n for n in nodes if _ep_of(n) in alive_ep_set]

    latencies = sorted(alive_eps.values())
    if latencies:
        p50 = latencies[len(latencies) // 2]
        p95 = latencies[int(len(latencies) * 0.95)] if len(latencies) > 1 else latencies[0]
        log_sink(f"[gha] ping stats: p50={p50*1000:.0f}ms p95={p95*1000:.0f}ms "
                 f"max={latencies[-1]*1000:.0f}ms ({len(latencies)} alive endpoints"
                 + (f", {slow_filtered} slow filtered (>{max_ping_ms:g}ms)" if max_ping_ms > 0 and slow_filtered > 0 else "")
                 + ")")
        for ep, lat in list(alive_eps.items())[:3]:
            log_sink(f"[gha]   fastest-sample: {lat*1000:.0f}ms  {ep[0]}:{ep[1]}")

    return result

# ---------------------------------------------------------------------- geo

# Кеш IP → (country_code, flag) для geo-переименования.
# Сильная дедупликация: 10000 узлов на ~5 уникальных CDN-IP = 5 запросов вместо 10k.
_geo_cache: dict[str, tuple[str, str]] = {}
_geo_cache_lock = threading.Lock()

# fallback если вся цепочка провайдеров (api.ip.sb → ip-api.com → ipwho.is)
# недоступна / rate-limit / невалидный IP. Если страна не определена
# (цепочка fail и в имени нет флага) —
_GEO_FALLBACK_CODE = "🌐"   # Земной шар вместо "??" + "🏳"
_GEO_FALLBACK_FLAG = "🌐"

# Региональные indicator-символы для emoji-флагов.
# U+1F1E6 = 'A' (regional indicator A), U+1F1FF = 'Z'.
# Emoji-флаг = 2 таких символа → "🇩🇪" → "DE".
_REGIONAL_INDICATOR_A = 0x1F1E6

def _extract_flag_from_name(name: str) -> tuple[str, str] | None:
    """Извлечь emoji-флаг из имени узла, вернуть (flag, iso_code) или None.

    Emoji-флаг = 2 региональных indicator-символа (U+1F1E6..U+1F1FF).
    Например "🇩🇪" = U+1F1E9 + U+1F1EA = 'D' + 'E' → "DE".

    Используется когда цепочка провайдеров НЕ смогла определить страну
    (DNS-resolve fail для РФ-доменов на Azure US, rate-limit). Берём флаг
    из оригинального имени (например "Литва 🇱🇹" → 🇱🇹 → "LT") → итоговое имя "🇱🇹 LT peppo".
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

    Используется для geo-lookup'а: провайдеры гео принимают только IP,
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
    """Гео IP: цепочка api.ip.sb → ip-api.com → ipwho.is (subgen.geo).

    Возвращает (code, flag); вся цепочка не смогла → ("🌐", "🌐").
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
                      log_sink, known_ips: dict[str, str] | None = None) -> None:
    """Переименовать узлы как основное приложение: «<флаг> <ISO> peppo».

    ВХОД: список XrayNode (mutates node.name + node.raw_url).
    Гео берётся через цепочку провайдеров (api.ip.sb → ip-api.com → ipwho.is)
    для host узла (IP берётся напрямую, для домена — DNS-resolve). Кеш по IP —
    до 10000 узлов делают ~5000 запросов (IP дублируются у CDN-узлов).

    ЗАЧЕМ DNS-RESOLVE ВООБЩЕ: гео-провайдеры принимают только IP, не домен —
    чтобы узнать страну узла, нужно сначала узнать его IP. Но TCP-ping и так
    резолвит каждый host внутри socket.create_connection — поэтому с v7
    успешные подключения захватывают свой IP (getpeername) и передаются сюда
    через known_ips: для этих хостов DNS-резолв ПРОПУСКАЕТСЯ. Реальный DNS
    остаётся только для known_good-узлов (не проходили пинг) и хостов,
    чей endpoint был мёртв (их и так нет в финале).

    Имя формата: «🇩🇪 DE peppo» (с пробелом перед peppo, как в serialize_working).
    На fallback (geo недоступно): «🌐 peppo» (земля вместо "??").
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

    # Собираем уникальные хосты → IP.
    # Сначала берём IP, уже захваченные во время TCP-ping (getpeername) —
    # для них DNS-resolve НЕ нужен (см. докстринг).
    unique_hosts = {n.host for n in nodes if n.host}
    host_to_ip: dict[str, str] = {}
    to_resolve: list[str] = []
    reused_from_ping = 0
    for h in unique_hosts:
        known = (known_ips or {}).get(h, "")
        if known:
            host_to_ip[h] = known
            reused_from_ping += 1
        else:
            to_resolve.append(h)
    if known_ips:
        log_sink(f"[gha] --geo-rename: {reused_from_ping}/{len(unique_hosts)} hosts "
                 f"reuse IPs captured during ping (no DNS needed)")
    if not to_resolve:
        log_sink(f"[gha] --geo-rename: DNS-resolve skipped — all IPs known from ping")
    else:
        log_sink(f"[gha] --geo-rename: DNS-resolve {len(to_resolve)} hosts "
                 f"(known_good / непингованные)")

        # Резолвим домены параллельно (IP-хосты проходят instantly).
        def _resolve_one(host: str) -> tuple[str, str]:
            return host, _resolve_host_to_ip(host, timeout=min(3.0, timeout))

        resolved_count = 0
        failed_resolve = 0
        with ThreadPoolExecutor(max_workers=max(4, workers), thread_name_prefix="dns") as ex:
            futures = {ex.submit(_resolve_one, h): h for h in to_resolve}
            for fut in as_completed(futures):
                host, ip = fut.result()
                host_to_ip[host] = ip
                resolved_count += 1
                if not ip:
                    failed_resolve += 1
                if resolved_count % 50 == 0 or resolved_count == len(to_resolve):
                    log_sink(f"[gha] --geo-rename: DNS-resolve progress "
                             f"{resolved_count}/{len(to_resolve)} ({failed_resolve} failed)")
        log_sink(f"[gha] --geo-rename: DNS done, {len(to_resolve) - failed_resolve} resolved, "
                 f"{failed_resolve} failed")

    # Уникальные IP → geo lookup (кеш; цепочка api.ip.sb → ip-api.com → ipwho.is).
    unique_ips = {ip for ip in host_to_ip.values() if ip}
    log_sink(f"[gha] --geo-rename: looking up {len(unique_ips)} unique IPs")

    # Для каждого IP — запрос к цепочке провайдеров (см. _geoip_lookup_ip).
    # Лимит параллелизма — 8 (api.ip.sb может rate-limit'ить; отказ провайдера
    # уходит следующему по цепочке).
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
    # ВСЕ узлы получают "peppo" формат. Если цепочка определила страну —
    # "🇩🇪 DE peppo". Если НЕ определила (DNS-resolve fail для РФ-доменов
    # на Azure US, или rate-limit) — извлекаем emoji-флаг из оригинального имени
    # (например "Литва 🇱🇹" → 🇱🇹 → "LT") → итоговое имя "🇱🇹 LT peppo".
    # Если в имени флага нет → настоящий fallback "🌐 peppo".
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
            # Цепочка определила страну → "🇩🇪 DE peppo".
            new_name = f"{flag} {code} peppo"
            renamed_count += 1
        else:
            # Цепочка не смогла. Пытаемся извлечь флаг из оригинального
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

    log_sink(f"[gha] --geo-rename: {renamed_count} renamed (chain ip.sb→ip-api→ipwho), "
             f"{flag_from_name_count} from name (flag extracted), "
             f"{real_fallback_count} real fallback (no flag)")

# ---------------------------------------------------------------------- dedup

def _dedup_by_server(nodes: list[XrayNode], log_sink, label: str) -> list[XrayNode]:
    """Дедупликация по серверу (host:port:pbk:sid:sni) — держать fp=chrome+firefox.

    Один сервер с 5-49 разными fp — оставляем только chrome и firefox
    (если их нет — первый попавшийся). Вызывается ДО TCP-ping и geo-rename
    (по вердикту владельца: незачем 5 раз пинговать/резолвить один сервер —
    fp не меняет ни TCP-connect, ни IP). Порядок внутри — по первому
    вхождению группы; SNI-сортировка ниже наведёт итоговый порядок.
    """
    groups: dict[str, list[XrayNode]] = {}
    for n in nodes:
        key = f"{n.host}:{n.port}:{n.query.get('pbk','')}:{n.query.get('sid','')}:{n.query.get('sni','')}"
        groups.setdefault(key, []).append(n)
    deduped: list[XrayNode] = []
    for group in groups.values():
        chrome = [n for n in group if (n.query.get("fp") or "").lower() == "chrome"]
        firefox = [n for n in group if (n.query.get("fp") or "").lower() == "firefox"]
        kept = []
        if chrome:
            kept.append(chrome[0])  # первый chrome
        if firefox:
            kept.append(firefox[0])  # первый firefox
        if not kept:
            # Нет chrome/firefox — оставляем первый (random/qq/safari)
            kept = [group[0]]
        deduped.extend(kept)
    log_sink(f"[gha] {label} server-dedup: {len(nodes)} → {len(deduped)} "
             f"({len(nodes) - len(deduped)} duplicates removed, kept chrome+firefox per server)")
    return deduped

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
    # --extra-sources-file — мёрджит доп. файл (например data/tg_subs.txt,
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
    p.add_argument("--min-ping-ms", type=float, default=80,
                   help="Отбраковка подозрительно быстрых TCP-connect (мс). "
                        "Калибровка на known_good: рабочие узлы 185-320ms, "
                        "CDN/Railway/Vercel 10-50ms (TCP ок, прокси нет). "
                        "Default 80, 0 = выключено. Побочка: US-хостинг "
                        "рядом с раннером GHA отбрасывается.")
    p.add_argument("--max-ping-ms", type=float, default=2000,
                   help="Максимальный TCP-connect (latency), мс. Узлы с ping выше "
                        "этого значения отбраковываются (FakeDNS/медленные серверы). "
                        "Default 2000 — по вердикту владельца (1000 был слишком "
                        "жёстким: GHA-замер 2026-10-09 — p50=173ms p95=424ms "
                        "max=997ms у живых + 764 узла срезано в диапазоне "
                        "1000-1500ms). 0 = без лимита. ВАЖНО: --ping-timeout "
                        "должен быть БОЛЬШЕ этого значения (connect дольше "
                        "таймаута убивается таймаутом раньше фильтра).")
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
                   help="(УСТАРЕЛО: cidr_check по умолчанию False) "
                        "Алиас для дефолтного поведения — не проверять IP-CIDR. "
                        "Оставлен для обратной совместимости.")
    p.add_argument("--tspu-sim-strict-cidr", action="store_true",
                   help="(с --tspu-sim) ВКЛЮЧИТЬ IP-CIDR проверку (по умолчанию OFF). "
                        "Только для полного blackout'а (когда TSPU whitelist'ит весь интернет). "
                        "По умолчанию OFF — убивает все зарубежные VPN-серверы "
                        "потому что их IP не в BS-CIDR. SNI blacklist достаточно "
                        "для обычного ограниченного режима.")
    p.add_argument("--geo-rename", action="store_true",
                   help="Переименовать узлы как основное приложение: "
                        "«<флаг> <ISO-код> peppo» (например, «🇩🇪 DE peppo»). "
                        "Гео — цепочка api.ip.sb → ip-api.com → ipwho.is; "
                        "запрос ИДЁТ ИЗ GHA, не через прокси узла (GHA на Azure US/EU). "
                        "Для доменных host'ов делается DNS-resolve. "
                        "Кеш по IP (10000 узлов = ~10000 запросов, но IP дублируются → ~5000). "
                        "Без --geo-rename узлы пишутся как есть.")
    p.add_argument("--geo-rename-workers", type=int, default=8,
                   help="Параллелизм geo-lookup (по умолчанию: 8). "
                        "Больше — быстрее; отказ провайдера уходит следующему по цепочке.")
    p.add_argument("--geo-rename-timeout", type=float, default=8.0,
                   help="Таймаут одного geo-запроса, сек (по умолчанию: 8.0).")
    # known-good patterns — фильтр по проверенным на мобилке конфигам.
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
    # Дедупликация по серверу (host:port:pbk:sid:sni).
    # Оставляет только fp=chrome и fp=firefox на каждый уникальный сервер.
    p.add_argument("--dedup-by-server", action="store_true", default=True,
                   help="Дедуплицировать по host:port:pbk:sid:sni. "
                        "Оставлять только fp=chrome и fp=firefox на сервер. "
                        "Default: ON. Работает В НАЧАЛЕ пайплайна (сразу после "
                        "сбора, ДО TCP-ping и geo-rename): fp-варианты одного "
                        "сервера живут на одном host:port — TCP-результат "
                        "идентичен, пинговать каждый незачем.")
    p.add_argument("--no-dedup-by-server", dest="dedup_by_server",
                   action="store_false",
                   help="НЕ дедуплицировать (все fp остаются).")
    # Разделение финала на БС (мобилка РФ) и ЧС (WiFi / не-RU).
    # На мобильной сети РФ ТСПУ блокирует ЧС-SNI (instagram, chatgpt, ...).
    # На WiFi / вне РФ — ЧС-SNI работает (нет ТСПУ). Поэтому делим финал:
    #   preload_bs.txt  — БС + серый + фейк + none (НЕ ЧС) → для мобилки РФ
    #   preload_chs.txt — ТОЛЬКО ЧС-SNI → для WiFi / не-RU
    # subs.txt (в GHA workflow) = preload_bs.txt (base64).
    p.add_argument("--split-bs-chs", action="store_true", default=True,
                   help="Разделить финал на 2 файла: preload_bs.txt (БС+серый+фейк+none, "
                        "для мобилки РФ) и preload_chs.txt (только ЧС-SNI, для WiFi/не-RU). "
                        "Default: ON — две подписки под разный тип сети.")
    p.add_argument("--no-split-bs-chs", dest="split_bs_chs",
                   action="store_false",
                   help="НЕ разделять на БС/ЧС. Только preload.txt (как в v48).")
    p.add_argument("--cross-dedup", action="store_true", default=False,
                   help="Убирать из ЧС-списка узлы с тем же (host, port, "
                        "protocol), что уже есть в БС. Default OFF: разные "
                        "credential на одном сервере — это разные конфиги.")
    # --drop-geo-fallback — отбрасывать узлы «🌐 peppo»: гео не определилось
    # после цепочки api.ip.sb → ip-api.com → ipwho.is И в имени нет флага.
    # Обоснование: такой узел не даёт предсказуемой страны выхода — бесполезен
    # для GEO-обхода (не поможет сменить IP) и занимает слот в финальной
    # подписке, который мог занять узел с флагом. Замер v59: большая часть
    # «🌐 peppo» — мёртвые.
    p.add_argument("--drop-geo-fallback", action="store_true", default=True,
                   help="Отбрасывать узлы, у которых гео не определилось после "
                        "цепочки api.ip.sb → ip-api.com → ipwho.is и в имени "
                        "нет флага (имя '🌐 peppo'). Обоснование: бесполезен "
                        "для GEO-обхода, занимает слот в финальной подписке; "
                        "по замерам v59 большая часть — мёртвые. Default: ON.")
    p.add_argument("--no-drop-geo-fallback", dest="drop_geo_fallback",
                   action="store_false",
                   help="НЕ отбрасывать '🌐 peppo' узлы (оставить в финале).")
    # --vless-only — собирать ТОЛЬКО vless:// конфиги (отсев trojan/ss/vmess/hy2/tuic).
    p.add_argument("--vless-only", action="store_true", default=False,
                   help="Собирать ТОЛЬКО vless:// конфиги. Все trojan/ss/vmess/"
                        "hysteria2/tuic отбрасываются. Default: OFF (все протоколы).")
    # saved_subs/ — авто-мёрдж (как в локальном GUI по умолчанию).
    # GHA автоматически их подхватывает. --no-saved-subs чтобы выключить.
    p.add_argument("--saved-subs-dir", type=Path,
                   default=REPO / "data" / "saved_subs",
                   help="Каталог с локально-сохранёнными конфигами (data/saved_subs "
                        "по умолчанию). Все *.txt и *.json (кроме README.txt) "
                        "авто-добавляются к списку источников. Зеркалит локальный "
                        "GUI (sources_page._use_saved_subs = True).")
    p.add_argument("--drop-cdn-ips", action=argparse.BooleanOptionalAction,
                   default=True,
                   help="Отбрасывать узлы с IPv4-host в CDN-диапазонах "
                        "(Cloudflare/Fastly/Akamai/CloudFront). Проверено "
                        "вручную: CDN IP в публичных подписках = фейк "
                        "(403 / reality verify fail / TLS fail). Default ON, "
                        "отключается --no-drop-cdn-ips.")
    p.add_argument("--guess-source-type", action=argparse.BooleanOptionalAction,
                   default=True,
                   help="Угадывать БС/ЧС по ключевым словам в URL (wl/bl/"
                        "white/black) и теле подписки — для источников без "
                        "явной секции. Default ON по вердикту владельца: "
                        "распределение БС/ЧС соответствует реальности (e2e: "
                        "BS=62/ChS=23). Явные секции sources.txt работают "
                        "всегда. Отключается --no-guess-source-type.")
    p.add_argument("--no-saved-subs", action="store_true",
                   help="Не мёрджить saved_subs/ в источники. По умолчанию ON — "
                        "повторяет поведение GUI (тумблер «Использовать импортированные "
                        "подписки (data/saved_subs/)» ON по умолчанию).")
    args = p.parse_args(argv)

    def log(msg: str) -> None:
        print(msg, flush=True)

    # 1) Читаем источники.
    # авто-мёрджим saved_subs/*.txt + *.json — как в локальном GUI
    # (sources_page.get_sources с тумблером _use_saved_subs=True по умолчанию).
    saved_subs_dir = args.saved_subs_dir if not args.no_saved_subs else None
    # extra_sources — URL'ы из доп. файла (--extra-sources-file).
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
                                          use_saved_subs=not args.no_saved_subs,
                                          guess_source_type=args.guess_source_type)
    if not sources:
        log("[gha] FATAL: sources list is empty")
        return 1
    # Логируем классификацию источников по секциям.
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
        # Сниффинг тела подписки на слова "white"/"black" — угадывание
        # БС/ЧС для источников без явной секции. Default ON по вердикту
        # владельца (распределение соответствует реальности, e2e: BS=62/"
        # ChS=23); opt-out --no-guess-source-type. Переклассификация
        # логируется ниже (body-analysis: N reclassified).
        body_tags: dict[str, str] = {}
        if args.guess_source_type:
            def _on_body(url: str, body: str) -> None:
                head = body[:5000].lower()
                has_white = any(w in head for w in (
                    "white", "бс", "белый", "белые", "whitelist",
                    "wl list", "white list", "белые списки", "бс список",
                ))
                has_black = any(w in head for w in (
                    "black", "чс", "чёрный", "чёрные", "blacklist",
                    "bl list", "black list", "чёрные списки", "чс список",
                ))
                if has_white and not has_black:
                    body_tags[url] = "bs"
                elif has_black and not has_white:
                    body_tags[url] = "chs"
        else:
            _on_body = None

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

    # Обновить source_tags на основе body-анализа (override URL-based tag).
    body_overrides = 0
    for url, body_tag in body_tags.items():
        url_tag = source_tags.get(url, "mixed")
        if url_tag != body_tag and body_tag != "mixed":
            source_tags[url] = body_tag
            body_overrides += 1
    if body_overrides:
        log(f"[gha] body-analysis: {body_overrides} sources reclassified "
            f"(БС/ЧС по содержимому подписки, не по URL)")

    # Присваиваем каждому узлу его tag (bs/chs/mixed) из source_tags.
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

    # Debug stats — сколько конфигов дал каждый источник (топ-10).
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

    # ДЕДУП ПО СЕРВЕРУ — В НАЧАЛЕ ПАЙПЛАЙНА (по вердикту владельца v7:
    # «дедупликаты логично проводить в начале, а не в конце»). fp-варианты
    # одного сервера (chrome/firefox/safari/qq) живут на одном host:port —
    # TCP-результат у них ИДЕНТИЧЕН, поэтому дедуп ДО пинга срезает ~50%
    # сокетов (замер GHA 2026-10-09: BS 10211→4717, ChS 8381→4414), а
    # geo-rename получает меньше уникальных хостов. Порядок наводится
    # SNI-сортировкой ниже. known_good-узлы аппендятся ПОЗЖЕ пинга и этому
    # дедупу не подвергаются — конфиги проверены владельцем вручную.
    if args.dedup_by_server and nodes:
        nodes = _dedup_by_server(nodes, log, "pool")

    # --vless-only — отсев НЕ-vless конфигов (trojan/ss/vmess/hy2/tuic).
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
            # cidr_check по умолчанию OFF. Включается только через --tspu-sim-strict-cidr.
            # Причина: GHA на Azure US/EU, IP-CIDR проверка убивает все зарубежные VPN.
            use_cidr = bool(getattr(args, 'tspu_sim_strict_cidr', False))
            if cidr_count == 0 and use_cidr:
                log("[gha] WARNING: data/cidr_whitelist.txt пуст — TSPU-sim strict-cidr "
                    "не работает. Запустите scripts/sync_sni_whitelist.py --with-cidr.")
            tspu_summary_dict = _tspu_summary(nodes)
            log(f"[gha] --tspu-sim breakdown: {tspu_summary_dict}")
            before = len(nodes)
            # Фильтруем: reject только ЧС-SNI (instagram/chatgpt) + fake + empty.
            # Серые/белые SNI + ЛЮБОЙ IP → PASS (cidr_check=False по умолчанию).
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

    # 4) Опциональный TCP-ping — дешёвый фильтр мёртвых TCP-эндпоинтов.
    #    Порядок узлов СОХРАНЯЕТСЯ (SNI-сортировка не ломается).
    #    Пингуем уникальные host:port; успешные подключения захватывают IP
    #    (getpeername) — он переиспользуется в geo-rename без повторного DNS.
    ping_host_ips: dict[str, str] = {}  # host -> IPv4 с пинга (для --geo-rename)
    if args.with_ping and nodes:
        log(f"[gha] TCP-ping {len(nodes)} nodes (workers={args.ping_workers}, "
            f"timeout={args.ping_timeout}s"
            + (f", min_ping={args.min_ping_ms:g}ms" if args.min_ping_ms > 0 else "")
            + (f", max_nodes={args.max_ping_nodes}" if args.max_ping_nodes > 0 else "")
            + (f", max_ping={args.max_ping_ms:g}ms" if args.max_ping_ms > 0 else "")
            + ")")
        alive = _ping_filter(nodes, timeout=args.ping_timeout,
                             workers=args.ping_workers, log_sink=log,
                             max_nodes=args.max_ping_nodes,
                             max_ping_ms=args.max_ping_ms,
                             min_ping_ms=args.min_ping_ms,
                             drop_cdn_ips=args.drop_cdn_ips,
                             host_ips_out=ping_host_ips)
        log(f"[gha] ping: {len(alive)}/{len(nodes)} alive "
            f"({len(ping_host_ips)} host IPs captured для geo-rename)")
        nodes = alive

    # 5) --max-servers применяется в самом конце (после geo-rename и сплита).

    # 5b) known-good: append проверенных вручную конфигов в финал.
    #     Фильтр по паттернам включается через --known-good-mode (в GHA — none).
    kg_nodes_to_append: list[XrayNode] = []
    if args.known_good:
        nodes, kg_nodes_to_append = _apply_known_good_filter(
            nodes, args.known_good,
            mode=args.known_good_mode,
            ip_prefix=args.known_good_ip_prefix,
            log_sink=log,
        )
        # Append known_good configs (проверены вручную) в финал preload.txt.
        # Дедуп: не добавляем если уже в nodes (по node.key).
        existing_keys = {n.key for n in nodes}
        for kg in kg_nodes_to_append:
            if kg.key not in existing_keys:
                nodes.append(kg)
                existing_keys.add(kg.key)
        if kg_nodes_to_append:
            log(f"[gha] --known-good: appended {len(kg_nodes_to_append)} verified configs "
                f"to final list (total now: {len(nodes)})")

    if not nodes:
        log("[gha] WARNING: 0 nodes after filter — preload.txt NOT written (existing file kept)")
        return 1

    # 6) Опциональное geo-переименование: «<флаг> <ISO-код> peppo» как в основном
    #    приложении (subgen.geo.serialize_working). Гео — цепочка провайдеров
    #    (api.ip.sb → ip-api.com → ipwho.is). Запрос идёт ИЗ GHA
    #    (не через прокси узла), для доменных host'ов делается DNS-resolve.
    if args.geo_rename and nodes:
        _geo_rename_nodes(
            nodes,
            workers=args.geo_rename_workers,
            timeout=args.geo_rename_timeout,
            log_sink=log,
            known_ips=ping_host_ips,
        )

    # drop-geo-fallback: узел без гео после цепочки провайдеров и без флага
    # в имени → бесполезен для GEO-обхода, жрёт слот в финальной подписке.
    if args.drop_geo_fallback and nodes:
        before_count = len(nodes)
        nodes = [n for n in nodes if n.name != "🌐 peppo"]
        dropped = before_count - len(nodes)
        log(f"[gha] --drop-geo-fallback: dropped {dropped} '🌐 peppo' nodes "
            f"(гео неизвестно после цепочки ip.sb/ip-api/ipwho + нет флага "
            f"в имени). Before: {before_count}, after: {len(nodes)}")

    # SPLIT БС/ЧС СРАЗУ (до --max-servers!). Каждый список обрезается
    # не последовательно". Теперь: сначала разделили БС/ЧС, потом обрезали.
    bs_nodes: list[XrayNode] = []
    chs_nodes: list[XrayNode] = []
    if args.split_bs_chs:
        # SPLIT по source_tag + протоколу.
        # БС = только из явных БС-источников (WHITE*/бс) + vless+reality/tls/hy2/tuic.
        # ЧС-источники = ЧС.
        for n in nodes:
            proto = (n.protocol or "").lower()
            security = (n.query.get("security") or "").lower()
            sni = (n.query.get("sni") or n.query.get("host") or "").strip()
            tag = (n.extra or {}).get("bs_chs", "mixed")
            
            is_vless_encrypted = proto == "vless" and security in ("reality", "tls")
            is_udp_proto = proto in ("hysteria2", "hy2", "tuic")
            is_bs_protocol = (is_vless_encrypted and sni) or is_udp_proto
            
            # БС = явный БС-источник AND БС-протокол.
            # MIXED → ЧС (не пихать тысячи мусорных конфигов в БС).
            if tag == "bs" and is_bs_protocol:
                bs_nodes.append(n)
            else:
                chs_nodes.append(n)
        log(f"[gha] SPLIT (before max-servers): BS={len(bs_nodes)}, "
            f"ChS={len(chs_nodes)}, total={len(nodes)}")

        # Дедуп по серверу перенесён В НАЧАЛО пайплайна (см. вызов
        # _dedup_by_server сразу после collect) — по вердикту владельца v7.
        # Здесь остаётся только cross-dedup и обрезка --max-servers.

        # Cross-dedup БС↔ЧС по (host, port, protocol) — по умолчанию ВЫКЛ:
        # host:port:proto ≠ идентичность конфига (разные uuid = разные аккаунты
        # на том же сервере). Включается флагом --cross-dedup.
        if args.cross_dedup:
            bs_keys = {(n.host, str(n.port), n.protocol) for n in bs_nodes}
            chs_before = len(chs_nodes)
            chs_nodes = [n for n in chs_nodes
                         if (n.host, str(n.port), n.protocol) not in bs_keys]
            chs_dedup = chs_before - len(chs_nodes)
            if chs_dedup:
                log(f"[gha] cross-dedup BS↔ChS: removed {chs_dedup} duplicates from ChS")
        # --max-servers применяется к ОБАМ спискам (БС и ЧС) независимо.
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

    # Записываем preload_bs.txt + preload_chs.txt (раздельные списки).
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

        # Записать source_map.json — маппинг URL → source_url.
        # alive_test.py использует это для статистики alive/dead по источникам.
        source_map: dict[str, str] = {}
        for n in bs_nodes + chs_nodes:
            src = n.source_url or "?"
            short = src.split("/")[-1] if "/" in src else src[:40]
            source_map[n.raw_url] = short
        sm_path = args.output.parent / "source_map.json"
        sm_path.write_text(json.dumps(source_map, ensure_ascii=False),
                            encoding="utf-8")
        log(f"[gha] wrote source_map.json ({len(source_map)} entries) "
            f"for alive_test source tracking")

        # ФИНАЛЬНЫЕ source stats — кто дожил до финала (после всех фильтров).
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
