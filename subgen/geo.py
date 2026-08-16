"""Geoip: lookup страны по IP через api.ip.sb + кеш + эмодзи-флаги."""
from __future__ import annotations

import json
import re
import threading
import time

from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen

from subgen.config import (
    FLAG_EMOJI,
    GEOIP_API,
    GEOIP_FALLBACK_CODE,
    GEOIP_FALLBACK_FLAG,
    GEOIP_MAX_RATE_PER_SEC,
)
from xray_runtime import XrayNode

_geo_lock = threading.Lock()
_geo_cache: dict[str, tuple[str, str]] = {}  # ip -> (country_code, flag)

# Хинт о стране выхода из path узла: /pyip=ProxyIP.JP.CMLiussss.net и т.п.
# Это реальная страна egress-сервера (указывает провайдер подписки), в отличие
# от host, который у многих узлов — фронтовый Cloudflare-адрес (регистрация US).
_PYIP_PATTERN = re.compile(
    r"pyip\s*=\s*(?:ProxyIP\.)?([A-Z]{2,3})(?=[.\s]|$)",
    re.IGNORECASE,
)
# Дополнительные типовые поля, где подписочники указывают страну выхода.
_EXTRA_COUNTRY_PATTERNS = (
    r"country\s*=\s*([A-Z]{2})",
    r"region\s*=\s*([A-Z]{2})",
)
_EGRESS_PROBES = (
    ("api.ip.sb", 443, "api.ip.sb", "/ip"),
    ("ipinfo.io", 443, "ipinfo.io", "/ip"),
    ("ifconfig.me", 443, "ifconfig.me", "/ip"),
    ("icanhazip.com", 443, "icanhazip.com", "/"),
)
_EGRESS_SAMPLE_SECONDS = 1.5



def load_geo_cache(geo_cache_path) -> dict[str, tuple[str, str]]:
    """Загрузить geo-кеш из файла (если есть и валиден)."""
    geo_cache: dict[str, tuple[str, str]] = {}
    if geo_cache_path.exists():
        try:
            raw = json.loads(geo_cache_path.read_text(encoding="utf-8"))
        except Exception:
            return geo_cache
        if isinstance(raw, dict):
            for key, value in raw.items():
                if isinstance(value, list) and len(value) == 2:
                    geo_cache[key] = (str(value[0]), str(value[1]))
    return geo_cache


def country_flag(code: str) -> str:
    """Двухбуквенный ISO-код -> эмодзи-флаг (региональные индикаторы)."""
    code = str(code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return GEOIP_FALLBACK_FLAG
    known = FLAG_EMOJI.get(code)
    if known:
        return known
    # Универсальный вариант: строим из двух букв.
    base = 0x1F1E6
    try:
        return "".join(chr(base + ord(letter) - ord("A")) for letter in code)
    except Exception:
        return GEOIP_FALLBACK_FLAG


def geoip_lookup(ip: str, *, timeout: float) -> tuple[str, str]:
    """Вернуть (country_code, flag) для IP через https://api.ip.sb/geoip.

    Кешируется по IP. При любой ошибке/лимите возвращается fallback.
    """
    ip = str(ip or "").strip()
    with _geo_lock:
        cached = _geo_cache.get(ip)
    if cached is not None:
        return cached
    result = (GEOIP_FALLBACK_CODE, GEOIP_FALLBACK_FLAG)
    try:
        request = Request(
            GEOIP_API.format(ip=ip),
            headers={
                "User-Agent": "MTProxyAutoSwitch-sub-generator/1.0",
                "Accept": "application/json",
            },
        )
        with urlopen(request, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        code = str((payload or {}).get("country_code") or "").strip().upper()
        if len(code) == 2 and code.isalpha():
            result = (code, country_flag(code))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        result = (GEOIP_FALLBACK_CODE, GEOIP_FALLBACK_FLAG)
    with _geo_lock:
        _geo_cache[ip] = result
    return result


def rate_limit_sleep(last_call: list[float]) -> None:
    """Соблюдаем лимит api.ip.sb (до 5 запросов/сек)."""
    with _geo_lock:
        now = time.monotonic()
        elapsed = now - last_call[0]
        min_interval = 1.0 / GEOIP_MAX_RATE_PER_SEC
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        last_call[0] = time.monotonic()


def node_ip(node: XrayNode) -> str:
    """Хост для geoip: если это IPv4/IPv6 — как есть, иначе DNS-имя.

    api.ip.sb принимает и DNS-имена (resolve самостоятельно), но rate-limit
    и кеш удобнее держать по строке хоста.
    """
    return node.host


def _node_text(node: XrayNode) -> str:
    """Декодированный текст узла для поиска хинтов о стране."""
    raw = node.raw_url or ""
    if node.protocol == "vmess":
        decoded = _b64decode(raw.split("://", 1)[1])
        return decoded or raw
    return raw


def pyip_hint(node: XrayNode) -> str:
    """Страна выхода из метаданных узла (pyip=ProxyIP.JP... и т.п.).

    У многих узлов из подписок host — фронтовый Cloudflare-адрес
    (регистрация US), а реальный egress-сервер указан в path как
    ``pyip=ProxyIP.JP.CMLiussss.net`` (JP/KR/SG/US). Провайдер подписки
    именно эту страну считает страной выхода — она совпадает с тем,
    что видят hiddify/2ip.

    Возвращает двухбуквенный код страны или "" если хинта нет.
    """
    text = _node_text(node)
    decoded_url = unquote(text)
    for source in (decoded_url, text):
        match = _PYIP_PATTERN.search(source)
        if match:
            code = match.group(1).upper()
            if len(code) == 2:
                return code
        for pattern in _EXTRA_COUNTRY_PATTERNS:
            match = re.search(pattern, source, re.IGNORECASE)
            if match:
                code = match.group(1).upper()
                if len(code) == 2:
                    return code
    return ""


def egress_ip_via_node(node: XrayNode, *, timeout: float) -> str:
    """Реальный egress-IP узла: поднять прокси и спросить ``/ip``-эндпоинты.

    Точный метод: страна определяется по фактическому IP выхода через узел,
    а не по host (который у многих — Cloudflare front). Медленнее pyip-хинта
    (поднимает временный core-процесс), поэтому используется как fallback
    для узлов без pyip-метаданных.
    """
    if not node.raw_url:
        return ""

    def _probe(socks_host: str, socks_port: int) -> str:
        from checkers.base import http_get_body

        for target_host, target_port, server_name, path in _EGRESS_PROBES:
            ok, body, _status = http_get_body(
                socks_host,
                socks_port,
                target_host,
                target_port,
                server_name,
                path,
                timeout=timeout,
                max_bytes=4096,
            )
            if ok and body:
                ip = body.decode("utf-8", errors="replace").strip()
                # IPv4 или IPv6.
                if ip and re.match(r"^[0-9A-Fa-f:.]+$", ip):
                    return ip
        return ""

    from checkers.base import run_with_node

    result = run_with_node(node.raw_url, _probe, timeout=timeout, budget=max(8.0, timeout * 4.0))
    if result is None:
        return ""
    return str(result or "").strip()



def set_node_name(node: XrayNode, name: str) -> None:
    """Пересобрать node.raw_url так, чтобы имя узла стало name.

    Для vless/trojan/ss/hy2 — fragment (#имя), для vmess — поле ps в JSON.
    """
    from urllib.parse import quote

    raw = node.raw_url
    protocol = node.protocol
    if protocol == "vmess":
        encoded = _vmess_set_ps(raw, name)
        if encoded:
            node.raw_url = encoded
            node.name = name
        return
    base = raw.split("#", 1)[0] if "#" in raw else raw
    node.raw_url = f"{base}#{quote(name, safe='')}"
    node.name = name


def _vmess_set_ps(raw_url: str, ps: str) -> str:
    """Заменить поле ps внутри vmess://base64({json})."""
    import base64

    payload = raw_url.split("://", 1)[1]
    if "#" in payload:
        payload = payload.split("#", 1)[0]
    decoded = _b64decode(payload)
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        return ""
    if not isinstance(data, dict):
        return ""
    data["ps"] = ps
    rebuilt = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.urlsafe_b64encode(rebuilt.encode("utf-8")).decode("ascii").rstrip("=")


def _b64decode(value: str) -> str:
    import base64

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = value + ("=" * ((4 - len(value) % 4) % 4))
            return decoder(padded).decode("utf-8", errors="replace")
        except Exception:
            continue
    return ""


def geo_for_node(
    node: XrayNode,
    geo_cache: dict[str, tuple[str, str]],
    last_call: list[float],
    *,
    timeout: float,
    prefer_hint: bool = True,
) -> tuple[str, str]:
    """(country_code, flag) для узла, с учётом кеша/лимитов.

    Порядок определения страны выхода:

    1. **pyip-хинт** из path узла (``pyip=ProxyIP.JP...``) — быстро и бесплатно,
       провайдер подписки указывает именно эту страну egress-сервера. Совпадает
       с тем, что видят hiddify/2ip.
    2. **Реальный egress-IP** через сам узел (поднимаем прокси и спрашиваем
       ``/ip``-эндпоинт) — точно, но медленнее (нужен core-процесс). Используется
       для узлов без pyip-метаданных.
    3. **Fallback** — geoip по host узла (у Cloudflare-fronted узлов это даёт US).

    Если ``prefer_hint`` выключен, pyip-хинт пропускается (точный egress).
    """
    hint = pyip_hint(node) if prefer_hint else ""
    if hint:
        code = hint
        flag = country_flag(code)
        with _geo_lock:
            geo_cache[node.host] = (code, flag)
        return code, flag

    # Узлы без хинта — определяем по реальному IP выхода через сам узел.
    egress_ip = egress_ip_via_node(node, timeout=timeout)
    if egress_ip:
        with _geo_lock:
            cached = geo_cache.get(egress_ip)
        if cached is not None:
            return cached
        rate_limit_sleep(last_call)
        code, flag = geoip_lookup(egress_ip, timeout=timeout)
        with _geo_lock:
            geo_cache[egress_ip] = (code, flag)
        if code != GEOIP_FALLBACK_CODE:
            return code, flag

    # Fallback: страна по host узла.
    ip = node_ip(node)
    with _geo_lock:
        cached = geo_cache.get(ip)
    if cached is not None:
        return cached
    rate_limit_sleep(last_call)
    code, flag = geoip_lookup(ip, timeout=timeout)
    with _geo_lock:
        geo_cache[ip] = (code, flag)
    return code, flag


def serialize_working(

    items: list,
    geo_cache: dict[str, tuple[str, str]],
    last_call: list[float],
    *,
    timeout: float,
    progress: Callable[[int, int, str], None],
) -> list[dict[str, Any]]:
    """Назначить geoip-имена и вернуть строки для экспорта."""
    total = len(items)
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(items, start=1):
        node = item.node
        code, flag = geo_for_node(node, geo_cache, last_call, timeout=timeout)
        if code == GEOIP_FALLBACK_CODE and flag == GEOIP_FALLBACK_FLAG:
            new_name = " peppo"
        else:
            new_name = f"{flag} {code} peppo"
        set_node_name(node, new_name)
        progress(index, total, new_name)
        rows.append(
            {
                "url": node.raw_url,
                "protocol": node.protocol,
                "host": node.host,
                "port": node.port,
                "name": new_name,
                "country_code": code,
                "flag": flag,
                "latency_ms": item.dc_latency_ms if item.dc_latency_ms is not None else item.latency_ms,
                "download_kbps": item.download_kbps,
                "upload_kbps": item.upload_kbps,
            }
        )
    return rows
