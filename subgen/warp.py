"""Генерация WARP-конфигов через Cloudflare API и публичные генераторы.

Иерархия источников (по убыванию приоритета):
  1. **Прямой Cloudflare API** (``api.cloudflareclient.com/v0a737/reg``) —
     генерирует ключи локально (X25519), регистрирует устройство в
     Cloudflare без посредников. Самый надёжный и быстрый способ.
     Не требует авторизации, даёт ``warp_plus: true`` (бонус по рефералке).
  2. **generator-config-warp.vercel.app/api/warp-data** — публичный
     генератор, fallback если Cloudflare API недоступен (блокировка по IP).
     Отдаёт JSON с privKey, peer_pub, client_ipv4, client_ipv6.
  3. **cyb-portal.com/api/warp** — последний fallback. Отдаёт готовый
     WireGuard .conf в base64. Требует User-Agent, может rate-limit-ить.

Все 3 источника дают ОДИН И ТОТ ЖЕ результат — WireGuard-конфиг для
Cloudflare WARP. Отличается только private_key (генерируется случайно
при каждом вызове) и client_id (выдаётся Cloudflare).
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


# --- Источники WARP-конфигов (по приоритету) -----------------------------

# 1. Прямой Cloudflare API. Не требует авторизации. Самый надёжный.
#    Эндпоинт /v0a737/reg — это тот же, что использует официальный клиент
#    Cloudflare WARP при первой регистрации устройства.
CLOUDFLARE_WARP_API = "https://api.cloudflareclient.com/v0a737/reg"

# 2. Публичный генератор на Vercel — fallback если Cloudflare API недоступен
#    (например, IP SubGenerator заблокирован Cloudflare). Отдаёт JSON.
VERCEL_WARP_API = "https://generator-config-warp.vercel.app/api/warp-data"

# 3. cyb-portal — последний fallback. Отдаёт готовый WireGuard .conf.
CYB_PORTAL_WARP_API = "https://cyb-portal.com/api/warp"

# Стандартный endpoint Cloudflare WARP и peer public key.
WARP_DEFAULT_ENDPOINT_HOST = "engage.cloudflareclient.com"
WARP_DEFAULT_ENDPOINT_PORT = 2408

# DNS по умолчанию — Cloudflare DNS (быстрый, но не разблокирует сервисы).
WARP_DEFAULT_DNS = ["1.1.1.1", "1.0.0.1"]

# DNS от xbox-dns.ru — российский сервис, который резолвит заблокированные
# домены (chatgpt.com, openai.com, discord.com) через неразблокированные IP.
# cyb-portal использует именно этот DNS в своих WARP-конфигах — это их
# «фишка», которая позволяет открывать ChatGPT через WARP.
# Работает только внутри WARP-туннеля (сам DNS-сервер может быть заблокирован
# снаружи, но через WireGuard-туннель он доступен).
XBOX_DNS_IPV4 = ["111.88.96.50", "111.88.96.51"]
XBOX_DNS_IPV6 = ["2a00:ab00:1233:26::50", "2a00:ab00:1233:26::51"]
XBOX_DNS_ALL = XBOX_DNS_IPV4 + XBOX_DNS_IPV6

WARP_DEFAULT_MTU = 1280

WARP_DEFAULT_NAME = "peppo WARP"
WARP_ENDPOINT_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

# Альтернативные WARP endpoints. Cloudflare слушает WARP на нескольких IP
# и портах — это позволяет обойти DPI/ТСПУ на мобильных сетях РФ, которые
# режут стандартный порт 2408 или SNI engage.cloudflareclient.com.
#
# IP 162.159.192.1 — классический WARP (работает везде, где нет блокировок).
# IP 162.159.193.10 — альтернативный WARP IP (менее известен, реже блокируется).
# IP 188.114.96/97/98 — WARP+ CDN IP (используются для ChatGPT, OpenAI
#   их не блокирует, т.к. это Cloudflare CDN). На этих IP WARP+ включён
#   автоматически — трафик идёт через Cloudflare для Zero Trust (CFZT).
WARP_ENDPOINTS: list[tuple[str, str]] = [
    ("engage.cloudflareclient.com", "peppo WARP"),
    ("162.159.192.1", "peppo WARP"),
    ("162.159.193.10", "peppo WARP"),
    ("188.114.96.0", "peppo WARP+ 🤖"),
    ("188.114.97.0", "peppo WARP+ 🤖"),
    ("188.114.98.0", "peppo WARP+ 🤖"),
    ("162.159.195.1", "peppo WARP"),
    # Дополнительные WARP anycast IP — менее известны, реже блокируются.
    ("162.159.192.5", "peppo WARP"),
    ("162.159.193.5", "peppo WARP"),
    # Cloudflare CDN IP — выглядят как обычный Cloudflare CDN, DPI не режет.
    ("188.114.96.1", "peppo WARP+ 🤖"),
    ("188.114.97.1", "peppo WARP+ 🤖"),
    ("188.114.98.1", "peppo WARP+ 🤖"),
]

# WARP слушает на нескольких портах. На мобильных сетях РФ разные порты
# ведут себя по-разному из-за DPI/ТСПУ:
#   2408 — стандартный, часто режется
#   500  — выглядит как IPSec/IKE, иногда проходит
#   854, 859, 864, 878, 880, 890 — Cloudflare CDN порты, редко режутся
#   1701 — L2TP, иногда открыт
#   1843 — другой L2TP-порт, иногда проходит
#   2371 — редко режется
#   2506 — альтернативный
#   3138, 3476, 3581, 3854, 4177, 4198, 4233 — Cloudflare anycast
#   443  — HTTPS, почти никогда не блокируется
#   4500 — IPSec NAT-T, обычно открыт
#   5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886 —
#         Cloudflare редкие порты, DPI их обычно не знает
#   8443 — альтернативный HTTPS, часто проходит
WARP_PORTS: list[tuple[int, str]] = [
    (2408, ""),
    (500, ""),
    (854, ""),
    (859, ""),
    (864, ""),
    (878, ""),
    (880, ""),
    (890, ""),
    (1701, ""),
    (1843, ""),
    (2371, ""),
    (2506, ""),
    (3138, ""),
    (3476, ""),
    (3581, ""),
    (3854, ""),
    (4177, ""),
    (4198, ""),
    (4233, ""),
    (443, ""),
    (4500, ""),
    (5279, ""),
    (5956, ""),
    (7103, ""),
    (7152, ""),
    (7156, ""),
    (7281, ""),
    (7559, ""),
    (8319, ""),
    (8443, ""),
    (8742, ""),
    (8854, ""),
    (8886, ""),
]


@dataclass
class WarpPreset:
    """Пресет генерации WARP-конфигов.

    user_facing — имя пресета для UI.
    description — что делает, для кого подходит.
    endpoints — список (host, label) для генерации конфигов.
    ports — список (port, label) для генерации конфигов.
    icon — эмодзи-иконка пресета, добавляется к имени узла (например 📱).
    dns — список DNS-серверов для конфига. Если None — используется
          стандартный Cloudflare DNS (1.1.1.1). Для ChatGPT-пресета
          используется xbox-dns.ru (111.88.96.50/51) — он резолвит
          заблокированные домены через неразблокированные IP.
    mtu — MTU для конфига. По умолчанию 1280. Можно указать 1380 или 1420
          для вариации — разный MTU даёт разный размер пакетов, что может
          помочь обойти DPI, который детектит WireGuard по размеру пакетов.
    keepalive — PersistentKeepalive в секундах. 25 = стандарт, 10 = чаще
                (для нестабильных сетей), 0 = выключить.
    total — сколько всего конфигов будет сгенерировано.
    """
    user_facing: str
    description: str
    endpoints: list[tuple[str, str]]
    ports: list[tuple[int, str]]
    icon: str = ""
    dns: list[str] | None = None
    mtu: int = 1280
    keepalive: int = 25

    @property
    def total(self) -> int:
        # N endpoints × M ports = N×M URL (декартово произведение).
        # Если 1 endpoint + N портов → N URL.
        # Если N endpoints + 1 порт → N URL.
        # Если N endpoints + M портов → N×M URL.
        return len(self.endpoints) * len(self.ports)


# Пресеты для кнопок в UI. Пользователь жмёт одну кнопку — получает
# оптимальную конфигурацию под свой сценарий, без понимания портов/IP/DNS.
#
# DNS по умолчанию (None) → Cloudflare DNS (1.1.1.1, 1.0.0.1) — быстрый,
# но не разблокирует сервисы.
#
# Для ChatGPT, максимального и полного обхода используется xbox-dns.ru
# (111.88.96.50/51, 2a00:ab00:...) — это тот же DNS, что cyb-portal
# прописывает в своих конфигах. Он резолвит chatgpt.com, openai.com,
# discord.com через неразблокированные IP, позволяя открывать эти
# сервисы через WARP-туннель.
#
# MTU: 1280 (стандарт), 1380 (чуть больше), 1420 (максимум). Разный MTU
# даёт разный размер пакетов — это может помочь обойти DPI, который
# детектит WireGuard по характерному размеру пакетов.
#
# Keepalive: 25 (стандарт), 10 (чаще — для нестабильных сетей), 0 (выкл).
# Более частый keepalive помогает поддерживать соединение через NAT/DPI,
# но увеличивает трафик.
WARP_PRESETS: list[WarpPreset] = [
    WarpPreset(
        user_facing="Авто",
        description="1 конфиг, стандартный порт 2408, DNS Cloudflare.",
        endpoints=[("engage.cloudflareclient.com", "peppo WARP")],
        ports=[(2408, "")],
        icon="",
    ),
    WarpPreset(
        user_facing="🌐 Мобильный интернет",
        description="3 конфига, порты 2408/500/4500. Для МТС/Билайн/МегаФон/Tele2.",
        endpoints=[("162.159.192.1", "peppo WARP")],
        ports=[(2408, ""), (500, ""), (4500, "")],
        icon="📱",
    ),
    WarpPreset(
        user_facing="🤖 Нейросети ChatGPT",
        description="2 конфига, WARP+ IP, порт 443, DNS xbox-dns.ru. Открывает ChatGPT/Claude/Gemini.",
        endpoints=[
            ("188.114.97.0", "peppo WARP+ 🤖"),
            ("188.114.98.0", "peppo WARP+ 🤖"),
        ],
        ports=[(443, "")],
        icon="🤖",
        dns=XBOX_DNS_ALL,
    ),
    WarpPreset(
        user_facing="🛡️ Максимальный обход",
        description="6 конфигов, порты 2408/500/1701/443/4500/8443, DNS xbox-dns.ru.",
        endpoints=[("162.159.192.1", "peppo WARP")],
        ports=[(2408, ""), (500, ""), (1701, ""), (443, ""), (4500, ""), (8443, "")],
        icon="🛡️",
        dns=XBOX_DNS_ALL,
    ),
    WarpPreset(
        user_facing="🚀 Полный обход",
        description="16 конфигов: 4 IP × 4 порта, DNS xbox-dns.ru, разный MTU/keepalive.",
        endpoints=[
            ("188.114.96.0", "peppo WARP+ 🚀"),
            ("188.114.97.0", "peppo WARP+ 🚀"),
            ("188.114.98.0", "peppo WARP+ 🚀"),
            ("162.159.192.1", "peppo WARP 🚀"),
        ],
        ports=[(443, ""), (8443, ""), (500, ""), (4500, "")],
        icon="🚀",
        dns=XBOX_DNS_ALL,
        mtu=1280,
        keepalive=25,
    ),
]


@dataclass
class WireGuardConfig:
    """Распарсенный WireGuard .conf."""

    private_key: str
    address: str  # IPv4 (например "172.16.0.2")
    address_ipv6: str | None = None
    dns: list[str] | None = None
    mtu: int = 1280
    peer_public_key: str = WARP_ENDPOINT_PEER_PUBLIC_KEY
    endpoint_host: str = "engage.cloudflareclient.com"
    endpoint_port: int = 2408
    allowed_ips: str = "0.0.0.0/0,::/0"
    keepalive: int = 25


def _generate_x25519_keypair() -> tuple[str, str]:
    """Сгенерировать пару X25519 ключей для WireGuard.

    Возвращает (private_key_b64, public_key_b64). Использует cryptography
    (стандартная зависимость). Если библиотека недоступна — поднимает
    RuntimeError с подсказкой установить её.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise RuntimeError(
            "Библиотека 'cryptography' не установлена — не могу сгенерировать "
            "WireGuard ключи. Установи: pip install cryptography"
        ) from exc
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(priv_bytes).decode("ascii"),
        base64.b64encode(pub_bytes).decode("ascii"),
    )


def fetch_warp_from_cloudflare(timeout: float = 15.0) -> WireGuardConfig:
    """Получить WARP-конфиг напрямую от Cloudflare API.

    1. Генерирует X25519 ключи локально.
    2. POST /v0a737/reg с public_key — Cloudflare регистрирует устройство
       и отдаёт endpoint, peer_public_key, client_ipv4/ipv6.
    3. Возвращает WireGuardConfig.

    Не требует посредников (cyb-portal, vercel и т.д.). Самый быстрый
    и надёжный способ. Даёт warp_plus=true (бонус).

    Поднимает RuntimeError при сетевых ошибках или если Cloudflare API
    заблокировал IP SubGenerator.
    """
    import datetime
    priv_b64, pub_b64 = _generate_x25519_keypair()
    payload = json.dumps({
        "key": pub_b64,
        "install_id": "",
        "warp_enabled": True,
        "tos": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "type": "Android",
        "locale": "ru_RU",
    }).encode("utf-8")
    req = urllib.request.Request(
        CLOUDFLARE_WARP_API,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            # User-Agent как у официального Android-клиента — Cloudflare
            # пропускает такие запросы без rate-limit.
            "User-Agent": "okhttp/3.10.0.7",
            "CF-Client-Version": "6.30.3623.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"Cloudflare API отклонил регистрацию (HTTP {exc.code}): {exc.reason}"
        )
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Не удалось подключиться к Cloudflare API: {exc.reason}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Cloudflare API вернул невалидный JSON: {exc}")

    # Парсим ответ Cloudflare в WireGuardConfig.
    config = data.get("config") or {}
    interface = config.get("interface") or {}
    addresses = interface.get("addresses") or {}
    peers = config.get("peers") or []
    peer = peers[0] if peers else {}
    peer_endpoint = peer.get("endpoint") or {}

    # Endpoint Cloudflare: "162.159.192.9:0" — порт 0 значит «по умолчанию»,
    # подставляем 2408 (стандартный WARP порт).
    endpoint_v4 = str(peer_endpoint.get("v4") or "162.159.192.1:2408")
    if ":" in endpoint_v4:
        endpoint_host, _, endpoint_port_str = endpoint_v4.rpartition(":")
        try:
            endpoint_port = int(endpoint_port_str)
        except ValueError:
            endpoint_port = WARP_DEFAULT_ENDPOINT_PORT
        # Cloudflare отдаёт порт 0 — подставляем стандартный 2408.
        if endpoint_port == 0:
            endpoint_port = WARP_DEFAULT_ENDPOINT_PORT
    else:
        endpoint_host = endpoint_v4
        endpoint_port = WARP_DEFAULT_ENDPOINT_PORT

    client_ipv4 = str(addresses.get("v4") or "172.16.0.2")
    # Убираем CIDR-суффикс, если есть (Cloudflare отдаёт "172.16.0.2/32").
    if "/" in client_ipv4:
        client_ipv4 = client_ipv4.split("/", 1)[0]
    client_ipv6 = str(addresses.get("v6") or "")
    if "/" in client_ipv6:
        client_ipv6 = client_ipv6.split("/", 1)[0]
    peer_public_key = str(peer.get("public_key") or WARP_ENDPOINT_PEER_PUBLIC_KEY)

    return WireGuardConfig(
        private_key=priv_b64,
        address=client_ipv4,
        address_ipv6=client_ipv6 or None,
        dns=list(WARP_DEFAULT_DNS),
        mtu=WARP_DEFAULT_MTU,
        peer_public_key=peer_public_key,
        endpoint_host=endpoint_host,
        endpoint_port=endpoint_port,
    )


def fetch_warp_from_vercel(timeout: float = 15.0) -> WireGuardConfig:
    """Получить WARP-конфиг от публичного генератора на Vercel.

    GET /api/warp-data — отдаёт JSON {privKey, peer_pub, client_ipv4, client_ipv6}.
    Используется как fallback, если прямой Cloudflare API недоступен.

    Поднимает RuntimeError при сетевых ошибках.
    """
    req = urllib.request.Request(
        VERCEL_WARP_API,
        headers={
            "User-Agent": "SubGenerator/1.0 (https://tetta-prod.ru)",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Vercel WARP API HTTP {exc.code}: {exc.reason}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Не удалось подключиться к Vercel WARP API: {exc.reason}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Vercel WARP API вернул невалидный JSON: {exc}")

    if not isinstance(data, dict) or not data.get("success"):
        msg = data.get("message") if isinstance(data, dict) else "неизвестная ошибка"
        raise RuntimeError(f"Vercel WARP API отклонил запрос: {msg}")

    return WireGuardConfig(
        private_key=str(data.get("privKey") or ""),
        address=str(data.get("client_ipv4") or "172.16.0.2"),
        address_ipv6=str(data.get("client_ipv6") or "") or None,
        dns=list(WARP_DEFAULT_DNS),
        mtu=WARP_DEFAULT_MTU,
        peer_public_key=str(data.get("peer_pub") or WARP_ENDPOINT_PEER_PUBLIC_KEY),
        endpoint_host=WARP_DEFAULT_ENDPOINT_HOST,
        endpoint_port=WARP_DEFAULT_ENDPOINT_PORT,
    )


def fetch_warp_from_cyb_portal(timeout: float = 30.0) -> WireGuardConfig:
    """Получить WARP-конфиг от cyb-portal.com (последний fallback).

    GET /api/warp — отдаёт JSON с configBase64 и importText (готовый .conf).
    Может rate-limit-ить (HTTP 429), требует User-Agent.

    Поднимает RuntimeError при сетевых ошибках.
    """
    req = urllib.request.Request(
        CYB_PORTAL_WARP_API,
        headers={
            "User-Agent": "SubGenerator/1.0 (https://tetta-prod.ru)",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise RuntimeError(
                "cyb-portal перегружен (HTTP 429). Подожди 30-60 сек и попробуй ещё раз."
            )
        raise RuntimeError(f"cyb-portal /api/warp HTTP {exc.code}: {exc.reason}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Не удалось подключиться к cyb-portal: {exc.reason}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"cyb-portal вернул невалидный JSON: {exc}")

    if not isinstance(data, dict) or not data.get("success"):
        raise RuntimeError(
            "cyb-portal вернул ошибку: " + str(data.get("error") or data)
        )
    content = data.get("content") or {}
    if not isinstance(content, dict):
        raise RuntimeError("cyb-portal вернул пустой content")
    conf_text = str(content.get("importText") or "")
    if not conf_text:
        b64 = str(content.get("configBase64") or "")
        if b64:
            try:
                conf_text = base64.b64decode(b64).decode("utf-8", errors="replace")
            except Exception as exc:
                raise RuntimeError(f"Не удалось декодировать configBase64: {exc}")
    if not conf_text:
        raise RuntimeError("cyb-portal вернул пустой WARP-конфиг")
    cfg = parse_wireguard_conf(conf_text)
    if cfg is None:
        raise RuntimeError(
            "Не удалось распарсить WireGuard .conf от cyb-portal "
            "(нет PrivateKey или Address)"
        )
    return cfg


# Список источников по приоритету. Каждый — callable, возвращающий WireGuardConfig.
# При ошибке (RuntimeError) переходим к следующему. Если все упали —
# возвращаем ошибку последнего.
_WARP_SOURCES: list[tuple[str, callable]] = [
    ("Cloudflare API (прямой)", fetch_warp_from_cloudflare),
    ("Vercel WARP generator", fetch_warp_from_vercel),
    ("cyb-portal.com", fetch_warp_from_cyb_portal),
]


def fetch_warp_config_parsed(timeout: float = 30.0) -> WireGuardConfig:
    """Получить WARP-конфиг, перебирая источники по приоритету.

    Порядок:
      1. Прямой Cloudflare API (самый быстрый, без посредников).
      2. Vercel WARP generator (fallback).
      3. cyb-portal.com (последний fallback).

    Возвращает WireGuardConfig от первого источника, который ответил успешно.
    Если все источники недоступны — поднимает RuntimeError с описанием,
    какие источники пробовались и какие ошибки возникли.
    """
    errors: list[str] = []
    for source_name, fetcher in _WARP_SOURCES:
        try:
            cfg = fetcher(timeout=timeout)
            if cfg and cfg.private_key and cfg.address:
                return cfg
            errors.append(f"{source_name}: пустой конфиг")
        except RuntimeError as exc:
            errors.append(f"{source_name}: {exc}")
        except Exception as exc:
            errors.append(f"{source_name}: {type(exc).__name__}: {exc}")
    raise RuntimeError(
        "Все источники WARP-конфигов недоступны:\n  - " + "\n  - ".join(errors)
    )


def fetch_warp_config(timeout: float = 30.0) -> dict[str, Any]:
    """Совместимость со старым API — возвращает dict.

    Сейчас не используется (все вызовы идут через fetch_warp_config_parsed),
    оставлено для обратной совместимости с возможными внешними импортами.
    """
    cfg = fetch_warp_config_parsed(timeout=timeout)
    return {
        "success": True,
        "content": {
            "importText": (
                f"[Interface]\n"
                f"PrivateKey = {cfg.private_key}\n"
                f"Address = {cfg.address}\n"
                f"DNS = {','.join(cfg.dns or WARP_DEFAULT_DNS)}\n"
                f"MTU = {cfg.mtu}\n\n"
                f"[Peer]\n"
                f"PublicKey = {cfg.peer_public_key}\n"
                f"Endpoint = {cfg.endpoint_host}:{cfg.endpoint_port}\n"
                f"AllowedIPs = 0.0.0.0/0,::/0\n"
            ),
        },
    }


def parse_wireguard_conf(text: str) -> WireGuardConfig | None:
    """Распарсить WireGuard .conf (текст [Interface]/[Peer]).

    Возвращает WireGuardConfig или None, если конфиг невалиден.
    """
    if not text:
        return None
    cfg = WireGuardConfig(private_key="", address="")
    in_interface = False
    in_peer = False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("["):
            in_interface = line.lower().startswith("[interface")
            in_peer = line.lower().startswith("[peer")
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if in_interface:
            if key == "privatekey":
                cfg.private_key = value
            elif key == "address":
                # Может быть "172.16.0.2" или "172.16.0.2, 2606:4700:..."
                parts = [p.strip() for p in value.split(",") if p.strip()]
                if parts:
                    cfg.address = parts[0]
                if len(parts) > 1:
                    cfg.address_ipv6 = parts[1]
            elif key == "dns":
                cfg.dns = [d.strip() for d in value.split(",") if d.strip()]
            elif key == "mtu":
                try:
                    cfg.mtu = int(value)
                except ValueError:
                    pass
        elif in_peer:
            if key == "publickey":
                cfg.peer_public_key = value
            elif key == "endpoint":
                # "engage.cloudflareclient.com:2408" или "162.159.192.1:2408"
                if ":" in value:
                    host, _, port = value.rpartition(":")
                    cfg.endpoint_host = host
                    try:
                        cfg.endpoint_port = int(port)
                    except ValueError:
                        pass
            elif key == "allowedips":
                cfg.allowed_ips = value
            elif key in ("persistentkeepalive", "keepalive"):
                try:
                    cfg.keepalive = int(value)
                except ValueError:
                    pass
    if not cfg.private_key or not cfg.address:
        return None
    return cfg


def warp_config_to_uri(cfg: WireGuardConfig, name: str = WARP_DEFAULT_NAME) -> str:
    """Собрать warp:// URL из WireGuardConfig.

    Формат поддерживается Karing, Hiddify, v2rayN:
      warp://<private_key_urlencoded>@<endpoint_host>:<endpoint_port>?
            peer=<public_key>&address=<ip>&mtu=<mtu>&dns=<dns>#<name>

    ВАЖНО: private_key — это base64, который содержит '+', '/', '='. В URL
    userinfo эти символы ломают парсинг (Karing видит '+' как часть host,
    '/' как path separator, '=' как разделитель query). Поэтому private_key
    ОБЯЗАТЕЛЬНО URL-кодируется: + → %2B, / → %2F, = → %3D.

    Без этого Karing/Hiddify не распознают warp:// URL и не добавляют узел.
    """
    # URL-кодируем private_key — это критично для парсинга URL.
    # base64 private key содержит +, /, = — они ломают URL.
    encoded_private_key = urllib.parse.quote(cfg.private_key, safe="")
    params: dict[str, str] = {
        "peer": cfg.peer_public_key,
        "address": cfg.address,
        "mtu": str(cfg.mtu),
    }
    if cfg.dns:
        params["dns"] = ",".join(cfg.dns)
    if cfg.keepalive:
        params["keepalive"] = str(cfg.keepalive)
    query = urllib.parse.urlencode(params, safe="=")
    # Имя узла — в fragment, URL-encoded.
    fragment = urllib.parse.quote(name, safe="")
    return f"warp://{encoded_private_key}@{cfg.endpoint_host}:{cfg.endpoint_port}?{query}#{fragment}"


def generate_warp_uri(
    timeout: float = 30.0, name: str = WARP_DEFAULT_NAME
) -> str:
    """Полный flow: запросить WARP-конфиг и вернуть warp:// URL.

    Использует fetch_warp_config_parsed, который перебирает источники
    (Cloudflare API → Vercel → cyb-portal) по приоритету.

    Поднимает RuntimeError при сетевых ошибках или невалидном конфиге.
    """
    cfg = fetch_warp_config_parsed(timeout=timeout)
    return warp_config_to_uri(cfg, name=name)


def warp_config_to_uri_with_endpoint(
    cfg: WireGuardConfig,
    endpoint_host: str,
    endpoint_port: int,
    name: str = WARP_DEFAULT_NAME,
) -> str:
    """Собрать warp:// URL с кастомным endpoint:port.

    Используется для пресетов: один private_key → несколько URL с разными
    endpoint (162.159.192.1, 188.114.97.0, ...) и портами (2408, 500, 443,
    ...). Все URL используют один private_key, но разные endpoint:port —
    это позволяет обойти DPI, который режет конкретный порт или IP.
    """
    # Копируем конфиг, чтобы не мутировать исходный.
    from copy import deepcopy
    cfg_copy = deepcopy(cfg)
    cfg_copy.endpoint_host = endpoint_host
    cfg_copy.endpoint_port = endpoint_port
    return warp_config_to_uri(cfg_copy, name=name)


def generate_warp_uris_for_preset(
    preset: WarpPreset,
    timeout: float = 30.0,
) -> list[str]:
    """Сгенерировать несколько warp:// URL по пресету.

    Один запрос к cyb-portal → один private_key → N URL с разными
    endpoint:port. N = preset.total.

    Возвращает список warp:// URL, готовых для добавления в подписку.
    Поднимает RuntimeError при сетевых ошибках.
    """
    cfg = fetch_warp_config_parsed(timeout=timeout)
    return _build_uris_for_preset(cfg, preset)


def _build_uris_for_preset(cfg: WireGuardConfig, preset: WarpPreset) -> list[str]:
    """Внутренняя функция: собрать URL по пресету из уже готового конфига.

    Имена узлов короткие: «peppo WARP 📱», «peppo WARP+ 🤖», «peppo WARP 🛡️».
    Порт в имя НЕ добавляем — endpoint:port в URL достаточно.

    DNS: если в пресете указан dns (например xbox-dns.ru для ChatGPT),
    подменяем DNS в конфиге на него. Это позволяет резолвить заблокированные
    домены (chatgpt.com, openai.com) через неразблокированные IP —
    именно так работает cyb-portal, и мы воспроизводим это в пресетах.

    MTU и keepalive: применяем значения из пресета. Для пресета «🚀 Полный
    обход» (icon='🚀') — варьируем MTU между 1280/1380/1420 и keepalive
    между 25/10/0, чтобы получить больше разнообразия пакетов для обхода DPI.
    """
    from copy import deepcopy
    uris: list[str] = []
    icon = preset.icon
    # Если в пресете указан кастомный DNS — подменяем в копии конфига.
    if preset.dns:
        cfg = deepcopy(cfg)
        cfg.dns = list(preset.dns)
    # Применяем MTU и keepalive из пресета.
    cfg.mtu = preset.mtu
    cfg.keepalive = preset.keepalive

    # Для пресета «🚀 Полный обход» — варьируем MTU и keepalive, чтобы
    # получить больше разнообразия пакетов. DPI детектит WireGuard по
    # характерному размеру пакетов (1280 MTU), меняя MTU мы меняем размер.
    vary_mtu = icon == "🚀"
    mtu_variants = [1280, 1380, 1420]
    keepalive_variants = [25, 10, 0]
    variant_idx = 0

    # Генерация URL:
    # - 1 endpoint + N портов → N URL (меняем только порт)
    # - N endpoints + 1 порт → N URL (меняем только IP)
    # - N endpoints + M портов → N×M URL (все комбинации — максимум разнообразия)
    multi_endpoints = len(preset.endpoints) > 1
    multi_ports = len(preset.ports) > 1
    if multi_endpoints and multi_ports:
        # Декартово произведение endpoints × ports — максимум комбинаций.
        for endpoint_host, endpoint_label in preset.endpoints:
            for port, _port_label in preset.ports:
                name = endpoint_label
                if vary_mtu:
                    cfg_copy = deepcopy(cfg)
                    cfg_copy.mtu = mtu_variants[variant_idx % len(mtu_variants)]
                    cfg_copy.keepalive = keepalive_variants[variant_idx % len(keepalive_variants)]
                    variant_idx += 1
                    uris.append(
                        warp_config_to_uri_with_endpoint(cfg_copy, endpoint_host, port, name=name)
                    )
                else:
                    uris.append(
                        warp_config_to_uri_with_endpoint(cfg, endpoint_host, port, name=name)
                    )
    elif multi_endpoints:
        # Несколько endpoints, один порт — по URL на каждый endpoint.
        for endpoint_host, endpoint_label in preset.endpoints:
            port = preset.ports[0][0] if preset.ports else 2408
            name = endpoint_label
            if vary_mtu:
                cfg_copy = deepcopy(cfg)
                cfg_copy.mtu = mtu_variants[variant_idx % len(mtu_variants)]
                cfg_copy.keepalive = keepalive_variants[variant_idx % len(keepalive_variants)]
                variant_idx += 1
                uris.append(
                    warp_config_to_uri_with_endpoint(cfg_copy, endpoint_host, port, name=name)
                )
            else:
                uris.append(
                    warp_config_to_uri_with_endpoint(cfg, endpoint_host, port, name=name)
                )
    else:
        # Один endpoint, несколько портов — N URL с разными портами.
        endpoint_host, endpoint_label = preset.endpoints[0]
        for port, _port_label in preset.ports:
            if icon and icon not in endpoint_label:
                name = f"{endpoint_label} {icon}"
            else:
                name = endpoint_label
            if vary_mtu:
                cfg_copy = deepcopy(cfg)
                cfg_copy.mtu = mtu_variants[variant_idx % len(mtu_variants)]
                cfg_copy.keepalive = keepalive_variants[variant_idx % len(keepalive_variants)]
                variant_idx += 1
                uris.append(
                    warp_config_to_uri_with_endpoint(cfg_copy, endpoint_host, port, name=name)
                )
            else:
                uris.append(
                    warp_config_to_uri_with_endpoint(cfg, endpoint_host, port, name=name)
                )
    return uris


def generate_warp_uris_for_presets(
    preset_indices: list[int],
    timeout: float = 30.0,
) -> list[str]:
    """Сгенерировать warp:// URL для нескольких пресетов.

    Один запрос к cyb-portal → один private_key → URL для всех выбранных
    пресетов. Это эффективнее, чем вызывать generate_warp_uris_for_preset
    для каждого пресета отдельно (один запрос вместо N).

    preset_indices — список индексов в WARP_PRESETS (например, [1, 2] =
    «Мобильный интернет» + «Нейросети ChatGPT»).

    Возвращает список warp:// URL, готовых для добавления в подписку.
    Дубликаты по endpoint:port удаляются — если два пресета генерируют
    один и тот же endpoint:port (например 162.159.192.1:2408 есть и в
    «Мобильном», и в «Максимальном»), в подписке остаётся только первый
    (из более раннего пресета в списке preset_indices).

    Поднимает RuntimeError при сетевых ошибках.
    """
    if not preset_indices:
        return []
    cfg = fetch_warp_config_parsed(timeout=timeout)
    all_uris: list[str] = []
    seen_endpoint_port: set[tuple[str, int]] = set()
    import re
    # Регулярка надёжнее urlsplit для warp:// URL с приватным ключом,
    # который может содержать '/', '+', '=' — urlsplit ломается на таких
    # символах и не находит port.
    endpoint_re = re.compile(r"@([^:/?#]+):(\d+)\b")
    for idx in preset_indices:
        if idx < 0 or idx >= len(WARP_PRESETS):
            continue
        preset = WARP_PRESETS[idx]
        for uri in _build_uris_for_preset(cfg, preset):
            # Дедупликация по (endpoint_host, endpoint_port) — если
            # 162.159.192.1:2408 уже добавлен из «Мобильного» пресета,
            # не дублируем его из «Максимального».
            m = endpoint_re.search(uri)
            if m:
                endpoint_host = m.group(1).lower()
                endpoint_port = int(m.group(2))
                endpoint_key = (endpoint_host, endpoint_port)
                if endpoint_key in seen_endpoint_port:
                    continue
                seen_endpoint_port.add(endpoint_key)
            all_uris.append(uri)
    return all_uris


if __name__ == "__main__":
    # Быстрый тест из CLI: python -m subgen.warp
    print("=== Тест WARP ===")
    try:
        uri = generate_warp_uri()
        print("warp:// URL:")
        print(uri)
    except Exception as exc:
        print(f"Ошибка: {exc}")
