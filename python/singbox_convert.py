"""Конвертация узлов xray-формата в конфигурацию sing-box (как Karing).

sing-box читает свой формат outbound'ов, отличающийся от xray-core:
  - транспорт и TLS живут ВНУТРИ outbound'а (transport / tls), а не в
    отдельном streamSettings;
  - reality — вложенный блок tls.reality (public_key/short_id), а не
    realitySettings; pbk ДОЛЖЕН быть нормализован до URL-safe base64
    БЕЗ padding (sing-box декодирует через base64.RawURLEncoding: std
    '+'/'/' он отвергает — падает на старте с «decode public_key:
    illegal base64 data at input byte K», K = позиция первого '+');
  - vless-transport'ы: tcp (в т.ч. header http), ws, grpc, httpupgrade,
    http (h2) — конвертируются; xhttp/splithttp, kcp, quic — в sing-box
    НЕТ, такие узлы пропускаются.

Конвертер самодостаточен: не импортирует xray_runtime на уровне модуля
(у того ленивые импорты сюда), тип узла — «утка» с полями protocol/host/
port/credential/query/extra.
"""
from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — только для типизации
    from xray_runtime import XrayNode


# Транспорты, которые умеет sing-box (в терминах xray-network).
SUPPORTED_NETWORKS = {"tcp", "ws", "grpc", "httpupgrade", "http"}
# Протоколы, которые умеет конвертировать этот модуль.
SUPPORTED_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria",
    "hysteria2",
}

# uTLS-фингерпринты, которые принимает sing-box (взаимодействие с
# _safe_fingerprint из xray_runtime: она отдаёт подмножество этого набора).
_SINGBOX_FINGERPRINTS = {
    "chrome", "firefox", "edge", "safari", "ios", "android",
    "random", "qq", "360", "randomized",
}
_SINGBOX_DEFAULT_FP = "chrome"


def _normalize_reality_pbk(value: str) -> str:
    """Нормализовать Reality publicKey под ДЕКОДЕР sing-box (RawURLEncoding).

    БАГФИКС (P0, инцидент лог.zip 2026-09-16): sing-box парсит public_key
    через base64.RawURLEncoding — ТОЛЬКО URL-safe алфавит ('-'/'_') без '='.
    Std-символы '+'/'/' он отвергает («initialize outbound[N]: decode
    public_key: illegal base64 data at input byte K» — K указывает ровно
    на позицию первого '+'). Старая нормализация делала ОБРАТНОЕ: приводила
    url-safe к std ('-'→'+', '_'→'/') и этим ЛОМАЛА рабочие ключи — 109
    из 122 reality-нод упавшего батча содержали std-символы после
    нормализации. Каждый пул с reality-нодой не стартовал, и все 200 узлов
    батча сваливались в медленный per-node fallback (а там — memory-bomb
    из полных XrayCoreRuntime на каждый узел, см. runtime/core.py).

    Возврат "" = ключ не декодируется как base64 — узел помечается
    unsupported в sing_box_outbound и идёт через xray-путь, а не валит
    весь батч.
    """
    import base64 as _b64
    text = str(value or "").strip()
    if not text:
        return text
    # К URL-safe алфавиту и без паддинга — так декодирует sing-box
    # (и xray-core v26+: RawURLEncoding, см. runtime/configs.py).
    cleaned = text.replace("+", "-").replace("/", "_").rstrip("=")
    # Валидация алфавита (b64decode с altchars принимает ОБА алфавита,
    # поэтому '+'/'/' отвергаем только явной проверкой символов).
    if not cleaned or not all(c.isalnum() or c in "-_" for c in cleaned):
        return ""
    try:
        padded = cleaned + "=" * (-len(cleaned) % 4)
        decoded = _b64.b64decode(padded, altchars=b"-_", validate=True)
        # Reality public key — X25519, 32 байта. Длину не проверяем строго
        # (принципиальна валидность base64 для декодера sing-box).
        if len(decoded) == 0:
            return ""
        return cleaned
    except Exception:
        return ""


def _q(query: dict[str, str], *names: str, default: str = "") -> str:
    """Первое непустое значение из query по списку имён-синонимов."""
    for name in names:
        value = str(query.get(name) or "").strip()
        if value:
            return value
    return default


def _resolve_fp(query: dict[str, str], fp: str | None) -> str | None:
    """Выбрать uTLS-фингерпринт для sing-box.

    Внешний override fp (матрица fingerprint-тестов) используется как есть
    («none» = системный TLS, вернём None). Иначе — fp из ссылки узла; если
    его нет или он не поддерживается sing-box — None (uTLS не задаём,
    sing-box сам применит дефолт; для reality — дефолт chrome).
    """
    if fp is not None:
        value = str(fp or "").strip().lower()
        if not value or value == "none":
            return None
        return value if value in _SINGBOX_FINGERPRINTS else _SINGBOX_DEFAULT_FP
    value = str(query.get("fp") or query.get("fingerprint") or "").strip().lower()
    if not value:
        return None
    return value if value in _SINGBOX_FINGERPRINTS else None


def _transport_block(query: dict[str, str]) -> tuple[dict[str, Any] | None, str | None]:
    """Собрать sing-box transport из xray streamSettings-параметров.

    Возвращает (transport|None, None) или (None, причина-пропуска).
    transport=None значит «голый TCP» — валидный случай.
    """
    network = _q(query, "type", "network", "net", default="tcp").lower()
    if network == "h2":
        network = "http"
    if network in ("xhttp", "splithttp"):
        return None, f"transport {network} не поддерживается sing-box"
    if network == "kcp":
        return None, "transport kcp не поддерживается sing-box"
    if network == "quic":
        return None, "transport quic не поддерживается sing-box"
    if network not in SUPPORTED_NETWORKS:
        return None, f"transport {network} не поддерживается sing-box"

    if network == "tcp":
        header = _q(query, "headerType", "header").lower()
        if not header or header == "none":
            return None, None
        if header != "http":
            return None, f"tcp header {header} не поддерживается sing-box"
        # xray tcp+headerType=http == v2ray-http транспорт sing-box.
        transport: dict[str, Any] = {"type": "http"}
        host = _q(query, "host")
        if host:
            transport["host"] = [item.strip() for item in host.split(",") if item.strip()]
        path = _q(query, "path")
        if path:
            transport["path"] = path.split(",")[0].strip()
        return transport, None

    if network == "ws":
        transport = {"type": "ws"}
        path = _q(query, "path")
        if path:
            transport["path"] = path
        host = _q(query, "host")
        if host:
            transport["headers"] = {"Host": host}
        # early-data (xray: ed=2048 в wsSettings) — переносим.
        ed = _q(query, "ed")
        if ed.isdigit() and int(ed) > 0:
            transport["max_early_data"] = int(ed)
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return transport, None

    if network == "grpc":
        service = _q(query, "serviceName", "service")
        return {"type": "grpc", "service_name": service}, None

    if network == "httpupgrade":
        transport = {"type": "httpupgrade"}
        path = _q(query, "path")
        if path:
            transport["path"] = path
        host = _q(query, "host")
        if host:
            transport["host"] = host
        return transport, None

    # network == "http" (h2 в терминах xray)
    transport = {"type": "http"}
    host = _q(query, "host")
    if host:
        transport["host"] = [item.strip() for item in host.split(",") if item.strip()]
    path = _q(query, "path")
    if path:
        transport["path"] = path.split(",")[0].strip()
    return transport, None


def _tls_block(node: "XrayNode", fp: str | None) -> tuple[dict[str, Any] | None, str | None]:
    """Собрать sing-box tls-блок из xray security/tls/reality параметров."""
    query = node.query
    security = _q(query, "security", "tls").lower()
    # hysteria/hysteria2 — QUIC-протоколы, TLS для них ОБЯЗАТЕЛЕН в sing-box
    # («initialize outbound: TLS required»), параметр security в их ссылках
    # обычно не задаётся — считаем включённым.
    if node.protocol in ("hysteria", "hysteria2", "hy2") and security in ("", "none"):
        security = "tls"
    sni = _q(query, "sni", "peer", "host", "serverName")
    insecure = _q(
        query, "allowInsecure", "insecure", "allow_insecure",
    ).lower() in ("1", "true", "yes")
    alpn_raw = _q(query, "alpn")
    resolved_fp = _resolve_fp(query, fp)

    if security in ("", "none"):
        return None, None
    if security == "tls":
        tls: dict[str, Any] = {"enabled": True}
        if sni:
            tls["server_name"] = sni
        if insecure:
            tls["insecure"] = True
        if alpn_raw:
            tls["alpn"] = [item.strip() for item in alpn_raw.split(",") if item.strip()]
        if resolved_fp:
            tls["utls"] = {"enabled": True, "fingerprint": resolved_fp}
        return tls, None
    if security == "reality":
        tls = {"enabled": True}
        if sni:
            tls["server_name"] = sni
        # reality в sing-box ТРЕБУЕТ uTLS (без него: «uTLS is required by
        # reality client») — фингерпринт всегда ставим (нет fp -> chrome).
        tls["utls"] = {"enabled": True, "fingerprint": resolved_fp or _SINGBOX_DEFAULT_FP}
        pbk = _q(query, "pbk", "publicKey")
        if not pbk:
            # v11: без public_key reality невалиден — sing-box падает при старте
            # «decode public_key: illegal base64 data». В подписках бывают битые
            # reality-конфиги без pbk — их нельзя добавлять в pool, иначе весь
            # батч из 200 нод падает из-за одной кривой.
            return None, "reality without public_key (pbk)"
        normalized_pbk = _normalize_reality_pbk(pbk)
        if not normalized_pbk:
            # pbk есть, но не декодируется как URL-safe base64 = мусор
            # ('-', 'abc', одинарные символы). Узел помечаем unsupported —
            # он пойдёт через xray-путь, а не уронит весь батч.
            return None, f"reality with invalid public_key (pbk={pbk!r})"
        reality: dict[str, Any] = {"enabled": True, "public_key": normalized_pbk}
        sid = _q(query, "sid", "shortId")
        if sid:
            reality["short_id"] = sid
        tls["reality"] = reality
        return tls, None
    return None, f"security {security} не поддерживается sing-box"


def sing_box_outbound(
    node: "XrayNode",
    *,
    tag: str = "proxy",
    fp: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Конвертировать узел xray-формата в sing-box outbound.

    Возвращает (outbound, None) при успехе или (None, причина) — узел
    пропускается (в sing-box-режиме не тестируется xray-ядром).
    """
    protocol = str(node.protocol or "").lower()
    if protocol == "hy2":
        protocol = "hysteria2"
    if protocol not in SUPPORTED_PROTOCOLS:
        return None, f"протокол {protocol} не поддерживается sing-box"

    query = node.query
    outbound: dict[str, Any] = {
        "type": protocol,
        "tag": tag,
        "server": node.host,
        "server_port": int(node.port),
    }

    if protocol == "vless":
        outbound["uuid"] = node.credential
        security = _q(query, "security", "tls").lower()
        flow = _q(query, "flow")
        # flow (xtls-rprx-vision) оставляем только на Reality — та же
        # логика, что в xray-билдере (на голом TLS flow ломает ядро).
        if flow and security == "reality":
            outbound["flow"] = flow
        packet_encoding = _q(query, "packetEncoding")
        if packet_encoding in ("xudp", "packetaddr"):
            outbound["packet_encoding"] = packet_encoding
    elif protocol == "vmess":
        outbound["uuid"] = node.credential
        outbound["security"] = str((node.extra or {}).get("scy") or "auto")
        try:
            outbound["alter_id"] = int((node.extra or {}).get("aid") or 0)
        except (TypeError, ValueError):
            outbound["alter_id"] = 0
    elif protocol == "trojan":
        outbound["password"] = node.credential
    elif protocol == "shadowsocks":
        outbound["method"] = _q(query, "method", default="aes-256-gcm")
        outbound["password"] = node.credential
    elif protocol == "hysteria":
        outbound["auth_str"] = node.credential
        outbound["up_mbps"] = _int_or(query, ("upmbps", "up_mbps", "up"), 100)
        outbound["down_mbps"] = _int_or(query, ("downmbps", "down_mbps", "down"), 100)
    elif protocol == "hysteria2":
        outbound["password"] = node.credential
        obfs = _q(query, "obfs")
        if obfs:
            if obfs == "1":
                obfs = "salamander"
            obfs_password = _q(query, "obfs-password", "obfsPassword", "obfs_password")
            if obfs == "salamander" or not obfs_password:
                outbound["obfs"] = {"type": "salamander", "password": obfs_password}
            else:
                return None, f"obfs {obfs} не поддерживается sing-box"

    # TLS/Reality.
    tls, tls_reason = _tls_block(node, fp)
    if tls_reason:
        return None, tls_reason
    if tls is not None:
        outbound["tls"] = tls

    # Транспорт.
    transport, transport_reason = _transport_block(query)
    if transport_reason:
        return None, transport_reason
    if transport is not None:
        outbound["transport"] = transport

    return outbound, None


def _int_or(query: dict[str, str], names: tuple[str, ...], default: int) -> int:
    for name in names:
        value = str(query.get(name) or "").strip()
        if value.isdigit():
            return int(value)
    return default


def sing_box_unsupported_reason(node: "XrayNode", fp: str | None = None) -> str | None:
    """Причина, по которой узел НЕ конвертируется в sing-box (None = можно)."""
    outbound, reason = sing_box_outbound(node, tag="probe", fp=fp)
    return reason


def _socks_inbound(listen_host: str, listen_port: int) -> dict[str, Any]:
    return {
        "type": "socks",
        "tag": "socks-in",
        "listen": listen_host,
        "listen_port": int(listen_port),
    }


def _dns_block(final_detour: str) -> dict[str, Any]:
    """DNS sing-box 1.12+: НОВЫЙ формат серверов (старый address/detour
    в 1.13 запрещён — «ENABLE_DEPRECATED_LEGACY_DNS_SERVERS»).

    Два сервера: bootstrap через прямой UDP (резолв адреса самого узла,
    если хост — домен; см. route.default_domain_resolver) и основной DoH
    через прокси (разрешение целей на стороне туннеля). Параметры целей
    через локальный SOCKS передаются ДОМЕННОЙ строкой, поэтому основной
    резолв выполняет сервер туннеля — как в xray-конфиге.
    """
    return {
        "servers": [
            {"type": "udp", "tag": "dns-bootstrap", "server": "8.8.8.8"},
            {"type": "https", "tag": "dns-proxy", "server": "1.1.1.1", "detour": final_detour},
        ],
        "final": "dns-proxy",
        "strategy": "ipv4_only",
    }


def _route_block(final: str) -> dict[str, Any]:
    return {
        "final": final,
        "auto_detect_interface": True,
        "default_domain_resolver": "dns-bootstrap",
        "rules": [{"ip_is_private": True, "outbound": "block"}],
    }


def sing_box_full_config(
    node: "XrayNode",
    listen_host: str,
    listen_port: int,
    *,
    fp: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Полный конфиг sing-box для одиночного узла (SOCKS-inbound)."""
    outbound, reason = sing_box_outbound(node, tag="proxy", fp=fp)
    if outbound is None:
        return None, reason
    return (
        {
            "log": {"level": "warn"},
            "dns": _dns_block("proxy"),
            "inbounds": [_socks_inbound(listen_host, listen_port)],
            "outbounds": [
                outbound,
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
            ],
            "route": _route_block("proxy"),
        },
        None,
    )


def sing_box_urltest_config(
    nodes: list["XrayNode"],
    listen_port: int = 2080,
    *,
    probe_url: str = "https://www.gstatic.com/generate_204",
    interval: str = "5m",
    tolerance_ms: int = 150,
    fp: str | None = None,
) -> tuple[dict[str, Any] | None, int, int]:
    """Конфиг sing-box «автовыбор»: все узлы + urltest-группа.

    Аналог xray leastLoad-балансера: группа urltest сама меряет RTT до
    probe_url через каждый узел и переключается на лучший.

    Возвращает (config|None, сконвертировано, пропущено).
    """
    outbounds: list[dict[str, Any]] = []
    tags: list[str] = []
    skipped = 0
    for index, node in enumerate(nodes, 1):
        tag = f"proxy-{index}"
        outbound, reason = sing_box_outbound(node, tag=tag, fp=fp)
        if outbound is None:
            skipped += 1
            continue
        outbounds.append(outbound)
        tags.append(tag)
    if not outbounds:
        return None, 0, skipped

    urltest: dict[str, Any] = {
        "type": "urltest",
        "tag": "auto",
        "outbounds": tags,
        "url": probe_url,
        "interval": interval,
        "tolerance": tolerance_ms,
    }
    config = {
        "log": {"level": "warn"},
        "dns": _dns_block("auto"),
        "inbounds": [_socks_inbound("127.0.0.1", listen_port)],
        "outbounds": outbounds + [
            urltest,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": _route_block("auto"),
    }
    return config, len(outbounds), skipped
