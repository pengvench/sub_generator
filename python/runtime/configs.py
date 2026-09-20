"""Сборка конфигов ядер: Xray-core (SOCKS-inbound + outbound + stream) и
sing-box (hysteria/hy2); запись временного конфиг-файла."""
from __future__ import annotations


import json
import logging
import tempfile
from typing import Any

from .types import XrayNode, _safe_fingerprint, _truthy, _SAFE_DEFAULT_FINGERPRINT  # noqa: F401

_logger = logging.getLogger(__name__)


def _unquote_query(value: str) -> str:
    """Раскодировать %-encoding в query-параметре, если он закодирован.

    parse_qs обычно уже раскодирует значения, но звенья конвейера могут
    передавать параметр в сыром виде (%7B%22…%7D) — поддерживаем оба.
    """
    text = str(value or "")
    if "%" in text:
        try:
            from urllib.parse import unquote

            decoded = unquote(text)
            # Двойное кодирование встречается у некоторых генераторов.
            if "%" in decoded:
                decoded = unquote(decoded)
            return decoded
        except Exception:  # noqa: BLE001
            return text
    return text


def _xray_config(
    node: XrayNode,
    listen_host: str,
    listen_port: int,
    *,
    fp: str | None = None,
) -> dict[str, Any]:
    """Собрать конфиг Xray-core с SOCKS-inbound.

    DNS — ЛОКАЛЬНЫЙ системный ("localhost" = системный резолвер) с fallback
    на обычный UDP DNS (1.1.1.1/8.8.8.8 — НЕ DoH): DoH-эндпоинты могут
    блокироваться/не работать (требование пользователя), а системный DNS
    доступен всегда — он же обслуживает все остальные приложения машины.
    """
    outbound = _xray_outbound(node, fp=fp)
    inbounds: list[dict[str, Any]] = [
        {
            "listen": listen_host,
            "port": listen_port,
            "protocol": "socks",
            "tag": "socks-in",
            "settings": {"udp": True, "auth": "noauth"},
            # sniffing: routeOnly=False (НЕ маршрутизировать по sniffed-домену).
            # Раньше было routeOnly=True + fakedns в destOverride — это требует
            # FakeIP-объект в dns-секции, без него xray-core v26 падает при
            # старте («core exited» на каждом узле). В SOCKS-режиме FakeIP
            # вообще неработоспособен (клиент уже резолвит IP локально и
            # прокси не может сопоставить IP→домен для SNI).
            # Теперь: только http/tls/quic sniffing для корректного SNI,
            # без fakedns, без routeOnly — конфиг валиден на чистом xray v26.
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": False,
            },
        }
    ]
    outbounds: list[dict[str, Any]] = [
        outbound,
        {
            "protocol": "blackhole",
            "tag": "block",
            "settings": {"response": {"type": "none"}},
        },
    ]
    routing_rules: list[dict[str, Any]] = [
        # Локальный трафик — в block, чтобы не уходил через прокси.
        {
            "type": "field",
            "outboundTag": "block",
            "ip": ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        }
    ]
    # DNS — ЛОКАЛЬНЫЙ системный резолвер (первый) + обычный UDP DNS как
    # fallback. DoH убран: может блокироваться (требование пользователя).
    # Домены целей уходят в туннель как домены — резолвит их удалённый
    # сервер, локальный DNS нужен только для адреса самого узла.
    dns_servers = ["localhost", "1.1.1.1", "8.8.8.8"]

    return {
        "log": {"loglevel": "warning", "access": "", "error": ""},
        "dns": {
            "servers": dns_servers,
            "queryStrategy": "UseIPv4",
            "disableFallback": False,
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": routing_rules,
        },
    }

def _xray_outbound(node: XrayNode, *, fp: str | None = None) -> dict[str, Any]:
    q = node.query
    stream = _xray_stream_settings(q, fp=fp)
    flow = (q.get("flow") or "").strip()
    security = (q.get("security") or q.get("tls") or "").strip().lower()
    # flow (xtls-rprx-vision и т.п.) поддерживается ТОЛЬКО на Reality.
    # На TLS-узлах xray-core падает на старте — узел ложно «мёртв» (core
    # exited). Выкидываем flow на не-Reality узлах.
    if flow and security != "reality":
        flow = ""
    if node.protocol == "vless":
        user = {"id": node.credential, "encryption": q.get("encryption") or "none"}
        if flow:
            user["flow"] = flow
        outbound = {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {"vnext": [{"address": node.host, "port": node.port, "users": [user]}]},
            "streamSettings": stream,
        }
    elif node.protocol == "vmess":
        user = {"id": node.credential, "alterId": int(node.extra.get("aid") or 0), "security": node.extra.get("scy") or "auto"}
        outbound = {
            "protocol": "vmess",
            "tag": "proxy",
            "settings": {"vnext": [{"address": node.host, "port": node.port, "users": [user]}]},
            "streamSettings": stream,
        }
    elif node.protocol == "trojan":
        outbound = {
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {"servers": [{"address": node.host, "port": node.port, "password": node.credential}]},
            "streamSettings": stream,
        }
    elif node.protocol == "shadowsocks":
        outbound = {
            "protocol": "shadowsocks",
            "tag": "proxy",
            "settings": {
                "servers": [
                    {
                        "address": node.host,
                        "port": node.port,
                        "method": q.get("method") or "aes-256-gcm",
                        "password": node.credential,
                    }
                ]
            },
        }
    else:
        raise ValueError(f"Unsupported xray protocol: {node.protocol}")
    # Анти-детект ТСПУ: mux консолидирует параллельные TLS-соединения к одному
    # SNI в одно (Сигнал 3 «заморозки»). XTLS Vision несовместим с TCP-mux
    # («MUX is not compatible with XTLS raw connections») — только XUDP.
    # v15: XHTTP/splithttp НЕСОВМЕСТИМ с mux (документация Xray-core:
    # «XHTTP does not support mux») — для этих транспортов mux выключен.
    # Раньше mux включался всем vless/vmess/trojan подряд — Happ-подобные
    # CDN-фронтинг конфиги (vless+xhttp через Fastly) из-за этого не
    # проходили туннелирование трафика.
    _network_name = (node.query.get("type") or node.query.get("network") or "tcp").strip().lower()
    if node.protocol in ("vless", "vmess", "trojan") and _network_name not in ("xhttp", "splithttp"):
        if flow == "xtls-rprx-vision":
            outbound["mux"] = {"enabled": True, "concurrency": -1, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}
        else:
            outbound["mux"] = {"enabled": True, "concurrency": 8, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}
    return outbound

def _resolve_stream_fingerprint(query: dict[str, str], fp: str | None) -> str | None:
    """Выбрать TLS-фингерпринт uTLS для stream-конфига.

    Приоритет:
      1. fp_override (fp) из fingerprint-матрицы/активного теста — используется
         КАК ЕСТЬ, без _safe_fingerprint (нужен настоящий chrome/random, чтобы
         проверить устойчивость к DPI).
      2. fp из query-ссылки узла — через _safe_fingerprint (безопасный режим).
      3. Неизвестный/пустой — _SAFE_DEFAULT_FINGERPRINT (как раньше).

    Возвращает None только если fp == "none" (системный TLS, без uTLS).
    """
    if fp is not None:
        value = str(fp or "").strip().lower()
        if not value or value == "none":
            return None
        return value
    return _safe_fingerprint(query.get("fp") or query.get("fingerprint"))


def _normalize_reality_pbk(value: str) -> str:
    """Нормализовать Reality publicKey (pbk) до base64URL БЕЗ padding.

    xray-core v26+ парсит publicKey через base64.RawURLEncoding: принимает
    ТОЛЬКО URL-safe алфавит ('-'/'_') без '='. Старая нормализация
    («+»/«/» + padding) валидна для StdEncoding, но xray v26 её отвергает —
    каждый Reality-узел падал с «core exited» ( reproducing: xray -test
    возвращает «Failed to build REALITY config: invalid "password"»).
    Подписи дают pbk в URL-safe виде — пропускаем как есть; standard-вариант
    конвертируем в URL-safe и срезаем padding.
    Ничего не делает с пустым/не-base64 значением (передаём как есть —
    ядро само выдаст внятную ошибку в stderr).
    """
    text = str(value or "").strip()
    if not text:
        return text
    cleaned = text.replace("+", "-").replace("/", "_").rstrip("=")
    if not cleaned or not all(c.isalnum() or c in "-_" for c in cleaned):
        return text
    return cleaned

def _xray_stream_settings(query: dict[str, str], *, fp: str | None = None) -> dict[str, Any]:
    network = (query.get("type") or query.get("network") or query.get("net") or "tcp").strip()
    if network == "h2":
        network = "http"
    security = query.get("security") or query.get("tls") or ""
    stream: dict[str, Any] = {"network": network}
    if query.get("packetEncoding"):
        stream["packetEncoding"] = query["packetEncoding"]
    if security and security != "none":
        stream["security"] = security
    sni = query.get("sni") or query.get("serverName") or query.get("host") or ""
    resolved_fp = _resolve_stream_fingerprint(query, fp)
    if security == "tls":
        tls: dict[str, Any] = {}
        if sni:
            tls["serverName"] = sni
        if _truthy(query.get("allowInsecure") or query.get("allow_insecure") or query.get("insecure")):
            tls["allowInsecure"] = True
        if resolved_fp is not None:
            tls["fingerprint"] = resolved_fp
        if query.get("alpn"):
            tls["alpn"] = [item.strip() for item in str(query.get("alpn") or "").split(",") if item.strip()]
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality: dict[str, Any] = {}
        if sni:
            reality["serverName"] = sni
        for source, target in [("pbk", "publicKey"), ("publicKey", "publicKey"), ("sid", "shortId"), ("spx", "spiderX")]:
            if query.get(source):
                value = query[source]
                # pbk/publicKey приходит URL-safe и без padding — нормализуем,
                # иначе ядро падает на старте и узел ложно «мёртв».
                if target == "publicKey":
                    value = _normalize_reality_pbk(value)
                reality[target] = value
        if resolved_fp is not None:
            reality["fingerprint"] = resolved_fp
        stream["realitySettings"] = reality
    if network == "ws":
        ws: dict[str, Any] = {}
        if query.get("path"):
            ws["path"] = query["path"]
        if query.get("host"):
            ws["headers"] = {"Host": query["host"]}
        stream["wsSettings"] = ws
    elif network == "tcp":
        header_type = query.get("headerType") or query.get("header") or ""
        if header_type and header_type != "none":
            tcp: dict[str, Any] = {"header": {"type": header_type}}
            if header_type == "http":
                request: dict[str, Any] = {}
                if query.get("host"):
                    request["headers"] = {"Host": [item.strip() for item in query["host"].split(",") if item.strip()]}
                if query.get("path"):
                    request["path"] = [item.strip() for item in query["path"].split(",") if item.strip()]
                if request:
                    tcp["header"]["request"] = request
            stream["tcpSettings"] = tcp
    elif network == "http":
        http: dict[str, Any] = {}
        if query.get("host"):
            http["host"] = [item.strip() for item in query["host"].split(",") if item.strip()]
        if query.get("path"):
            http["path"] = query["path"]
        stream["httpSettings"] = http
    elif network == "grpc":
        service = query.get("serviceName") or query.get("service") or ""
        stream["grpcSettings"] = {"serviceName": service}
        if (query.get("mode") or "").lower() == "multi":
            stream["grpcSettings"]["multiMode"] = True
        if query.get("authority"):
            stream["grpcSettings"]["authority"] = query["authority"]
    elif network == "httpupgrade":
        httpupgrade: dict[str, Any] = {}
        if query.get("path"):
            httpupgrade["path"] = query["path"]
        if query.get("host"):
            httpupgrade["host"] = query["host"]
        stream["httpupgradeSettings"] = httpupgrade
    elif network == "xhttp":
        xhttp: dict[str, Any] = {}
        if query.get("path"):
            xhttp["path"] = query["path"]
        if query.get("host"):
            xhttp["host"] = query["host"]
        if query.get("mode"):
            xhttp["mode"] = query["mode"]
        # v15: passthrough параметра extra — Happ-подобные подписки задают
        # tuning XHTTP (scMaxEachPostBytes/scMaxConcurrentPosts/xPaddingBytes/
        # noGRPCHeader) именно через него; раньше параметр молча терялся и
        # узел ходил с дефолтами транспорта.
        _extra_raw = query.get("extra")
        if _extra_raw:
            try:
                _extra = json.loads(_unquote_query(_extra_raw))
                if isinstance(_extra, dict):
                    xhttp["extra"] = _extra
            except Exception:  # noqa: BLE001 — битый extra не должен ронять конфиг
                _logger.debug("xhttp extra не разобран: %r", _extra_raw[:120])
        stream["xhttpSettings"] = xhttp
    elif network == "splithttp":
        xhttp: dict[str, Any] = {}
        if query.get("path"):
            xhttp["path"] = query["path"]
        if query.get("host"):
            xhttp["host"] = query["host"]
        if query.get("mode"):
            xhttp["mode"] = query["mode"]
        _extra_raw = query.get("extra")
        if _extra_raw:
            try:
                _extra = json.loads(_unquote_query(_extra_raw))
                if isinstance(_extra, dict):
                    xhttp["extra"] = _extra
            except Exception:  # noqa: BLE001
                pass
        stream["splithttpSettings"] = xhttp
    elif network == "kcp":
        kcp: dict[str, Any] = {
            "mtu": int(query.get("mtu") or 1350),
            "tti": int(query.get("tti") or 50),
            "uplinkCapacity": int(query.get("uplinkCapacity") or query.get("up") or 12),
            "downlinkCapacity": int(query.get("downlinkCapacity") or query.get("down") or 100),
            "congestion": _truthy(query.get("congestion")),
            "readBufferSize": int(query.get("readBufferSize") or 2),
            "writeBufferSize": int(query.get("writeBufferSize") or 2),
            "header": {"type": query.get("headerType") or query.get("header") or "none"},
        }
        if query.get("seed"):
            kcp["seed"] = query["seed"]
        stream["kcpSettings"] = kcp
    elif network == "quic":
        stream["quicSettings"] = {
            "security": query.get("quicSecurity") or query.get("securityType") or query.get("host") or "none",
            "key": query.get("key") or query.get("path") or "",
            "header": {"type": query.get("headerType") or query.get("header") or "none"},
        }
    return stream


def _sing_box_outbound(node: XrayNode, *, fp: str | None = None) -> dict[str, Any]:
    """Собрать sing-box outbound для ЛЮБОГО протокола ссылки узла.

    Требуется для режима «только sing-box»: vless/vmess/trojan/ss тоже
    должны собираться в корректный sing-box-конфиг (раньше builder умел
    только hysteria/hy2 и ставил password всем подряд).

    v11: бросает SingBoxUnsupported для неподдерживаемых транспортов/протоколов
    (kcp/quic/xhttp/legacy-scy). Это позволяет _sing_box_supports() и тестам
    ловить unsupported-случай как исключение, а не как ValueError.
    """
    # v11: пред-проверка поддержки через sing_box_unsupported_reason.
    # Если узел не поддерживается — кидаем SingBoxUnsupported (не ValueError).
    try:
        from singbox_convert import sing_box_unsupported_reason
        reason = sing_box_unsupported_reason(node, fp=fp)
        if reason:
            raise SingBoxUnsupported(reason)
    except SingBoxUnsupported:
        raise
    except Exception as exc:
        # singbox_convert недоступен (ленивый импорт) — продолжаем по
        # старому пути; причину фиксируем для диагностики сборок exe.
        _logger.debug("singbox_convert недоступен, старый путь: %s", exc)
    q = node.query
    protocol = node.protocol
    outbound: dict[str, Any] = {
        "tag": "proxy",
        "server": node.host,
        "server_port": node.port,
    }
    if protocol == "vless":
        outbound["type"] = "vless"
        outbound["uuid"] = node.credential
        flow = (q.get("flow") or "").strip()
        security = (q.get("security") or q.get("tls") or "").strip().lower()
        # flow (xtls-rprx-vision) валиден только на Reality — как в xray-builder.
        if flow and security == "reality":
            outbound["flow"] = flow
    elif protocol == "vmess":
        outbound["type"] = "vmess"
        outbound["uuid"] = node.credential
        outbound["security"] = node.extra.get("scy") or "auto"
        outbound["alter_id"] = int(node.extra.get("aid") or 0)
    elif protocol == "trojan":
        outbound["type"] = "trojan"
        outbound["password"] = node.credential
    elif protocol == "shadowsocks":
        outbound["type"] = "shadowsocks"
        outbound["method"] = q.get("method") or "aes-256-gcm"
        outbound["password"] = node.credential
    elif protocol in ("hysteria", "hysteria2", "hy2"):
        outbound["type"] = "hysteria2" if protocol in ("hysteria2", "hy2") else "hysteria"
        if protocol in ("hysteria2", "hy2"):
            outbound["password"] = node.credential
            if q.get("obfs"):
                obfs_type = q.get("obfs")
                if obfs_type == "1":
                    obfs_type = "salamander"
                outbound["obfs"] = {
                    "type": obfs_type,
                    "password": q.get("obfs-password") or q.get("obfsPassword") or q.get("obfs_password") or "",
                }
        else:
            outbound["auth_str"] = node.credential
            outbound["up_mbps"] = int(q.get("upmbps") or q.get("up_mbps") or q.get("up") or 100)
            outbound["down_mbps"] = int(q.get("downmbps") or q.get("down_mbps") or q.get("down") or 100)
            if q.get("obfs"):
                outbound["obfs"] = {"type": "salamander", "password": q.get("obfs-password") or ""}
    else:
        raise SingBoxUnsupported(f"Unsupported sing-box protocol: {protocol}")

    # TLS: hysteria/hy2 всегда с TLS (протокол TLS-based). Остальные — по security.
    if protocol in ("hysteria", "hysteria2", "hy2"):
        tls = _sing_box_tls(node, {**q, "security": q.get("security") or "tls"}, fp)
        if tls is None:
            tls = {"enabled": True}
        if "server_name" not in tls:
            sni = q.get("sni") or q.get("peer") or node.host
            if sni:
                tls["server_name"] = sni
        outbound["tls"] = tls
    else:
        tls = _sing_box_tls(node, q, fp)
        if tls is not None:
            outbound["tls"] = tls
    # Транспорт (ws/grpc/http) — только для не-hysteria протоколов.
    if protocol not in ("hysteria", "hysteria2", "hy2"):
        transport = _sing_box_transport(q)
        if transport is not None:
            outbound["transport"] = transport
    return outbound

def _sing_box_config(
    node: XrayNode,
    listen_host: str,
    listen_port: int,
    *,
    fp: str | None = None,
) -> dict[str, Any]:
    """Собрать конфиг sing-box с SOCKS-inbound (ЛЮБОЙ протокол узла).

    DNS-резолвинг выполняет САМ прокси-сервер (через outbound proxy): все
    DNS-серверы в секции `dns.servers` имеют `"detour": "proxy"`, поэтому
    DoH/UDP DNS-запросы идут через прокси-сервер узла, а не через локальный
    резолвер. Это критично для заблокированных сетей, где локальный DNS
    режется провайдером.
    """
    outbound = _sing_box_outbound(node, fp=fp)

    inbounds: list[dict[str, Any]] = [
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": listen_host,
            "listen_port": listen_port,
        }
    ]
    outbounds: list[dict[str, Any]] = [outbound]
    route: dict[str, Any] = {"final": "proxy", "auto_detect_interface": True}

    # DNS — ЛОКАЛЬНЫЙ системный резолвер (type: local). DoH через прокси
    # убран: DoH-эндпоинты могут блокироваться/не работать (требование
    # пользователя). Домены целей уходят в туннель как домены — их
    # резолвит удалённый сервер; локальный DNS нужен только для адреса
    # самого узла, а он всегда доступен (обслуживает всю систему).
    dns_block: dict[str, Any] = {
        "servers": [
            {
                "tag": "local",
                "type": "local",
            },
        ],
        "final": "local",
        "strategy": "ipv4_only",
    }

    result: dict[str, Any] = {
        "log": {"level": "warn", "disabled": False},
        "dns": dns_block,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
    }
    return result

def _write_temp_config(config: dict[str, Any]) -> str:
    handle = tempfile.NamedTemporaryFile("w", prefix="mtproxy-autoswitch-core-", suffix=".json", delete=False, encoding="utf-8")
    with handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
    return handle.name


class SingBoxUnsupported(Exception):
    """Узел не может быть представлен в sing-box (kcp/quic/xhttp/legacy-scy).

    v11: заглушка для обратной совместимости со старым test_singbox_mode.py.
    Реальный raise в _sing_box_outbound не делаем (это потребует глубокой
    переработки конфигуратора) — но исключение определено, чтобы импорт работал.
    """
    pass

def _sing_box_supports(node: Any) -> tuple[bool, str]:
    """Проверить, поддерживает ли sing-box данный узел.

    Возвращает (supported, reason). reason пустой если supported=True.
    Аналог старого API для test_singbox_mode.py.
    """
    # Импорт здесь — чтобы избежать циклического импорта.
    from singbox_convert import sing_box_unsupported_reason
    reason = sing_box_unsupported_reason(node)
    if reason:
        return (False, reason)
    return (True, "")


class SingBoxUnsupported(Exception):
    """Узел не может быть представлен в sing-box (kcp/quic/xhttp/legacy-scy).

    v11: заглушка для обратной совместимости со старым test_singbox_mode.py.
    Реальный raise в _sing_box_outbound не делаем (это потребует глубокой
    переработки конфигуратора) — но исключение определено, чтобы импорт работал.
    """
    pass

def _sing_box_supports(node: Any) -> tuple[bool, str]:
    """Проверить, поддерживает ли sing-box данный узел.

    Возвращает (supported, reason). reason пустой если supported=True.
    Аналог старого API для test_singbox_mode.py.
    """
    # Импорт здесь — чтобы избежать циклического импорта.
    from singbox_convert import sing_box_unsupported_reason
    reason = sing_box_unsupported_reason(node)
    if reason:
        return (False, reason)
    return (True, "")


def _sing_box_tls(node: XrayNode, query: dict[str, str], fp: str | None) -> dict[str, Any] | None:
    """TLS-блок sing-box outbound (tls/reality) из query-параметров.

    Возвращает None, если узел без TLS. Для Reality обязательно включается
    uTLS (требование sing-box).
    """
    security = (query.get("security") or query.get("tls") or "").strip().lower()
    if not security or security == "none":
        return None
    sni = query.get("sni") or query.get("peer") or query.get("serverName") or query.get("host") or ""
    tls: dict[str, Any] = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    if _truthy(query.get("insecure") or query.get("allowInsecure") or query.get("allow_insecure")):
        tls["insecure"] = True
    if query.get("alpn"):
        tls["alpn"] = [item.strip() for item in query["alpn"].split(",") if item.strip()]
    resolved_fp = _resolve_stream_fingerprint(query, fp)
    if security == "reality":
        reality: dict[str, Any] = {"enabled": True}
        pbk = query.get("pbk") or query.get("publicKey") or ""
        if pbk:
            reality["public_key"] = _normalize_reality_pbk(pbk)
        if query.get("sid"):
            reality["short_id"] = query["sid"]
        # Reality в sing-box ТРЕБУЕТ uTLS — без фингерпринта ядро падает.
        reality_fp = resolved_fp or _SAFE_DEFAULT_FINGERPRINT
        tls["utls"] = {"enabled": True, "fingerprint": reality_fp}
        tls["reality"] = reality
    else:
        if resolved_fp is not None:
            tls["utls"] = {"enabled": True, "fingerprint": resolved_fp}
    return tls

def _sing_box_transport(query: dict[str, str]) -> dict[str, Any] | None:
    """Транспорт для sing-box outbound из query-параметров ссылки узла.

    Возвращает None для чистого TCP (транспорта нет), dict — для ws/grpc/http.
    Неподдерживаемые sing-box транспорты (xhttp/splithttp) дают ValueError —
    узел честно отбраковывается, а не тестируется молча неправильно.
    """
    network = (query.get("type") or query.get("network") or query.get("net") or "tcp").strip().lower()
    if network in ("", "tcp", "raw"):
        header_type = (query.get("headerType") or query.get("header") or "").strip().lower()
        if header_type and header_type != "none":
            # headerType=http поверх TCP sing-box не поддерживает в outbound.
            return None
        return None
    if network == "ws":
        transport: dict[str, Any] = {"type": "ws"}
        if query.get("path"):
            transport["path"] = query["path"]
        if query.get("host"):
            transport["headers"] = {"Host": query["host"]}
        if query.get("ed") or query.get("eh") or (query.get("path") or "").find("ed=2048") >= 0:
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return transport
    if network in ("grpc",):
        transport = {"type": "grpc"}
        service = query.get("serviceName") or query.get("service") or ""
        if service:
            transport["service_name"] = service
        return transport
    if network in ("http", "h2"):
        transport = {"type": "http"}
        if query.get("host"):
            transport["host"] = [item.strip() for item in query["host"].split(",") if item.strip()]
        if query.get("path"):
            transport["path"] = query["path"]
        return transport
    if network == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if query.get("path"):
            transport["path"] = query["path"]
        if query.get("host"):
            transport["host"] = query["host"]
        return transport
    # v11: SingBoxUnsupported вместо ValueError — для совместимости с
    # _sing_box_supports() и test_singbox_mode.py.
    raise SingBoxUnsupported(f"sing-box does not support transport: {network}")
