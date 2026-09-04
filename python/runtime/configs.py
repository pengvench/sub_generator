"""Сборка конфигов ядер: Xray-core (SOCKS-inbound + outbound + stream) и
sing-box (hysteria/hy2); запись временного конфиг-файла."""
from __future__ import annotations


import json
import tempfile
from typing import Any

from .types import XrayNode, _safe_fingerprint, _truthy


def _xray_config(
    node: XrayNode,
    listen_host: str,
    listen_port: int,
    *,
    fp: str | None = None,
) -> dict[str, Any]:
    """Собрать конфиг Xray-core с SOCKS-inbound.

    DNS-резолвинг выполняет САМ прокси-сервер (через outbound proxy), а не
    локальный резолвер: DoH к https://1.1.1.1/dns-query (без +local, чтобы
    не резолвить 1.1.1.1 через системный DNS — это уже IP) и UDP DNS к
    8.8.8.8 (тоже через прокси, благодаря routing rule 53/UDP → proxy).
    localhost убран: системный резолвер может быть отравлен на заблокированных
    сетях. Это критично: если локальный DNS режется, узел всё равно сможет
    резолвить домены через прокси.
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
    # DNS только через прокси: DoH к Cloudflare (1.1.1.1 — это уже IP, не
    # требует локального резолва) + UDP DNS к Google.UDP DNS сам по себе
    # пойдёт через прокси благодаря routing rule 53/UDP → proxy ниже.
    dns_servers = ["https://1.1.1.1/dns-query", "8.8.8.8", "1.0.0.1"]

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


def _xray_outbound(node: XrayNode, *, fp: str | None = None, tag: str = "proxy") -> dict[str, Any]:
    """Xray-outbound для узла.

    ``tag`` — имя outbound в конфиге (по умолчанию "proxy"; автовыборка
    использует "proxy-1".."proxy-N" для балансера).
    """
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
            "tag": tag,
            "settings": {"vnext": [{"address": node.host, "port": node.port, "users": [user]}]},
            "streamSettings": stream,
        }
    elif node.protocol == "vmess":
        user = {"id": node.credential, "alterId": int(node.extra.get("aid") or 0), "security": node.extra.get("scy") or "auto"}
        outbound = {
            "protocol": "vmess",
            "tag": tag,
            "settings": {"vnext": [{"address": node.host, "port": node.port, "users": [user]}]},
            "streamSettings": stream,
        }
    elif node.protocol == "trojan":
        outbound = {
            "protocol": "trojan",
            "tag": tag,
            "settings": {"servers": [{"address": node.host, "port": node.port, "password": node.credential}]},
            "streamSettings": stream,
        }
    elif node.protocol == "shadowsocks":
        outbound = {
            "protocol": "shadowsocks",
            "tag": tag,
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
    if node.protocol in ("vless", "vmess", "trojan"):
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
    """Нормализовать Reality publicKey (pbk) до валидного base64.

    Подписки отдают pbk в двух вариациях, которые xray не принимает как есть:
      - URL-safe base64 ('-'/'_' вместо '+'/'/');
      - без padding ('abc123' вместо 'abc123=').
    Без нормализации ядро падает на старте («core exited») и весь узел
    ложно считается мёртвым, хотя достаточно привести ключ к стандартному
    виду. Ничего не делает с пустым/не-base64 значением (передаём как есть —
    ядро само выдаст внятную ошибку в stderr).
    """
    text = str(value or "").strip()
    if not text:
        return text
    if "-" in text or "_" in text:
        text = text.replace("-", "+").replace("_", "/")
    if text and len(text) % 4 != 0:
        text = text + "=" * (-len(text) % 4)
    return text


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
        stream["xhttpSettings"] = xhttp
    elif network == "splithttp":
        xhttp: dict[str, Any] = {}
        if query.get("path"):
            xhttp["path"] = query["path"]
        if query.get("host"):
            xhttp["host"] = query["host"]
        if query.get("mode"):
            xhttp["mode"] = query["mode"]
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


def _sing_box_outbound(node: XrayNode, *, fp: str | None = None, tag: str = "proxy") -> dict[str, Any]:
    """sing-box outbound для узла (hysteria/hysteria2/hy2).

    Выделен из _sing_box_config: используется и для проверки одного узла,
    и для сборки конфига-автовыборки (несколько outbound + urltest).
    """
    outbound: dict[str, Any] = {
        "type": node.protocol,
        "tag": tag,
        "server": node.host,
        "server_port": node.port,
    }
    if node.protocol == "hysteria":
        outbound["auth_str"] = node.credential
        outbound["up_mbps"] = int(node.query.get("upmbps") or node.query.get("up_mbps") or node.query.get("up") or 100)
        outbound["down_mbps"] = int(node.query.get("downmbps") or node.query.get("down_mbps") or node.query.get("down") or 100)
    else:
        outbound["password"] = node.credential
    sni = node.query.get("sni") or node.query.get("peer") or node.query.get("host") or ""
    tls = {"enabled": True, **({"server_name": sni} if sni else {})}
    if _truthy(node.query.get("insecure") or node.query.get("allowInsecure") or node.query.get("allow_insecure")):
        tls["insecure"] = True
    if node.query.get("alpn"):
        tls["alpn"] = [item.strip() for item in node.query["alpn"].split(",") if item.strip()]
    resolved_sing_fp = _resolve_stream_fingerprint(node.query, fp)
    if resolved_sing_fp is None:
        tls["utls"] = {"enabled": False}
    else:
        tls["utls"] = {"enabled": True, "fingerprint": resolved_sing_fp}
    outbound["tls"] = tls
    if node.query.get("obfs"):
        obfs_type = node.query.get("obfs")
        if obfs_type == "1":
            obfs_type = "salamander"
        outbound["obfs"] = {"type": obfs_type, "password": node.query.get("obfs-password") or node.query.get("obfsPassword") or node.query.get("obfs_password") or ""}
    return outbound


def _sing_box_config(
    node: XrayNode,
    listen_host: str,
    listen_port: int,
    *,
    fp: str | None = None,
) -> dict[str, Any]:
    """Собрать конфиг sing-box с SOCKS-inbound.

    DNS-резолвинг выполняет САМ прокси-сервер (через outbound proxy): все
    DNS-серверы в секции `dns.servers` имеют `"detour": "proxy"`, поэтому
    DoH/UDP DNS-запросы идут через прокси-сервер узла, а не через локальный
    резолвер. Это критично для заблокированных сетей, где локальный DNS
    режется провайдером.
    """
    outbound: dict[str, Any] = _sing_box_outbound(node, fp=fp, tag="proxy")

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

    # DNS только через прокси: каждый сервер имеет "detour": "proxy",
    # поэтому DoH/UDP DNS идут через outbound proxy. Если локальный DNS
    # режется провайдером — это не влияет на проверку: узел резолвит
    # домены через свой собственный DNS-сервер.
    dns_block: dict[str, Any] = {
        "servers": [
            {
                "tag": "proxy-doh-cf",
                "address": "https://1.1.1.1/dns-query",
                "detour": "proxy",
            },
            {
                "tag": "proxy-doh-google",
                "address": "https://dns.google/dns-query",
                "detour": "proxy",
            },
            {
                "tag": "proxy-udp-cf",
                "address": "1.1.1.1",
                "detour": "proxy",
            },
            {
                "tag": "proxy-udp-google",
                "address": "8.8.8.8",
                "detour": "proxy",
            },
        ],
        "final": "proxy-doh-cf",
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
