"""Парсинг ссылок узлов (vless/vmess/trojan/ss/hysteria) и извлечение ссылок
из тел подписок (plain/base64/JSON/Clash-YAML)."""
from __future__ import annotations


import base64
import contextlib
import json
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

from .types import NODE_LINK_RE, SING_BOX_PROTOCOLS, XrayNode
from .uritools import NODE_SCHEMES, _decode_base64, _decode_base64_plain, _sanitize_node_uri


def parse_node_link(raw_url: str, *, source_url: str = "") -> XrayNode | None:
    raw_url = _sanitize_node_uri(raw_url)
    if not raw_url:
        return None
    scheme = raw_url.split(":", 1)[0].lower()
    if scheme == "vmess":
        return _parse_vmess(raw_url, source_url)
    if scheme == "ss":
        return _parse_shadowsocks(raw_url, source_url)
    if scheme in {"vless", "trojan", "hysteria", "hysteria2", "hy2"}:
        return _parse_uri_node(raw_url, source_url)
    return None


def _parse_vmess(raw_url: str, source_url: str) -> XrayNode | None:
    payload = raw_url.split("://", 1)[1]
    decoded = _decode_base64(payload)
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        return None
    host = str(data.get("add") or data.get("host") or "").strip()
    port = int(data.get("port") or 0)
    uuid = str(data.get("id") or "").strip()
    if not host or not port or not uuid:
        return None
    query = {
        "security": str(data.get("tls") or data.get("security") or ""),
        "network": str(data.get("net") or "tcp"),
        "path": str(data.get("path") or ""),
        "host": str(data.get("host") or data.get("sni") or ""),
        "sni": str(data.get("sni") or ""),
        "alpn": str(data.get("alpn") or ""),
        "fp": str(data.get("fp") or ""),
    }
    return XrayNode(
        protocol="vmess",
        raw_url=raw_url,
        name=str(data.get("ps") or host),
        host=host,
        port=port,
        credential=uuid,
        query=query,
        source_url=source_url,
        runtime="xray",
        extra=data,
    )


def _parse_uri_node(raw_url: str, source_url: str) -> XrayNode | None:
    try:
        parsed = urlparse(raw_url)
    except ValueError:
        return None

    protocol = parsed.scheme.lower()

    try:
        host = parsed.hostname or ""
        port = int(parsed.port or 0)
    except (ValueError, TypeError):
        return None

    credential = unquote(parsed.username or "")
    if not host or not port or not credential:
        return None

    query = {
        key: values[-1]
        for key, values in parse_qs(
            parsed.query,
            keep_blank_values=True,
        ).items()
    }

    name = unquote(parsed.fragment or "") or f"{protocol}://{host}:{port}"
    runtime = "sing-box" if protocol in SING_BOX_PROTOCOLS else "xray"

    if protocol == "hy2":
        protocol = "hysteria2"

    return XrayNode(
        protocol=protocol,
        raw_url=raw_url,
        name=name,
        host=host,
        port=port,
        credential=credential,
        query=query,
        source_url=source_url,
        runtime=runtime,
    )


def _parse_shadowsocks(raw_url: str, source_url: str) -> XrayNode | None:
    try:
        parsed = urlparse(raw_url)
    except ValueError:
        # Python 3.12: urlparse кидает ValueError на битые bracketed-netloc
        # (например, спам-маскировка GitHub "[email protected]"). Мусор.
        return None
    fragment = unquote(parsed.fragment or "")
    main = raw_url.split("://", 1)[1].split("#", 1)[0]
    main = main.split("?", 1)[0]

    method = ""
    password = ""
    host = parsed.hostname or ""
    port = int(parsed.port or 0)

    if "@" in main:
        userinfo = main.rsplit("@", 1)[0]
        decoded_userinfo = _decode_base64_plain(userinfo) if ":" not in userinfo else unquote(userinfo)
        if ":" not in decoded_userinfo:
            decoded_userinfo = unquote(userinfo)
        if ":" in decoded_userinfo:
            method, password = decoded_userinfo.split(":", 1)
    else:
        decoded = _decode_base64_plain(main)
        if "@" in decoded:
            userinfo, hostport = decoded.rsplit("@", 1)
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            host, port = _split_host_port(hostport, default_port=8388)

    if not host or not port or not method or not password:
        return None
    return XrayNode(
        protocol="shadowsocks",
        raw_url=raw_url,
        name=fragment or f"ss://{host}:{port}",
        host=host,
        port=port,
        credential=password,
        query={"method": method},
        source_url=source_url,
        runtime="xray",
    )


def _split_host_port(hostport: str, *, default_port: int) -> tuple[str, int]:
    value = str(hostport or "").strip()
    if value.startswith("[") and "]" in value:
        host, _, rest = value[1:].partition("]")
        port_text = rest[1:] if rest.startswith(":") else ""
        try:
            return host, int(port_text or default_port)
        except ValueError:
            return host, default_port
    host, sep, port_text = value.rpartition(":")
    if sep:
        try:
            return host, int(port_text or default_port)
        except ValueError:
            return host, default_port
    return value, default_port


def _subscription_lines(text: str) -> list[str]:
    """Извлечь список node-ссылок из тела подписки.

    Пробует несколько интерпретаций тела:
      1. текст как есть;
      2. URL-декодированный текст;
      3. base64 (однократно);
      4. URL-декодированный base64;
      5. многоуровневый base64 (base64 внутри base64, до 3 уровней).

    Для каждой интерпретации извлекаются узлы, и выбирается вариант с
    максимальным числом распознанных node-ссылок (приоритет у протоколов
    из NODE_SCHEMES, а не просто у наибольшего числа строк).
    """
    text = str(text or "").strip()
    if not text:
        return []

    candidates: list[str] = []
    seen_text: set[str] = set()

    def add_candidate(value: str) -> None:
        value = str(value or "").strip()
        if value and value not in seen_text:
            seen_text.add(value)
            candidates.append(value)

    add_candidate(text)
    # URL-декодированный вариант.
    unquoted = text
    with contextlib.suppress(Exception):
        decoded_unquoted = unquote(text)
        if decoded_unquoted != text:
            unquoted = decoded_unquoted
            add_candidate(unquoted)
    # base64-варианты (в т.ч. URL-safe) и многоуровневые — и для исходного
    # текста, и для URL-декодированного (например %3D в url-encoded base64).
    for decoded in _decode_base64_multi(text):
        add_candidate(decoded)
    if unquoted != text:
        for decoded in _decode_base64_multi(unquoted):
            add_candidate(decoded)


    best: list[str] = []
    best_score = -1
    for candidate in candidates:
        lines = _node_lines_from_candidate(candidate)
        score = _candidate_score(lines)
        if score > best_score:
            best_score = score
            best = lines
    return best


def _candidate_score(lines: list[str]) -> int:
    """Оценка кандидата: доминирует число строк с известными протоколами."""
    recognized = 0
    for line in lines:
        lowered = line.lower()
        if any(lowered.startswith(scheme) for scheme in NODE_SCHEMES):
            recognized += 1
    return recognized * 10000 + len(lines)


def _looks_like_readable_text(value: str) -> bool:
    """Отбросить бинарный мусор после декодирования base64.

    Читаемый текст не содержит управляющих символов (кроме \r \n \t)
    и включает хотя бы одну букву/цифру.
    """
    if not value:
        return False
    if any(ord(ch) < 32 and ch not in "\r\n\t" for ch in value):
        return False
    return any(ch.isalnum() for ch in value)


def _node_lines_from_candidate(candidate: str) -> list[str]:
    """Извлечь node-ссылки из одной интерпретации тела подписки."""
    extracted: list[str] = []
    seen: set[str] = set()

    def remember(value: str) -> None:
        clean = _sanitize_node_uri(value)
        if clean and clean not in seen:
            seen.add(clean)
            extracted.append(clean)

    for value in _node_links_from_text(candidate):
        remember(value)
    if extracted:
        return extracted
    for value in _node_links_from_json(candidate):
        remember(value)
    if extracted:
        return extracted
    for value in _node_links_from_clash_yaml(candidate):
        remember(value)
    if extracted:
        return extracted
    lines: list[str] = []
    for line in candidate.replace("\r", "\n").split("\n"):
        value = _sanitize_node_uri(line)
        if value:
            lines.append(value)
    return lines


def _decode_base64_multi(value: str, *, max_depth: int = 3) -> list[str]:
    """Декодировать base64, включая URL-encoded и многоуровневый.

    Возвращает список всех уникальных результатов декодирования
    (не более max_depth уровней вложенности).
    """
    results: list[str] = []
    seen: set[str] = set()

    def walk(current: str, depth: int) -> None:
        current = str(current or "").strip()
        if not current or depth > max_depth:
            return
        # Строгий вариант: декодированная строка содержит node-ссылки
        # (://), переносы строк или JSON.
        decoded = _decode_base64(current)
        if decoded and decoded != current and decoded not in seen:
            seen.add(decoded)
            results.append(decoded)
            walk(decoded, depth + 1)
            return
        # «Сырой» вариант: промежуточный уровень многоуровневого base64
        # не обязан содержать :// и \n, но обязан дать читаемый текст.
        plain = _decode_base64_plain(current)
        if (
            plain
            and plain != current
            and plain not in seen
            and _looks_like_readable_text(plain)
        ):
            seen.add(plain)
            results.append(plain)
            walk(plain, depth + 1)

    walk(value, 1)
    return results


def _node_links_from_text(text: str) -> list[str]:
    values: list[str] = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.lower().startswith(scheme) for scheme in NODE_SCHEMES):
            values.append(stripped)
            continue
        values.extend(match.group(0) for match in NODE_LINK_RE.finditer(stripped))
    if not values:
        values.extend(match.group(0) for match in NODE_LINK_RE.finditer(str(text or "")))
    return values


def _node_links_from_json(text: str) -> list[str]:
    raw = str(text or "").strip()
    if not raw or raw[0] not in "{[":
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    links: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            links.extend(_node_links_from_text(value))
            return
        if isinstance(value, list):
            for item in value:
                walk(item)
            return
        if not isinstance(value, dict):
            return
        converted = _node_link_from_json_object(value)
        if converted:
            links.append(converted)
        for item in value.values():
            walk(item)

    walk(payload)
    return links


def _node_link_from_json_object(item: dict[str, Any]) -> str:
    protocol = str(item.get("protocol") or item.get("type") or "").strip().lower()
    if not protocol:
        return ""
    if protocol == "shadowsocks":
        return _shadowsocks_link_from_json(item)
    if protocol in {"vless", "trojan"}:
        return _standard_link_from_json(item, protocol)
    return ""


def _standard_link_from_json(item: dict[str, Any], protocol: str) -> str:
    try:
        credential = ""
        server = str(item.get("server") or item.get("address") or "").strip()
        port = int(item.get("server_port") or item.get("port") or 0)
        if protocol == "trojan":
            credential = str(item.get("password") or "").strip()
        else:
            credential = str(item.get("uuid") or item.get("id") or item.get("user") or "").strip()
        settings = item.get("settings") if isinstance(item.get("settings"), dict) else {}
        if protocol == "vless" and (not server or not port or not credential):
            for vnext in settings.get("vnext") or []:
                if not isinstance(vnext, dict):
                    continue
                server = str(vnext.get("address") or vnext.get("server") or server or "").strip()
                port = int(vnext.get("port") or port or 0)
                users = vnext.get("users") or []
                if users and isinstance(users[0], dict):
                    credential = str(users[0].get("id") or users[0].get("uuid") or credential or "").strip()
                break
        if not server or not port or not credential:
            return ""
        query = _query_from_json_transport(item)
        tag = quote(str(item.get("tag") or item.get("name") or ""), safe="")
        url = f"{protocol}://{quote(credential, safe='')}@{server}:{port}"
        if query:
            url += "?" + query
        if tag:
            url += "#" + tag
        return url
    except Exception:
        return ""


def _query_from_json_transport(item: dict[str, Any]) -> str:
    params: dict[str, str] = {}
    stream = item.get("streamSettings") if isinstance(item.get("streamSettings"), dict) else {}
    if stream:
        if stream.get("network"):
            params["type"] = str(stream.get("network") or "")
        if stream.get("security"):
            params["security"] = str(stream.get("security") or "")
        tls = stream.get("tlsSettings") if isinstance(stream.get("tlsSettings"), dict) else {}
        if tls:
            if tls.get("serverName"):
                params["sni"] = str(tls.get("serverName") or "")
            if tls.get("fingerprint"):
                params["fp"] = str(tls.get("fingerprint") or "")
            if tls.get("alpn"):
                alpn = tls.get("alpn")
                params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
            if tls.get("allowInsecure") is True:
                params["allowInsecure"] = "1"
        reality = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}
        if reality:
            params["security"] = "reality"
            for source, target in [
                ("serverName", "sni"),
                ("fingerprint", "fp"),
                ("publicKey", "pbk"),
                ("shortId", "sid"),
                ("spiderX", "spx"),
            ]:
                if reality.get(source):
                    params[target] = str(reality.get(source) or "")
        ws = stream.get("wsSettings") if isinstance(stream.get("wsSettings"), dict) else {}
        if ws:
            if ws.get("path"):
                params["path"] = str(ws.get("path") or "")
            headers = ws.get("headers") if isinstance(ws.get("headers"), dict) else {}
            if headers.get("Host") or headers.get("host"):
                params["host"] = str(headers.get("Host") or headers.get("host") or "")
        grpc = stream.get("grpcSettings") if isinstance(stream.get("grpcSettings"), dict) else {}
        if grpc:
            if grpc.get("serviceName"):
                params["serviceName"] = str(grpc.get("serviceName") or "")
            if grpc.get("authority"):
                params["authority"] = str(grpc.get("authority") or "")
            if grpc.get("multiMode") is True:
                params["mode"] = "multi"
        for settings_key in ("xhttpSettings", "splithttpSettings", "httpupgradeSettings"):
            transport_settings = stream.get(settings_key) if isinstance(stream.get(settings_key), dict) else {}
            if transport_settings:
                if transport_settings.get("path"):
                    params["path"] = str(transport_settings.get("path") or "")
                if transport_settings.get("host"):
                    params["host"] = str(transport_settings.get("host") or "")
                if transport_settings.get("mode"):
                    params["mode"] = str(transport_settings.get("mode") or "")
    tls = item.get("tls") if isinstance(item.get("tls"), dict) else {}
    if tls:
        if tls.get("enabled") is True or str(tls.get("enabled") or "").lower() == "true":
            params["security"] = "tls"
        if tls.get("server_name") or tls.get("sni"):
            params["sni"] = str(tls.get("server_name") or tls.get("sni") or "")
        if tls.get("alpn"):
            alpn = tls.get("alpn")
            params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    transport = item.get("transport") if isinstance(item.get("transport"), dict) else {}
    if transport:
        if transport.get("type") or transport.get("network"):
            params["type"] = str(transport.get("type") or transport.get("network") or "")
        if transport.get("path"):
            params["path"] = str(transport.get("path") or "")
        headers = transport.get("headers") if isinstance(transport.get("headers"), dict) else {}
        if headers.get("Host") or headers.get("host"):
            params["host"] = str(headers.get("Host") or headers.get("host") or "")
    return "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='/@:')}" for k, v in params.items() if v)


def _shadowsocks_link_from_json(item: dict[str, Any]) -> str:
    try:
        server = str(item.get("server") or item.get("address") or "").strip()
        port = int(item.get("server_port") or item.get("port") or 0)
        method = str(item.get("method") or "").strip()
        password = str(item.get("password") or "").strip()
        if not server or not port or not method or not password:
            return ""
        userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
        tag = quote(str(item.get("tag") or item.get("name") or ""), safe="")
        url = f"ss://{userinfo}@{server}:{port}"
        if tag:
            url += "#" + tag
        return url
    except Exception:
        return ""


def _node_links_from_clash_yaml(text: str) -> list[str]:
    """Извлечь node-ссылки из Clash-формата YAML (секция ``proxies``)."""
    raw = str(text or "")
    if "proxies:" not in raw:
        return []
    try:
        import yaml  # отложенный импорт: зависимость опциональна
    except Exception:
        return []
    try:
        payload = yaml.safe_load(raw)
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    proxies = payload.get("proxies")
    if not isinstance(proxies, list):
        return []
    links: list[str] = []
    for item in proxies:
        if not isinstance(item, dict):
            continue
        link = _node_link_from_clash_proxy(item)
        if link:
            links.append(link)
    return links


def _node_link_from_clash_proxy(item: dict[str, Any]) -> str:
    """Собрать node-ссылку из одного Clash-прокси."""
    try:
        proxy_type = str(item.get("type") or "").strip().lower()
        server = str(item.get("server") or item.get("host") or "").strip()
        port = int(item.get("port") or 0)
        name = str(item.get("name") or item.get("tag") or "").strip()
        if not proxy_type or not server or not port:
            return ""
        tag = quote(name, safe="")
        query = _clash_query(item)

        if proxy_type in ("vless",):
            uuid = str(item.get("uuid") or "").strip()
            if not uuid:
                return ""
            url = f"vless://{quote(uuid, safe='')}@{server}:{port}"
            if query:
                url += "?" + query
            if tag:
                url += "#" + tag
            return url

        if proxy_type in ("trojan",):
            password = str(item.get("password") or "").strip()
            if not password:
                return ""
            url = f"trojan://{quote(password, safe='')}@{server}:{port}"
            if query:
                url += "?" + query
            if tag:
                url += "#" + tag
            return url

        if proxy_type in ("ss", "shadowsocks"):
            method = str(item.get("cipher") or item.get("method") or "").strip()
            password = str(item.get("password") or "").strip()
            if not method or not password:
                return ""
            userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
            url = f"ss://{userinfo}@{server}:{port}"
            if tag:
                url += "#" + tag
            return url

        if proxy_type == "vmess":
            payload: dict[str, Any] = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": str(port),
                "id": str(item.get("uuid") or ""),
                "aid": str(item.get("alterId") or item.get("aid") or "0"),
                "scy": str(item.get("cipher") or item.get("security") or "auto"),
                "net": str(item.get("network") or "tcp"),
                "type": "none",
                "tls": "" if not item.get("tls") else "tls",
            }
            host = ""
            ws_opts = item.get("ws-opts")
            if isinstance(ws_opts, dict):
                if ws_opts.get("path"):
                    payload["path"] = str(ws_opts.get("path"))
                headers = ws_opts.get("headers")
                if isinstance(headers, dict) and (headers.get("Host") or headers.get("host")):
                    host = str(headers.get("Host") or headers.get("host"))
            else:
                if item.get("ws-path"):
                    payload["path"] = str(item.get("ws-path"))
            headers = item.get("headers")
            if not host and isinstance(headers, dict):
                host = str(headers.get("Host") or headers.get("host") or "")
            if host:
                payload["host"] = host
            sni = str(item.get("servername") or item.get("sni") or "").strip()
            if sni:
                payload["sni"] = sni
            encoded = base64.urlsafe_b64encode(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            url = f"vmess://{encoded}"
            if tag:
                url += "#" + tag
            return url

        return ""
    except Exception:
        return ""


def _clash_query(item: dict[str, Any]) -> str:
    """Собрать query-строку из транспортных полей Clash-прокси."""
    params: dict[str, str] = {}
    network = str(item.get("network") or "").strip().lower()
    if network and network != "tcp":
        params["type"] = network
    tls = item.get("tls")
    tls_enabled = False
    if isinstance(tls, bool):
        tls_enabled = tls
    elif tls is not None:
        tls_enabled = str(tls).strip().lower() in {"true", "1", "yes", "on"}
    if tls_enabled:
        params["security"] = "tls"
    sni = str(item.get("servername") or item.get("sni") or "").strip()
    if sni:
        params["sni"] = sni
    alpn = item.get("alpn")
    if alpn:
        params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    fp = str(item.get("client-fingerprint") or "").strip()
    if fp:
        params["fp"] = fp
    if item.get("skip-cert-verify") is True:
        params["allowInsecure"] = "1"
    ws_opts = item.get("ws-opts")
    if isinstance(ws_opts, dict):
        if ws_opts.get("path"):
            params["path"] = str(ws_opts.get("path"))
        headers = ws_opts.get("headers")
        if isinstance(headers, dict) and (headers.get("Host") or headers.get("host")):
            params["host"] = str(headers.get("Host") or headers.get("host"))
    else:
        if item.get("ws-path"):
            params["path"] = str(item.get("ws-path"))
        ws_headers = item.get("ws-headers")
        if isinstance(ws_headers, dict) and (ws_headers.get("Host") or ws_headers.get("host")):
            params["host"] = str(ws_headers.get("Host") or ws_headers.get("host"))
    grpc_opts = item.get("grpc-opts")
    if isinstance(grpc_opts, dict):
        if grpc_opts.get("grpc-service-name"):
            params["serviceName"] = str(grpc_opts.get("grpc-service-name"))
        if grpc_opts.get("grpc-mode"):
            params["mode"] = str(grpc_opts.get("grpc-mode"))
    h2_opts = item.get("h2-opts")
    if isinstance(h2_opts, dict):
        if h2_opts.get("path"):
            params["path"] = str(h2_opts.get("path"))
        if h2_opts.get("host"):
            params["host"] = str(h2_opts.get("host"))
    return "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='/@:')}" for k, v in params.items() if v)


DEFAULT_XRAY_SUBSCRIPTIONS = [
    "https://raw.githubusercontent.com/misha12333211-ctrl/proxy-subs/refs/heads/main/2.txt",
    "https://raw.githubusercontent.com/misha12333211-ctrl/proxy-subs/refs/heads/main/4.txt",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt",
    "https://yax.nenadoblokirowatgnidda.ru/exec?url=http%3A%2F%2F77.110.104.181%3A5002%2Fsub%2FVGdSdSwxNzg2MDE1NDU56hnfxM-O2I",
]

LEGACY_XRAY_SUBSCRIPTION_PATTERNS = (
    "charity.invisibleshrimp.su/",
    "s3.toostep.top/",
    "github.com/zieng2/wl",
    "github.com/whoahaow/rjsxrd",
    "github.com/igareck/vpn-configs-for-russia",
)

def is_legacy_xray_subscription(url: str) -> bool:
    """True, если URL относится к удалённому списку подписок."""
    return any(pattern in url for pattern in LEGACY_XRAY_SUBSCRIPTION_PATTERNS)


DEFAULT_XRAY_SUBSCRIPTIONS = [
    "https://raw.githubusercontent.com/misha12333211-ctrl/proxy-subs/refs/heads/main/2.txt",
    "https://raw.githubusercontent.com/misha12333211-ctrl/proxy-subs/refs/heads/main/4.txt",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt",
    "https://yax.nenadoblokirowatgnidda.ru/exec?url=http%3A%2F%2F77.110.104.181%3A5002%2Fsub%2FVGdSdSwxNzg2MDE1NDU56hnfxM-O2I",
]

LEGACY_XRAY_SUBSCRIPTION_PATTERNS = (
    "charity.invisibleshrimp.su/",
    "s3.toostep.top/",
    "github.com/zieng2/wl",
    "github.com/whoahaow/rjsxrd",
    "github.com/igareck/vpn-configs-for-russia",
)

def is_legacy_xray_subscription(url: str) -> bool:
    """True, если URL относится к удалённому списку подписок."""
    return any(pattern in url for pattern in LEGACY_XRAY_SUBSCRIPTION_PATTERNS)
