"""Канонизация URI узлов: санитизация, base64-декод, нормализация padding,
дедупликационный текст (используется XrayNode.key)."""
from __future__ import annotations


import base64
import contextlib
import html
import json
import re
from urllib.parse import parse_qs, quote, unquote, urlsplit, urlunsplit

# Схемы ссылок узлов — фундаментальная константа канонизации URI.
NODE_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "hysteria://")


def _sanitize_node_uri(raw_uri: object) -> str:
    try:
        value = html.unescape(str(raw_uri or ""))
    except Exception:
        return ""
    value = value.replace("\r", "").replace("\n", "").strip()
    if not value:
        return ""
    lowered = value.lower()
    indices = [lowered.find(scheme) for scheme in NODE_SCHEMES if lowered.find(scheme) >= 0]
    if indices:
        value = value[min(indices):]
    value = re.sub(r"[\s\)\]>,\.;]+$", "", value)
    if "#" in value and not value.lower().startswith("vmess://"):
        base, fragment = value.split("#", 1)
        with contextlib.suppress(Exception):
            fragment = quote(unquote(fragment), safe="")
        value = base + "#" + fragment
    return value


def _normalize_base64_padding(value: str) -> str:
    """Привести base64-строку к каноническому виду с правильным padding.

    Некоторые подписки отдают pbk/sid без '=' в конце (URL-safe без padding),
    другие — с '='. Например:
      pbk=abc123      (без padding)
      pbk=abc123=     (с padding)

    Это ОДИН И ТОТ ЖЕ ключ, но без нормализации они считаются разными
    конфигами. Добавляем padding по длине (base64 должен быть кратен 4).
    """
    if not value:
        return value
    # Убираем существующий padding для пересчёта.
    stripped = value.rstrip("=")
    # Добавляем правильный padding.
    pad_len = (-len(stripped)) % 4
    return stripped + ("=" * pad_len)


# Query-параметры, которые содержат base64-данные и нуждаются в
# нормализации padding. Без этого один и тот же Reality-узел с
# pbk=abc123 (без =) и pbk=abc123= (с =) считаются разными.
_BASE64_QUERY_PARAMS = frozenset({
    "pbk", "sid", "publickey", "public-key",
    "privatekey", "private-key",
    "spxfingerprint", "spx",
})


def _normalize_ss_userinfo(userinfo: str) -> str:
    """Нормализовать userinfo из ss:// URL.

    ss://userinfo@host:port — userinfo может быть:
      1. base64("method:password") — стандартный v2ray-формат
      2. "method:password" — plaintext (v2rayN/happ могут так отдавать)

    Декодируем base64 в "method:password", если это возможно — так оба
    варианта считаются одинаковыми при дедупликации.
    """
    if not userinfo:
        return userinfo
    # Если уже содержит ':' — это plaintext "method:password".
    if ":" in userinfo:
        return userinfo
    # Пробуем декодировать base64 → "method:password".
    try:
        # URL-safe base64 decode (c padding коррекцией).
        padded = _normalize_base64_padding(userinfo)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            with contextlib.suppress(Exception):
                decoded = decoder(padded).decode("utf-8", errors="replace")
                if ":" in decoded:
                    return decoded
    except Exception:
        pass
    return userinfo


def _node_dedup_text(raw_uri: str) -> str:
    value = _sanitize_node_uri(raw_uri)
    if not value:
        return ""
    if value.lower().startswith("vmess://"):
        decoded = _decode_base64_plain(value[8:].split("#", 1)[0])
        with contextlib.suppress(Exception):
            payload = json.loads(decoded)
            # Удаляем поле ``ps`` (имя узла) перед канонизацией JSON —
            # vmess-узлы с разными именами, но одинаковыми параметрами
            # (add/port/id/aid/scy/net/host/sni/...) должны считаться
            # одним конфигом при дедупликации.
            if isinstance(payload, dict):
                payload.pop("ps", None)
            return "vmess://" + json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return value
    if "#" in value:
        value = value.split("#", 1)[0]
    parsed = urlsplit(value)
    if not parsed.scheme:
        return value
    query = ""
    if parsed.query:
        items = parse_qs(parsed.query, keep_blank_values=True)
        parts: list[str] = []
        for key in sorted(items):
            for item in sorted(items[key]):
                # Нормализация base64-параметров (pbk, sid, publicKey и т.д.):
                # добавляем padding, чтобы abc123 и abc123= считались одним ключом.
                normalized_item = item
                if key.lower() in _BASE64_QUERY_PARAMS:
                    normalized_item = _normalize_base64_padding(item)
                parts.append(f"{quote(str(key), safe='')}={quote(str(normalized_item), safe='/@:')}")
        query = "&".join(parts)
    host = (parsed.hostname or "").lower()
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    # Собираем userinfo: username и password (если есть).
    # Для ss:// URL userinfo может быть как "method:password" (plain),
    # так и base64("method:password"). Нормализуем base64 в plain,
    # чтобы оба варианта считались одним конфигом.
    if parsed.username:
        username = unquote(parsed.username)
        password = unquote(parsed.password) if parsed.password else ""
        if parsed.scheme.lower() == "ss":
            # Для ss://: если password есть, это уже plaintext "method:password".
            # Если нет — username может быть base64("method:password").
            if password:
                userinfo_str = f"{username}:{password}"
            else:
                userinfo_str = _normalize_ss_userinfo(username)
        else:
            # Для vless/trojan/hysteria — username это UUID/password,
            # password обычно не используется.
            userinfo_str = username
            if password:
                userinfo_str = f"{username}:{password}"
        userinfo = quote(userinfo_str, safe=":")
        netloc = f"{userinfo}@{netloc}"
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), netloc, path, query, ""))


def _decode_base64(value: str) -> str:
    compact = "".join(str(value or "").strip().split())
    if not compact:
        return ""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        with contextlib.suppress(Exception):
            padded = compact + "=" * (-len(compact) % 4)
            decoded = decoder(padded.encode("ascii"))
            text = decoded.decode("utf-8", errors="replace")
            stripped = text.lstrip()
            if "://" in text or "\n" in text or stripped.startswith(("{", "[")):
                return text
    return value


def _decode_base64_plain(value: str) -> str:
    compact = "".join(str(value or "").strip().split())
    if not compact:
        return ""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        with contextlib.suppress(Exception):
            padded = compact + "=" * (-len(compact) % 4)
            return decoder(padded.encode("ascii")).decode("utf-8", errors="replace")
    return value
