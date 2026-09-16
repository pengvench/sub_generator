"""Канонизация URI узлов: санитизация, base64-декод, нормализация padding,
дедупликационный текст (используется XrayNode.key)."""
from __future__ import annotations


import base64
import contextlib
import html
import json
import logging
import re
from urllib.parse import parse_qs, quote, unquote, urlsplit, urlunsplit

_logger = logging.getLogger(__name__)

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

# Режимы дедупликации. См. _node_dedup_text(mode=...).
DEDUP_MODE_STRICT = "strict"        # текущее поведение: весь canonical URL
DEDUP_MODE_NORMAL = "normal"        # игнор: fp/fingerprint/spx (uTLS-фингерпринты)
DEDUP_MODE_AGGRESSIVE = "aggressive"  # игнор: всё, кроме protocol+host+port+sni+credential
DEDUP_MODES = (DEDUP_MODE_STRICT, DEDUP_MODE_NORMAL, DEDUP_MODE_AGGRESSIVE)

# Параметры uTLS-фингерпринтов — не влияют на сам узел, только на DPI-маскировку
# клиента. Два конфига, отличающихся ТОЛЬКО fp/fingerprint/spx, — это ОДИН И ТОТ
# ЖЕ бэкенд. В normal/aggressive режимах они удаляются из dedup-ключа.
_FP_QUERY_PARAMS = frozenset({"fp", "fingerprint", "spx"})

# В aggressive-режиме оставляем только эти параметры (всё остальное отбрасывается).
# SNI/host — куда подключаемся, type — транспорт (ws/grpc/tcp), security — tls/reality,
# pbk/sid — Reality-ключи (без них разные узлы на одном IP:port). Остальное
# (alpn, allowInsecure, flow, fp, path-нюансы) — не критично для идентичности.
_AGGRESSIVE_KEEP_PARAMS = frozenset({
    "host", "sni", "type", "security",
    "pbk", "sid", "publickey", "public-key",
    "serviceName",
})


# Глобальный режим дедупликации (аналог set_forced_runtime).
# Устанавливается один раз на старте конвейера через set_dedup_mode().
# По умолчанию — DEDUP_MODE_STRICT (обратная совместимость со старым поведением).
_DEDUP_MODE: str = DEDUP_MODE_STRICT


def set_dedup_mode(mode: str | None) -> None:
    """Установить глобальный режим дедупликации.

    Вызывается из pipeline.py при разборе аргументов (--dedup-mode).
    Влияет на все последующие вызовы ``_node_dedup_text`` и ``XrayNode.key``.
    """
    global _DEDUP_MODE
    value = str(mode or "").strip().lower()
    if value not in DEDUP_MODES:
        value = DEDUP_MODE_STRICT
    _DEDUP_MODE = value


def get_dedup_mode() -> str:
    """Текущий глобальный режим дедупликации."""
    return _DEDUP_MODE


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
    except Exception as exc:
        # Горячий путь парсинга: падение декодеров = штатный fallback
        # ( userinfo остаётся как есть). Причина — только в debug.
        _logger.debug("декодирование userinfo %r не удалось: %s", (userinfo or "")[:40], exc)
    return userinfo


def _node_dedup_text(raw_uri: str, *, mode: str | None = None) -> str:
    """Канонизированный текст узла для дедупликации (хешируется в XrayNode.key).

    ``mode`` управляет агрессивностью дедупликации:
      - ``strict`` (по умолчанию, обратная совместимость): весь canonical URL,
        включая fp/fingerprint/spx/alpn/path-нюансы. Два конфига с разным
        uTLS-фингерпринтом считаются РАЗНЫМИ узлами.
      - ``normal``: игнорирует только ``fp``/``fingerprint``/``spx`` (uTLS-маскировка
        клиента не меняет бэкенд). Убирает 5-15% мусорных дубликатов от подписок,
        которые раздают один бэкенд с разными фингерпринтами для DPI-обхода.
      - ``aggressive``: оставляет только ``protocol + host + port + credential +
        sni/host + type + security + pbk/sid``. Убирает 30-50% дубликатов, но
        рискованно: разные ``flow`` (xtls-rprx-vision vs none) или разные ``path``
        у WS-транспорта считаются одним узлом. Имеет смысл для очень больших
        подписок (10k+), где цель — найти РАЗНЫЕ бэкенды, а не разные маскировки.

    Если ``mode`` не указан — используется глобальный режим (см. set_dedup_mode).

    vmess-узлы во ВСЕХ режимах канонизируются по JSON-телу (без ``ps``).
    """
    if mode is None:
        mode = _DEDUP_MODE
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
                # В normal/aggressive режимах удаляем маскировочные поля vmess.
                if mode in (DEDUP_MODE_NORMAL, DEDUP_MODE_AGGRESSIVE):
                    for fp_key in ("fp", "fingerprint", "spx"):
                        payload.pop(fp_key, None)
                if mode == DEDUP_MODE_AGGRESSIVE:
                    # Оставляем только ключевые поля идентичности.
                    keep = {"add", "port", "id", "aid", "scy", "net", "host", "sni", "security"}
                    payload = {k: v for k, v in payload.items() if k in keep}
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
            # normal: выкидываем fp/fingerprint/spx.
            if mode == DEDUP_MODE_NORMAL and key.lower() in _FP_QUERY_PARAMS:
                continue
            # aggressive: выкидываем всё, кроме белого списка.
            if mode == DEDUP_MODE_AGGRESSIVE and key.lower() not in _AGGRESSIVE_KEEP_PARAMS:
                continue
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
    # aggressive: убираем path (ws-маршруты у одного бэкенда могут отличаться,
    # но это всё ещё тот же сервер). Нормальный режим оставляет path.
    if mode == DEDUP_MODE_AGGRESSIVE:
        path = ""
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
