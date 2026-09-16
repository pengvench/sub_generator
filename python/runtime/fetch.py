"""Загрузка тел подписок: локальные файлы, HTTP(S) с зеркалами, retry-таймауты,
SSL-контексты, gzip/декодирование тела."""
from __future__ import annotations


import contextlib
import gzip
import ssl
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunsplit
from urllib.request import Request, urlopen

from .types import SUBSCRIPTION_USER_AGENT


def _fetch_text(
    url: str,
    *,
    timeout: float,
    log_sink: Callable[[str], None] | None = None,
) -> str:
    clean_url = str(url or "").strip()

    # Happ (Hiddify) зашифрованные подписки happ://cryptN/... — расшифровываем
    # RSA-ключом в обычный https:// URL и идём дальше по стандартному пути.
    # Без ключей / без cryptography — внятная ошибка (не молчаливый fetch failed).
    if clean_url.lower().startswith("happ://"):
        from .happ_decrypt import decrypt_happ_link
        plain_url = decrypt_happ_link(clean_url)
        if not plain_url:
            raise RuntimeError(
                "happ subscription decrypt failed "
                "(keys in data/happ_keys/pkcs1_keys.json, pip install cryptography)"
            )
        if log_sink is not None:
            log_sink(f"[xray] happ subscription decrypted: {plain_url[:80]}")
        clean_url = plain_url

    # Локальный файл (кастомный кеш конфигов, выбранный пользователем):
    # читаем как есть, а декодирование base64 / извлечение только ссылок
    # выполняет _subscription_lines ниже по конвейеру.
    if clean_url.startswith("file://"):
        local_path = Path(clean_url[len("file://"):])
    else:
        local_path = Path(clean_url)
    if clean_url and local_path.exists() and local_path.is_file():
        try:
            data = local_path.read_bytes()
            if log_sink is not None:
                log_sink(f"[xray] reading local config file: {local_path}")
            return _decode_subscription_body(data)
        except OSError as exc:
            if log_sink is not None:
                log_sink(f"[xray] cannot read local config file {local_path}: {exc}")
            raise RuntimeError("local config file read failed") from exc

    errors: list[str] = []
    for candidate_url in _subscription_candidate_urls(clean_url):

        headers = _subscription_headers(candidate_url)
        for current_timeout in _subscription_timeouts(timeout):
            for context in _subscription_ssl_contexts():
                try:
                    req = Request(candidate_url, headers=headers)
                    with urlopen(req, timeout=current_timeout, context=context) as resp:
                        encoding = str(resp.headers.get("Content-Encoding", "") or "")
                        return _decode_subscription_body(resp.read(), encoding=encoding)
                except HTTPError as exc:
                    # HTTP 4xx/5xx — подписка недоступна/заблокирована.
                    # Нет смысла перебирать все таймауты и SSL-контексты.
                    marker = f"{urlparse(candidate_url).netloc or '?'}:HTTP_{exc.code}"
                    if marker not in errors:
                        errors.append(marker)
                    break
                except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
                    marker = f"{urlparse(candidate_url).netloc or '?'}:{type(exc).__name__}"
                    if marker not in errors:
                        errors.append(marker)
                except Exception as exc:
                    marker = f"{urlparse(candidate_url).netloc or '?'}:{type(exc).__name__}"
                    if marker not in errors:
                        errors.append(marker)
    if log_sink is not None and errors:
        log_sink(f"[xray] source fetch attempts failed {clean_url}: {' | '.join(errors[:5])}")
    raise RuntimeError("subscription fetch failed")


def _subscription_headers(url: str) -> dict[str, str]:
    # ВАЖНО: не задаём Host вручную. urllib сам выставляет корректный Host для
    # каждого запроса, включая редиректы (github.com -> raw.githubusercontent.com).
    # Ручной Host не обновляется при 302 и ломает редирект: GitHub отвечает 500.
    return {
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
        "Connection": "close",
        "User-Agent": SUBSCRIPTION_USER_AGENT,
        "X-Device-Locale": "en",
        "X-Device-OS": "Windows",
    }


def _subscription_timeouts(timeout: float) -> list[float]:
    base = max(3.0, float(timeout or 8.0))
    values = [base, max(base, 15.0), max(base, 30.0)]
    out: list[float] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def _subscription_ssl_contexts() -> list[ssl.SSLContext | None]:
    contexts: list[ssl.SSLContext | None] = [None]
    with contextlib.suppress(Exception):
        contexts.append(ssl._create_unverified_context())
    return contexts


def _subscription_candidate_urls(url: str) -> list[str]:
    target = str(url or "").strip()
    if not target:
        return []
    urls = [target]
    with contextlib.suppress(Exception):
        parsed = urlparse(target)
        host = str(parsed.netloc or "").strip().lower()
        parts = [part for part in str(parsed.path or "").split("/") if part]
        if host == "raw.githubusercontent.com" and len(parts) >= 5 and parts[2] == "refs" and parts[3] == "heads":
            owner = parts[0]
            repo = parts[1]
            branch = parts[4]
            tail = parts[5:]
            canonical_path = "/" + "/".join([owner, repo, branch] + tail)
            canonical = urlunsplit((parsed.scheme or "https", parsed.netloc, canonical_path, parsed.query or "", ""))
            if canonical not in urls:
                urls.append(canonical)
            jsd_path = "/gh/" + "/".join([owner, repo + "@" + branch] + tail)
            for cdn_host in ("cdn.jsdelivr.net", "gcore.jsdelivr.net", "fastly.jsdelivr.net"):
                cdn_url = urlunsplit(("https", cdn_host, jsd_path, parsed.query or "", ""))
                if cdn_url not in urls:
                    urls.append(cdn_url)
    return urls


def _decode_subscription_body(raw: bytes, *, encoding: str = "") -> str:
    data = bytes(raw or b"")
    if data[:2] == b"\x1f\x8b" or "gzip" in str(encoding or "").lower():
        with contextlib.suppress(Exception):
            data = gzip.decompress(data)
    return data.decode("utf-8", errors="replace")
