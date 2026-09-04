"""Замеры скорости через SOCKS: M-Lab NDT7 (WebSocket-клиент на чистых
сокетах), speed.cloudflare.com, proof.ovh.net, speedtest.tele2.net;
upload через POST /__up."""
from __future__ import annotations


import base64
import contextlib
import json
import secrets
import socket
import ssl
import struct
import time
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .netsocks import (
    _recv_exact,
    _socks_https_download_kbps,
    _socks_https_upload_kbps,
    _socks_open_connection,
)
from .types import (
    M_LAB_LOCATE_URL,
    M_LAB_NDT7_SAMPLE_SEC,
    M_LAB_NDT7_TIMEOUT_SEC,
    XRAY_PROBE_SPEED_TEST_BYTES,
    XRAY_PROBE_SPEED_TEST_SECONDS,
    XRAY_SPEED_TEST_HOST,
    XRAY_SPEED_TEST_PATH,
    XRAY_SPEED_UPLOAD_PATH,
)


# ---------------------------------------------------------------------------
# M-Lab NDT7: WebSocket-клиент на чистом socket (без внешних зависимостей).
# ---------------------------------------------------------------------------

def _ws_build_frame(opcode: int, payload: bytes) -> bytes:
    """Собрать клиентский WebSocket-кадр (RFC 6455, маскированный)."""
    mask_key = secrets.token_bytes(4)
    length = len(payload)
    header = bytearray([0x80 | opcode])
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack(">H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack(">Q", length))
    header.extend(mask_key)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return bytes(header) + masked


def _ws_read_frame(sock: socket.socket) -> tuple[int, bytes]:
    """Прочитать один серверный WebSocket-кадр (без маски)."""
    head = _recv_exact(sock, 2)
    if len(head) < 2:
        return 0x8, b""
    fin_op = head[0]
    opcode = fin_op & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _recv_exact(sock, 8))[0]
    mask_key = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length)
    if masked and mask_key and len(mask_key) == 4:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return opcode, payload


_mlab_cached_url: str | None = None
_mlab_cache_until: float = 0.0


def _mlab_fetch_target(timeout: float = 8.0) -> str | None:
    """Запросить M-Lab Locate API и вернуть wss:// URL ближайшего NDT7-сервера.

    Результат кешируется на 10 минут — не дёргаем locate API при каждой ноде.
    """
    global _mlab_cached_url, _mlab_cache_until
    now = time.monotonic()
    if _mlab_cache_until > now:
        return _mlab_cached_url
    try:
        req = Request(
            M_LAB_LOCATE_URL,
            headers={"User-Agent": "MTProxyAutoSwitch/1.0", "Accept": "application/json"},
        )
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if not isinstance(data, dict):
            _mlab_cache_until = now + 60.0
            return None
        results = data.get("results") or []
        for item in results:
            if not isinstance(item, dict):
                continue
            urls = item.get("urls") or []
            for u in urls:
                text = str(u or "")
                if text.startswith("wss://") and ("/ndt/v7" in text or "ndt" in text):
                    _mlab_cached_url = text
                    _mlab_cache_until = now + 600.0
                    return text
        _mlab_cache_until = now + 60.0
        return None
    except Exception:
        # Любая ошибка (сеть, парсинг, UnboundLocalError) — не должна валить
        # стресс-тест. Fallback на speed.cloudflare.com сработает.
        _mlab_cache_until = now + 60.0
        return None


def _ws_url_to_target(ws_url: str) -> tuple[str, int, str] | None:
    """Разобрать wss://host:port/path на (host, port, path)."""
    try:
        parts = urlparse(ws_url)
        host = parts.hostname or ""
        port = parts.port or 443
        path = parts.path or "/ndt/v7/download"
        if not host:
            return None
        return host, int(port), path
    except Exception:
        return None


def _mlab_ndt7_download_kbps(
    socks_host: str,
    socks_port: int,
    timeout: float = M_LAB_NDT7_TIMEOUT_SEC,
    sample_seconds: float = M_LAB_NDT7_SAMPLE_SEC,
) -> float | None:
    """Прогнать NDT7 download-тест через SOCKS-прокси и вернуть скорость в кбит/с.

    Если locate не вернул URL или канал недоступен — возвращаем None (без фатала).
    """
    ws_url = _mlab_fetch_target(timeout=min(8.0, timeout))
    if not ws_url:
        return None
    target = _ws_url_to_target(ws_url)
    if target is None:
        return None
    host, port, path = target
    raw: socket.socket | None = None
    tls: socket.socket | None = None
    try:
        raw = _socks_open_connection(socks_host, socks_port, host, port, timeout)
        if raw is None:
            return None
        raw.settimeout(timeout)
        context = ssl.create_default_context()
        tls = context.wrap_socket(raw, server_hostname=host)
        raw = None
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: net.measurementlab.ndt.v7\r\n"
            f"\r\n"
        ).encode("ascii")
        tls.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = tls.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 65536:
                break
        if not response.startswith(b"HTTP/1.1 101"):
            return None

        # NDT7: клиент отправляет текстовое сообщение {"msg":"hello"} на download-канал,
        # сервер затем шлёт тестовый поток бинарных кадров.
        hello = b'{"msg":"hello"}'
        tls.sendall(_ws_build_frame(0x1, hello))
        total = 0
        started: float | None = None
        deadline = time.perf_counter() + timeout
        sample_deadline: float | None = None
        while time.perf_counter() < deadline:
            opcode, payload = _ws_read_frame(tls)
            if opcode in (0x8, 0xA):
                break
            if opcode == 0x9:
                try:
                    tls.sendall(_ws_build_frame(0xA, payload))
                except Exception:
                    pass
                continue
            if opcode in (0x1, 0x2):
                if started is None:
                    started = time.perf_counter()
                    sample_deadline = started + max(0.5, float(sample_seconds))
                total += len(payload)
                if sample_deadline is not None and time.perf_counter() >= sample_deadline:
                    break
        if started is None or total <= 0:
            return None
        elapsed = max(0.001, time.perf_counter() - started)
        return (total * 8.0 / 1000.0) / elapsed
    except Exception:
        return None
    finally:
        if tls is not None:
            with contextlib.suppress(Exception):
                tls.close()
        if raw is not None:
            with contextlib.suppress(Exception):
                raw.close()


def _xray_download_speed(
    socks_host: str,
    socks_port: int,
    timeout: float,
    *,
    max_bytes: int = XRAY_PROBE_SPEED_TEST_BYTES,
    sample_seconds: float = XRAY_PROBE_SPEED_TEST_SECONDS,
) -> float | None:
    return _socks_https_download_kbps(
        socks_host,
        socks_port,
        XRAY_SPEED_TEST_HOST,
        443,
        XRAY_SPEED_TEST_HOST,
        XRAY_SPEED_TEST_PATH,
        max_bytes,
        min(max(2.0, timeout), max(2.0, float(sample_seconds) + 4.0)),
        sample_seconds=sample_seconds,
    )


# Скорость загрузки — единый надёжный замер, используемый и в стресс-тесте,
# и в финальном recheck. speed.cloudflare.com не работает через Cloudflare
# Worker-прокси (даёт None/0), поэтому после него идут внешние fallback-хосты.
# Большой объём (16MB) и длинный sample-период (8s) сглаживают ramp-up
# у worker-узлов, замер становится стабильным (проверено: 1.8→7.6 MB/s).
XRAY_SPEED_TEST_BIG_BYTES = 16 * 1024 * 1024
XRAY_SPEED_TEST_BIG_SECONDS = 8.0


def _download_speed_probe(
    socks_host: str,
    socks_port: int,
    timeout: float,
) -> float | None:
    """Надёжный замер скорости загрузки (КБ/с).

    Пробуем по порядку, берём первый успешный результат:
      1) NDT7 (M-Lab) — объективный замер до ближайшего сервера;
      2) speed.cloudflare.com — стандартный короткий замер;
      3) proof.ovh.net /files/100Mb.dat (16MB, 8s) — fallback для worker-узлов;
      4) speedtest.tele2.net /100MB.zip (16MB, 8s) — последний fallback.
    Возвращает None, если ни один источник не сработал.
    """
    big_timeout = max(8.0, float(timeout))
    ndt7 = _mlab_ndt7_download_kbps(socks_host, socks_port, timeout=big_timeout)
    if ndt7 is not None and ndt7 > 0:
        return ndt7
    cf = _xray_download_speed(socks_host, socks_port, timeout=big_timeout)
    if cf is not None and cf > 0:
        return cf
    ovh = _socks_https_download_kbps(
        socks_host,
        socks_port,
        "proof.ovh.net",
        443,
        "proof.ovh.net",
        "/files/100Mb.dat",
        XRAY_SPEED_TEST_BIG_BYTES,
        big_timeout,
        sample_seconds=XRAY_SPEED_TEST_BIG_SECONDS,
    )
    if ovh is not None and ovh > 0:
        return ovh
    tele2 = _socks_https_download_kbps(
        socks_host,
        socks_port,
        "speedtest.tele2.net",
        443,
        "speedtest.tele2.net",
        "/100MB.zip",
        XRAY_SPEED_TEST_BIG_BYTES,
        big_timeout,
        sample_seconds=XRAY_SPEED_TEST_BIG_SECONDS,
    )
    if tele2 is not None and tele2 > 0:
        return tele2
    return None


def _xray_upload_speed(

    socks_host: str,
    socks_port: int,
    timeout: float,
    *,
    max_bytes: int = XRAY_PROBE_SPEED_TEST_BYTES,
    sample_seconds: float = XRAY_PROBE_SPEED_TEST_SECONDS,
) -> float | None:
    """Прогнать upload-тест через speed.cloudflare.com (POST /__up) через SOCKS-прокси."""
    return _socks_https_upload_kbps(
        socks_host,
        socks_port,
        XRAY_SPEED_TEST_HOST,
        443,
        XRAY_SPEED_TEST_HOST,
        XRAY_SPEED_UPLOAD_PATH,
        max_bytes,
        min(max(2.0, timeout), max(2.0, float(sample_seconds) + 4.0)),
        sample_seconds=sample_seconds,
    )
