"""Telegram-пробы через SOCKS: MTProto-латентность (abridged-протокол) и
обязательный медиа-фильтр t.me/s/<канал> (реальное видео с CDN)."""
from __future__ import annotations


import contextlib
import secrets
import socket
import ssl
import struct
import time
import urllib.parse

from .netsocks import _recv_exact, _socks_open_connection, _socks_https_get_body
from .types import (
    TG_MEDIA_MIN_BODY_BYTES,
    TG_MEDIA_PAGE_HOST,
    TG_MEDIA_PAGE_PATH,
    TG_MEDIA_RANGE_SPAN,
    TG_MEDIA_VIDEO_SRC_RE,
    TG_MEDIA_VIDEO_TAG_RE,
    TG_MEDIA_WINDOW_BYTES,
)


def _tg_media_video_urls(html: bytes) -> list[str]:
    """Вытащить URL видео из HTML t.me/s/<канал>.

    Веб-превью Telegram рендерит видео постов как
    ``<video src="https://cdn4.telesco.pe/file/<id>.mp4?token=<signed>" class=...>``.
    Тег парсится ЦЕЛИКОМ (``<video ...>``): класс ``blured`` ищется только
    среди атрибутов ЭТОГО тега — хвост после src мог дотянуться до класса
    соседнего видео и ложно отправить полноразмерное видео в конец списка.
    Токен в URL подписан, поэтому менять query нельзя — анти-кеш делаем
    случайным Range-стартом, а не подменой параметров.
    Порядок: сначала «чистые» (не blured) видео — они полноразмерные.
    """
    urls: list[str] = []
    blured: list[str] = []
    for tag_match in TG_MEDIA_VIDEO_TAG_RE.finditer(html):
        attrs = tag_match.group(1)
        src_match = TG_MEDIA_VIDEO_SRC_RE.search(attrs)
        if src_match is None:
            continue
        url = src_match.group(1).decode("ascii", errors="replace")
        if url in urls or url in blured:
            continue
        if b"blured" in attrs:
            blured.append(url)
        else:
            urls.append(url)
    return urls + blured


def _tg_media_ranged_download(
    socks_host: str,
    socks_port: int,
    video_url: str,
    timeout: float,
    *,
    range_start: int | None = None,
) -> tuple[float | None, int, int]:
    """Скачать окно видео по Range через прокси и измерить скорость.

    Анти-кеш (хардкор): старт окна — СЛУЧАЙНЫЙ байт в первых 8 МБ файла.
    Edge-кеш CDN держит выровненные сегменты с нуля (0-2MB кешированы у всех),
    а случайное окно (например, bytes=5242880-7340031) с высокой вероятностью
    идёт до origin — это честная скорость узла, а не кеш соседа.

    Возвращает (kbps, status, downloaded_bytes); kbps=None при неудаче.
    """
    parsed = urllib.parse.urlsplit(video_url)
    host = (parsed.hostname or "").strip()
    if not host:
        return None, 0, 0
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    if range_start is None:
        range_start = secrets.randbelow(max(1, TG_MEDIA_RANGE_SPAN))
    range_end = range_start + TG_MEDIA_WINDOW_BYTES - 1
    range_header = f"bytes={range_start}-{range_end}"

    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, host, port, timeout)
        if raw_sock is None:
            return None, 0, 0
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            raw_sock = None
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n"
                "Accept: video/mp4,video/*;q=0.9,*/*;q=0.8\r\n"
                f"Range: {range_header}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)

            buf = b""
            deadline = time.perf_counter() + timeout
            while b"\r\n\r\n" not in buf and time.perf_counter() < deadline:
                piece = tls_sock.recv(4096)
                if not piece:
                    break
                buf += piece
                if len(buf) > 65536:
                    break
            header_end = buf.find(b"\r\n\r\n")
            if header_end < 0 or not buf.startswith(b"HTTP/"):
                return None, 0, 0
            try:
                status = int(buf.split(b" ", 2)[1])
            except (IndexError, ValueError):
                return None, 0, 0
            if status not in (200, 206):
                return None, status, 0

            # Тело: Content-Length известна (206 partial) — читаем окно.
            body = buf[header_end + 4 :]
            body_started = time.perf_counter()
            while len(body) < TG_MEDIA_WINDOW_BYTES and time.perf_counter() < deadline:
                piece = tls_sock.recv(min(262144, TG_MEDIA_WINDOW_BYTES - len(body)))
                if not piece:
                    break
                body += piece
            elapsed = max(0.001, time.perf_counter() - body_started)
            if len(body) < TG_MEDIA_MIN_BODY_BYTES:
                # Окно за пределами файла (416-подобный случай) — сигнал
                # вызывающему попробовать другой старт/кандидата.
                return None, status, len(body)
            kbps = (len(body) / 1024.0) / elapsed
            return kbps, status, len(body)
    except Exception:
        return None, 0, 0
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def _tg_media_probe(socks_host: str, socks_port: int, timeout: float) -> float | None:
    """Полный цикл Telegram-медиа фильтра: страница -> видео -> скорость.

    1. Скачиваем HTML https://t.me/s/peppe_poppo через прокси узла.
    2. Извлекаем ссылки на видео постов канала (cdn4.telesco.pe, signed).
    3. Скачиваем СЛУЧАЙНОЕ окно (анти-кеш) первого подходящего видео.
       При неудаче (окно за EOF/короткое) — второй кандидат или другой старт.

    Возвращает скорость в КБ/с или None. Порог применения — TG_MEDIA_MIN_KBPS:
    вызывается для КАЖДОГО узла в стресс-тесте (обязательный фильтр).
    """
    page_timeout = min(12.0, max(6.0, timeout))
    ok, body, status = _socks_https_get_body(
        socks_host,
        socks_port,
        TG_MEDIA_PAGE_HOST,
        443,
        TG_MEDIA_PAGE_HOST,
        TG_MEDIA_PAGE_PATH,
        page_timeout,
        max_bytes=512 * 1024,
    )
    if not ok or status != 200 or not body:
        return None
    urls = _tg_media_video_urls(body)
    if not urls:
        return None

    dl_timeout = min(25.0, max(10.0, timeout * 1.5))
    attempts: list[tuple[str, int | None]] = [(urls[0], None)]
    if len(urls) > 1:
        attempts.append((urls[1], None))
    attempts.append((urls[0], 0))  # контроль с нулевого байта (макс. кеш-скорость)

    for url, forced_start in attempts:
        kbps, _status, _bytes = _tg_media_ranged_download(
            socks_host,
            socks_port,
            url,
            dl_timeout,
            range_start=forced_start,
        )
        if kbps is not None and kbps > 0:
            return kbps
    return None
def _encode_abridged_packet(data: bytes) -> bytes:
    length = len(data) >> 2
    if length < 127:
        return struct.pack("B", length) + data
    return b"\x7f" + int(length).to_bytes(3, "little") + data


def _read_abridged_packet(sock: socket.socket) -> bytes:
    first = _recv_exact(sock, 1)
    if not first:
        return b""
    length = first[0]
    if length >= 127:
        extra = _recv_exact(sock, 3)
        if len(extra) < 3:
            return b""
        length = int.from_bytes(extra + b"\0", "little")
    return _recv_exact(sock, length << 2)


def _socks_mtproto_latency(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float,
) -> float | None:
    started = time.perf_counter()
    sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
    if sock is None:
        return None
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\xef")
        nonce = secrets.randbits(127)
        nonce_bytes = nonce.to_bytes(16, "little", signed=True)
        body = struct.pack("<I", 0xBE7E8EF1) + nonce_bytes
        message_id = int(time.time() * (2**32)) & ~3
        payload = struct.pack("<q", 0) + struct.pack("<q", message_id) + struct.pack("<i", len(body)) + body
        sock.sendall(_encode_abridged_packet(payload))
        response = _read_abridged_packet(sock)
        if len(response) < 40 or response[:8] != b"\0" * 8:
            return None
        body_len = struct.unpack("<i", response[16:20])[0]
        if body_len <= 0 or 20 + body_len > len(response):
            return None
        response_body = response[20 : 20 + body_len]
        if nonce_bytes not in response_body:
            return None
        return (time.perf_counter() - started) * 1000.0
    except Exception:
        return None
    finally:
        with contextlib.suppress(Exception):
            sock.close()

