"""Проверка Telegram-медиа через веб-версию t.me/s/<канал>.

Проблема: спид-тест (NDT7 / speed.cloudflare.com / proof.ovh.net) измеряет
скорость до ЧУЖИХ CDN и отсеивает кучу конфигов, которые отлично работают
именно с Telegram. Абстрактная скорость до Cloudflare не отражает
способность узла грузить медиа из Telegram.

Идея (пользователь): у Telegram есть веб-версия каналов —
``https://t.me/s/<канал>``. Страница канала содержит прямые ссылки на
видео (``<video src="https://cdn4.telesco.pe/file/....mp4?token=...">``) —
это настоящий Telegram-CDN. Проверка:

1. **Загрузка страницы канала** через SOCKS5 узла — t.me доступен через
   прокси. Токен видео при этом выписывается на IP-адрес выхода прокси.
2. **Стриминговая загрузка видео** через ТОТ ЖЕ прокси (токен валиден,
   потому что egress IP совпадает) с Range-запросом.
3. Если видео реально грузится — узел справляется с медиа Telegram и
   принимается, даже если общий спид-тест не прошёл (``tg_media_ok``).

Загрузка небыстрая, поэтому предусмотрены (по требованию пользователя):
- ``first_byte_timeout`` — если после запроса вообще ничего не грузится;
- ``stall_timeout`` — данные шли, но загрузка застопорилась;
- ``hard_timeout`` — общий бюджет на одно видео;
- счёт полученных байт и скорость считаются по факту движения данных.
"""

from __future__ import annotations

import contextlib
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from . import base

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Настройки по умолчанию.
# ---------------------------------------------------------------------------

# Канал для проверки (пользовательский): в канале есть видео-посты.
TG_WEB_CHANNEL_URL = "https://t.me/s/peppe_poppo"

# Сколько видео пробовать, если первое не грузится (например, битый файл).
TG_MEDIA_VIDEOS_TO_TRY = 2

# Таймауты (сек).
TG_MEDIA_FETCH_TIMEOUT = 10.0  # загрузка HTML-страницы канала
TG_MEDIA_FIRST_BYTE_TIMEOUT = 8.0  # «вообще ничего не грузится» после запроса
TG_MEDIA_STALL_TIMEOUT = 6.0  # данные шли, но остановились (застой)
TG_MEDIA_HARD_TIMEOUT = 25.0  # общий бюджет на одно видео

# Объёмы (байт).
TG_MEDIA_MAX_BYTES = 4 * 1024 * 1024  # докачиваем максимум 4 МБ
TG_MEDIA_MIN_BYTES = 512 * 1024  # минимум скачанного для «видео грузится»

# Порог скорости видео (КБ/с): 512 КБ/с = ~4 Мбит/с — уверенный стриминг
# 720p и терпеливая загрузка 1080p. Поднят с 256 по требованию: проверка
# должна пропускать только узлы, на которых видео реально смотрится.
TG_MEDIA_MIN_KBPS = 512.0

# Редиректы CDN: сколько прыжков по Location допускаем.
TG_MEDIA_MAX_REDIRECTS = 2

# Паттерны ссылок на видео/фото в HTML веб-версии t.me/s/.
_VIDEO_SRC_RE = re.compile(
    r'<video[^>]+src="(https://cdn\d+\.telesco\.pe/file/[^"]+)"',
    re.IGNORECASE,
)
_PHOTO_SRC_RE = re.compile(
    r"background-image:url\('(https://cdn\d+\.telesco\.pe/file/[^']+)'\)",
    re.IGNORECASE,
)
_DATA_POST_RE = re.compile(r'data-post="([^"/]+)/(\d+)"')


# ---------------------------------------------------------------------------
# Результат.
# ---------------------------------------------------------------------------


@dataclass
class TgMediaResult:
    """Результат проверки Telegram-медиа (видео из t.me/s/)."""

    accepted: bool
    reason: str = ""
    channel_ok: bool = False  # страница канала t.me/s/ загрузилась
    page_status: int = 0
    video_url: str | None = None
    bytes_received: int = 0
    kbps: float | None = None
    content_length: int | None = None
    details: dict = field(default_factory=dict)

    def row(self) -> dict:
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "channel_ok": self.channel_ok,
            "page_status": self.page_status,
            "video_url": self.video_url,
            "bytes_received": self.bytes_received,
            "kbps": round(self.kbps, 1) if self.kbps else None,
            "content_length": self.content_length,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Разбор HTML веб-версии канала.
# ---------------------------------------------------------------------------


def extract_tg_video_urls(html: str) -> list[str]:
    """Вытащить прямые ссылки на видео (cdn*.telesco.pe .mp4) из HTML.

    Ссылки уникализируются с сохранением порядка появления — первое видео
    в канале обычно самое свежее.
    """
    urls: list[str] = []
    for match in _VIDEO_SRC_RE.findall(html):
        url = match.strip().replace("&amp;", "&")
        if url not in urls:
            urls.append(url)
    return urls


def extract_tg_photo_urls(html: str) -> list[str]:
    """Вытащить ссылки на фото-превью (cdn*.telesco.pe .jpg) — fallback."""
    urls: list[str] = []
    for match in _PHOTO_SRC_RE.findall(html):
        url = match.strip().replace("&amp;", "&")
        if url not in urls:
            urls.append(url)
    return urls


def _channel_page_url_for_pagination(channel_url: str, html: str) -> str | None:
    """URL более старой страницы канала (?before=<id>) — если в текущей нет видео."""
    split = urlsplit(channel_url)
    posts = _DATA_POST_RE.findall(html)
    if not posts:
        return None
    try:
        oldest = min(int(post_id) for _, post_id in posts)
    except ValueError:
        return None
    path = split.path or "/s/"
    return f"{split.scheme}://{split.netloc}{path}?before={oldest}"


# ---------------------------------------------------------------------------
# Стриминговая загрузка видео с детекцией застоя.
# ---------------------------------------------------------------------------


@dataclass
class _StreamOutcome:
    ok: bool
    reason: str
    received: int = 0
    kbps: float | None = None
    content_length: int | None = None


def _send_video_request(tls_sock, url_split, server_name: str, max_bytes: int) -> None:
    path = url_split.path or "/"
    if url_split.query:
        path += f"?{url_split.query}"
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {server_name}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n"
        f"Accept: */*\r\n"
        f"Range: bytes=0-{max_bytes - 1}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")
    tls_sock.sendall(request)


def _parse_redirect(raw_headers: bytes) -> str | None:
    location = None
    for line in raw_headers.decode("latin1", errors="replace").split("\r\n"):
        if line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()
            break
    return location


def _tg_video_stream_download(
    socks_host: str,
    socks_port: int,
    video_url: str,
    *,
    max_bytes: int = TG_MEDIA_MAX_BYTES,
    min_bytes: int = TG_MEDIA_MIN_BYTES,
    first_byte_timeout: float = TG_MEDIA_FIRST_BYTE_TIMEOUT,
    stall_timeout: float = TG_MEDIA_STALL_TIMEOUT,
    hard_timeout: float = TG_MEDIA_HARD_TIMEOUT,
) -> _StreamOutcome:
    """Стриминговая загрузка видео через SOCKS5 с контролем «живости».

    Три механизма защиты от «висящей» загрузки:
    - ``first_byte_timeout`` — после запроса нет НИ БАЙТА (вообще не грузится);
    - ``stall_timeout`` — байты шли, но поток остановился (застой);
    - ``hard_timeout`` — общий бюджет; скачанное до его истечения засчитывается.

    Скорость считается от первого байта тела ответа (чистая пропускная
    способность, без TLS-хендшейка).
    """
    current_url = video_url
    redirects_left = TG_MEDIA_MAX_REDIRECTS
    while True:
        url_split = urlsplit(current_url)
        server_name = url_split.hostname or ""
        port = url_split.port or 443
        raw_sock: socket.socket | None = None
        try:
            raw_sock = base._socks_open_connection(
                socks_host, socks_port, server_name, port, min(15.0, first_byte_timeout + stall_timeout)
            )
            if raw_sock is None:
                return _StreamOutcome(False, "cdn_connect_failed")
            with base._wrap_tls(raw_sock, server_name, first_byte_timeout) as tls_sock:
                raw_sock = None
                _send_video_request(tls_sock, url_split, server_name, max_bytes)

                # --- Заголовки: ждём не дольше first_byte_timeout. ---
                tls_sock.settimeout(first_byte_timeout)
                headers, initial_body, status_code, _is_chunked, content_length = base._http_read_headers(
                    tls_sock, first_byte_timeout
                )
                if status_code == 0:
                    return _StreamOutcome(False, "no_http_response")
                if status_code in (301, 302, 303, 307, 308):
                    if redirects_left <= 0:
                        return _StreamOutcome(False, "too_many_redirects")
                    redirects_left -= 1
                    location = _parse_redirect(headers)
                    if not location:
                        return _StreamOutcome(False, "redirect_without_location")
                    if location.startswith("http://") or location.startswith("https://"):
                        current_url = location
                    else:
                        current_url = f"{url_split.scheme}://{url_split.netloc}{location}"
                    continue
                if status_code not in (200, 206):
                    return _StreamOutcome(False, f"http_status_{status_code}")

                # --- Тело: стримим с контролем застоя. ---
                # До первого байта тела действует first_byte_timeout («вообще
                # ничего не грузится»), после него — stall_timeout (данные
                # шли, но поток встал) и общий бюджет hard_timeout.
                received = len(initial_body)
                first_byte_at = time.perf_counter() if received > 0 else None
                hard_deadline: float | None = (
                    first_byte_at + max(1.0, hard_timeout) if first_byte_at is not None else None
                )
                tls_sock.settimeout(stall_timeout if received > 0 else first_byte_timeout)
                while received < max_bytes:
                    if hard_deadline is not None and time.perf_counter() >= hard_deadline:
                        break  # общий бюджет на видео истёк
                    try:
                        chunk = tls_sock.recv(min(65536, max_bytes - received))
                    except (socket.timeout, TimeoutError):
                        # Тишина: нет ни байта («не грузится») или поток встал.
                        break
                    if not chunk:
                        break  # соединение закрыто (файл скачан целиком)
                    if first_byte_at is None:
                        # Первый байт тела: отсчёт скорости и бюджета начался.
                        first_byte_at = time.perf_counter()
                        hard_deadline = first_byte_at + max(1.0, hard_timeout)
                        tls_sock.settimeout(stall_timeout)
                    received += len(chunk)

                if received <= 0:
                    return _StreamOutcome(False, "no_data", received=0, content_length=content_length)
                elapsed = max(0.001, time.perf_counter() - (first_byte_at or time.perf_counter()))
                kbps = (received / 1024.0) / elapsed
                # Успех: скачали достаточно (или весь файл целиком). Порог
                # скорости проверяет вызывающая сторона (min_kbps конфигурации).
                got_enough = received >= min_bytes or (
                    content_length is not None and content_length > 0 and received >= content_length
                )
                if not got_enough:
                    # Застой / обрыв / бюджет — данных недостаточно.
                    return _StreamOutcome(
                        False, "stalled", received=received, kbps=kbps, content_length=content_length
                    )
                return _StreamOutcome(
                    True, "ok", received=received, kbps=kbps, content_length=content_length
                )
        except (socket.timeout, TimeoutError):
            return _StreamOutcome(False, "no_data")
        except Exception:
            return _StreamOutcome(False, "cdn_error")
        finally:
            if raw_sock is not None:
                with contextlib.suppress(Exception):
                    raw_sock.close()


# ---------------------------------------------------------------------------
# Полная проверка: страница канала -> видео -> стриминг.
# ---------------------------------------------------------------------------


def run_tg_media_check(
    socks_host: str,
    socks_port: int,
    *,
    channel_url: str = TG_WEB_CHANNEL_URL,
    min_kbps: float = TG_MEDIA_MIN_KBPS,
    max_bytes: int = TG_MEDIA_MAX_BYTES,
    min_bytes: int = TG_MEDIA_MIN_BYTES,
    hard_timeout: float = TG_MEDIA_HARD_TIMEOUT,
    first_byte_timeout: float = TG_MEDIA_FIRST_BYTE_TIMEOUT,
    stall_timeout: float = TG_MEDIA_STALL_TIMEOUT,
    fetch_timeout: float = TG_MEDIA_FETCH_TIMEOUT,
    videos_to_try: int = TG_MEDIA_VIDEOS_TO_TRY,
) -> TgMediaResult:
    """Проверить загрузку видео из веб-версии Telegram-канала через прокси узла.

    Страница канала и видео качаются через ОДИН И ТОТ ЖЕ прокси: токен видео
    выписывается на egress-IP прокси, поэтому качать надо с того же выхода.
    """
    channel_split = urlsplit(channel_url)
    channel_host = channel_split.netloc or "t.me"

    def _fetch_page(url: str) -> tuple[bool, str, int]:
        split = urlsplit(url)
        ok, body, status = base.http_get_body(
            socks_host,
            socks_port,
            split.netloc or channel_host,
            split.port or 443,
            split.netloc or channel_host,
            split.path + (f"?{split.query}" if split.query else ""),
            timeout=fetch_timeout,
            max_bytes=2 * 1024 * 1024,
        )
        html_text = body.decode("utf-8", errors="replace") if ok else ""
        return ok, html_text, status

    # 1. Страница канала: t.me/s/<канал> должен открыться через прокси.
    ok, page_html, status = _fetch_page(channel_url)
    if not ok or status != 200 or "tgme_widget_message" not in page_html:
        return TgMediaResult(
            accepted=False,
            reason="channel_unreachable",
            channel_ok=False,
            page_status=status,
            details={"channel": channel_url},
        )

    # 2. Видео в текущей странице; если нет — одна страница старее (?before=).
    video_urls = extract_tg_video_urls(page_html)
    if not video_urls:
        older = _channel_page_url_for_pagination(channel_url, page_html)
        if older:
            ok2, older_html, status2 = _fetch_page(older)
            if ok2 and status2 == 200:
                video_urls = extract_tg_video_urls(older_html)
    if not video_urls:
        return TgMediaResult(
            accepted=False,
            reason="no_videos_in_channel",
            channel_ok=True,
            page_status=status,
            details={"channel": channel_url},
        )

    # 3. Стриминговая загрузка: пробуем до videos_to_try видео.
    last: _StreamOutcome | None = None
    tried_urls: list[str] = []
    for video_url in video_urls[: max(1, videos_to_try)]:
        tried_urls.append(video_url)
        outcome = _tg_video_stream_download(
            socks_host,
            socks_port,
            video_url,
            max_bytes=max_bytes,
            min_bytes=min_bytes,
            first_byte_timeout=first_byte_timeout,
            stall_timeout=stall_timeout,
            hard_timeout=hard_timeout,
        )
        last = outcome
        if outcome.ok and outcome.kbps is not None and outcome.kbps >= min_kbps:
            return TgMediaResult(
                accepted=True,
                reason="ok",
                channel_ok=True,
                page_status=status,
                video_url=video_url,
                bytes_received=outcome.received,
                kbps=outcome.kbps,
                content_length=outcome.content_length,
                details={"tried": tried_urls, "min_kbps": min_kbps},
            )
        # «Битое» видео (нет данных/редирект/статус) — пробуем следующее;
        # медленное (ok, но ниже порога) тоже пробуем следующее: вдруг первое
        # видео лежит на медленном CDN-файле.

    reason = "video_too_slow" if (last is not None and last.ok) else (last.reason if last else "no_data")
    return TgMediaResult(
        accepted=False,
        reason=reason,
        channel_ok=True,
        page_status=status,
        video_url=tried_urls[-1] if tried_urls else None,
        bytes_received=last.received if last else 0,
        kbps=last.kbps if last else None,
        content_length=last.content_length if last else None,
        details={"tried": tried_urls, "min_kbps": min_kbps},
    )


# ---------------------------------------------------------------------------
# Проверка узла целиком (поднятие core + стриминг).
# ---------------------------------------------------------------------------


def check_node_tg_media_detailed(
    node_url: str,
    timeout: float = TG_MEDIA_HARD_TIMEOUT,
    root_dir: Optional[Path] = None,
    *,
    channel_url: str = TG_WEB_CHANNEL_URL,
    min_kbps: float = TG_MEDIA_MIN_KBPS,
) -> TgMediaResult:
    """Детальная проверка Telegram-медиа для узла (поднять core + качать видео)."""
    if not node_url:
        return TgMediaResult(accepted=False, reason="empty_node")

    def _run(host: str, port: int) -> TgMediaResult:
        return run_tg_media_check(
            host,
            port,
            channel_url=channel_url,
            min_kbps=min_kbps,
            hard_timeout=timeout,
        )

    # Бюджет: страница (fetch_timeout) + до 2 видео по hard_timeout + запас.
    budget = max(30.0, float(timeout) * 2.0 + 30.0)
    result = base.run_with_node(node_url, _run, timeout=max(10.0, min(timeout, 15.0)), root_dir=root_dir, budget=budget)
    if result is None:
        return TgMediaResult(accepted=False, reason="node_start_failed")
    return result


def check_node_tg_media(
    node_url: str,
    timeout: float = TG_MEDIA_HARD_TIMEOUT,
    root_dir: Optional[Path] = None,
    *,
    channel_url: str = TG_WEB_CHANNEL_URL,
    min_kbps: float = TG_MEDIA_MIN_KBPS,
) -> bool:
    """Упрощённая проверка Telegram-медиа (bool)."""
    return check_node_tg_media_detailed(
        node_url, timeout=timeout, root_dir=root_dir, channel_url=channel_url, min_kbps=min_kbps
    ).accepted


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m checkers.tg_media <node_url>")
        sys.exit(1)
    r = check_node_tg_media_detailed(sys.argv[1])
    print(
        f"TG-MEDIA for {sys.argv[1]}: {'PASS' if r.accepted else 'FAIL'} "
        f"reason={r.reason} bytes={r.bytes_received} kbps={r.kbps}"
    )
