"""Потоковое видео-тестирование узла (YouTube / DASH-сегменты).

Один общий speedtest не отражает качество потокового видео: для YouTube
важна стабильность получения подряд сегментов, отсутствие таймаутов и
ровная скорость между сегментами.

Здесь для каждого узла выполняются:

1. **YouTube-доступность** — TLS-handshake и GET к www.youtube.com
   и googlevideo.com (медиа-хосты) через узел: сервер видеопотоков
   раздаёт сегменты, если узел корректно пробивает блокировку.

2. **Антибот-проверка YouTube** — отдельный GET главной страницы:
   YouTube часто открывает прокси-узлы, но отдаёт капчу / consent /
   "sorry" вместо плеера (узлы-битрейдеры, datacenter IP). Такие узлы
   помечаются как бот-отсев.

3. **DASH-сегменты** — последовательная загрузка N сегментов по 1-2 МБ
   (Range-запросы), для каждого сегмента измеряются скорость и время.
   По результатам считаются:
   - средняя скорость (avg_speed_kbps);
   - количество таймаутов (timeouts);
   - джиттер скорости между сегментами (jitter_kbps) — разброс скорости.

Узел принимается, если YouTube доступен (и не отсеял как бота) и средняя
скорость сегментов достаточна (>= минимального порога), а таймаутов мало.

Если YouTube/сервер сегментов недоступен — проверка считается
информативной (accepted=False только при полном отсутствии сети).
"""

from __future__ import annotations

import contextlib
import logging
import socket
import ssl
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import base

logger = logging.getLogger(__name__)

# Цели YouTube.
VIDEO_YOUTUBE_HOSTS: tuple[tuple[str, str, int], ...] = (
    ("www.youtube.com", "www.youtube.com", 443),
    ("googlevideo.com", "googlevideo.com", 443),  # медиа-хосты (r*.googlevideo.com)
    ("yt3.ggpht.com", "yt3.ggpht.com", 443),  # превью/контент
)

# Сервер DASH-сегментов (отдаёт диапазоны; важен не контент, а скорость).
DASH_SEGMENT_HOST = "proof.ovh.net"
DASH_SEGMENT_PORT = 443
DASH_SEGMENT_PATH = "/files/10Mb.dat"  # большой файл, режем Range-запросами

# Параметры сегментов.
VIDEO_SEGMENTS_COUNT = 20  # сегментов подряд
VIDEO_SEGMENT_BYTES = 2 * 1024 * 1024  # ~2 МБ на сегмент
VIDEO_SEGMENT_TIMEOUT = 6.0  # таймаут на один сегмент
VIDEO_MAX_TIMEOUTS = 4  # допустимое число таймаутов
VIDEO_MIN_AVG_KBPS = 1024.0  # минимальная средняя скорость (КБ/с) ~ 8 Мбит/с

# Антибот-проверка YouTube: страница может открываться, но YouTube отдаёт
# капчу / consent / "sorry" — тогда узел помечается как бот-отсев (частая
# проблема прокси-серверов, как и на других сайтах).
YOUTUBE_PAGE_PATH = "/"
YOUTUBE_PAGE_MAX_BYTES = 256 * 1024
# Признаки нормального HTML страницы плеера.
YOUTUBE_OK_MARKERS: tuple[bytes, ...] = (
    b"ytInitialPlayerResponse",
    b"playabilityStatus",
)
# Признаки бот-отсева / блокировки контента.
YOUTUBE_BOT_MARKERS: tuple[bytes, ...] = (
    b"consent.youtube.com",
    b"sorry/index",
    b"google.com/sorry/",
    b"captcha",
    b"botguard",
    b"UNPLAYABLE",
    b"unplayable",
    b"service unavailable",
)


@dataclass
class VideoCheckResult:
    """Результат потокового видео-тестирования."""

    accepted: bool
    reason: str = ""
    youtube: bool = False
    youtube_hosts: dict = field(default_factory=dict)
    youtube_bot_detected: bool = False
    segments_ok: int = 0
    segments_total: int = 0
    avg_speed_kbps: float | None = None
    jitter_kbps: float | None = None
    timeouts: int = 0
    details: dict = field(default_factory=dict)

    def row(self) -> dict:
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "youtube": self.youtube,
            "youtube_hosts": self.youtube_hosts,
            "youtube_bot_detected": self.youtube_bot_detected,
            "segments_ok": self.segments_ok,
            "segments_total": self.segments_total,
            "avg_speed_kbps": round(self.avg_speed_kbps, 1) if self.avg_speed_kbps is not None else None,
            "jitter_kbps": round(self.jitter_kbps, 1) if self.jitter_kbps is not None else None,
            "timeouts": self.timeouts,
            "details": self.details,
        }


def _http_get_status(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    timeout: float,
    extra_headers: dict[str, str] | None = None,
) -> int:
    """GET через SOCKS+SSL, возвращает HTTP-статус (0 при ошибке)."""
    raw: socket.socket | None = None
    try:
        raw = base._socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw is None:
            return 0
        raw.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=server_name) as tls_sock:
            raw = None
            header_lines = [
                f"GET {path} HTTP/1.1\r\n",
                f"Host: {server_name}\r\n",
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n",
                f"Accept: */*\r\n",
                f"Connection: close\r\n",
            ]
            for key, value in (extra_headers or {}).items():
                header_lines.append(f"{key}: {value}\r\n")
            header_lines.append("\r\n")
            tls_sock.sendall("".join(header_lines).encode("ascii"))
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            if not response.startswith(b"HTTP/"):
                return 0
            parts = response.split(b" ", 2)
            try:
                return int(parts[1])
            except (IndexError, ValueError):
                return 0
    except Exception:
        return 0
    finally:
        if raw is not None:
            with contextlib.suppress(Exception):
                raw.close()


def _http_get_range_speed(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    offset: int,
    length: int,
    timeout: float,
) -> float | None:
    """GET с Range-запросом, вернуть скорость (КБ/с) или None при таймауте."""
    raw: socket.socket | None = None
    try:
        raw = base._socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw is None:
            return None
        raw.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=server_name) as tls_sock:
            raw = None
            start = offset
            end = offset + length - 1
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n"
                f"Range: bytes={start}-{end}\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)

            buffer = b""
            body_bytes = 0
            started: float | None = None
            deadline = time.perf_counter() + timeout
            while body_bytes < length and time.perf_counter() < deadline:
                chunk = tls_sock.recv(min(65536, length - body_bytes + 4096))
                if not chunk:
                    break
                if started is None:
                    buffer += chunk
                    header_end = buffer.find(b"\r\n\r\n")
                    if header_end < 0:
                        continue
                    headers = buffer[:header_end]
                    if not headers.startswith(b"HTTP/"):
                        return None
                    status = headers.split(b" ", 2)[1:2]
                    # 200/206 — отдаёт контент.
                    if not status or not (status[0].startswith(b"2")):
                        return None
                    body = buffer[header_end + 4 :]
                    body_bytes += len(body)
                    started = time.perf_counter()
                    buffer = b""
                else:
                    body_bytes += len(chunk)
            if started is None or body_bytes <= 0:
                return None
            elapsed = max(0.001, time.perf_counter() - started)
            return (body_bytes / 1024.0) / elapsed
    except (socket.timeout, TimeoutError):
        return None  # таймаут сегмента
    except Exception:
        return None
    finally:
        if raw is not None:
            with contextlib.suppress(Exception):
                raw.close()


def _run_video(
    socks_host: str,
    socks_port: int,
    timeout: float,
) -> VideoCheckResult:
    """Выполнить видео-проверку через поднятый SOCKS-прокси узла."""
    youtube_hosts: dict[str, bool] = {}
    youtube_any = False
    for host, server_name, port in VIDEO_YOUTUBE_HOSTS:
        # Сначала TLS-handshake, затем GET (достаточно 200/302/403/416).
        ok = base.tls_handshake_ok(socks_host, socks_port, host, port, server_name, timeout)
        if ok:
            status = _http_get_status(socks_host, socks_port, host, port, server_name, "/", timeout)
            ok = status != 0  # любой HTTP-ответ = сервер отдаёт контент
        youtube_hosts[host] = ok
        youtube_any = youtube_any or ok

    # Антибот-проверка: YouTube может открыть страницу, но отдать капчу /
    # consent / "sorry" вместо плеера — узел тогда бот-отсев.
    youtube_bot_detected = False
    ok, body, _status = base.http_get_body(
        socks_host,
        socks_port,
        "www.youtube.com",
        443,
        "www.youtube.com",
        YOUTUBE_PAGE_PATH,
        timeout,
        YOUTUBE_PAGE_MAX_BYTES,
    )
    if ok and body:
        lower = body.lower()
        youtube_bot_detected = any(m in lower for m in YOUTUBE_BOT_MARKERS)

    # DASH-сегменты: последовательная загрузка с Range-запросами.
    speeds: list[float] = []
    timeouts = 0
    segment_bytes = VIDEO_SEGMENT_BYTES
    for i in range(VIDEO_SEGMENTS_COUNT):
        offset = i * segment_bytes
        speed = _http_get_range_speed(
            socks_host,
            socks_port,
            DASH_SEGMENT_HOST,
            DASH_SEGMENT_PORT,
            DASH_SEGMENT_HOST,
            DASH_SEGMENT_PATH,
            offset,
            segment_bytes,
            VIDEO_SEGMENT_TIMEOUT,
        )
        if speed is None:
            timeouts += 1
            if timeouts > VIDEO_MAX_TIMEOUTS:
                break  # слишком много таймаутов — поток нестабилен
        else:
            speeds.append(speed)

    segments_ok = len(speeds)
    avg_speed: float | None = None
    jitter: float | None = None
    if speeds:
        avg_speed = sum(speeds) / len(speeds)
        if len(speeds) > 1:
            jitter = statistics.pstdev(speeds)  # джиттер скорости между сегментами

    accepted = (
        youtube_any
        and not youtube_bot_detected
        and segments_ok >= VIDEO_SEGMENTS_COUNT - VIDEO_MAX_TIMEOUTS
        and avg_speed is not None
        and avg_speed >= VIDEO_MIN_AVG_KBPS
        and timeouts <= VIDEO_MAX_TIMEOUTS
    )
    if youtube_bot_detected:
        reason = "youtube_bot_detected"
    else:
        reason = "ready" if accepted else "video_unstable"

    return VideoCheckResult(
        accepted=accepted,
        reason=reason,
        youtube=youtube_any,
        youtube_hosts=youtube_hosts,
        youtube_bot_detected=youtube_bot_detected,
        segments_ok=segments_ok,
        segments_total=VIDEO_SEGMENTS_COUNT,
        avg_speed_kbps=round(avg_speed, 1) if avg_speed is not None else None,
        jitter_kbps=round(jitter, 1) if jitter is not None else None,
        timeouts=timeouts,
        details={
            "segment_bytes": segment_bytes,
            "segment_host": DASH_SEGMENT_HOST,
            "timeouts": timeouts,
            "max_timeouts": VIDEO_MAX_TIMEOUTS,
            "min_avg_kbps": VIDEO_MIN_AVG_KBPS,
            "youtube_bot_detected": youtube_bot_detected,
            "speeds": [round(s, 1) for s in speeds[:10]],  # первые 10 сегментов
        },
    )


def check_node_video_detailed(
    node_url: str,
    timeout: float = 5.0,
    root_dir: Optional[Path] = None,
) -> VideoCheckResult:
    """Детальное потоковое видео-тестирование узла."""
    if not node_url:
        return VideoCheckResult(accepted=False, reason="empty_node")

    def _run(host: str, port: int) -> VideoCheckResult:
        return _run_video(host, port, timeout)

    # YouTube (3 хоста) + 20 сегментов по ~6s.
    budget = max(40.0, timeout * 24.0)
    result = base.run_with_node(node_url, _run, timeout=timeout, root_dir=root_dir, budget=budget)
    if result is None:
        return VideoCheckResult(accepted=False, reason="node_start_failed")
    return result


def check_node_video(
    node_url: str,
    timeout: float = 5.0,
    root_dir: Optional[Path] = None,
) -> bool:
    """Упрощённая видео-проверка (bool)."""
    return check_node_video_detailed(node_url, timeout=timeout, root_dir=root_dir).accepted


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m checkers.video <node_url>")
        sys.exit(1)
    r = check_node_video_detailed(sys.argv[1])
    print(
        f"VIDEO for {sys.argv[1]}: {'PASS' if r.accepted else 'FAIL'} "
        f"youtube={r.youtube} bot={r.youtube_bot_detected} avg={r.avg_speed_kbps}KB/s "
        f"jitter={r.jitter_kbps}KB/s timeouts={r.timeouts}/{r.segments_total} reason={r.reason}"
    )
