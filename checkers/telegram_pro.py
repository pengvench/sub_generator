"""Продвинутые Telegram-проверки узла и расчёт ``telegram_score``.

Telegram важен для пользователя не только скоростью: сюда входят установка
соединения, авторизация на транспортном уровне (MTProto auth) и загрузка
медиа-данных. Один общий speedtest не отражает качество Telegram.

Здесь для каждого узла выполняются:

1. **MTProto connect** — установка MTProto-сессии (abridged transport) до DC
   Telegram: 1.2.x.x / 1.3.x.x / 1.4.x.x, ping-латентность nonce-запросом.
2. **MTProto auth** — примитивный авторизационный обмен (req_pq -> resPQ):
   сервер отвечает на запрос простых чисел — это подтверждает, что
   транспортный слой MTProto жив и принимает клиентские пакеты.
3. **Upload (загрузка файла)** — реальная передача данных от клиента к
   инфраструктуре Telegram (POST api.telegram.org с измерением скорости).

``telegram_score`` (0..100) — взвешенная сумма компонентов. Узел с высокой
скоростью, но обрывающимся MTProto, получает низкий балл.

Download-компонент удалён: он тестировал GET ``cdn4.telegram.org/``, но этот
хост (149.154.167.99) недоступен во многих сетях даже без VPN (TCP-коннект
не проходит), а код требовал HTTP 2xx при фактическом 404. В результате
download всегда давал ``None``, а ``telegram_score`` был искусственно
ограничен 80. Вес download перенесён на upload.
"""

from __future__ import annotations

import contextlib
import logging
import secrets
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import base
from xray_runtime import (
    TELEGRAM_API_HEAD_TARGET,
    TELEGRAM_MEDIA_DC,
    _encode_abridged_packet,
    _read_abridged_packet,
    _socks_mtproto_latency,
)

logger = logging.getLogger(__name__)

# DC Telegram для MTProto-проверок (основные IP, резолвятся клиентом).
TELEGRAM_MT_PROTO_DCS: tuple[tuple[str, int], ...] = (
    ("149.154.175.50", 443),  # DC1
    ("149.154.167.50", 443),  # DC2
    ("149.154.175.100", 443),  # DC3
    ("149.154.167.91", 443),  # DC4
    ("91.108.56.130", 443),  # DC5
)

# Хост для «загрузки файла» (приём данных Telegram-инфраструктурой).
TELEGRAM_UPLOAD_HOST = "api.telegram.org"
TELEGRAM_UPLOAD_PATH = "/file/bot0/sendDocument"

# Вес компонентов в telegram_score (сумма = 1.0).
TG_WEIGHTS = {
    "connect": 0.30,  # MTProto connect (установка соединения)
    "auth": 0.30,  # MTProto auth (транспортный обмен)
    "upload": 0.40,  # загрузка файла
}

# Таймауты.
TG_TIMEOUT = 5.0
TG_UPLOAD_BYTES = 4 * 1024 * 1024  # 4 МБ «загрузка файла»
TG_UPLOAD_SAMPLE_SEC = 3.0
# Порог скорости для «хорошего» Telegram (КБ/с), как медиа-порог Xray.
TG_GOOD_KBPS = 2048.0

# Константы MTProto.
MTProto_INVOKE_WITH_LAYER = 0x00000000  # не используется, placeholder
MTProto_REQ_PQ = 0x60469778  # req_pq — запрос простых чисел (обмен до auth_key)
MTProto_RES_PQ = 0x05162463  # resPQ — ответ сервера на req_pq


@dataclass
class TelegramProResult:
    """Результат продвинутой Telegram-проверки."""

    accepted: bool
    reason: str = ""
    telegram_score: float = 0.0
    connect: bool = False
    connect_ms: float | None = None
    auth: bool = False
    upload: bool = False
    upload_kbps: float | None = None
    download: bool = False
    download_kbps: float | None = None
    details: dict = field(default_factory=dict)

    def row(self) -> dict:
        return {
            "accepted": self.accepted,
            "telegram_score": round(self.telegram_score, 1),
            "reason": self.reason,
            "connect": self.connect,
            "connect_ms": round(self.connect_ms, 1) if self.connect_ms else None,
            "auth": self.auth,
            "upload": self.upload,
            "upload_kbps": round(self.upload_kbps, 1) if self.upload_kbps else None,
            "download": self.download,
            "download_kbps": round(self.download_kbps, 1) if self.download_kbps else None,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# MTProto auth (req_pq -> resPQ) через SOCKS-прокси.
# ---------------------------------------------------------------------------

def _socks_mtproto_auth(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float,
) -> bool:
    """MTProto auth-обмен: req_pq -> resPQ через abridged transport.

    Имитирует первую фазу авторизации: клиент шлёт req_pq с nonce, сервер
    отвечает resPQ (список простых чисел + public key fingerprint). Это
    доказывает, что MTProto-транспорт узла живой и принимает пакеты выше
    уровня ping.
    """
    sock: socket.socket | None = None
    try:
        sock = base._socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if sock is None:
            return False
        sock.settimeout(timeout)
        sock.sendall(b"\xef")  # abridged transport flag

        nonce = secrets.randbits(127)
        nonce_bytes = nonce.to_bytes(16, "little", signed=True)
        # body = constructor(req_pq) + nonce
        body = struct.pack("<I", MTProto_REQ_PQ) + nonce_bytes
        message_id = int(time.time() * (2**32)) & ~3
        payload = (
            struct.pack("<q", 0)  # auth_key_id (0 = не авторизован)
            + struct.pack("<q", message_id)
            + struct.pack("<i", len(body))
            + body
        )
        sock.sendall(_encode_abridged_packet(payload))

        response = _read_abridged_packet(sock)
        if len(response) < 40 or response[:8] != b"\0" * 8:
            return False
        body_len = struct.unpack("<i", response[16:20])[0]
        if body_len <= 0 or 20 + body_len > len(response):
            return False
        response_body = response[20 : 20 + body_len]
        # resPQ constructor: 0x05162463
        if len(response_body) < 4:
            return False
        if struct.unpack("<I", response_body[:4])[0] != MTProto_RES_PQ:
            return False
        return True
    except Exception:
        return False
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()


# ---------------------------------------------------------------------------
# Upload через SOCKS+SSL (инфраструктура Telegram).
# ---------------------------------------------------------------------------

def _socks_https_upload_kbps(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    max_bytes: int,
    timeout: float,
    *,
    sample_seconds: float,
) -> float | None:
    """POST-загрузка через SOCKS+SSL (аналог ``_socks_https_upload_kbps``)."""
    raw_sock: socket.socket | None = None
    try:
        raw_sock = base._socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {max_bytes}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            started = time.perf_counter()
            chunk = b"\x00" * 65536
            sent = 0
            sample_deadline = started + max(0.5, float(sample_seconds))
            while sent < max_bytes and time.perf_counter() < sample_deadline:
                tls_sock.sendall(chunk)
                sent += len(chunk)
            elapsed = max(0.001, time.perf_counter() - started)
            with contextlib.suppress(Exception):
                tls_sock.settimeout(1.0)
                tls_sock.recv(4096)
            return (sent / 1024.0) / elapsed
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


# ---------------------------------------------------------------------------
# Основная проверка.
# ---------------------------------------------------------------------------

def _run_telegram_pro(
    socks_host: str,
    socks_port: int,
    timeout: float,
) -> TelegramProResult:
    """Выполнить Telegram-проверки через поднятый SOCKS-прокси узла."""
    connect_ms: float | None = None
    connect_ok = False
    for dc_host, dc_port in TELEGRAM_MT_PROTO_DCS:
        ms = _socks_mtproto_latency(socks_host, socks_port, dc_host, dc_port, timeout)
        if ms is not None:
            connect_ms = ms
            connect_ok = True
            break
    # connect-компонент также считается успешным при любом отклике MTProto
    # (может быть DC5, недоступный с некоторых точек выхода).

    auth_ok = False
    for dc_host, dc_port in TELEGRAM_MT_PROTO_DCS:
        if _socks_mtproto_auth(socks_host, socks_port, dc_host, dc_port, timeout):
            auth_ok = True
            break

    upload_kbps = _socks_https_upload_kbps(
        socks_host,
        socks_port,
        TELEGRAM_UPLOAD_HOST,
        443,
        TELEGRAM_UPLOAD_HOST,
        TELEGRAM_UPLOAD_PATH,
        TG_UPLOAD_BYTES,
        timeout,
        sample_seconds=TG_UPLOAD_SAMPLE_SEC,
    )
    upload_ok = upload_kbps is not None and upload_kbps >= TG_GOOD_KBPS * 0.25

    # telegram_score = взвешенная сумма компонентов (0..100).
    score = 0.0
    score += TG_WEIGHTS["connect"] * 100.0 if connect_ok else 0.0
    score += TG_WEIGHTS["auth"] * 100.0 if auth_ok else 0.0
    score += TG_WEIGHTS["upload"] * 100.0 if upload_ok else 0.0

    # Порог: connect+auth обязательны, score >= 60.
    accepted = connect_ok and auth_ok and score >= 60.0
    reason = "ready" if accepted else "telegram_unstable"

    return TelegramProResult(
        accepted=accepted,
        reason=reason,
        telegram_score=round(score, 1),
        connect=connect_ok,
        connect_ms=round(connect_ms, 1) if connect_ms is not None else None,
        auth=auth_ok,
        upload=upload_ok,
        upload_kbps=round(upload_kbps, 1) if upload_kbps is not None else None,
        download=False,
        download_kbps=None,
        details={
            "dcs_tried": len(TELEGRAM_MT_PROTO_DCS),
            "upload_bytes": TG_UPLOAD_BYTES,
            "weights": TG_WEIGHTS,
            "good_kbps": TG_GOOD_KBPS,
        },
    )


def check_node_telegram_pro_detailed(
    node_url: str,
    timeout: float = TG_TIMEOUT,
    root_dir: Optional[Path] = None,
) -> TelegramProResult:
    """Детальная продвинутая Telegram-проверка узла."""
    if not node_url:
        return TelegramProResult(accepted=False, reason="empty_node")

    def _run(host: str, port: int) -> TelegramProResult:
        return _run_telegram_pro(host, port, timeout)

    # connect(до 5 DC) + auth(до 5 DC) + upload.
    budget = max(20.0, timeout * 16.0)
    result = base.run_with_node(node_url, _run, timeout=timeout, root_dir=root_dir, budget=budget)
    if result is None:
        return TelegramProResult(accepted=False, reason="node_start_failed")
    return result


def check_node_telegram_pro(
    node_url: str,
    timeout: float = TG_TIMEOUT,
    root_dir: Optional[Path] = None,
) -> bool:
    """Упрощённая продвинутая Telegram-проверка (bool)."""
    return check_node_telegram_pro_detailed(node_url, timeout=timeout, root_dir=root_dir).accepted


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m checkers.telegram_pro <node_url>")
        sys.exit(1)
    r = check_node_telegram_pro_detailed(sys.argv[1])
    print(
        f"TELEGRAM-PRO for {sys.argv[1]}: {'PASS' if r.accepted else 'FAIL'} "
        f"score={r.telegram_score} reason={r.reason}"
    )
    print(f"  connect={r.connect}({r.connect_ms}ms) auth={r.auth} "
          f"upload={r.upload_kbps}KB/s download={r.download_kbps}KB/s")
