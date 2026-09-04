"""
Initial Check: быстрая проверка доступности узла (TCP + HTTP HEAD).

Заменяет тяжёлый видео-тест на этапе первичного отсева.
Цель: отфильтровать мёртвые узлы за 2-3 секунды.

Проверка выполняется через поднятый core-процесс узла (локальный SOCKS5),
а не через aiohttp с proxy=vless:// — aiohttp умеет только HTTP-прокси и не
может работать с vless/vmess/trojan ссылками.
"""
from __future__ import annotations

import contextlib
import socket
import ssl
import time
from typing import Any

from . import base
from subgen.checker_thresholds import get_threshold

# Константы для проверки.
CHECK_HOST = "clients3.google.com"
CHECK_PORT = 443
CHECK_PATH = "/generate_204"
EXPECTED_STATUS = 204


def _http_head_status(
    socks_host: str,
    socks_port: int,
    timeout: float,
) -> tuple[bool, float, int]:
    """TCP connect + TLS + HTTP HEAD через SOCKS5.

    Возвращает (успех, latency_ms, http_status). При сетевой ошибке
    возвращает (False, None, 0).
    """
    started = time.perf_counter()
    raw: socket.socket | None = None
    try:
        raw = base._socks_open_connection(
            socks_host, socks_port, CHECK_HOST, CHECK_PORT, timeout
        )
        if raw is None:
            return False, 0.0, 0
        raw.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=CHECK_HOST) as tls_sock:
            raw = None
            request = (
                f"HEAD {CHECK_PATH} HTTP/1.1\r\n"
                f"Host: {CHECK_HOST}\r\n"
                f"User-Agent: SubGenerator/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            # Читаем только статус-строку (ответ на HEAD короткий).
            data = b""
            while b"\r\n" not in data:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        status = 0
        if data:
            try:
                status = int(data.split(b" ", 2)[1])
            except (IndexError, ValueError):
                status = 0
        latency_ms = (time.perf_counter() - started) * 1000.0
        return True, latency_ms, status
    except (socket.timeout, TimeoutError, ConnectionError, OSError):
        return False, 0.0, 0
    except Exception:
        return False, 0.0, 0
    finally:
        if raw is not None:
            with contextlib.suppress(Exception):
                raw.close()


def _run_check(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Одна проверка через поднятый SOCKS5-прокси узла."""
    ok, latency_ms, status = _http_head_status(host, port, timeout)
    result: dict[str, Any] = {
        "passed": False,
        "tcp_ok": False,
        "http_ok": False,
        "latency_ms": None,
        "error": None,
    }
    if not ok:
        result["error"] = "connection_failed"
        return result

    result["tcp_ok"] = True
    result["latency_ms"] = round(latency_ms, 2)
    if status == EXPECTED_STATUS:
        result["http_ok"] = True
        result["passed"] = True
    else:
        result["error"] = f"http_status_{status}"
    return result


def run_initial_check(
    node: dict[str, Any] | None,
    proxy_url: str,
    timeout: float | None = None,
) -> dict[str, Any]:
    """
    Выполняет быструю проверку через поднятый core-процесс узла:
    1. TCP подключение (через SOCKS5).
    2. HTTP HEAD запрос.

    timeout: переопределяет таймаут из checker_thresholds.json (если задан).
    """
    timeout_sec = timeout if timeout is not None else float(get_threshold("initial_check", "timeout", 3.0))
    budget = max(10.0, timeout_sec * 4.0)

    result = base.run_with_node(
        proxy_url,
        lambda host, port: _run_check(host, port, timeout_sec),
        timeout=timeout_sec,
        budget=budget,
    )
    if result is None:
        return {
            "passed": False,
            "tcp_ok": False,
            "http_ok": False,
            "latency_ms": None,
            "error": "node_start_failed",
        }
    return result


def format_result(result: dict[str, Any]) -> str:
    """Форматирует результат для логов."""
    if result.get("passed"):
        return f"OK (latency={result.get('latency_ms')}ms)"
    return f"FAIL ({result.get('error')})"
