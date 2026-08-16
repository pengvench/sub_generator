"""Проверка стабильности маршрута узла: RTT, jitter, packet loss.

Скорость 300 Мбит/с ничего не значит при loss = 8%: потоковое видео будет
рваться, звонки — заикаться, игры — лагать. Здесь для каждого узла
собирается серия замеров RTT (через поднятый узел до контрольного хоста)
и вычисляются:

- ``ping_avg`` — средний RTT (мс);
- ``ping_p95`` — 95-й процентиль RTT (мс);
- ``jitter`` — среднее абсолютное отклонение последовательных RTT (мс) —
  скачки задержки (для VoIP/игр важнее, чем средний RTT);
- ``loss`` — доля неудачных попыток (0..1), «packet loss» через прокси.

Измеряем через TLS-handshake к неблокируемому контрольному хосту: полный
handshake (TCP connect + TLS round-trips) — это то, что реально происходит
при каждом открытии сайта/приложения, и включает в себя состояние маршрута.
Для loss важно, что неудачная попытка считается именно сетевой потерей
(таймаут/сброс), а не отсутствием соединения к прокси.
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

# Контрольный хост для замера RTT (не блокируется в РФ, стабилен).
ROUTE_CONTROL_HOST = "www.google.com"
ROUTE_CONTROL_PORT = 443
ROUTE_CONTROL_SNI = "www.google.com"

# Число замеров RTT.
ROUTE_PROBES = 10
# Таймаут одного замера.
ROUTE_PROBE_TIMEOUT = 4.0
# Порог потерь, при котором узел считается нестабильным (5%).
ROUTE_MAX_LOSS = 0.05
# Порог среднего RTT (мс) — «слишком далёкий» маршрут.
ROUTE_MAX_AVG_MS = 500.0
# Порог 95-го процентиля (мс).
ROUTE_MAX_P95_MS = 800.0
# Порог джиттера (мс).
ROUTE_MAX_JITTER_MS = 80.0


@dataclass
class RouteCheckResult:
    """Результат проверки стабильности маршрута."""

    accepted: bool
    reason: str = ""
    ping_avg: float | None = None
    ping_p95: float | None = None
    jitter: float | None = None
    loss: float | None = None
    probes_ok: int = 0
    probes_total: int = 0
    details: dict = field(default_factory=dict)

    def row(self) -> dict:
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "ping_avg": round(self.ping_avg, 1) if self.ping_avg is not None else None,
            "ping_p95": round(self.ping_p95, 1) if self.ping_p95 is not None else None,
            "jitter": round(self.jitter, 1) if self.jitter is not None else None,
            "loss": round(self.loss, 4) if self.loss is not None else None,
            "probes_ok": self.probes_ok,
            "probes_total": self.probes_total,
            "details": self.details,
        }


def _rtt_probe(socks_host: str, socks_port: int, timeout: float) -> float | None:
    """Один замер RTT: TCP connect + TLS handshake до контрольного хоста.

    Возвращает время в мс или None при сетевой потере (таймаут/сброс).
    """
    started = time.perf_counter()
    raw: socket.socket | None = None
    try:
        raw = base._socks_open_connection(
            socks_host, socks_port, ROUTE_CONTROL_HOST, ROUTE_CONTROL_PORT, timeout
        )
        if raw is None:
            return None
        raw.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=ROUTE_CONTROL_SNI) as tls_sock:
            raw = None
            # Один round-trip прикладного уровня (HTTP) — близко к реальному RTT.
            tls_sock.sendall(
                (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {ROUTE_CONTROL_HOST}\r\n"
                    f"User-Agent: SubGenerator/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            tls_sock.recv(1)
        return (time.perf_counter() - started) * 1000.0
    except (socket.timeout, TimeoutError, ConnectionError, OSError):
        return None
    except Exception:
        return None
    finally:
        if raw is not None:
            with contextlib.suppress(Exception):
                raw.close()


def _run_route(
    socks_host: str,
    socks_port: int,
    timeout: float,
) -> RouteCheckResult:
    """Выполнить серию замеров RTT через поднятый SOCKS-прокси узла."""
    rtts: list[float] = []
    lost = 0
    for _ in range(ROUTE_PROBES):
        ms = _rtt_probe(socks_host, socks_port, timeout)
        if ms is None:
            lost += 1
        else:
            rtts.append(ms)

    probes_ok = len(rtts)
    probes_total = ROUTE_PROBES

    ping_avg: float | None = None
    ping_p95: float | None = None
    jitter: float | None = None
    loss: float | None = None
    if rtts:
        ping_avg = sum(rtts) / len(rtts)
        sorted_rtts = sorted(rtts)
        idx = min(len(sorted_rtts) - 1, int(len(sorted_rtts) * 0.95))
        ping_p95 = sorted_rtts[idx]
        if len(rtts) > 1:
            # Среднее абсолютное отклонение между соседними замерами (jitter).
            diffs = [abs(b - a) for a, b in zip(rtts, rtts[1:])]
            jitter = sum(diffs) / len(diffs)
        else:
            jitter = 0.0
        loss = lost / probes_total

    accepted = (
        probes_ok > 0
        and loss is not None
        and loss <= ROUTE_MAX_LOSS
        and ping_avg is not None
        and ping_avg <= ROUTE_MAX_AVG_MS
        and ping_p95 is not None
        and ping_p95 <= ROUTE_MAX_P95_MS
        and jitter is not None
        and jitter <= ROUTE_MAX_JITTER_MS
    )
    reason = "ready" if accepted else "route_unstable"
    if loss is not None and loss > ROUTE_MAX_LOSS:
        reason = "high_loss"

    return RouteCheckResult(
        accepted=accepted,
        reason=reason,
        ping_avg=round(ping_avg, 1) if ping_avg is not None else None,
        ping_p95=round(ping_p95, 1) if ping_p95 is not None else None,
        jitter=round(jitter, 1) if jitter is not None else None,
        loss=round(loss, 4) if loss is not None else None,
        probes_ok=probes_ok,
        probes_total=probes_total,
        details={
            "control_host": ROUTE_CONTROL_HOST,
            "probes": [round(x, 1) for x in rtts],
            "max_loss": ROUTE_MAX_LOSS,
            "max_avg_ms": ROUTE_MAX_AVG_MS,
            "max_p95_ms": ROUTE_MAX_P95_MS,
            "max_jitter_ms": ROUTE_MAX_JITTER_MS,
        },
    )


def check_node_route_detailed(
    node_url: str,
    timeout: float = ROUTE_PROBE_TIMEOUT,
    root_dir: Optional[Path] = None,
) -> RouteCheckResult:
    """Детальная проверка стабильности маршрута узла."""
    if not node_url:
        return RouteCheckResult(accepted=False, reason="empty_node")

    def _run(host: str, port: int) -> RouteCheckResult:
        return _run_route(host, port, timeout)

    # ROUTE_PROBES замеров по ROUTE_PROBE_TIMEOUT + запас.
    budget = max(20.0, timeout * (ROUTE_PROBES + 2))
    result = base.run_with_node(node_url, _run, timeout=timeout, root_dir=root_dir, budget=budget)
    if result is None:
        return RouteCheckResult(accepted=False, reason="node_start_failed")
    return result


def check_node_route(
    node_url: str,
    timeout: float = ROUTE_PROBE_TIMEOUT,
    root_dir: Optional[Path] = None,
) -> bool:
    """Упрощённая проверка стабильности маршрута (bool)."""
    return check_node_route_detailed(node_url, timeout=timeout, root_dir=root_dir).accepted


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m checkers.route <node_url>")
        sys.exit(1)
    r = check_node_route_detailed(sys.argv[1])
    print(
        f"ROUTE for {sys.argv[1]}: {'PASS' if r.accepted else 'FAIL'} "
        f"avg={r.ping_avg}ms p95={r.ping_p95}ms jitter={r.jitter}ms loss={r.loss} "
        f"({r.probes_ok}/{r.probes_total}) reason={r.reason}"
    )
