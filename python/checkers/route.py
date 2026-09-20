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

# Множители адаптивных порогов от rtt_hint (медиана сквозной латентности
# канала из initial-check, мс). Замер RTT здесь — ПОЛНЫЙ TLS-handshake через
# туннель (TCP connect + SOCKS CONNECT + TLS + HTTP RTT ≈ 3-5 сквозных RTT),
# а не одиночный ping: на каналах с высокой латентностью (мобильные сети,
# initial p50 > 500мс) базовый порог avg≤500 математически недостижим почти
# ни для одной ноды — конвейер выкашивает живые рабочие узлы (инцидент
# 2026-09-17: 61 из 111 живых отклонён, у 51 причиной был avg>500 при
# собственной медиане канала юзера 614мс).
ROUTE_RTT_SCALE_AVG = 1.0
ROUTE_RTT_SCALE_P95 = 1.5
ROUTE_RTT_SCALE_JITTER = 0.25


def route_thresholds(rtt_hint_ms: float | None) -> dict[str, float]:
    """Пороги стабильности маршрута с учётом латентности канала.

    При ``rtt_hint_ms`` выше базового порога avg пороги масштабируются от
    сквозной латентности канала: медленный канал юзера не должен браковать
    ноды, которые на этом канале физически не могут ответить быстрее.
    ``loss`` не масштабируется — потери не объясняются латентностью канала.
    """
    max_avg = ROUTE_MAX_AVG_MS
    max_p95 = ROUTE_MAX_P95_MS
    max_jitter = ROUTE_MAX_JITTER_MS
    if rtt_hint_ms is not None and rtt_hint_ms > ROUTE_MAX_AVG_MS:
        max_avg = max(max_avg, rtt_hint_ms * ROUTE_RTT_SCALE_AVG)
        max_p95 = max(max_p95, rtt_hint_ms * ROUTE_RTT_SCALE_P95)
        max_jitter = max(max_jitter, rtt_hint_ms * ROUTE_RTT_SCALE_JITTER)
    return {"avg_ms": max_avg, "p95_ms": max_p95, "jitter_ms": max_jitter, "loss": ROUTE_MAX_LOSS}


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
    *,
    probes: int = ROUTE_PROBES,
    deadline: float | None = None,
    rtt_hint_ms: float | None = None,
) -> RouteCheckResult:
    """Выполнить серию замеров RTT через поднятый SOCKS-прокси узла.

    ``probes`` — число замеров (стресс-тест resilience использует укороченную
    серию — те же пороги, но меньше попыток).
    ``deadline`` — time.monotonic() момент, после которого новые пробы не
    начинаются (уже идущая попытка дорабатывает до своего timeout).
    ``rtt_hint_ms`` — медиана сквозной латентности канала (initial-check p50):
    на медленных каналах пороги avg/p95/jitter масштабируются от неё, чтобы
    собственная латентность канала юзера не браковала живые ноды.
    """
    probe_count = max(3, int(probes))
    thresholds = route_thresholds(rtt_hint_ms)
    max_avg = thresholds["avg_ms"]
    max_p95 = thresholds["p95_ms"]
    max_jitter = thresholds["jitter_ms"]
    rtts: list[float] = []
    lost = 0
    for i in range(probe_count):
        if deadline is not None and time.monotonic() >= deadline:
            break
        ms = _rtt_probe(socks_host, socks_port, timeout)
        if ms is None:
            lost += 1
        else:
            rtts.append(ms)

    probes_ok = len(rtts)
    probes_total = probes_ok + lost

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

    violations: list[str] = []
    # v15 (инцидент 2026-09-19, лог юзера: 35 узлов убиты high_loss при
    # ОДНОМ потерянном зонде из 5): с малым числом зондов (стресс-режим — 5)
    # гранулярность потерь 20%: один таймаут-спайк (скачок нагрузки конвейера
    # на 32 параллельных проверках) мгновенно давал «loss 20% > 5%» и узел
    # отбрасывался. Допускаем ОДИН потерянный зонд: порог потерь =
    # max(ROUTE_MAX_LOSS, 1/probes) — при 5 зондах 20% (1/5 проходит, 2/5 — нет),
    # при 10 — 10%. Потери 2+ зондов по-прежнему бракуются.
    eff_max_loss = max(ROUTE_MAX_LOSS, 1.0 / max(1, probe_count))
    if loss is not None and loss > eff_max_loss:
        violations.append(f"loss {loss:.0%} > {eff_max_loss:.0%}")
    if ping_avg is not None and ping_avg > max_avg:
        violations.append(f"avg {ping_avg:.0f} > {max_avg:.0f}ms")
    if ping_p95 is not None and ping_p95 > max_p95:
        violations.append(f"p95 {ping_p95:.0f} > {max_p95:.0f}ms")
    if jitter is not None and jitter > max_jitter:
        violations.append(f"jitter {jitter:.0f} > {max_jitter:.0f}ms")

    accepted = (
        probes_ok > 0
        and probes_total >= 3
        and loss is not None
        and loss <= eff_max_loss
        and ping_avg is not None
        and ping_avg <= max_avg
        and ping_p95 is not None
        and ping_p95 <= max_p95
        and jitter is not None
        and jitter <= max_jitter
    )
    reason = "ready" if accepted else "route_unstable"
    if loss is not None and loss > eff_max_loss:
        reason = "high_loss"
    elif probes_total < 3:
        # Дедлайн батареи съел время на пробы — данных мало, вердикта нет.
        reason = "not_measured"

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
            "max_avg_ms": round(max_avg, 1),
            "max_p95_ms": round(max_p95, 1),
            "max_jitter_ms": round(max_jitter, 1),
            "rtt_hint_ms": round(rtt_hint_ms, 1) if rtt_hint_ms is not None else None,
            "violations": violations,
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
