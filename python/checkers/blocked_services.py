"""Проверка доступа к ЗАБЛОКИРОВАННЫМ сервисам через узел.

Философия (пользователь): главный критерий отбора — не абстрактный пинг и не
скорость, а РЕАЛЬНАЯ работа заблокированных сервисов: Telegram (отдельный
этап telegram_pro), Instagram, YouTube, Discord, ИИ-сервисы. Пинг годится
только для отсеивания совсем мёртвых конфигов.

Метод (не «просто HTTP-запрос сайтам»):
1. **TCP-коннект к конкретным IP сервисов** — прямые адреса заблокированных
   ресурсов (Instagram/Meta, Cloudflare-CDN, Google/YouTube) из реестра
   заблокированных IP (rulist/antifilter — те же списки, что использует
   Zapret). IP-уровень: если цензор режет по подсетям — коннект не пройдёт.
2. **TLS-хендшейк с настоящим SNI** к домену сервиса: ТСПУ может
   пропускать TCP, но рвать ClientHello с SNI instagram.com. Это ловит
   SNI-DPI, который TCP-пинг не видит (модель Smart Connect из v2whitelist:
   TCP-открытый порт != работающий сервис).

Комбинированный вердикт по каждому сервису: TCP до IP И TLS до домена.
Обязательные сервисы: instagram, youtube, discord. ИИ (chatgpt/gemini) —
информативно: их доступность зависит от гео выхода (OpenAI сам банит РФ),
это работа ai-geo этапа, не DPI.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import base

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Цели: IP взяты из реестра заблокированных IP (bol-van/rulist,
# reestr_resolved4.txt — те же данные, на которых строит списки Zapret),
# плюс стабильные representatives диапазонов сервисов.
# ---------------------------------------------------------------------------

SERVICES: dict[str, dict] = {
    # v11: упрощено. Раньше у каждого сервиса было по 2 IP из реестра + TLS-SNI.
    # Теперь: 1 представитель IP + TLS-SNI. Этого достаточно для проверки
    # «прокси-узел коннектится к заблокированному IP + TLS с SNI проходит».
    # 5 IP × 5 сервисов = 25 проб на узел — оверкилл для массового этапа.
    # 1 IP × 3 сервиса = 3 пробы — в 8 раз быстрее.
    "instagram": {
        "required": True,
        "ips": ("31.13.33.28",),  # Meta/Instagram (реестр РФ)
        "host": "instagram.com",
    },
    "youtube": {
        "required": True,
        "ips": ("142.250.180.20",),  # Google/YouTube (реестр РФ)
        "host": "www.youtube.com",
    },
    "discord": {
        "required": True,
        "ips": ("162.159.128.233",),  # discord.gg (Cloudflare)
        "host": "discord.gg",
    },
    # ИИ-сервисы — информативно (гео-зависимы, OpenAI банит РФ).
    # В v11 их гео проверяется на этапе ai_geo (consensus CF+ipinfo+ip-api),
    # здесь — только TCP/TLS досягаемость.
    "openai": {
        "required": False,
        "ips": ("104.16.3.81",),  # Cloudflare (реестр)
        "host": "chatgpt.com",
    },
    "gemini": {
        "required": False,
        "ips": ("142.250.185.174",),  # Google
        "host": "gemini.google.com",
    },
}

# Таймаут одной пробы (сек).
SERVICES_TIMEOUT = 8.0


@dataclass
class ServiceProbe:
    """Результат проверки одного сервиса."""

    name: str
    tcp_ok: bool = False
    tls_ok: bool = False
    latency_ms: float | None = None
    required: bool = True

    @property
    def passed(self) -> bool:
        # Сервис «работает» = TCP до IP И TLS с SNI. Только TCP — не считается:
        # ТСПУ может держать TCP и рвать TLS (SNI-детект). Только TLS без TCP
        # тоже не считается (значит IP-путь кривой, приложения не оживут).
        return self.tcp_ok and self.tls_ok


@dataclass
class BlockedServicesResult:
    """Итог проверки заблокированных сервисов через узел."""

    accepted: bool
    reason: str = ""
    services: dict = field(default_factory=dict)  # name -> ServiceProbe.row()
    required_passed: int = 0
    required_total: int = 0
    info_passed: int = 0
    info_total: int = 0

    def row(self) -> dict:
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "services": self.services,
            "required_passed": self.required_passed,
            "required_total": self.required_total,
            "info_passed": self.info_passed,
            "info_total": self.info_total,
        }


def _tcp_probe(
    socks_host: str,
    socks_port: int,
    target_ip: str,
    timeout: float,
) -> tuple[bool, float | None]:
    """TCP-коннект к IP через SOCKS узла. Возвращает (ok, latency_ms)."""
    import time as _time

    started = _time.perf_counter()
    sock = base._socks_open_connection(socks_host, socks_port, target_ip, 443, timeout)
    if sock is None:
        return False, None
    import contextlib

    with contextlib.suppress(Exception):
        sock.close()
    return True, (_time.perf_counter() - started) * 1000.0


def _run_services_check(
    socks_host: str,
    socks_port: int,
    timeout: float,
    *,
    required_extra: tuple[str, ...] = (),
) -> BlockedServicesResult:
    """Проверить все сервисы через поднятый SOCKS5 узла."""
    probes: dict[str, ServiceProbe] = {}
    for name, spec in SERVICES.items():
        probe = ServiceProbe(
            name=name,
            required=bool(spec.get("required", False)) or name in required_extra,
        )
        # 1) TCP до IP сервисов (по одному достаточно).
        for ip in spec["ips"]:
            ok, _lat = _tcp_probe(socks_host, socks_port, ip, timeout)
            if ok:
                probe.tcp_ok = True
                break
        # 2) TLS-хендшейк с настоящим SNI домена сервиса.
        host = spec["host"]
        probe.tls_ok = base.tls_handshake_ok(socks_host, socks_port, host, 443, host, timeout)
        probes[name] = probe

    required = [p for p in probes.values() if p.required]
    info = [p for p in probes.values() if not p.required]
    req_passed = sum(1 for p in required if p.passed)
    info_passed = sum(1 for p in info if p.passed)

    accepted = req_passed == len(required) and len(required) > 0
    failed_names = [p.name for p in required if not p.passed]
    if accepted:
        reason = "services_ok"
    elif failed_names:
        reason = f"blocked:{','.join(failed_names)}"
    else:
        reason = "node_start_failed"

    return BlockedServicesResult(
        accepted=accepted,
        reason=reason,
        services={name: {
            "tcp": p.tcp_ok,
            "tls": p.tls_ok,
            "passed": p.passed,
            "required": p.required,
            "latency_ms": round(p.latency_ms, 1) if p.latency_ms is not None else None,
        } for name, p in probes.items()},
        required_passed=req_passed,
        required_total=len(required),
        info_passed=info_passed,
        info_total=len(info),
    )


def check_node_blocked_services_detailed(
    node_url: str,
    timeout: float = SERVICES_TIMEOUT,
    root_dir: Optional[Path] = None,
) -> BlockedServicesResult:
    """Проверить доступ к заблокированным сервисам через узел (детально)."""
    if not node_url:
        return BlockedServicesResult(accepted=False, reason="empty_node")

    def _check(host: str, port: int) -> BlockedServicesResult:
        return _run_services_check(host, port, timeout)

    # 5 сервисов x (до 2 TCP + 1 TLS) — бюджет с запасом.
    budget = max(40.0, timeout * 8.0)
    result = base.run_with_node(node_url, _check, timeout=timeout, root_dir=root_dir, budget=budget)
    if result is None:
        return BlockedServicesResult(accepted=False, reason="node_start_failed")
    return result


def check_node_blocked_services(
    node_url: str,
    timeout: float = SERVICES_TIMEOUT,
    root_dir: Optional[Path] = None,
) -> bool:
    """Проверить доступ к заблокированным сервисам (bool)."""
    return check_node_blocked_services_detailed(node_url, timeout=timeout, root_dir=root_dir).accepted


def format_result(result: BlockedServicesResult) -> str:
    """Строка для логов: инста/ютуб/дискорд/ИИ по флагам."""
    parts = []
    for name, row in result.services.items():
        mark = "✅" if row["passed"] else ("⚠️" if not row["required"] else "❌")
        parts.append(f"{name}={'+' if row['passed'] else '-'}{mark}")
    return " ".join(parts)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m checkers.blocked_services <node_url>")
        sys.exit(1)
    r = check_node_blocked_services_detailed(sys.argv[1])
    print(f"SERVICES for {sys.argv[1]}: {'PASS' if r.accepted else 'FAIL'} reason={r.reason}")
    print(f"  {format_result(r)}")
