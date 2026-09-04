"""Проверка CIDR-whitelist ограничений через прокси-узел.

Реализует метод ``cidrwhitelist`` из инструментария dpi-ch (dpich):
проверяет, не ограничивает ли цензор доступ по IP-подсетям (CIDR-цензура).

Логика (как в ``checkers/cidrwhitelist.go``):
- отправляются HEAD-запросы к "regular" ресурсам (не в whitelist) и к
  "whitelisted" ресурсам;
- если доступен хотя бы один regular ресурс — ограничений нет;
- если доступны ТОЛЬКО whitelisted ресурсы — CIDR-whitelist обнаружен;
- если недоступны ни те, ни другие — нет доступа к сети.

В отличие от dpich, проверка выполняется через локальный SOCKS5-прокси
узла, т.е. оценивается способность узла достучаться до обычных ресурсов.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import base

logger = logging.getLogger(__name__)

# Ресурсы, которые почти наверняка НЕ в whitelist (regular).
CIDR_REGULAR_HOSTS = (
    "github.com",
    "ru.wikipedia.org",
    "www.google.com",
)
# Ресурсы, которые обычно в whitelist (доступны даже при CIDR-цензуре).
CIDR_WHITELISTED_HOSTS = (
    "ya.ru",
    "vk.ru",
)
# Таймаут проверки (сек).
CIDR_TIMEOUT = 8.0


@dataclass
class CidrCheckResult:
    """Результат проверки CIDR-whitelist ограничений."""

    accepted: bool
    regular_alive: int = 0
    whitelisted_alive: int = 0
    reason: str = ""
    details: dict = field(default_factory=dict)

    def row(self) -> dict:
        return {
            "accepted": self.accepted,
            "regular_alive": self.regular_alive,
            "whitelisted_alive": self.whitelisted_alive,
            "reason": self.reason,
            "details": self.details,
        }


def _run_checks(
    host: str,
    port: int,
    timeout: float,
    regular_hosts: tuple[str, ...],
    whitelisted_hosts: tuple[str, ...],
) -> CidrCheckResult:
    """Выполнить CIDR-whitelist проверку через локальный SOCKS5-прокси."""
    regular_alive = 0
    for target in regular_hosts:
        if base.tls_handshake_ok(host, port, target, 443, target, timeout):
            regular_alive += 1

    whitelisted_alive = 0
    for target in whitelisted_hosts:
        if base.tls_handshake_ok(host, port, target, 443, target, timeout):
            whitelisted_alive += 1

    # Ресурсы не из whitelist доступны — ограничений нет.
    if regular_alive > 0:
        return CidrCheckResult(
            accepted=True,
            regular_alive=regular_alive,
            whitelisted_alive=whitelisted_alive,
            reason="no_cidr_restriction",
            details={"regular": list(regular_hosts), "whitelisted": list(whitelisted_hosts)},
        )

    # Доступны ТОЛЬКО ресурсы из whitelist — CIDR-цензура обнаружена.
    if whitelisted_alive > 0:
        return CidrCheckResult(
            accepted=False,
            regular_alive=regular_alive,
            whitelisted_alive=whitelisted_alive,
            reason="cidr_whitelist_detected",
            details={"regular": list(regular_hosts), "whitelisted": list(whitelisted_hosts)},
        )

    # Недоступны ни те, ни другие — нет доступа к сети.
    return CidrCheckResult(
        accepted=False,
        regular_alive=regular_alive,
        whitelisted_alive=whitelisted_alive,
        reason="no_internet_access",
        details={"regular": list(regular_hosts), "whitelisted": list(whitelisted_hosts)},
    )


def check_node_cidr(
    node_url: str,
    timeout: float = CIDR_TIMEOUT,
    root_dir: Optional[Path] = None,
    regular_hosts: tuple[str, ...] = CIDR_REGULAR_HOSTS,
    whitelisted_hosts: tuple[str, ...] = CIDR_WHITELISTED_HOSTS,
) -> bool:
    """Проверить, не ограничен ли узел CIDR-whitelist цензурой.

    Возвращает True, если узел может достучаться до обычных (не whitelisted)
    ресурсов, т.е. CIDR-ограничений нет.
    """
    result = check_node_cidr_detailed(
        node_url,
        timeout=timeout,
        root_dir=root_dir,
        regular_hosts=regular_hosts,
        whitelisted_hosts=whitelisted_hosts,
    )
    return result.accepted


def check_node_cidr_detailed(
    node_url: str,
    timeout: float = CIDR_TIMEOUT,
    root_dir: Optional[Path] = None,
    regular_hosts: tuple[str, ...] = CIDR_REGULAR_HOSTS,
    whitelisted_hosts: tuple[str, ...] = CIDR_WHITELISTED_HOSTS,
) -> CidrCheckResult:
    """Детальная CIDR-whitelist проверка узла (возвращает CidrCheckResult)."""
    if not node_url:
        return CidrCheckResult(accepted=False, reason="empty_node")

    def _check(host: str, port: int) -> CidrCheckResult:
        return _run_checks(host, port, timeout, regular_hosts, whitelisted_hosts)

    result = base.run_with_node(node_url, _check, timeout=timeout, root_dir=root_dir)
    if result is None:
        return CidrCheckResult(accepted=False, reason="node_start_failed")
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m checkers.cidr <node_url>")
        sys.exit(1)
    url = sys.argv[1]
    res = check_node_cidr_detailed(url)
    print(f"CIDR check for {url}: {'PASS' if res.accepted else 'FAIL'}")
    print(
        f"  regular_alive={res.regular_alive} whitelisted_alive={res.whitelisted_alive} "
        f"reason={res.reason}"
    )
