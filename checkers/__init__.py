"""Пакет проверок узлов.

Содержит реальные проверки доступности и обхода блокировок через
прокси-узел:

- ``checkers.dpi`` — DPI-проверка (методы dpi-ch через прокси);
- ``checkers.cidr`` — проверка CIDR-whitelist ограничений;
- ``checkers.zapret`` — Zapret-стиль тесты (DPI suite tcp 16-20 + HTTP);
- ``checkers.dpi_active`` — активное DPI-тестирование протокола узла
  (SNI-варианты, фрагментация/большой ClientHello, ECH, TLS 1.2/1.3);
- ``checkers.telegram_pro`` — продвинутые Telegram-проверки (MTProto
  connect/auth, upload) и ``telegram_score``;
- ``checkers.route`` — стабильность маршрута (RTT, jitter, loss).
"""

from .dpi import (
    DPI_ACCEPT_FRACTION,
    DPI_DEFAULT_TARGET,
    DPI_DEFAULT_TARGETS,
    DpiCheckResult,
    check_node_dpi,
    check_node_dpi_detailed,
)

from .cidr import (
    CidrCheckResult,
    check_node_cidr,
    check_node_cidr_detailed,
)
from .zapret import (
    DPI_SUITE_URL,
    STATUS_BLOCKED,
    ZapretCheckResult,
    ZapretHttpResult,
    ZapretProbeResult,
    ZapretTarget,
    check_node_zapret,
    check_node_zapret_detailed,
    load_dpi_suite,
)
from .dpi_active import (
    DpiActiveResult,
    check_node_dpi_active,
    check_node_dpi_active_detailed,
)
from .telegram_pro import (
    TelegramProResult,
    check_node_telegram_pro,
    check_node_telegram_pro_detailed,
)
from .route import (
    RouteCheckResult,
    check_node_route,
    check_node_route_detailed,
)

__all__ = [
    "DPI_ACCEPT_FRACTION",
    "DPI_DEFAULT_TARGET",
    "DPI_DEFAULT_TARGETS",
    "DpiCheckResult",
    "check_node_dpi",
    "check_node_dpi_detailed",
    "CidrCheckResult",
    "check_node_cidr",
    "check_node_cidr_detailed",
    "DPI_SUITE_URL",
    "STATUS_BLOCKED",
    "ZapretCheckResult",
    "ZapretHttpResult",
    "ZapretProbeResult",
    "ZapretTarget",
    "check_node_zapret",
    "check_node_zapret_detailed",
    "load_dpi_suite",
    "DpiActiveResult",
    "check_node_dpi_active",
    "check_node_dpi_active_detailed",
    "TelegramProResult",
    "check_node_telegram_pro",
    "check_node_telegram_pro_detailed",
    "RouteCheckResult",
    "check_node_route",
    "check_node_route_detailed",
]
