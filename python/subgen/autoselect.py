"""Генерация конфигураций «автовыбора» из финальных рабочих узлов.

Два артефакта (оба кладутся в data/):
  - autoselect_xray.json — полная конфигурация xray-core: все узлы тегами
    proxy-1..proxy-N + burstObservatory (проба https://t.me/peppe_poppo)
    + routing-балансер leastLoad: клиент сам меряет узлы каждые 5 минут и
    водит трафик через наименее загруженный (как AutoPizduk.txt).
  - autoselect_singbox.json — эквивалент для sing-box: узлы (конвертация
    из xray-формата через singbox_convert) + urltest-группа «auto»,
    которая сама меряет RTT до пробы и переключается на лучший узел.

Формат xray-конфига воспроизводит проверенный артефакт прогона
2026-09-04 (лог4): socks-in 2080 + sniffing, mux на каждом outbound,
DNS через DoH/UDP, geoip:private -> direct, udp443 -> block, весь
трафик через балансер.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from subgen.config import DATA_DIR

LogSink = Callable[[str], None]

# Проба здоровья узлов (реальный HTTP-обход: телеграм-канал автора).
AUTOSELECT_PROBE_URL = "https://t.me/peppe_poppo"
AUTOSELECT_OBSERVATORY_INTERVAL = "5m"
AUTOSELECT_OBSERVATORY_TIMEOUT = "8s"
AUTOSELECT_URLTEST_INTERVAL = "5m"
AUTOSELECT_URLTEST_TOLERANCE_MS = 150
AUTOSELECT_LISTEN_PORT = 2080

AUTOSELECT_XRAY_PATH = DATA_DIR / "autoselect_xray.json"
AUTOSELECT_SINGBOX_PATH = DATA_DIR / "autoselect_singbox.json"


def build_xray_autoselect_config(nodes: list[Any]) -> dict[str, Any] | None:
    """Полный xray-конфиг автовыбора (leastLoad-балансер).

    nodes — список XrayProbeResult (рабочие узлы финального экспорта).
    Возвращает None, если узлов нет.
    """
    from xray_runtime import _xray_outbound

    outbounds: list[dict[str, Any]] = []
    for index, item in enumerate(nodes, 1):
        node = getattr(item, "node", item)
        try:
            outbound = _xray_outbound(node)
        except ValueError:
            continue
        outbound["tag"] = f"proxy-{index}"
        outbounds.append(outbound)
    if not outbounds:
        return None
    outbounds.append({"protocol": "freedom", "tag": "direct", "settings": {}})
    outbounds.append(
        {
            "protocol": "blackhole",
            "tag": "block",
            "settings": {"response": {"type": "none"}},
        }
    )
    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": ["https://1.1.1.1/dns-query", "8.8.8.8"],
            "queryStrategy": "UseIPv4",
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": AUTOSELECT_LISTEN_PORT,
                "protocol": "socks",
                "tag": "socks-in",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": False,
                },
            }
        ],
        "outbounds": outbounds,
        "burstObservatory": {
            "subjectSelector": ["proxy-"],
            "pingConfig": {
                "destination": AUTOSELECT_PROBE_URL,
                "connectivity": "https://www.gstatic.com/generate_204",
                "interval": AUTOSELECT_OBSERVATORY_INTERVAL,
                "timeout": AUTOSELECT_OBSERVATORY_TIMEOUT,
                "sampling": 2,
            },
        },
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [
                {
                    "tag": "auto",
                    "selector": ["proxy-"],
                    "strategy": {"type": "leastLoad"},
                    "fallbackTag": "direct",
                }
            ],
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "network": "udp", "port": 443, "outboundTag": "block"},
                {"type": "field", "network": "tcp,udp", "balancerTag": "auto"},
            ],
        },
    }


def build_sing_box_autoselect_config(nodes: list[Any]) -> dict[str, Any] | None:
    """Полный sing-box-конфиг автовыбора (urltest-группа).

    Возвращает None, если ни один узел не конвертировался.
    """
    from singbox_convert import sing_box_urltest_config

    plain_nodes = [getattr(item, "node", item) for item in nodes]
    config, _converted, _skipped = sing_box_urltest_config(
        plain_nodes,
        AUTOSELECT_LISTEN_PORT,
        probe_url=AUTOSELECT_PROBE_URL,
        interval=AUTOSELECT_URLTEST_INTERVAL,
        tolerance_ms=AUTOSELECT_URLTEST_TOLERANCE_MS,
    )
    return config


def write_autoselect_configs(working: list[Any], log_sink: LogSink | None = None) -> dict[str, str]:
    """Записать оба конфига автовыбора в data/ и залогировать.

    Возвращает словарь {артефакт: путь} (только записанное).
    """
    log = log_sink or (lambda _msg: None)
    written: dict[str, str] = {}

    xray_config = build_xray_autoselect_config(working)
    if xray_config is not None:
        count = sum(1 for o in xray_config["outbounds"] if str(o.get("tag", "")).startswith("proxy-"))
        try:
            AUTOSELECT_XRAY_PATH.parent.mkdir(parents=True, exist_ok=True)
            AUTOSELECT_XRAY_PATH.write_text(
                json.dumps(xray_config, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            written["xray"] = str(AUTOSELECT_XRAY_PATH)
            log(
                f"[autoselect] Xray-конфиг: {count} узлов, leastLoad, "
                f"проба {AUTOSELECT_PROBE_URL} -> {AUTOSELECT_XRAY_PATH}"
            )
        except Exception as exc:
            log(f"[autoselect] не удалось записать Xray-конфиг: {exc}")

    singbox_config = build_sing_box_autoselect_config(working)
    if singbox_config is not None:
        count = sum(
            1
            for o in singbox_config["outbounds"]
            if str(o.get("tag", "")).startswith("proxy-")
        )
        try:
            AUTOSELECT_SINGBOX_PATH.parent.mkdir(parents=True, exist_ok=True)
            AUTOSELECT_SINGBOX_PATH.write_text(
                json.dumps(singbox_config, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            written["singbox"] = str(AUTOSELECT_SINGBOX_PATH)
            log(
                f"[autoselect] sing-box-конфиг: {count} узлов, urltest, "
                f"проба {AUTOSELECT_PROBE_URL} -> {AUTOSELECT_SINGBOX_PATH}"
            )
        except Exception as exc:
            log(f"[autoselect] не удалось записать sing-box-конфиг: {exc}")

    return written
