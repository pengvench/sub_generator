"""Автовыборка — готовый конфиг-балансер из проверенных рабочих узлов.

Идея (по мотивам конфигов с leastLoad-балансером): вместо статичной
подписки, где клиент сам выбирает узел, собираем ГОТОВЫЙ конфиг, в котором
ядро само переключается на лучший узел:

  - Xray-конфиг: burstObservatory фоново меряет все узлы, routing через
    balancer со стратегией leastLoad — на каждое соединение выбирается
    наименее нагруженный/быстрый узел;
  - sing-box-конфиг: urltest-группа для hysteria/hy2 (xray их не умеет).

Ключевое отличие от «пинга gstatic» (как в чужих конфигах): проба
функциональная — observatory/urltest стучится в https://t.me/peppe_poppo
и https://www.gstatic.com/generate_204, т.е. узел выбирается по реальной
досягаемости целей, ради которых вообще ставят VPN, а не по абстрактному
RTT. DNS узла резолвится самим прокси (в т.ч. заблокированный t.me).

Вход: строки отчёта (rows из subgen.pipeline — финальные проверенные
узлы). Выход: файлы data/autoselect_xray.json (+ data/autoselect_singbox.json,
если среди рабочих узлов есть hy2/hysteria).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from runtime.parse import parse_node_link
from runtime.configs import _xray_outbound, _sing_box_outbound
from runtime.types import SING_BOX_PROTOCOLS
from subgen.config import DATA_DIR
from subgen.logging import log

# Локальные порты автовыборки (SOCKS/HTTP-вход).
AUTOSELECT_XRAY_SOCKS_PORT = 2080
AUTOSELECT_SINGBOX_MIXED_PORT = 2081

# Функциональная проба узлов: t.me — главный критерий пользователя
# (Telegram должен открываться), gstatic — контрольный белый хост.
AUTOSELECT_PROBE_URL = "https://t.me/peppe_poppo"
AUTOSELECT_CONNECTIVITY_URL = "https://www.gstatic.com/generate_204"
AUTOSELECT_PROBE_INTERVAL = "5m"
AUTOSELECT_PROBE_TIMEOUT = "8s"
AUTOSELECT_SAMPLING = 2

# Максимум узлов в конфиге (первыми идут лучшие — rows уже отсортированы).
AUTOSELECT_MAX_NODES = 100


def build_xray_autoselect(nodes: list, *, max_nodes: int = AUTOSELECT_MAX_NODES) -> dict[str, Any]:
    """Собрать Xray-конфиг с leastLoad-балансером по проверенным узлам."""
    outbounds: list[dict[str, Any]] = []
    proxy_tags: list[str] = []
    for index, node in enumerate(nodes[:max_nodes], start=1):
        tag = f"proxy-{index}"
        # Тег узла пишем в streamSettings? Нет — тег outbound. Имя узла
        # сохраняем в комментарии... JSON комментариев не имеет; имя узла
        # остаётся в исходной подписке (subs.txt), конфиг — рабочий артефакт.
        outbound = _xray_outbound(node, tag=tag)
        outbounds.append(outbound)
        proxy_tags.append(tag)

    outbounds.append({"protocol": "freedom", "tag": "direct", "settings": {}})
    outbounds.append({"protocol": "blackhole", "tag": "block", "settings": {"response": {"type": "none"}}})

    return {
        "log": {"loglevel": "warning"},
        "dns": {
            # DNS через балансер: узел сам резолвит домены (в т.ч. t.me)
            # на своей стороне. Локальный/провайдерский DNS не участвует.
            "servers": ["https://1.1.1.1/dns-query", "8.8.8.8"],
            "queryStrategy": "UseIPv4",
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": AUTOSELECT_XRAY_SOCKS_PORT,
                "protocol": "socks",
                "tag": "socks-in",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
            }
        ],
        "outbounds": outbounds,
        # Фоновое наблюдение: меряем все proxy-* узлы, проба — t.me
        # (функциональная, не просто RTT до гстатика).
        "burstObservatory": {
            "subjectSelector": ["proxy-"],
            "pingConfig": {
                "destination": AUTOSELECT_PROBE_URL,
                "connectivity": AUTOSELECT_CONNECTIVITY_URL,
                "interval": AUTOSELECT_PROBE_INTERVAL,
                "timeout": AUTOSELECT_PROBE_TIMEOUT,
                "sampling": AUTOSELECT_SAMPLING,
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
                # Локальные/приватные сети — напрямую.
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                # QUIC (UDP 443) — блок: YouTube/Google через QUIC ломает
                # балансировку и палит трафик (модель AutoPizduk-конфигов).
                {"type": "field", "network": "udp", "port": 443, "outboundTag": "block"},
                # Весь остальной трафик — через балансер автовыборки.
                {"type": "field", "network": "tcp,udp", "balancerTag": "auto"},
            ],
        },
    }


def build_singbox_autoselect(nodes: list, *, max_nodes: int = AUTOSELECT_MAX_NODES) -> dict[str, Any] | None:
    """Собрать sing-box-конфиг с urltest-группой (hysteria/hy2 узлы).

    Возвращает None, если узлов для sing-box нет.
    """
    sing_nodes = [n for n in nodes if n.protocol in SING_BOX_PROTOCOLS]
    if not sing_nodes:
        return None

    outbounds: list[dict[str, Any]] = []
    proxy_tags: list[str] = []
    for index, node in enumerate(sing_nodes[:max_nodes], start=1):
        tag = f"proxy-{index}"
        outbounds.append(_sing_box_outbound(node, tag=tag))
        proxy_tags.append(tag)

    outbounds.append({"type": "urltest", "tag": "auto", "outbounds": proxy_tags, "url": AUTOSELECT_PROBE_URL, "interval": AUTOSELECT_PROBE_INTERVAL})
    outbounds.append({"type": "direct", "tag": "direct"})

    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": AUTOSELECT_SINGBOX_MIXED_PORT,
            }
        ],
        "outbounds": outbounds,
        "route": {
            "final": "auto",
            "auto_detect_interface": True,
            "rules": [
                # Приватные сети — напрямую.
                {"ip_is_private": True, "outbound": "direct"},
            ],
        },
    }


def write_autoselect_files(
    rows: list[dict[str, Any]],
    *,
    log_sink: Callable[[str], None] | None = None,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    """Собрать и записать конфиги автовыборки из строк отчёта.

    rows — финальные строки subgen.pipeline (поля url/latency_ms/...),
    порядок уже «лучшие первыми» (конвейер сортирует при экспорте).

    Возвращает summary для отчёта: количество узлов, пути файлов.
    """
    sink = log_sink or log
    target_dir = out_dir or DATA_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    xray_nodes = []
    singbox_nodes = []
    skipped = 0
    for row in rows:
        node = parse_node_link(str(row.get("url") or ""))
        if node is None:
            skipped += 1
            continue
        if node.protocol in SING_BOX_PROTOCOLS:
            singbox_nodes.append(node)
        elif node.protocol in ("vless", "vmess", "trojan", "shadowsocks"):
            xray_nodes.append(node)
        else:
            skipped += 1

    summary: dict[str, Any] = {
        "enabled": True,
        "source_nodes": len(rows),
        "xray_nodes": len(xray_nodes),
        "singbox_nodes": len(singbox_nodes),
        "skipped": skipped,
        "probe_url": AUTOSELECT_PROBE_URL,
        "interval": AUTOSELECT_PROBE_INTERVAL,
        "strategy": "leastLoad (xray) / urltest (sing-box)",
        "files": {},
    }

    if xray_nodes:
        path = target_dir / "autoselect_xray.json"
        config = build_xray_autoselect(xray_nodes)
        path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
        summary["files"]["xray"] = str(path)
        sink(
            f"[autoselect] Xray-конфиг: {len(xray_nodes)} узлов, leastLoad, проба {AUTOSELECT_PROBE_URL} -> {path}"
        )
        sink(
            f"[autoselect]   SOCKS-прокси: 127.0.0.1:{AUTOSELECT_XRAY_SOCKS_PORT} (xray run -c {path.name})"
        )

    if singbox_nodes:
        path = target_dir / "autoselect_singbox.json"
        config = build_singbox_autoselect(singbox_nodes)
        if config is not None:
            path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            summary["files"]["singbox"] = str(path)
            sink(
                f"[autoselect] sing-box-конфиг: {len(singbox_nodes)} hy2/hysteria узлов, urltest -> {path}"
            )
            sink(
                f"[autoselect]   mixed-прокси: 127.0.0.1:{AUTOSELECT_SINGBOX_MIXED_PORT} (sing-box run -c {path.name})"
            )

    if not xray_nodes and not singbox_nodes:
        sink("[autoselect] WARNING: нет узлов для конфига автовыборки (rows пусты или не распарсились)")
        summary["enabled"] = False

    return summary
