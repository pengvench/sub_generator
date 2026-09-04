"""Фасад совместимости: прежняя точка входа рантайма (xray_runtime).

Исторически весь движок проверки узлов жил в одном файле xray_runtime.py
(~4800 строк — «спагетти в 1 файле»). Теперь это пакет ``runtime/``:

  runtime/types.py            — константы и dataclass-ы;
  runtime/uritools.py         — канонизация URI узлов;
  runtime/parse.py            — парсинг ссылок/подписок;
  runtime/fetch.py            — загрузка тел подписок;
  runtime/netsocks.py         — SOCKS5 + HTTP(S) поверх SOCKS;
  runtime/probes_ping.py      — TCP/UDP-пинги (предфильтр);
  runtime/probes_telegram.py  — MTProto + медиа-фильтр t.me/s/;
  runtime/probes_speed.py     — NDT7/Cloudflare/OVH/Tele2 спид-тесты;
  runtime/configs.py          — сборка конфигов xray/sing-box;
  runtime/procs.py            — Job Objects, терминация процессов;
  runtime/core.py             — XrayCoreRuntime + collect_subscription_nodes.

Этот модуль — тонкий фасад: реэкспортирует прежние имена, чтобы существующие
импорты (``from xray_runtime import ...`` в checkers/, subgen/, ui/, тестах)
продолжали работать без правок. Новый код должен импортировать из ``runtime``
напрямую.
"""
from __future__ import annotations

from runtime import (  # noqa: F401
    # --- public API ---
    XrayCoreRuntime,
    XrayNode,
    XrayProbeResult,
    XrayRuntimeConfig,
    collect_subscription_nodes,
    parse_node_link,
    # --- приватные имена, используемые вне пакета ---
    _decode_base64,
    _download_speed_probe,
    _find_free_port,
    _encode_abridged_packet,
    _node_dedup_text,
    _normalize_reality_pbk,
    _read_abridged_packet,
    _reason_counts,
    _reason_summary,
    _result_from_row,
    _safe_fingerprint,
    _sanitize_node_uri,
    _sing_box_config,
    _socks_https_download_kbps,
    _socks_https_get_body,
    _socks_https_head_status,
    _socks_https_latency,
    _socks_https_upload_kbps,
    _sing_box_outbound,
    _socks_mtproto_latency,
    _subprocess_no_window,
    _subscription_lines,
    _tcp_ping_node,
    _tcp_udp_ping_node,
    _terminate_process_tree,
    _tg_media_probe,
    _tg_media_video_urls,
    _truthy,
    _udp_ping_node,
    _wait_if_paused,
    _write_temp_config,
    _xray_config,
    _xray_download_speed,
    _xray_outbound,
    _xray_result_sort_key,
    _xray_upload_speed,
    # --- константы, используемые снаружи ---
    BLOCKED_MEDIA_TARGETS,
    CHATGPT_PROBE_TARGETS,
    GSTATIC_GENERATE_204,
    INSTAGRAM_PROBE_TARGETS,
    IP_SB_IP,
    M_LAB_LOCATE_URL,
    M_LAB_NDT7_SAMPLE_SEC,
    M_LAB_NDT7_TIMEOUT_SEC,
    NODE_LINK_RE,
    NODE_SCHEMES,
    PING_HTTPS_TARGETS,
    SING_BOX_PROTOCOLS,
    SUBSCRIPTION_USER_AGENT,
    TELEGRAM_API_HEAD_TARGET,
    TELEGRAM_DCS,
    TELEGRAM_MEDIA_DC,
    TELEGRAM_PROBE_TARGETS,
    TELEGRAM_XRAY_PROBE_TOTAL,
    TG_MEDIA_MIN_BODY_BYTES,
    TG_MEDIA_MIN_KBPS,
    TG_MEDIA_PAGE_HOST,
    TG_MEDIA_PAGE_PATH,
    TG_MEDIA_RANGE_SPAN,
    TG_MEDIA_VIDEO_SRC_RE,
    TG_MEDIA_VIDEO_TAG_RE,
    TG_MEDIA_WINDOW_BYTES,
    UDP_PROTOCOLS,
    XRAY_ACTIVE_SPEED_TEST_BYTES,
    XRAY_ACTIVE_SPEED_TEST_SECONDS,
    XRAY_DEAD_SOURCE_COOLDOWN_SEC,
    XRAY_DEAD_SOURCE_FAILURES,
    XRAY_GOOD_DOWNLOAD_KBPS,
    XRAY_MIN_MEDIA_KBPS,
    XRAY_PROTOCOLS,
    XRAY_PROBE_SPEED_TEST_BYTES,
    XRAY_PROBE_SPEED_TEST_SECONDS,
    XRAY_SPEED_TEST_BIG_BYTES,
    XRAY_SPEED_TEST_BIG_SECONDS,
    XRAY_SPEED_TEST_HOST,
    XRAY_SPEED_TEST_PATH,
    XRAY_SPEED_UPLOAD_PATH,
    XRAY_SUBSCRIPTION_FETCH_WORKERS,
)
