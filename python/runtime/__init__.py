"""Пакет runtime — движок проверки узлов (бывший god-файл xray_runtime.py).

Модули по слоям (снизу вверх):
  types            — константы и dataclass-ы (XrayNode, XrayProbeResult, ...);
  uritools         — канонизация URI (дедупликационный текст, base64, схемы);
  parse            — парсинг ссылок узлов и тел подписок;
  fetch            — загрузка тел подписок (HTTP, зеркала, SSL, gzip);
  netsocks         — SOCKS5-клиент и HTTP(S) поверх SOCKS;
  probes_ping      — дешёвые TCP/UDP-пинги (предфильтр без ядра);
  probes_telegram  — MTProto-латентность + медиа-фильтр t.me/s/;
  probes_speed     — замеры скорости (NDT7, Cloudflare, OVH, Tele2);
  configs          — сборка конфигов xray/sing-box;
  procs            — управление процессами ядер (Job Objects, терминация);
  core             — XrayCoreRuntime + collect_subscription_nodes.

Совместимость: модуль верхнего уровня ``xray_runtime`` реэкспортирует все
прежде публичные (и используемые вне пакета приватные) имена.
"""
from __future__ import annotations

from .types import (
    CHATGPT_PROBE_TARGETS,
    GSTATIC_GENERATE_204,
    INSTAGRAM_PROBE_TARGETS,
    IP_SB_IP,
    M_LAB_LOCATE_URL,
    M_LAB_NDT7_SAMPLE_SEC,
    M_LAB_NDT7_TIMEOUT_SEC,
    NODE_LINK_RE,
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
    XRAY_ACTIVE_SPEED_TEST_BYTES,
    XRAY_ACTIVE_SPEED_TEST_SECONDS,
    XRAY_DEAD_SOURCE_COOLDOWN_SEC,
    XRAY_DEAD_SOURCE_FAILURES,
    XRAY_GOOD_DOWNLOAD_KBPS,
    XRAY_MIN_MEDIA_KBPS,
    XRAY_PROTOCOLS,
    XRAY_PROBE_SPEED_TEST_BYTES,
    XRAY_PROBE_SPEED_TEST_SECONDS,
    XRAY_SPEED_TEST_HOST,
    XRAY_SPEED_TEST_PATH,
    XRAY_SPEED_UPLOAD_PATH,
    BLOCKED_MEDIA_TARGETS,
    XrayNode,
    XrayProbeResult,
    XrayRuntimeConfig,
    _LOYAAL_FINGERPRINTS,
    _SAFE_DEFAULT_FINGERPRINT,
    _safe_fingerprint,
    _truthy,
)
from .uritools import (
    NODE_SCHEMES,
    _BASE64_QUERY_PARAMS,
    _decode_base64,
    _decode_base64_plain,
    _node_dedup_text,
    _normalize_base64_padding,
    _normalize_ss_userinfo,
    _sanitize_node_uri,
)
from .parse import (
    _candidate_score,
    _clash_query,
    _decode_base64_multi,
    _looks_like_readable_text,
    _node_link_from_clash_proxy,
    _node_link_from_json_object,
    _node_lines_from_candidate,
    _node_links_from_clash_yaml,
    _node_links_from_json,
    _node_links_from_text,
    _parse_shadowsocks,
    _parse_uri_node,
    _parse_vmess,
    _query_from_json_transport,
    _shadowsocks_link_from_json,
    _split_host_port,
    _standard_link_from_json,
    _subscription_lines,
    parse_node_link,
)
from .fetch import (
    _decode_subscription_body,
    _fetch_text,
    _subscription_candidate_urls,
    _subscription_headers,
    _subscription_ssl_contexts,
    _subscription_timeouts,
)
from .netsocks import (
    _recv_exact,
    _socks_https_download_kbps,
    _socks_https_get_body,
    _socks_https_head_status,
    _socks_https_latency,
    _socks_https_upload_kbps,
    _socks_open_connection,
)
from .probes_ping import (
    UDP_PROTOCOLS,
    _tcp_ping_node,
    _tcp_udp_ping_node,
    _udp_ping_node,
)
from .probes_telegram import (
    _encode_abridged_packet,
    _read_abridged_packet,
    _socks_mtproto_latency,
    _tg_media_probe,
    _tg_media_ranged_download,
    _tg_media_video_urls,
)
from .probes_speed import (
    XRAY_SPEED_TEST_BIG_BYTES,
    XRAY_SPEED_TEST_BIG_SECONDS,
    _download_speed_probe,
    _mlab_fetch_target,
    _mlab_ndt7_download_kbps,
    _ws_build_frame,
    _ws_read_frame,
    _ws_url_to_target,
    _xray_download_speed,
    _xray_upload_speed,
)
from .configs import (
    _normalize_reality_pbk,
    _sing_box_outbound,
    _resolve_stream_fingerprint,
    _sing_box_config,
    _write_temp_config,
    _xray_config,
    _xray_outbound,
    _xray_stream_settings,
)
from .procs import (
    _assign_process_to_job,
    _cleanup_stale_bundle_cores,
    _close_windows_handle,
    _create_kill_on_close_job,
    _find_free_port,
    _pid_exists,
    _resolve_binary,
    _subprocess_no_window,
    _terminate_pid_tree,
    _terminate_process_tree,
    _windows_terminate_pid_tree,
    _windows_terminate_process,
)
from .core import (
    XRAY_SUBSCRIPTION_FETCH_WORKERS,
    XrayCoreRuntime,
    _collect_from_source,
    _normalize_selection_strategy,
    _reason_counts,
    _reason_summary,
    _result_from_row,
    _wait_if_paused,
    _xray_result_sort_key,
    collect_subscription_nodes,
)
