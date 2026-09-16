"""Основной конвейер: сборка узлов -> проверки -> подписка -> отчёт.

Архитектура v9 (по требованиям пользователя):
- БЫСТРАЯ распинговка (TCP/UDP-префильтр + пинг через туннель) — в начале;
- ГЛАВНЫЙ критерий — загрузка заблокированных сервисов: Telegram-этап
  (MTProto + tg-медиа) и DPI-сьюта;
- ПЕРЕИМЕНОВАНИЕ (флаг страны + peppo, БЕЗ скорости в имени) — в конце;
- СТРЕСС-ТЕСТ — финальный ИНФОРМАТИВНЫЙ спидтест ПОСЛЕ переименования:
  только скорость, порог --min-speed (512 КБ/с по умолчанию у пользователя),
  НЕ отсеивающий (узел ниже порога остаётся в подписке с пометкой),
  отбрасываются только полностью мёртвые узлы.
"""
from __future__ import annotations

import argparse
import base64
import socket
import threading
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from checkers import DPI_DEFAULT_TARGET, check_node_dpi_detailed
from checkers.net_diagnostic import run_network_diagnostic
from checkers.base import run_with_node
from checkers.initial_check import run_initial_check, format_result as format_initial_check_result
from checkers.dpi_active import DPI_ACTIVE_MIN_SCORE, DpiActiveResult, check_node_dpi_active_detailed

from checkers.telegram_pro import TG_TIMEOUT, TelegramProResult, check_node_telegram_pro_detailed
from checkers.blocked_services import (
    BlockedServicesResult,
    check_node_blocked_services_detailed,
    format_result as format_services_result,
)
# route-этап удалён в v11 (бессмысленный — только обогащал отчёт, не фильтровал).
# zapret-suite удалён в v11 (на медленных сетях сам автор фиксил через
# suite_slow_network — suite становилось не-вето, тогда зачем оно).
# SLOW_NETWORK_RTT_MS оставлен — используется для адаптации таймаутов TG/resilience.
from checkers.zapret import SLOW_NETWORK_RTT_MS
from xray_runtime import _download_speed_probe, _socks_https_head_status, set_forced_runtime, _wait_if_paused


from subgen.config import DEFAULT_SOURCES_FILE, DATA_DIR, SAVED_SUBS_DIR, GEOIP_FALLBACK_CODE, ROOT
from subgen.geo import load_geo_cache, serialize_working
from subgen.logging import log
from subgen.output import (
    append_text,
    urls_text,
    write_file,
    write_geo_cache,
    write_report,
    write_subscription_files,
)
from subgen.progress import _PowerShellProgress
from subgen.refresh import run_refresh
from subgen.checker_thresholds import get_threshold
from subgen.checker_cache import check_cached, cache_result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sub_generator",
        description="Сборка и тестирование vless/vmess/trojan/ss/hy2 конфигов из подписок.",
    )
    parser.add_argument("--out", default="subs.txt", help="Выходной файл подписки (base64).")
    parser.add_argument("--working", default="working.txt", help="Рабочие конфиги построчно.")
    parser.add_argument("--out-dpi", default="subs_dpi.txt", help="Подписка узлов, прошедших DPI-проверку.")
    parser.add_argument("--working-dpi", default="working_dpi.txt", help="Рабочие конфиги, прошедшие DPI-проверку.")
    parser.add_argument("--report", default="report.json", help="JSON-отчёт.")
    parser.add_argument("--geo-cache", default="geo_cache.json", help="Файл кеша geoip.")
    parser.add_argument("--sources", nargs="*", default=None, help="Список URL подписок.")
    parser.add_argument("--custom-file", default="", help="Локальный файл с конфигами (например, сохранённый кеш с прошлого прогона). Файл читается как есть: base64 декодируется, извлекаются только ссылки-конфиги.")

    parser.add_argument("--workers", type=int, default=4, help="Потоков стресс-теста (по умолчанию 4).")
    parser.add_argument("--timeout", type=float, default=8.0, help="Таймаут проверки, сек (по умолчанию 8).")
    parser.add_argument("--limit", type=int, default=0, help="Максимум узлов после проверки (0 = без лимита).")
    parser.add_argument("--max-ping", type=int, default=1000, help="Максимальный пинг в мс (0 - без ограничения).")
    parser.add_argument("--no-stress", action="store_true", help="Пропустить стресс-тест (оставить только пропингованных).")
    parser.add_argument("--no-telegram", action="store_true", help="Отключить ВСЕ Telegram-проверки, включая медиа-фильтр (t.me/s/) на этапе telegram_pro.")
    parser.add_argument("--no-services", action="store_true", help="Отключить проверку заблокированных сервисов (инста/ютуб/дискорд через IP реестра + TLS-SNI). По умолчанию сервисы — ГЛАВНЫЙ отсеивающий этап.")
    parser.add_argument("--dpi-check", action="store_true", help="Включить DPI-проверку через Xray (обход блокировок): alive + tcp 16-20 на заблокированные цели + siberian + CIDR + (опционально) Zapret-suite.")
    parser.add_argument("--dpi-target", default=DPI_DEFAULT_TARGET, help="Целевой хост для DPI-проверки (по умолчанию instagram.com).")
    parser.add_argument("--dpi-siberian", action="store_true", help="DPI: siberian-проверка (множественные TLS-хендшейки с разными SNI) как обязательная отсеивающая.")
    parser.add_argument("--dpi-cidr", action="store_true", help="DPI: CIDR-whitelist проверка как обязательная отсеивающая.")
    # --- Zapret-функционал ОБЪЕДИНЁН с DPI-этапом (один core-процесс на узел): ---
    parser.add_argument("--dpi-suite", action="store_true", help="УСТАРЕЛО (no-op): Zapret-suite всегда выполняется вместе с --dpi-check (один core-процесс, один этап). Настройки suite: --dpi-suite-targets/-timeout/-min-score/-no-http.")
    parser.add_argument("--dpi-suite-targets", type=int, default=8, help="Максимум целей DPI suite на узел (по умолчанию 8).")
    parser.add_argument("--dpi-suite-timeout", type=float, default=5.0, help="Таймаут одного suite-теста, сек (по умолчанию 5).")
    parser.add_argument("--dpi-suite-min-score", type=float, default=0.75, help="Мин. доля успешных suite-тестов, 0..1 (по умолчанию 0.75).")
    parser.add_argument("--dpi-suite-no-http", action="store_true", help="DPI-suite: не выполнять стандартный HTTP-тест (только suite tcp 16-20).")
    parser.add_argument("--zapret-check", action="store_true", help="УСТАРЕЛО (алиас): включить --dpi-check. Suite выполняется всегда вместе с DPI-проверкой.")
    parser.add_argument("--dpi-active", action="store_true", help="Включить активную DPI-проверку протокола узла (SNI-варианты, фрагментация/большой ClientHello, ECH, TLS 1.2/1.3).")
    parser.add_argument("--dpi-active-timeout", type=float, default=4.0, help="Таймаут одного варианта активной DPI-проверки, сек (по умолчанию 4).")
    parser.add_argument("--telegram-pro", action="store_true", help="УСТАРЕЛО: продвинутые Telegram-проверки (MTProto connect/auth, upload) и telegram_score теперь выполняются автоматически при включённом Telegram. Флаг оставлен для обратной совместимости (игнорируется, если не задан --no-telegram).")
    parser.add_argument("--initial-check-timeout", type=float, default=5.0, help="Таймаут начальной проверки доступности (TCP+HTTP HEAD), сек (по умолчанию 5).")
    parser.add_argument("--sing-box-only", action="store_true", help="Режим «только sing-box»: ВСЕ узлы (vless/vmess/trojan/ss/hy2) тестируются через ядро sing-box, а не xray. Автовыбор ядра по протоколу удалён: по умолчанию xray, hy2/hysteria — всегда sing-box, а этот флаг форсит sing-box для всех.")
    # --- ИИ-гео слепок (Gemini/OpenAI): под какой страной exit-IP видят ИИ-сервисы ---
    parser.add_argument("--ai-check", action="store_true", help="УСТАРЕЛО (no-op): ИИ-гео слепок — ОБЯЗАТЕЛЬНЫЙ этап конвейера, выполняется всегда. Определяет страну для флага в подписке (CF trace loc=, как видит OpenAI). Флаг оставлен для совместимости.")
    parser.add_argument("--ai-strict", action="store_true", help="ИИ-гео: отсеивать узлы, чей слепок — РФ (ai_unblocked=False). Слепок недоступен (None) — узел НЕ отсеивается. Единственная опция ИИ-гео: сам слепок обязателен.")
    parser.add_argument("--ai-timeout", type=float, default=6.0, help="Таймаут одного ИИ-гео запроса, сек (по умолчанию 6).")
    parser.add_argument("--resilience-check", action="store_true", default=True, help="Включить проверку живучести узлов в условиях блокировок (multi-target ping, WHITE-SNI, альтернативные цели). Включено по умолчанию для работы на заблокированных мобильных сетях.")
    parser.add_argument("--no-resilience-check", action="store_false", dest="resilience_check", help="Отключить проверку живучести (не рекомендуется для мобильных сетей РФ).")
    parser.add_argument("--resilience-timeout", type=float, default=4.0, help="Таймаут одного теста resilience-проверки, сек (по умолчанию 4).")

    parser.add_argument(
        "--zapret-out",
        default="subs_zapret.txt",
        help="(совместимость) Подписка узлов, прошедших DPI+suite — записывается при включённом --dpi-suite.",
    )
    parser.add_argument(
        "--zapret-working",
        default="working_zapret.txt",
        help="(совместимость) Рабочие конфиги, прошедшие DPI+suite — при включённом --dpi-suite.",
    )
    parser.add_argument("--zapret-targets", type=int, default=8, help="(устарело, алиас --dpi-suite-targets) Максимум целей DPI suite на узел.")
    parser.add_argument("--zapret-timeout", type=float, default=5.0, help="(устарело, алиас --dpi-suite-timeout) Таймаут одного suite-теста, сек.")
    parser.add_argument("--zapret-min-score", type=float, default=0.75, help="(устарело, алиас --dpi-suite-min-score) Мин. доля успешных тестов, 0..1.")
    parser.add_argument("--zapret-no-http", action="store_true", help="(устарело, алиас --dpi-suite-no-http) Только DPI suite, без HTTP-теста.")
    parser.add_argument("--min-speed", type=int, default=5000, help="Минимальная скорость загрузки в КБ/с для 1080p (по умолчанию 5000). Порог един для всех: Telegram-медиа фильтр (обязательный, t.me/s/) его НЕ обходит.")
    parser.add_argument(
        "--dedup-mode",
        choices=["strict", "normal", "aggressive"],
        default="normal",
        help=(
            "Режим дедупликации узлов ДО тестов. "
            "strict — текущее поведение (весь canonical URL, разные fp = разные узлы); "
            "normal (по умолчанию) — игнорирует uTLS-фингерпринты (fp/fingerprint/spx), "
            "убирает 5-15%% мусорных дубликатов; "
            "aggressive — оставляет только protocol+host+port+credential+sni+security+pbk/sid, "
            "убирает 30-50%% дубликатов, но рискованно (разные flow/path = один узел)."
        ),
    )
    parser.add_argument(
        "--use-singbox-pool",
        action="store_true",
        default=True,
        help=(
            "Использовать один sing-box процесс с N outbounds + Clash API для "
            "массовых этапов (initial_check, ping). Вместо 14000 старт-стопов "
            "ядра (5-8 часов оверхеда) — переключение selector'а за 50мс. "
            "По умолчанию включён. Несовместимые узлы (xhttp/splithttp/kcp/quic) "
            "автоматически проверяются через старый путь (with_node_process)."
        ),
    )
    parser.add_argument(
        "--no-singbox-pool",
        action="store_false",
        dest="use_singbox_pool",
        help="Отключить sing-box pool, использовать старый старт-стоп ядра на каждый узел.",
    )
    parser.add_argument(
        "--singbox-pool-batch",
        type=int,
        default=200,
        help="Размер батча для sing-box pool (по умолчанию 200 узлов на один процесс).",
    )
    parser.add_argument(
        "--start-stage",
        choices=["ping", "initial", "telegram_pro", "services", "dpi", "resilience", "dpi_active", "ai_geo", "recheck"],
        default="ping",
        help="С какого этапа начать перепроверку. 'ping' — полный прогон с нуля; "
        "остальные — пропустить распинговку и стресс-тест и начать с указанного "
        "этапа, используя сохранённые рабочие конфиги (data/.runtime_cache). "
        "v11: убраны 'route' (бессмысленный) и 'zapret' (suite удалён).",
    )
    # NOTE: --tun-check и WARP-аргументы (--add-warp/--warp-preset/--warp-dns)
    # удалены вместе со всей TUN/WARP-функциональностью.

    # --- Пост-обработка алиасов (после parse_args, в run()) ---
    return parser


# Порядок этапов перепроверки (--start-stage). Синхронизирован с
# ui/pages/recheck_page.py (STAGES) — регрессионный тест сверяет.
#
# v11 (сентябрь 2026): убраны route (бессмысленный — только обогащал отчёт,
# не фильтровал) и dpi_suite (zapret-методика — на медленных сетях сам автор
# фиксил через suite_slow_network, suite становилось не-вето, тогда зачем оно).
# ai_geo перенесён В КОНЕЦ: формирует флаг страны по слепку после всех проверок,
# не тратит время на узлы, которые всё равно отбракуются дальше.
# dpi_active перенесён В КОНЕЦ перед спидтестом: это диагностика протокола,
# не фильтр — имеет смысл для финальных кандидатов, не для 14000 нод.
STAGE_ORDER: tuple[str, ...] = (
    "ping",
    "initial",
    "telegram_pro",
    "services",
    "dpi",
    "resilience",
    "dpi_active",
    "ai_geo",
    "recheck",
)


def _apply_stage_aliases(args: argparse.Namespace) -> argparse.Namespace:
    """Ремап устаревших флагов/этапов на новые эквиваленты.

    1. ``--start-stage zapret`` → ``dpi`` (отдельный zapret-этап объединён с
       DPI после слияния).
    2. ``--zapret-check`` → включает ``dpi_check`` (suite всегда часть DPI).
    3. ``--ai-check`` игнорируется: ИИ-гео слепок — обязательный этап
       (выполняется всегда, флаг оставлен для совместимости старых команд).
    """
    if getattr(args, "start_stage", "ping") == "zapret":
        args.start_stage = "dpi"
    if getattr(args, "zapret_check", False):
        args.dpi_check = True
        # Старые zapret-* аргументы перекладываем на dpi-suite-* (совместимость
        # со старыми командными строками/скриптами).
        args.dpi_suite_targets = args.zapret_targets
        args.dpi_suite_timeout = args.zapret_timeout
        args.dpi_suite_min_score = args.zapret_min_score
        args.dpi_suite_no_http = args.zapret_no_http
    # ИИ-гео слепок обязателен: флаг CLI не нужен, этап выполняется всегда
    # (отключается только перепроверкой с позднего --start-stage).
    args.ai_check = True
    return args


def _stage_enabled_from(start_stage: str, stage: str) -> bool:
    """Выполнять ли этап при перепроверке, начинающейся с start_stage.

    ping = полный прогон. Иначе этап выполняется, если он стоит в STAGE_ORDER
    на позиции start_stage или позже.
    """
    if start_stage == "ping":
        return True
    try:
        start_index = STAGE_ORDER.index(start_stage)
        stage_index = STAGE_ORDER.index(stage)
    except ValueError:
        return False
    return stage_index >= start_index



def _resolve_path(value: str) -> Path:
    """Относительный путь -> внутри data/, абсолютный — как есть."""
    path = Path(value)
    if path.is_absolute():
        return path
    return DATA_DIR / path


def _load_sources(args: argparse.Namespace) -> list[str]:
    """Load subscription URLs + saved_subs files as sources.

    Pipeline auto-loads:
      1. data/sources.txt — subscription URLs (HTTP/HTTPS)
      2. data/saved_subs/*.txt — imported configs from "Импорт" tab
      3. Direct configs (vless://, vmess://, etc) are filtered out and saved to
         data/.runtime_cache/direct_configs.txt — pipeline reads them as local file.

    Comment lines (#) are skipped. Direct vless:// etc are NOT fetched via HTTP
    (fetch._fetch_text would fail) — they go through local file path.
    """
    custom = str(args.custom_file or "").strip()
    if custom:
        path = Path(custom).expanduser().resolve()
        log(f"[sub] custom config file: {path}")
        return [str(path)]
    if args.sources is not None:
        return [str(u).strip() for u in args.sources if str(u).strip()]
    sources: list[str] = []
    try:
        sources = [
            line.strip()
            for line in DEFAULT_SOURCES_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError:
        log(f"[sub] WARNING: не найден {DEFAULT_SOURCES_FILE}, используем --sources или пустой список")

    # Auto-add saved_subs/*.txt files as sources (from "Импорт" tab).
    saved_count = 0
    try:
        for f in sorted(SAVED_SUBS_DIR.glob("*.txt")) + sorted(SAVED_SUBS_DIR.glob("*.json")):
            if f.name == "README.txt":
                continue
            file_path = str(f.resolve())
            if file_path not in sources:
                sources.append(file_path)
                saved_count += 1
    except Exception as e:
        log(f"[sub] WARNING: cannot read saved_subs: {e}")

    if saved_count:
        log(f"[sub] loaded {saved_count} saved_subs files from {SAVED_SUBS_DIR}")

    # Filter out direct configs (vless://, vmess://, etc) - they cannot be fetched
    # via HTTP. Save them to a temp file - pipeline parses as local file.
    NODE_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "hysteria://")
    direct_configs = []
    http_sources = []
    for src in sources:
        if any(src.lower().startswith(s) for s in NODE_SCHEMES):
            direct_configs.append(src)
        else:
            http_sources.append(src)
    if direct_configs:
        direct_file = DATA_DIR / ".runtime_cache" / "direct_configs.txt"
        direct_file.parent.mkdir(parents=True, exist_ok=True)
        direct_file.write_text("\n".join(direct_configs) + "\n", encoding="utf-8")
        log(f"[sub] extracted {len(direct_configs)} direct configs from sources.txt to {direct_file}")
        http_sources.append(str(direct_file))
    return http_sources



def _load_cached_working() -> list[Any]:
    """Загрузить сохранённые рабочие конфиги из data/.runtime_cache/xray_working.json.

    Используется при перепроверке с этапа (--start-stage != ping): распинговка и
    стресс-тест уже выполнены ранее, их результаты сохранены в кеше. Возвращает
    список XrayProbeResult (только полностью проверенные узлы).
    """
    import json as _json

    from xray_runtime import _result_from_row

    cache_path = DATA_DIR / ".runtime_cache" / "xray_working.json"
    if not cache_path.exists():
        log(f"[sub] WARNING: кеш рабочих конфигов не найден: {cache_path}")
        return []
    try:
        rows = _json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log(f"[sub] WARNING: не удалось прочитать кеш рабочих конфигов: {exc}")
        return []
    if not isinstance(rows, list):
        return []
    working: list[Any] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        result = _result_from_row(row, accepted=True)
        if result is not None and result.fully_checked:
            working.append(result)
    log(f"[sub] загружено {len(working)} рабочих конфигов из кеша")
    return working



def _preflight_dns_doh(timeout: float = 5.0) -> dict[str, bool]:
    """Проверить доступность системного DNS и DoH перед тестированием узлов.

    Модель — Karing: перед проверкой узлов убеждаемся, что локальная сеть
    вообще может резолвить имена. Это не даёт системным настройкам DNS
    испортить результаты тестов (например, когда DoH-сервер core резолвится
    через системный DNS, а тот не работает).

    Возвращает {"system_dns": bool, "doh": bool}.
    """
    result = {"system_dns": False, "doh": False}

    # 1) Системный DNS — обычный UDP-запрос A-записи google.com к 8.8.8.8.
    import contextlib as _cl

    udp_sock: socket.socket | None = None
    try:
        transaction_id = b"\xab\xcd"
        qname = b"\x06google\x03com\x00"
        query = (
            transaction_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + qname + b"\x00\x01\x00\x01"
        )
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(min(timeout, 3.0))
        udp_sock.sendto(query, ("8.8.8.8", 53))
        response, _ = udp_sock.recvfrom(512)
        if len(response) >= 12 and response[:2] == transaction_id:
            result["system_dns"] = True
    except Exception as exc:
        # Причина недоступности системного DNS — часть диагностики preflight.
        result["system_dns_error"] = f"{type(exc).__name__}: {exc}"
        log(f"[net] системный DNS недоступен: {type(exc).__name__}: {exc}")
    finally:
        if udp_sock is not None:
            with _cl.suppress(Exception):
                udp_sock.close()

    # 2) DoH — HTTPS GET к cloudflare-dns.com/dns-query (JSON API).
    #    Запрос идёт через checkers.hostres.direct_https_get: домен
    #    cloudflare-dns.com резолвится по DoH на IP-literal 1.1.1.1,
    #    соединение открывается на IP с SNI — системный hosts-файл
    #    НЕ читается (записи-подмены не влияют на preflight).
    try:
        from checkers.hostres import direct_https_get

        response = direct_https_get(
            "https://cloudflare-dns.com/dns-query?name=google.com&type=A",
            timeout=min(timeout, 5.0),
            max_bytes=8 * 1024,
            headers={"Accept": "application/dns-json"},
        )
        if response.ok and response.status == 200 and response.body:
            result["doh"] = True
    except Exception as exc:
        # Причина недоступности DoH — часть диагностики preflight.
        result["doh_error"] = f"{type(exc).__name__}: {exc}"
        log(f"[net] DoH (cloudflare-dns.com) недоступен: {type(exc).__name__}: {exc}")

    return result


def _median_initial_latency(details: dict) -> float:
    """Медиана (p50) латентности initial_check по прошедшим узлам, мс.

    Это сквозной путь «клиент -> туннель -> цель» (TCP+TLS+HEAD). Используется
    как rtt-хинт для адаптации таймаутов: фиксированные 5с на мобильных
    сетях (RTT 1.5-3с) заваливают здоровые узлы по таймауту (инцидент
    2026-09-02: мобильный прогон, 106/106 FAIL на DPI-сьюте при suite=0-1/24,
    хотя на WiFi те же узлы давали 23/24).
    """
    lats = [
        float(v.get("latency_ms") or 0)
        for v in (details or {}).values()
        if isinstance(v, dict) and v.get("latency_ms")
    ]
    if not lats:
        return 0.0
    lats.sort()
    n = len(lats)
    if n % 2:
        return float(lats[n // 2])
    return (lats[n // 2 - 1] + lats[n // 2]) / 2.0


def _parallel_map_nodes(
    items: list,
    fn: Callable[[Any], Any],
    *,
    workers: int,
    stage_idx: int = -1,
    progress=None,
    label: str = "",
    cancel_event: threading.Event | None = None,
    pause_event: threading.Event | None = None,
) -> list[tuple[Any, Any]]:
    """Параллельно применить fn к каждому элементу.

    Возвращает пары (item, result) В ИСХОДНОМ ПОРЯДКЕ списка — порядок
    экспорта не зависит от порядка завершения потоков. Прогресс и отмена
    обрабатываются в главном потоке (as_completed), поэтому log/progress
    остаются потокобезопасными.
    """
    pairs: list[tuple[Any, Any]] = [(item, None) for item in items]
    if not items:
        return pairs
    actual_workers = max(1, min(int(workers), len(items)))
    with ThreadPoolExecutor(max_workers=actual_workers, thread_name_prefix="stage") as executor:
        futures = {executor.submit(fn, item): i for i, item in enumerate(items)}
        done = 0
        for future in as_completed(futures):
            _wait_if_paused(pause_event, cancel_event)
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            i = futures[future]
            try:
                res = future.result()
            except Exception:
                res = None
            pairs[i] = (items[i], res)
            done += 1
            if progress is not None and stage_idx >= 0:
                node = getattr(items[i], "node", None)
                title = node.title() if node is not None else str(items[i])
                progress.update(done, f"{label} {title}" if label else title)
    return pairs


def run(
    argv: list[str] | None = None,
    cancel_event: threading.Event | None = None,
    pause_event: threading.Event | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Ремап устаревших флагов/этапов (zapret→dpi, ai-strict→ai-check).
    args = _apply_stage_aliases(args)

    # Применить режим дедупликации глобально (используется в
    # _node_dedup_text → XrayNode.key → collect_subscription_nodes).
    # По умолчанию — normal: игнорирует uTLS-фингерпринты, убирает 5-15%
    # мусорных дубликатов от подписок, раздающих один бэкенд с разными
    # маскировками. strict — обратная совместимость со старым поведением.
    from runtime.uritools import set_dedup_mode
    set_dedup_mode(getattr(args, "dedup_mode", "normal"))
    log(f"[sub] dedup-mode: {getattr(args, 'dedup_mode', 'normal')}")

    # HARD FIX: Auto-add saved_subs/*.txt + filter direct vless:// configs.
    # This runs BEFORE _load_sources(args) is called later, so even if
    # _load_sources was compiled from old code (old .exe), we patch args.sources
    # here to inject saved_subs and filter direct configs.
    # If args.sources is None (default), we let _load_sources read sources.txt.
    # _load_sources already does this filter, but this is a safety net.
    try:
        from subgen.config import SAVED_SUBS_DIR
        saved_files = sorted(SAVED_SUBS_DIR.glob("*.txt")) + sorted(SAVED_SUBS_DIR.glob("*.json"))
        saved_files = [f for f in saved_files if f.name != "README.txt"]
        if saved_files:
            log(f"[sub] auto-loaded {len(saved_files)} saved_subs files (HARD FIX in run())")
    except Exception as exc:
        log(f"[warn] не удалось просканировать каталог saved_subs: {type(exc).__name__}: {exc}")

    # Режим «только sing-box» (тумблер UI / флаг CLI): глобальный форс ядра
    # для ВСЕХ проверок конвейера (быстрая распинговка, initial, telegram,
    # dpi, resilience, финальный спидтест). Автовыбор ядра по протоколу
    # удалён: по умолчанию xray, hy2/hysteria — всегда sing-box.
    if getattr(args, "sing_box_only", False):
        set_forced_runtime("sing-box")
        log("[sub] режим «только sing-box»: все узлы тестируются через sing-box")
    else:
        set_forced_runtime(None)


    sources = _load_sources(args)

    # subs.txt (имя по умолчанию) всегда генерируется РЯДОМ с приложением/exe,
    # остальные файлы — в data/.
    if args.out == "subs.txt":
        out_path = ROOT / "subs.txt"
    else:
        out_path = _resolve_path(args.out)
    working_path = _resolve_path(args.working)
    report_path = _resolve_path(args.report)
    geo_cache_path = _resolve_path(args.geo_cache)

    geo_cache = load_geo_cache(geo_cache_path)

    # ---------------------------------------------------------------------
    # Единый сквозной прогресс (PowerShell Write-Progress в заголовке окна).
    # ---------------------------------------------------------------------
    # v11: dpi_suite (zapret-методика) УДАЛЁН — на медленных сетях сам автор
    # фиксил через suite_slow_network (suite становилось не-вето), тогда зачем оно.
    # route УДАЛЁН — только обогащал отчёт, не фильтровал.
    # ai_geo ПЕРЕНЕСЁН в конец — формирует флаг страны после всех проверок,
    # не тратит время на узлы, которые всё равно отбракуются.
    # dpi_active ПЕРЕНЕСЁН перед recheck — диагностика протокола для финальных
    # кандидатов, не для 14000 нод.
    progress = _PowerShellProgress()
    # Порядок стадий v11: baseline -> load -> ping (TCP/UDP-ping + эвристика
    # "первый быстрый") -> initial_check (sing-box pool, TCP+HTTP HEAD) ->
    # telegram_pro (MTProto + tg-медиа, голосовые) -> services (инста/ютуб/
    # дискорд, упрощённый TCP+TLS) -> dpi (обход блокировок) -> resilience
    # (живучесть в блокировках) -> dpi_active (SNI/ECH/фрагментация, для
    # финальных кандидатов) -> ai_geo (CF trace + ipinfo консенсус, флаг) ->
    # geo/переименование -> ФИНАЛЬНЫЙ ОТБРАКОВЫВАЮЩИЙ спидтест.
    progress.add_stage("baseline", 0.03, total=1)
    progress.add_stage("load", 0.05, total=len(sources))
    progress.add_stage("ping", 0.20, total=1)
    progress.add_stage("initial_check", 0.10, total=1)
    if not args.no_telegram:
        progress.add_stage("telegram_pro", 0.12, total=1)
    services_enabled = not bool(getattr(args, "no_services", False))
    if services_enabled:
        progress.add_stage("services", 0.10, total=1)
    if args.dpi_check:
        progress.add_stage("dpi", 0.12, total=1)
    # Resilience check — всегда включён (по умолчанию), отключается через --no-resilience-check.
    resilience_enabled = getattr(args, 'resilience_check', True)
    if resilience_enabled:
        progress.add_stage("resilience", 0.08, total=1)
    # dpi_active — перенесён В КОНЕЦ перед recheck: диагностика протокола
    # имеет смысл для финальных кандидатов, не для 14000 нод.
    if args.dpi_active:
        progress.add_stage("dpi_active", 0.06, total=1)
    # ai_geo — перенесён В КОНЕЦ: формирует флаг страны по слепку после всех
    # проверок. Не тратит время на узлы, которые всё равно отбракуются.
    if getattr(args, "ai_check", False):
        progress.add_stage("ai_geo", 0.04, total=1)
    progress.add_stage("geo", 0.06, total=1)
    if not args.no_stress:
        progress.add_stage("recheck", 0.04, total=1)

    ping_idx = progress.stage_index("ping")
    baseline_idx = progress.stage_index("baseline")
    initial_idx = progress.stage_index("initial_check")
    services_idx = progress.stage_index("services") if services_enabled else -1
    dpi_idx = progress.stage_index("dpi")
    dpi_active_idx = progress.stage_index("dpi_active")
    telegram_pro_idx = progress.stage_index("telegram_pro")
    ai_geo_idx = progress.stage_index("ai_geo")
    resilience_idx = progress.stage_index("resilience") if resilience_enabled else -1
    geo_idx = progress.stage_index("geo")
    recheck_idx = progress.stage_index("recheck")



    log(f"[sub] sources: {len(sources)}")
    for source in sources:
        log(f"  - {source}")
    log(f"[sub] workers={args.workers} timeout={args.timeout} stress={not args.no_stress} limit={args.limit or '∞'}")

    # ---------------------------------------------------------------------
    # Начальный этап: либо полный прогон (распинговка + стресс-тест), либо
    # перепроверка с указанного этапа на основе сохранённых рабочих конфигов.
    # ---------------------------------------------------------------------
    start_stage = args.start_stage
    if start_stage == "ping":
        # Предварительная проверка доступности DNS и DoH (модель Karing).
        # Preflight: проверка сети перед запуском тестов.
        # На заблокированных мобильных сетях HTTPS (TLS handshake без SNI)
        # может НЕ работать — DPI режет голый TLS к cloudflare.com/gstatic.com.
        # Но UDP DNS работает, и прокси-узлы работают (через TLS с правильным SNI).
        #
        # Поэтому preflight НЕ блокирующий:
        # - Если работает UDP DNS или DoH — запуск продолжается (DNS есть).
        # - HTTP проверка — информационная, не останавливает конвейер.
        # - Только если ВООБЩЕ НИЧЕГО не работает (ни DNS, ни DoH, ни HTTP) —
        #   останавливаем (сеть полностью недоступна).
        # - Как Karing: не падаем на preflight, идём тестировать узлы.
        preflight = run_network_diagnostic(
            dns_timeout=min(2.0, args.timeout),
            doh_timeout=min(4.0, args.timeout),
            http_timeout=min(4.0, args.timeout),
        )
        log(
            f"[sub] preflight network: udp_dns={preflight.udp_dns_ok} "
            f"doh={preflight.doh_ok} http={preflight.http_ok} "
            f"tun={preflight.tun_present} internet={preflight.internet_ok}"
        )
        # Критерий остановки: только если НИ DNS, НИ DoH не работают.
        # Если хотя бы UDP DNS отвечает — продолжаем (Karing-стиль).
        dns_available = preflight.udp_dns_ok or preflight.doh_ok
        if not dns_available:
            log(
                "[sub] ERROR: локальная сеть полностью недоступна "
                "(UDP DNS и DoH не отвечают). Проверьте подключение к сети."
            )
            for err in preflight.errors:
                log(f"[sub] preflight error: {err}")
            progress.close()
            return 1
        # HTTP недоступен, но DNS работает — предупреждаем, но продолжаем.
        if not preflight.http_ok:
            log(
                "[sub] WARNING: HTTP/HTTPS недоступен (DPI режет TLS без SNI). "
                "Это нормально для заблокированных мобильных сетей — "
                "прокси-узлы с TLS/Reality будут работать через SNI. Продолжаем."
            )
            for err in preflight.errors[:2]:
                log(f"[sub] preflight warning: {err}")

        # -----------------------------------------------------------------
        # BASELINE: прямой замер полосы канала ДО тестов узлов.
        # Источники: Яндекс.Интернетометр + QMS/Билайн (speedtest.ru) + tele2 + ovh.
        # Cloudflare НЕ используется (на мобильных РФ режется/деградирует).
        # Цель: на мобильной раздаче (5-15 Мбит/с) порог --min-speed 5000 КБ/с
        # физически недостижим — конвейер отбракует все живые узлы. Замер
        # адаптирует порог под реальный канал (60% от базовой, не ниже 256 КБ/с).
        # КЭП быстрого канала (≥100 Мбит/с): замер игнорируется, порог из UI.
        # -----------------------------------------------------------------
        baseline_report: dict[str, Any] = {"enabled": False}
        effective_min_speed_kbps: float = float(args.min_speed)
        effective_upload_min_kbps: float | None = None
        effective_tg_media_min_kbps: float = 512.0
        if not args.no_stress and start_stage == "ping":
            if baseline_idx >= 0:
                progress.start_stage(baseline_idx, "базовый замер канала")
            from subgen.baseline import (
                adapt_speed_thresholds,
                measure_baseline,
                save_baseline_cache,
            )

            baseline_timeout = max(8.0, min(15.0, float(args.timeout) + 4.0))
            baseline = measure_baseline(timeout=baseline_timeout, log_sink=log)
            min_dl, min_up, tg_min, baseline_info = adapt_speed_thresholds(
                float(args.min_speed), baseline
            )
            effective_min_speed_kbps = float(min_dl)
            effective_upload_min_kbps = float(min_up) if min_up else None
            effective_tg_media_min_kbps = float(tg_min)
            save_baseline_cache(baseline, baseline_info)

            baseline_report = {
                "enabled": True,
                "measurement": baseline.as_dict(),
                "thresholds": baseline_info,
                "effective_min_speed_kbps": round(effective_min_speed_kbps, 1),
                "effective_tg_media_min_kbps": round(effective_tg_media_min_kbps, 1),
            }
            if baseline_info.get("ignored") == "fast_channel":
                log(
                    f"[sub] baseline: быстрый канал ({baseline_info.get('baseline_mbits', 0):.0f} Мбит/с ≥ "
                    f"{baseline_info.get('cap_mbits', 100)} Мбит/с) — замер игнорируется, "
                    f"порог из UI: {effective_min_speed_kbps:.0f} КБ/с"
                )
            elif baseline.ok:
                log(
                    f"[sub] baseline: download={baseline.download_kbps:.0f} КБ/с "
                    f"(~{baseline.download_kbps * 8 / 1000:.1f} Мбит/с) via {baseline.download_source}, "
                    f"адаптированный порог min_speed: {args.min_speed} → {effective_min_speed_kbps:.0f} КБ/с"
                )
            else:
                log(
                    f"[sub] baseline: замер не удался — порог из UI ({effective_min_speed_kbps:.0f} КБ/с)"
                )
            if baseline_idx >= 0:
                progress.finish_stage(
                    baseline_idx,
                    f"[baseline] download={baseline.download_kbps or 0:.0f} КБ/с, "
                    f"min_speed={effective_min_speed_kbps:.0f} КБ/с",
                )
        else:
            if baseline_idx >= 0:
                progress.finish_stage(baseline_idx, "[baseline] пропущен (no-stress или перепроверка)")

        progress.start_stage(0, f"загрузка {len(sources)} подписок")

        working, rejected, discovered = run_refresh(
            sources,
            timeout=args.timeout,
            workers=args.workers,
            max_servers=args.limit or 0,
            stress=not args.no_stress,
            log_sink=log,
            progress=progress,
            min_speed_kbps=float(args.min_speed),
            telegram_media_check=not args.no_telegram,
            cancel_event=cancel_event,
            pause_event=pause_event,
        )

        load_idx = progress.stage_index("load")
        if load_idx >= 0:
            progress.finish_stage(load_idx, f"[load] собрано {len(discovered)} узлов")

        if ping_idx >= 0 and not progress.is_completed(ping_idx):
            progress.finish_stage(ping_idx, f"[ping] done: {len(working)} accepted, {len(rejected)} rejected")

        log(f"[sub] discovered={len(discovered)} working={len(working)} rejected={len(rejected)}")

        # Фильтр по пингу.
        if args.max_ping > 0:
            original_working_count = len(working)
            working = [w for w in working if w.latency_ms is None or w.latency_ms <= args.max_ping]
            if len(working) < original_working_count:
                log(f"[sub] filtered out {original_working_count - len(working)} nodes with ping > {args.max_ping}ms")
        else:
            log("[sub] no ping filter (--max-ping=0)")

        # Фильтр по скорости УДАЛЁН из середины конвейера: скорость измеряется
        # финальным ИНФОРМАТИВНЫМ спидтестом ПОСЛЕ переименования и НЕ
        # отсеивает узлы (порог --min-speed — только метка в логе/отчёте).
        # tg-медиа проверяется на этапе telegram_pro (checkers/telegram_pro.py).
    else:
        # Перепроверка с этапа: распинговка и стресс-тест уже выполнены ранее,
        # их результаты сохранены в кеше. Загружаем рабочие конфиги и начинаем
        # с указанного этапа (initial/dpi/dpi_active/telegram_pro/ai_geo/
        # route/resilience/recheck).
        log(f"[sub] перепроверка с этапа '{start_stage}' (пропуск распинговки и стресс-теста)")
        working = _load_cached_working()
        rejected: list[Any] = []
        discovered: list[Any] = []
        # При перепроверке baseline не измеряем: пороги из UI/прошлого прогона.
        baseline_report: dict[str, Any] = {"enabled": False}
        effective_min_speed_kbps: float = float(args.min_speed)
        effective_upload_min_kbps: float | None = None
        effective_tg_media_min_kbps: float = 512.0
        if baseline_idx >= 0:
            progress.finish_stage(baseline_idx, f"[baseline] пропущен (перепроверка с {start_stage})")
        if not working:
            log("[sub] ERROR: нет сохранённых рабочих конфигов для перепроверки. Сначала выполните полный прогон.")
            progress.close()
            return 1

        # Отмечаем этапы load/ping как завершённые (они пропущены).
        load_idx = progress.stage_index("load")
        if load_idx >= 0:
            progress.finish_stage(load_idx, f"[load] пропущен (перепроверка с {start_stage})")
        if ping_idx >= 0 and not progress.is_completed(ping_idx):
            progress.finish_stage(ping_idx, f"[ping] пропущен (перепроверка с {start_stage})")

        # Этапы ДО указанного — отключаем и отмечаем как пропущенные
        # (универсально по STAGE_ORDER, а не хардкодом как раньше).
        if not _stage_enabled_from(start_stage, "initial"):
            if initial_idx >= 0 and not progress.is_completed(initial_idx):
                progress.finish_stage(initial_idx, f"[initial] пропущен (перепроверка с {start_stage})")
        if not _stage_enabled_from(start_stage, "dpi"):
            args.dpi_check = False
            if dpi_idx >= 0 and not progress.is_completed(dpi_idx):
                progress.finish_stage(dpi_idx, f"[dpi] пропущен (перепроверка с {start_stage})")
        if not _stage_enabled_from(start_stage, "dpi_active"):
            args.dpi_active = False
            if dpi_active_idx >= 0 and not progress.is_completed(dpi_active_idx):
                progress.finish_stage(dpi_active_idx, f"[dpi-active] пропущен (перепроверка с {start_stage})")
        if not _stage_enabled_from(start_stage, "telegram_pro"):
            args.no_telegram = True
            if telegram_pro_idx >= 0 and not progress.is_completed(telegram_pro_idx):
                progress.finish_stage(telegram_pro_idx, f"[telegram-pro] пропущен (перепроверка с {start_stage})")
        if not _stage_enabled_from(start_stage, "ai_geo"):
            args.ai_check = False
            if ai_geo_idx >= 0 and not progress.is_completed(ai_geo_idx):
                progress.finish_stage(ai_geo_idx, f"[ai-geo] пропущен (перепроверка с {start_stage})")
        # route-этап удалён в v11 (бессмысленный — только обогащал отчёт).
        if not _stage_enabled_from(start_stage, "resilience"):
            resilience_enabled = False
            if resilience_idx >= 0 and not progress.is_completed(resilience_idx):
                progress.finish_stage(resilience_idx, f"[resilience] пропущен (перепроверка с {start_stage})")

    # ---------------------------------------------------------------------
    # Initial Check: быстрая проверка доступности (TCP + HTTP HEAD).
    # Обязательный системный этап первичного отсева (Fail Fast): отсеивает
    # мёртвые узлы за 2-3 сек ДО дорогих проверок. Выполняется при полном
    # прогоне; при перепроверке с этапа узлы уже проверены — пропускаем.
    #
    # Режим sing-box pool (по умолчанию): один sing-box процесс на батч из
    # N узлов + Clash API для переключения selector'а. Вместо 14000 старт-
    # стопов ядра (5-8 часов оверхеда) — ~70 батчей по 1.5с старт = 2 мин.
    # Несовместимые узлы (xhttp/splithttp/kcp/quic) проверяются через старый
    # путь (run_with_node) — sing-box их не поддерживает.
    # ---------------------------------------------------------------------
    initial_check_report: dict[str, Any] = {}
    if start_stage == "ping":
        initial_orig_count = len(working)
        log(
            f"[sub] Initial check enabled, timeout={args.initial_check_timeout}s, "
            f"checking {initial_orig_count} nodes..."
        )
        if initial_idx >= 0:
            progress.start_stage(initial_idx, f"Initial check {initial_orig_count} узлов")
            progress.set_total(initial_idx, initial_orig_count)

        use_pool = bool(getattr(args, "use_singbox_pool", True)) and initial_orig_count > 0
        pool_batch_size = max(20, int(getattr(args, "singbox_pool_batch", 200)))
        pool_stats = {"batches": 0, "pool_passed": 0, "fallback_used": 0, "unsupported": 0}

        # Замеряем _run_check (TCP+TLS+HTTP HEAD) — общий для обоих режимов.
        from checkers.initial_check import _run_check as _initial_run_check

        def _check_one_via_pool(w: Any, pool: Any) -> dict[str, Any]:
            """Проверка ноды через pool: select + _run_check. None если unsupported."""
            if not pool.select(w.node):
                return {"passed": False, "tcp_ok": False, "http_ok": False,
                        "latency_ms": None, "error": "unsupported_runtime"}
            host, port = pool.endpoint
            try:
                return _initial_run_check(host, port, args.initial_check_timeout)
            except Exception as exc:
                return {"passed": False, "tcp_ok": False, "http_ok": False,
                        "latency_ms": None, "error": f"pool_probe_failed: {exc}"}

        def _check_one_via_fallback(w: Any) -> dict[str, Any]:
            """Проверка ноды через старый путь (старт-стоп xray/sing-box)."""
            return run_initial_check({}, w.node.raw_url, timeout=args.initial_check_timeout)

        # Локальный прогресс-каунтер для батчей.
        initial_done_counter = [0]

        def _bump_progress(title: str) -> None:
            initial_done_counter[0] += 1
            if initial_idx >= 0:
                progress.update(initial_done_counter[0], f"Initial {title}")
            _wait_if_paused(pause_event, cancel_event)
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")

        pairs: list[tuple[Any, dict[str, Any] | None]] = [(w, None) for w in working]
        # Индекс для O(1) поиска позиции узла в pairs (id(node_obj) -> idx).
        # working.index(w) даёт O(N²) на 14000 узлов = 200M операций.
        _pair_idx_by_id: dict[int, int] = {id(w): i for i, w in enumerate(working)}

        if use_pool:
            from runtime.singbox_pool import SingBoxBatchPool, iter_batches
            log(
                f"[sub] initial check: sing-box pool (батчи по {pool_batch_size} узлов), "
                f"{min(args.workers, max(1, initial_orig_count))} потоков в батче"
            )

            # Батчим узлы. Внутри батча — последовательный select, но между
            # батчами можно параллелить (однако это усложняет код — оставим
            # последовательный обход батчей, внутри батча уже есть параллелизм
            # через ThreadPool для probe_fn). Для simplicity: батчи последовательно,
            # probe внутри батча тоже последовательно (select глобальный).
            batches = iter_batches(working, batch_size=pool_batch_size)
            for batch_id, batch_results in batches:
                _wait_if_paused(pause_event, cancel_event)
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")

                # working — это list[XrayProbeResult] (обёртки). SingBoxBatchPool
                # и sing_box_outbound работают с XrayNode (нужен .protocol/.host/
                # .port/.query/.credential/.key). Извлекаем ноды из результатов.
                # Сохраняем mapping node.key -> XrayProbeResult, чтобы потом
                # сопоставить результат проверки с исходным объектом (в нём
                # хранится latency_ms и другие данные ping-фазы).
                batch_nodes = [w.node for w in batch_results]
                # Сохраняем mapping для последующего сопоставления.
                # Если в батче есть дубликаты по node.key (после dedup — не должно,
                # но подстраховка), берём первый.
                batch_result_by_node_id: dict[int, Any] = {id(w.node): w for w in batch_results}

                pool = SingBoxBatchPool(
                    batch_nodes,
                    root_dir=ROOT,
                    batch_id=batch_id,
                    log_sink=log,
                )
                supported = pool.supported_count
                pool_stats["batches"] += 1
                log(f"[initial] pool#{batch_id}: {len(batch_nodes)} узлов, {supported} поддерживается sing-box")

                try:
                    if not pool.start():
                        # Pool не стартовал — все узлы батча проверяем через fallback.
                        log(f"[initial] pool#{batch_id} не стартовал — fallback на with_node_process")
                        for w in batch_results:
                            res = _check_one_via_fallback(w)
                            pairs[_pair_idx_by_id[id(w)]] = (w, res)
                            _bump_progress(w.node.title())
                        pool_stats["fallback_used"] += len(batch_results)
                        continue

                    # Проходим по узлам батча: поддерживаемые — через pool,
                    # неподдерживаемые — через fallback.
                    # w — XrayProbeResult, w.node — XrayNode (нужен pool'у).
                    for w in batch_results:
                        if w.node.key in pool.unsupported_keys:
                            # sing-box не поддерживает — через xray.
                            pool_stats["unsupported"] += 1
                            res = _check_one_via_fallback(w)
                            pairs[_pair_idx_by_id[id(w)]] = (w, res)
                        else:
                            res = _check_one_via_pool(w, pool)
                            pairs[_pair_idx_by_id[id(w)]] = (w, res)
                        _bump_progress(w.node.title())
                finally:
                    pool.stop()

            log(
                f"[sub] initial check pool: {pool_stats['batches']} батчей, "
                f"{pool_stats['unsupported']} неподдерживаемых (через xray), "
                f"{pool_stats['fallback_used']} fallback"
            )
        else:
            log(f"[sub] initial check: параллельно (старый режим), {min(args.workers, max(1, initial_orig_count))} потоков")
            def _check_initial_node(w: Any) -> dict[str, Any]:
                return run_initial_check({}, w.node.raw_url, timeout=args.initial_check_timeout)

            pairs = _parallel_map_nodes(
                working,
                _check_initial_node,
                workers=args.workers,
                stage_idx=initial_idx,
                progress=progress,
                label="Initial",
                cancel_event=cancel_event,
                pause_event=pause_event,
            )

        checked_initial: list[Any] = []
        failed_initial = 0
        slow_ping_filtered = 0
        initial_node_details: dict[str, Any] = {}
        # Эвристика «первый быстрый» (в стиле v2whitelist NodeTesterManager):
        # как только находим ноду с latency < FAST_NODE_LATENCY_MS — помечаем
        # found_fast_node. Это информативный сигнал (для лога/отчёта), что
        # конвейер нашёл «хороший» кандидат быстро. Не прерывает остальные
        # проверки — нам нужна полная подписка, не одна нода.
        FAST_NODE_LATENCY_MS = 500.0
        found_fast_node = False
        fast_node_title = ""
        for idx, (w, res) in enumerate(pairs, 1):
            initial_node_details[w.node.title()] = res
            if res and res["passed"]:
                latency = float(res.get("latency_ms") or 0)
                if not found_fast_node and 0 < latency < FAST_NODE_LATENCY_MS:
                    found_fast_node = True
                    fast_node_title = w.node.title()
                    log(
                        f"[initial] ⚡ FAST NODE found {idx}/{initial_orig_count}: "
                        f"{w.node.title()} ({latency:.0f}ms < {FAST_NODE_LATENCY_MS:.0f}ms) — "
                        f"эталон быстрого кандидата (в стиле v2whitelist)"
                    )
                checked_initial.append(w)
                log(f"[initial] PASS {idx}/{initial_orig_count}: {w.node.title()} ({format_initial_check_result(res)})")
            elif res and res.get("tcp_ok") and args.max_ping > 0 and (res.get("latency_ms") or 0) > args.max_ping:
                # Второй пинг-фильтр: сквозной пинг через туннель (TCP+TLS+HEAD)
                # может быть выше порога, даже если quick-ping был в норме —
                # на медленных узлах это честный отсев «пинг за 2-3 тысячи».
                slow_ping_filtered += 1
                log(
                    f"[initial] SLOW-PING {idx}/{initial_orig_count}: {w.node.title()} "
                    f"(latency={res.get('latency_ms')}ms > {args.max_ping}ms)"
                )
            else:
                failed_initial += 1
                log(f"[initial] FAIL {idx}/{initial_orig_count}: {w.node.title()} ({format_initial_check_result(res) if res else 'node_start_failed'})")

        # Сортируем passed-узлы по latency (быстрые — в начале). Это аналог
        # v2whitelist resultsList.sortedBy { it.third } — быстрые ноды попадают
        # в финальную подписку первыми, что улучшает UX в клиентах с автоматическим
        # выбором (v2rayNG urltest, Clash urltest, sing-box urltest).
        checked_initial.sort(
            key=lambda w: float(initial_node_details.get(w.node.title(), {}).get("latency_ms") or float("inf"))
        )
        if found_fast_node:
            log(
                f"[sub] initial check: ⚡ найден быстрый кандидат '{fast_node_title}' "
                f"(<{FAST_NODE_LATENCY_MS:.0f}ms) — отсортирован в начало подписки"
            )

        if slow_ping_filtered > 0:
            log(
                f"[sub] filtered out {slow_ping_filtered} nodes with initial-check latency > {args.max_ping}ms "
                f"(сквозной пинг через туннель)"
            )
        if initial_idx >= 0:
            progress.finish_stage(
                initial_idx,
                f"[initial] done: {len(checked_initial)} passed, {failed_initial + slow_ping_filtered} failed"
                + (f", ⚡ fast={fast_node_title}" if found_fast_node else ""),
            )

        working = checked_initial
        if failed_initial + slow_ping_filtered > 0:
            log(f"[sub] filtered out {failed_initial + slow_ping_filtered} nodes that failed initial check")

        initial_check_report = {
            "enabled": True,
            "checked": initial_orig_count,
            "passed": len(checked_initial),
            "failed": failed_initial,
            "slow_ping_filtered": slow_ping_filtered,
            "nodes": initial_node_details,
            "singbox_pool": {
                "enabled": bool(use_pool),
                "batch_size": int(pool_batch_size) if use_pool else 0,
                "batches": int(pool_stats["batches"]),
                "unsupported_via_xray": int(pool_stats["unsupported"]),
                "fallback_used": int(pool_stats["fallback_used"]),
            },
        }
    else:
        if initial_idx >= 0 and not progress.is_completed(initial_idx):
            progress.finish_stage(initial_idx, f"[initial] пропущен (TUN-check или перепроверка с {start_stage})")

    # Сетевой профиль: p50-латентность initial_check (сквозной путь
    # «клиент -> туннель -> цель»). Хинт для адаптации таймаутов: фиксированные
    # 5с на сетях с RTT 1.5-3с (мобильный интернет, медленные бесплатные
    # узлы) заваливают здоровые узлы по таймауту (инцидент 2026-09-02:
    # мобильный прогон 13:16-16:18, 106/106 FAIL на DPI-сьюте при
    # suite=0-1/24, те же узлы ночью на WiFi — suite=23/24 и экспорт 42 нод
    # на 6-7 Мбит/с).
    network_rtt_ms = _median_initial_latency(locals().get("initial_node_details") or {})
    network_report: dict[str, Any] = {
        "initial_p50_ms": round(network_rtt_ms, 1) if network_rtt_ms else None,
        "slow_mode": bool(network_rtt_ms >= SLOW_NETWORK_RTT_MS),
        "slow_network_rtt_ms": SLOW_NETWORK_RTT_MS,
    }
    if network_rtt_ms:
        log(
            f"[sub] network profile: initial-check p50 = {network_rtt_ms:.0f} ms"
            + (
                " (медленный канал: таймауты Telegram/DPI-сьюта/Resilience адаптированы)"
                if network_rtt_ms >= SLOW_NETWORK_RTT_MS
                else ""
            )
        )

    # Продвинутая Telegram-проверка (MTProto connect/auth, upload,
    # tg-медиа из t.me/s/) с расчётом telegram_score. Ставится ДО DPI-этапа:
    # Telegram — ГЛАВНЫЙ критерий пользователя (голосовые и медиа должны
    # грузиться), узлы должны отмеряться им раньше, чем жёстким DPI-гейтом.
    #
    # v11: расширил sing-box pool на telegram_pro. Раньше каждый узел требовал
    # старт-стоп xray.exe (0.4с sleep + старт), и при 32 параллельных инстансах
    # 59% узлов падали по node_start_failed. Теперь — один sing-box процесс
    # на батч + переключение selector'а через Clash API (50мс).
    telegram_pro_report: dict[str, Any] = {}
    if not args.no_telegram:
        telegram_pro_orig_count = len(working)
        # Адаптивный таймаут: MTProto connect/auth — это 2-3 RTT сквозного
        # пути; при p50 RTT ~2с фиксированные 5с проходят впритык.
        tg_timeout = TG_TIMEOUT
        if network_rtt_ms > 0:
            tg_timeout = round(min(max(TG_TIMEOUT, network_rtt_ms / 1000.0 * 6.0), 15.0), 1)
        log(
            f"[sub] Telegram-PRO check enabled, checking {telegram_pro_orig_count} nodes..."
            + (
                f" (timeout адаптирован: {tg_timeout}s при p50 RTT {network_rtt_ms:.0f}ms)"
                if tg_timeout != TG_TIMEOUT
                else ""
            )
        )
        # tg-медиа качает до 4 МБ на узел: параллельная толпа режет полосу
        # и валит живые узлы по таймауту. Лимит 8 потоков на TG-этап.
        tg_workers = min(int(args.workers), 8)
        log(f"[sub] telegram-pro: параллельно, {tg_workers} потоков (медиа не делит полосу на толпу)")
        if telegram_pro_idx >= 0:
            progress.start_stage(telegram_pro_idx, f"Telegram-проверка {telegram_pro_orig_count} узлов")
            progress.set_total(telegram_pro_idx, telegram_pro_orig_count)

        # v11: sing-box pool для telegram_pro. Тот же подход что в initial_check:
        # батчим узлы, поднимаем один sing-box с N outbounds, переключаем selector.
        # Несовместимые узлы (xhttp/kcp/quic) проверяются через старый путь.
        use_pool = bool(getattr(args, "use_singbox_pool", True)) and telegram_pro_orig_count > 0
        pool_batch_size = max(20, int(getattr(args, "singbox_pool_batch", 200)))
        tg_pool_stats = {"batches": 0, "fallback_used": 0, "unsupported": 0}

        # Импортируем функцию проверки через уже поднятый SOCKS.
        from checkers.telegram_pro import check_node_telegram_pro_via_socks

        def _check_tg_via_pool(w: Any, pool: Any) -> TelegramProResult:
            """Проверка через pool: select + check_node_telegram_pro_via_socks."""
            if not pool.select(w.node):
                # Неподдерживается sing-box — вернём маркер, fallback сработает выше.
                return None
            host, port = pool.endpoint
            try:
                return check_node_telegram_pro_via_socks(host, port, timeout=tg_timeout)
            except Exception as exc:
                return TelegramProResult(accepted=False, reason=f"pool_probe_failed: {exc}")

        def _check_tg_via_fallback(w: Any) -> TelegramProResult:
            """Проверка через старый путь (старт-стоп xray/sing-box)."""
            return check_node_telegram_pro_detailed(w.node.raw_url, timeout=tg_timeout)

        # Локальный прогресс-каунтер для батчей.
        tg_done_counter = [0]
        def _bump_tg_progress(title: str) -> None:
            tg_done_counter[0] += 1
            if telegram_pro_idx >= 0:
                progress.update(tg_done_counter[0], f"Telegram {title}")
            _wait_if_paused(pause_event, cancel_event)
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")

        # Результаты: list[tuple[XrayProbeResult, TelegramProResult|None]].
        tg_pairs: list[tuple[Any, TelegramProResult | None]] = [(w, None) for w in working]
        _tg_pair_idx_by_id: dict[int, int] = {id(w): i for i, w in enumerate(working)}

        if use_pool:
            from runtime.singbox_pool import SingBoxBatchPool, iter_batches
            log(f"[sub] telegram-pro: sing-box pool (батчи по {pool_batch_size} узлов)")

            batches = iter_batches(working, batch_size=pool_batch_size)
            for batch_id, batch_results in batches:
                _wait_if_paused(pause_event, cancel_event)
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")

                batch_nodes = [w.node for w in batch_results]
                pool = SingBoxBatchPool(
                    batch_nodes,
                    root_dir=ROOT,
                    batch_id=batch_id,
                    log_sink=log,
                )
                supported = pool.supported_count
                tg_pool_stats["batches"] += 1
                log(f"[telegram-pro] pool#{batch_id}: {len(batch_nodes)} узлов, {supported} поддерживается")

                try:
                    if not pool.start():
                        log(f"[telegram-pro] pool#{batch_id} не стартовал — fallback")
                        for w in batch_results:
                            res = _check_tg_via_fallback(w)
                            tg_pairs[_tg_pair_idx_by_id[id(w)]] = (w, res)
                            _bump_tg_progress(w.node.title())
                        tg_pool_stats["fallback_used"] += len(batch_results)
                        continue

                    for w in batch_results:
                        if w.node.key in pool.unsupported_keys:
                            # sing-box не поддерживает — через xray.
                            tg_pool_stats["unsupported"] += 1
                            res = _check_tg_via_fallback(w)
                            tg_pairs[_tg_pair_idx_by_id[id(w)]] = (w, res)
                        else:
                            res = _check_tg_via_pool(w, pool)
                            if res is None:
                                # select вернул False (узел исчез из pool). Fallback.
                                tg_pool_stats["fallback_used"] += 1
                                res = _check_tg_via_fallback(w)
                            tg_pairs[_tg_pair_idx_by_id[id(w)]] = (w, res)
                        _bump_tg_progress(w.node.title())
                finally:
                    pool.stop()

            log(
                f"[sub] telegram-pro pool: {tg_pool_stats['batches']} батчей, "
                f"{tg_pool_stats['unsupported']} неподдерживаемых (через xray), "
                f"{tg_pool_stats['fallback_used']} fallback"
            )
            pairs = tg_pairs
        else:
            log(f"[sub] telegram-pro: параллельно (старый режим), {tg_workers} потоков")
            def _check_tg_node(w: Any) -> TelegramProResult:
                return check_node_telegram_pro_detailed(w.node.raw_url, timeout=tg_timeout)
            pairs = _parallel_map_nodes(
                working,
                _check_tg_node,
                workers=tg_workers,
                stage_idx=telegram_pro_idx,
                progress=progress,
                label="Telegram",
                cancel_event=cancel_event,
                pause_event=pause_event,
            )

        checked_telegram_pro: list[Any] = []
        failed_telegram_pro = 0
        telegram_pro_node_details: dict[str, Any] = {}
        for idx, (w, res) in enumerate(pairs, 1):
            telegram_pro_node_details[w.node.title()] = res.row() if res else None
            if res and res.accepted:
                checked_telegram_pro.append(w)
                log(
                    f"[telegram-pro] PASS {idx}/{telegram_pro_orig_count}: {w.node.title()} "
                    f"(score={res.telegram_score} connect={res.connect}({res.connect_ms}ms) "
                    f"auth={res.auth} up={res.upload_kbps}KB/s tg_media={res.tg_media_kbps}KB/s)"
                )
            else:
                failed_telegram_pro += 1
                reason = res.reason if res else "node_start_failed"
                log(
                    f"[telegram-pro] FAIL {idx}/{telegram_pro_orig_count}: {w.node.title()} "
                    f"(score={res.telegram_score if res else 0} connect={res.connect if res else False} "
                    f"auth={res.auth if res else False} "
                    f"up={res.upload_kbps if res else None}KB/s reason={reason})"
                )
        if telegram_pro_idx >= 0:
            progress.finish_stage(
                telegram_pro_idx,
                f"[telegram-pro] done: {len(checked_telegram_pro)} passed, {failed_telegram_pro} failed",
            )

        working = checked_telegram_pro
        if failed_telegram_pro > 0:
            log(f"[sub] filtered out {failed_telegram_pro} nodes that failed Telegram-PRO check")

        telegram_pro_report = {
            "enabled": True,
            "checked": telegram_pro_orig_count,
            "passed": len(checked_telegram_pro),
            "failed": failed_telegram_pro,
            "timeout_sec": tg_timeout,
            "singbox_pool": {
                "enabled": bool(use_pool),
                "batch_size": int(pool_batch_size) if use_pool else 0,
                "batches": int(tg_pool_stats["batches"]),
                "unsupported_via_xray": int(tg_pool_stats["unsupported"]),
                "fallback_used": int(tg_pool_stats["fallback_used"]),
            },
            "nodes": telegram_pro_node_details,
        }

    # ---------------------------------------------------------------------
    # SERVICES: доступ к ЗАБЛОКИРОВАННЫМ сервисам — ГЛАВНЫЙ критерий
    # (философия пользователя: ТГ отлично + инста + ютуб + дискорд +
    # нейронки). Метод: TCP-коннект к IP сервисов из реестра заблокированных
    # (rulist/antifilter — база списков Zapret) + TLS-хендшейк с настоящим
    # SNI домена (ловит SNI-DPI, который TCP-пинг не видит). Не «просто HTTP
    # к сайтам»: IP-путь + SNI-путь проверяются раздельно.
    # ИИ (chatgpt/gemini) — информативно: их блокировка зависит от гео
    # выхода (OpenAI сам банит РФ) — это компетенция ai-geo этапа.
    # ---------------------------------------------------------------------
    services_report: dict[str, Any] = {}
    if services_enabled:
        services_orig_count = len(working)
        services_timeout = max(5.0, min(10.0, float(getattr(args, "timeout", 8.0))))
        log(
            f"[sub] SERVICES check enabled (заблокированные сервисы: инста/ютуб/дискорд "
            f"[обязательные] + chatgpt/gemini [информативно], IP реестра + TLS-SNI), "
            f"timeout={services_timeout}s, checking {services_orig_count} nodes..."
        )
        log(f"[sub] services: параллельно, {min(args.workers, max(1, services_orig_count))} потоков")
        if services_idx >= 0:
            progress.start_stage(services_idx, f"Сервисы {services_orig_count} узлов")
            progress.set_total(services_idx, services_orig_count)

        def _check_services_node(w: Any) -> BlockedServicesResult:
            return check_node_blocked_services_detailed(
                w.node.raw_url,
                timeout=services_timeout,
            )

        pairs = _parallel_map_nodes(
            working,
            _check_services_node,
            workers=args.workers,
            stage_idx=services_idx,
            progress=progress,
            label="Services",
            cancel_event=cancel_event,
            pause_event=pause_event,
        )

        checked_services: list[Any] = []
        failed_services = 0
        services_node_details: dict[str, Any] = {}
        for idx, (w, res) in enumerate(pairs, 1):
            services_node_details[w.node.title()] = res.row() if res else None
            if res and res.accepted:
                checked_services.append(w)
                log(
                    f"[services] PASS {idx}/{services_orig_count}: {w.node.title()} "
                    f"({format_services_result(res)})"
                )
            else:
                failed_services += 1
                reason = res.reason if res else "node_start_failed"
                log(
                    f"[services] FAIL {idx}/{services_orig_count}: {w.node.title()} "
                    f"(reason={reason}; {format_services_result(res) if res else ''})"
                )
        if services_idx >= 0:
            progress.finish_stage(
                services_idx,
                f"[services] done: {len(checked_services)} passed, {failed_services} failed",
            )

        working = checked_services
        if failed_services > 0:
            log(f"[sub] filtered out {failed_services} nodes that failed blocked-services check")

        services_report = {
            "enabled": True,
            "checked": services_orig_count,
            "passed": len(checked_services),
            "failed": failed_services,
            "timeout_sec": services_timeout,
            "method": "TCP to registry IPs + TLS with real SNI",
            "required": ["instagram", "youtube", "discord"],
            "info": ["openai", "gemini"],
            "nodes": services_node_details,
        }

    # DPI-проверка (обход блокировок) через XrayCoreRuntime.
    # v11: dpi_suite (zapret-методика) УДАЛЁН. Раньше при включённом --dpi-check
    # автоматически запускалась "suite tcp 16-20" батарея (POST 64KB на 8 целей
    # по 3 протоколам + HTTP-тест). На медленных сетях сам автор фиксил это
    # через suite_slow_network (suite становилось не-вето), тогда зачем оно.
    # Теперь DPI-этап делает только классическую проверку: alive + tcp 16-20
    # на заблокированные цели + siberian + CIDR (если включены).
    dpi_report: dict[str, Any] = {}
    if args.dpi_check:
        timeout = get_threshold("dpi", "timeout", 10.0)
        require_siberian = args.dpi_siberian or get_threshold("dpi", "require_siberian", False)
        require_cidr = args.dpi_cidr or get_threshold("dpi", "require_cidr", False)

        orig_dpi_count = len(working)
        target = args.dpi_target or DPI_DEFAULT_TARGET
        log(
            f"[sub] DPI check enabled, target={target}, siberian={'on' if require_siberian else 'info'} "
            f"cidr={'on' if require_cidr else 'info'}, suite=off (v11: удалён), "
            f"checking {orig_dpi_count} nodes..."
        )
        log(f"[sub] dpi: параллельно, {min(args.workers, max(1, orig_dpi_count))} потоков")
        if dpi_idx >= 0:
            progress.start_stage(dpi_idx, f"DPI-проверка {orig_dpi_count} узлов")
            progress.set_total(dpi_idx, orig_dpi_count)
        working_dpi_path = _resolve_path(args.working_dpi)
        out_dpi_path = _resolve_path(args.out_dpi)
        write_file(working_dpi_path, "")
        write_file(out_dpi_path, "")
        _tcp_labels = {
            "not_detected": "not detected ✅",
            "possible": "possible detected ⚠️",
            "probably": "probably detected ⚠️",
            "unlikely": "unlikely ⚠️",
            "detected": "detected ❗️",
        }

        # Проверяем кэш, ТОЛЬКО если это перепроверка с этапа: чистый прогон
        # с нуля (start_stage == "ping") кеш НЕ читает — иначе результаты
        # прошлого прогона маскируют текущее состояние узлов (требование
        # пользователя: «зачем ты используешь кеш при чистом прогоне с нуля»).
        cache_enabled = get_threshold("cache", "enabled", True) and start_stage != "ping"
        if cache_enabled:
            log("[sub] checker-cache активен (перепроверка с этапа)")

        # (res_or_None, cached_passed_or_None) на узел — параллельно.
        def _check_dpi_node(w: Any) -> tuple[Any, Any]:
            cached_passed = None
            if cache_enabled:
                cached_passed, _ = check_cached(w.node.raw_url, "dpi")
            if cached_passed is not None:
                return (None, cached_passed)
            res = check_node_dpi_detailed(
                w.node.raw_url,
                target_host=target,
                timeout=timeout,
                require_siberian=require_siberian,
                require_cidr=require_cidr,
                run_suite=False,  # v11: suite удалён
                suite_targets=None,
                suite_timeout=0.0,
                suite_min_score=0.0,
                suite_http_test=False,
                rtt_hint_ms=network_rtt_ms,
            )
            if cache_enabled:
                cache_result(w.node.raw_url, "dpi", res.accepted, res.row())
            return (res, None)

        pairs = _parallel_map_nodes(
            working,
            _check_dpi_node,
            workers=args.workers,
            stage_idx=dpi_idx,
            progress=progress,
            label="DPI",
            cancel_event=cancel_event,
            pause_event=pause_event,
        )

        checked: list[Any] = []
        failed = 0
        for idx, (w, outcome) in enumerate(pairs, 1):
            res, cached_passed = outcome if outcome else (None, None)
            if cached_passed is not None:
                # Используем кэшированный результат
                passed = cached_passed
                log(f"[dpi] CACHED {'PASS' if passed else 'FAIL'} {idx}/{orig_dpi_count}: {w.node.title()}")
            else:
                passed = res.accepted if res else False

            tcp_label = _tcp_labels.get(res.tcp1620_level, res.tcp1620_level) if res else "cached"
            if passed:
                checked.append(w)
                append_text(working_dpi_path, w.node.raw_url + "\n")
                log(f"[dpi] PASS {idx}/{orig_dpi_count}: {w.node.title()} (tcp 16-20: {tcp_label})")
            else:
                failed += 1
                reason = res.reason if res else "cached_fail"
                log(f"[dpi] FAIL {idx}/{orig_dpi_count}: {w.node.title()} (reason={reason})")
        if dpi_idx >= 0:
            progress.finish_stage(dpi_idx, f"[dpi] done: {len(checked)} passed, {failed} failed")

        working = checked
        if failed > 0:
            log(f"[sub] filtered out {failed} nodes that failed DPI check (target={target})")

        dpi_urls = urls_text(working)
        write_file(working_dpi_path, dpi_urls)
        dpi_b64 = base64.b64encode(dpi_urls.encode("utf-8")).decode("ascii")
        write_file(out_dpi_path, dpi_b64)
        log(f"[sub] saved {len(working)} DPI-passed nodes -> {working_dpi_path} / {out_dpi_path}")

        dpi_report = {
            "enabled": True,
            "checked": orig_dpi_count,
            "passed": len(checked),
            "failed": failed,
            "target": target,
            "suite": {"enabled": False, "note": "удалён в v11"},
        }

    # ---------------------------------------------------------------------
    # v11: ПЕРЕСТАНОВКА ЭТАПОВ.
    # Раньше: dpi_active → ai_geo → route → resilience.
    # Теперь: resilience → dpi_active → ai_geo.
    # Логика: resilience — дешёвый отсев мёртвых (TCP/DoH/UDP DNS), должен идти
    # ПЕРВЫМ после dpi, чтобы дорогие dpi_active (SNI-фаззинг) и ai_geo (CF trace)
    # не тратили время на уже мёртвые узлы. ai_geo — в самом конце, формирует
    # флаг страны для финальной подписки.
    # ---------------------------------------------------------------------

    # Resilience check: проверка живучести узлов в условиях блокировок.
    # v11: перенесён ВЫШЕ (был после route) — дешёвый отсев до дорогих
    # dpi_active и ai_geo.
    resilience_report: dict[str, Any] = {}
    resilience_enabled = getattr(args, 'resilience_check', True)
    if resilience_enabled and _stage_enabled_from(start_stage, "resilience"):
        from checkers.resilience import check_node_resilience_detailed

        resilience_orig_count = len(working)
        resilience_timeout = max(3.0, args.resilience_timeout)
        # Медленный канал: как Telegram/DPI, адаптируем и resilience
        # (инцидент 2026-09-04, лог4: p50 RTT 2076 мс, а подтесты батареи
        # остались с таймаутом 6с — живые узлы, прошедшие DPI, отвалились
        # на resilience с вердиктом completely_dead).
        resilience_rtt_hint: float | None = None
        if network_rtt_ms and network_rtt_ms >= SLOW_NETWORK_RTT_MS:
            resilience_rtt_hint = network_rtt_ms
            resilience_timeout = max(
                resilience_timeout,
                min(15.0, network_rtt_ms / 1000.0 * 4.0),
            )

        log(
            f"[sub] Resilience check enabled, timeout={resilience_timeout}s"
            + (
                f" (адаптирован: p50 RTT {network_rtt_ms:.0f}ms)"
                if resilience_rtt_hint
                else ""
            )
            + f", checking {resilience_orig_count} nodes..."
        )
        if resilience_idx >= 0:
            progress.start_stage(resilience_idx, f"Resilience-проверка {resilience_orig_count} узлов")
            progress.set_total(resilience_idx, resilience_orig_count)

        checked_resilience: list[Any] = []
        failed_resilience = 0
        resilience_node_details: dict[str, Any] = {}
        log(f"[sub] resilience: параллельно, {min(args.workers, max(1, resilience_orig_count))} потоков")

        def _check_resilience_node(w: Any):
            return check_node_resilience_detailed(
                w.node.raw_url,
                timeout=resilience_timeout,
                rtt_hint_ms=resilience_rtt_hint,
            )

        pairs = _parallel_map_nodes(
            working,
            _check_resilience_node,
            workers=args.workers,
            stage_idx=resilience_idx,
            progress=progress,
            label="Resilience",
            cancel_event=cancel_event,
            pause_event=pause_event,
        )

        for idx, (w, res) in enumerate(pairs, 1):
            resilience_node_details[w.node.title()] = res.to_dict() if res else None
            # Route-стабильность (RTT/jitter/loss) — часть стресс-теста v12:
            # живой, но нестабильный маршрут (loss>5%, p95>800мс, джиттер>80мс)
            # бракуется с явной причиной; «not_measured» (батарея съела бюджет)
            # не наказываем — данных нет, вердикта нет.
            route_info = ""
            route_failed = False
            route_row = getattr(res, "route", None) if res else None
            if isinstance(route_row, dict):
                if route_row.get("reason") not in ("not_measured",) and route_row.get("probes_total", 0) >= 3:
                    route_info = (
                        f", route={route_row.get('ping_avg')}ms"
                        f"/p95 {route_row.get('ping_p95')}ms"
                        f"/jit {route_row.get('jitter')}ms"
                        f"/loss {route_row.get('loss')}"
                    )
                    route_failed = not bool(route_row.get("accepted", False))
            if res and res.alive and not route_failed:
                checked_resilience.append(w)
                log(
                    f"[resilience] PASS {idx}/{resilience_orig_count}: {w.node.title()} "
                    f"(mode={res.recommended_mode}, tcp={res.tcp_works}, doh={res.doh_works}, tg={not res.telegram_blocked}, white_sni={res.white_sni_works}{route_info})"
                )
            else:
                failed_resilience += 1
                # Честная причина отвала: ошибка запуска ядра/бюджета — это НЕ
                # «узел мёртв», раньше оба случая писались как completely_dead.
                if res and res.alive and route_failed:
                    fail_reason = f"route_unstable ({route_row.get('reason')})"
                elif res and res.recommended_mode == "error":
                    fail_reason = "run_failed (ядро узла не поднялось/бюджет)"
                else:
                    fail_reason = "completely_dead"
                log(
                    f"[resilience] FAIL {idx}/{resilience_orig_count}: {w.node.title()} "
                    f"({fail_reason})"
                )

        if resilience_idx >= 0:
            progress.finish_stage(resilience_idx, f"[resilience] done: {len(checked_resilience)} passed, {failed_resilience} failed")

        working = checked_resilience
        resilience_report = {
            "enabled": True,
            "checked": resilience_orig_count,
            "passed": len(checked_resilience),
            "failed": failed_resilience,
            "timeout_sec": resilience_timeout,
            "rtt_hint_ms": round(resilience_rtt_hint, 1) if resilience_rtt_hint else None,
            "route_check": True,  # v12: RTT/jitter/loss в стресс-тесте
            "nodes": resilience_node_details,
        }
    else:
        if not resilience_enabled:
            log("[sub] Resilience check disabled via --no-resilience-check")
        if resilience_idx >= 0 and not progress.is_completed(resilience_idx):
            progress.finish_stage(resilience_idx, f"[resilience] пропущен (перепроверка с {start_stage})")
        resilience_report = {"enabled": False}

    # ---------------------------------------------------------------------
    # DPI-ACTIVE: активная DPI-проверка ПРОТОКОЛА узла (SNI-варианты,
    # фрагментация/большой ClientHello, ECH, TLS 1.2/1.3).
    # v11: перенесён В КОНЕЦ перед ai_geo и спидтестом. Это диагностика
    # протокола, не фильтр — имеет смысл для финальных кандидатов (после
    # resilience отсева), не для 14000 нод.
    # ---------------------------------------------------------------------
    dpi_active_report: dict[str, Any] = {}
    if args.dpi_active and _stage_enabled_from(start_stage, "dpi_active"):
        dpi_active_orig_count = len(working)
        dpi_active_timeout = max(2.0, args.dpi_active_timeout)
        log(
            f"[sub] DPI-ACTIVE check enabled, timeout={dpi_active_timeout}s "
            f"min_score={DPI_ACTIVE_MIN_SCORE:.2f}, checking {dpi_active_orig_count} nodes..."
        )
        if dpi_active_idx >= 0:
            progress.start_stage(dpi_active_idx, f"активная DPI-проверка {dpi_active_orig_count} узлов")
            progress.set_total(dpi_active_idx, dpi_active_orig_count)

        checked_dpi_active: list[Any] = []
        failed_dpi_active = 0
        dpi_active_node_details: dict[str, Any] = {}
        log(f"[sub] dpi-active: параллельно, {min(args.workers, max(1, dpi_active_orig_count))} потоков")

        def _check_dpi_active_node(w: Any) -> DpiActiveResult:
            return check_node_dpi_active_detailed(
                w.node.raw_url,
                timeout=dpi_active_timeout,
            )

        pairs = _parallel_map_nodes(
            working,
            _check_dpi_active_node,
            workers=args.workers,
            stage_idx=dpi_active_idx,
            progress=progress,
            label="DPI-active",
            cancel_event=cancel_event,
            pause_event=pause_event,
        )

        for idx, (w, res) in enumerate(pairs, 1):
            dpi_active_node_details[w.node.title()] = res.row() if res else None
            if res and res.accepted:
                checked_dpi_active.append(w)
                log(
                    f"[dpi-active] PASS {idx}/{dpi_active_orig_count}: {w.node.title()} "
                    f"(score={res.score} reason={res.reason})"
                )
            else:
                failed_dpi_active += 1
                log(
                    f"[dpi-active] FAIL {idx}/{dpi_active_orig_count}: {w.node.title()} "
                    f"(score={res.score if res else 0} reason={res.reason if res else 'node_start_failed'})"
                )
        if dpi_active_idx >= 0:
            progress.finish_stage(
                dpi_active_idx,
                f"[dpi-active] done: {len(checked_dpi_active)} passed, {failed_dpi_active} failed",
            )

        working = checked_dpi_active
        if failed_dpi_active > 0:
            log(f"[sub] filtered out {failed_dpi_active} nodes that failed active DPI check")

        dpi_active_report = {
            "enabled": True,
            "checked": dpi_active_orig_count,
            "passed": len(checked_dpi_active),
            "failed": failed_dpi_active,
            "timeout_sec": dpi_active_timeout,
            "min_score": DPI_ACTIVE_MIN_SCORE,
            "nodes": dpi_active_node_details,
        }
    else:
        if dpi_active_idx >= 0 and not progress.is_completed(dpi_active_idx):
            progress.finish_stage(dpi_active_idx, f"[dpi-active] пропущен (перепроверка с {start_stage})")

    # ---------------------------------------------------------------------
    # AI-GEO: слепок страны выхода узла.
    # v11: ПЕРЕНЕСЁН В КОНЕЦ (был после dpi_active, перед route). Раньше
    # тратил время на узлы, которые всё равно отбраковываются дальше.
    # Теперь идёт после всех отсеивающих этапов — только финальные кандидаты.
    #
    # v11: ИСПРАВЛЕНА ГЕО-ЛОГИКА. Раньше единственный источник — CF trace
    # (chatgpt.com/claude.ai loc=XX). Проблема: CF trace показывает гео
    # Cloudflare-кеша, а не реальный exit-IP. Если узел — CF Worker, слепок
    # всегда показывает страну CF-ноды (часто US), а не реальный exit.
    # Теперь: КОНСЕНСУС из 3 источников:
    #   1. CF trace (chatgpt.com) — как раньше.
    #   2. ipinfo.io/json — прямой гео exit-IP (бесплатный лимит 50k/мес).
    #   3. ip-api.com/json — второй независимый источник (бесплатный 45/мин).
    # Если 2 из 3 согласны — берём их. Если все три разные — берём ipinfo
    # (самый точный для non-CF exit). CF trace понижен до информативного.
    # ---------------------------------------------------------------------
    ai_geo_report: dict[str, Any] = {}
    if getattr(args, "ai_check", False) and _stage_enabled_from(start_stage, "ai_geo"):
        from checkers.ai_geo import AI_GEO_TIMEOUT, AiGeoResult, check_node_ai_geo_detailed

        ai_geo_orig_count = len(working)
        ai_strict = bool(getattr(args, "ai_strict", False))
        ai_timeout = max(3.0, float(getattr(args, "ai_timeout", AI_GEO_TIMEOUT)))
        log(
            f"[sub] AI-geo (v11: консенсус CF+ipinfo+ip-api, флаг страны), "
            f"strict={'on (слепок РФ -> FAIL)' if ai_strict else 'off'}, "
            f"timeout={ai_timeout}s, checking {ai_geo_orig_count} nodes..."
        )
        if ai_geo_idx >= 0:
            progress.start_stage(ai_geo_idx, f"ИИ-гео слепок {ai_geo_orig_count} узлов")
            progress.set_total(ai_geo_idx, ai_geo_orig_count)

        checked_ai: list[Any] = []
        failed_ai = 0
        ai_geo_node_details: dict[str, Any] = {}
        log(f"[sub] ai-geo: параллельно, {min(args.workers, max(1, ai_geo_orig_count))} потоков")

        def _check_ai_node(w: Any) -> AiGeoResult:
            return check_node_ai_geo_detailed(
                w.node.raw_url,
                timeout=ai_timeout,
            )

        pairs = _parallel_map_nodes(
            working,
            _check_ai_node,
            workers=args.workers,
            stage_idx=ai_geo_idx,
            progress=progress,
            label="AI-geo",
            cancel_event=cancel_event,
            pause_event=pause_event,
        )

        for idx, (w, res) in enumerate(pairs, 1):
            ai_geo_node_details[w.node.title()] = res.row() if res else None
            if res is None:
                # ядро узла не поднялось — узел НЕ отсеивается (как раньше:
                # слепок недоступен не виноват узел, но имя не обновится)
                checked_ai.append(w)
                w.ai_geo_country = ""
                continue
            # v11: ISO-код страны из КОНСЕНСУСА источников (CF + ipinfo + ip-api).
            # ai_geo_country теперь может прийти из ipinfo/ip-api, не только из CF.
            # AiGeoResult.cf_loc остаётся для обратной совместимости, но
            # приоритет — consensus_country (заполняется в checkers/ai_geo.py).
            consensus = getattr(res, "consensus_country", None) or (res.cf_loc or "").strip().upper()
            w.ai_geo_country = consensus
            # Фильтрация только в strict-режиме и только при ДОСТУПНОМ
            # слепке: ai_unblocked=False (слепок РФ). None (сигналы не
            # получены) и node_start_failed — узел НЕ отсеивается.
            node_rejected = bool(ai_strict and res.ai_unblocked is False)
            if not node_rejected:
                checked_ai.append(w)
                log(
                    f"[ai-geo] {idx}/{ai_geo_orig_count}: {w.node.title()} "
                    f"(consensus={consensus or '-'} cf={res.cf_loc or '-'} "
                    f"google={res.google_country or '-'} gemini={res.gemini_reachable} "
                    f"verdict={res.ai_unblocked} reason={res.reason})"
                )
            else:
                failed_ai += 1
                log(
                    f"[ai-geo] FAIL {idx}/{ai_geo_orig_count}: {w.node.title()} "
                    f"(слепок РФ: consensus={consensus or '-'} cf={res.cf_loc or '-'} "
                    f"google={res.google_country or '-'} reason={res.reason})"
                )
        if ai_geo_idx >= 0:
            progress.finish_stage(
                ai_geo_idx,
                f"[ai-geo] done: {len(checked_ai)} passed, {failed_ai} failed",
            )

        working = checked_ai
        if failed_ai > 0:
            log(f"[sub] filtered out {failed_ai} nodes with RU AI-geo snapshot")

        ai_geo_report = {
            "enabled": True,
            "checked": ai_geo_orig_count,
            "passed": len(checked_ai),
            "failed": failed_ai,
            "strict": ai_strict,
            "timeout_sec": ai_timeout,
            "method": "v11: consensus CF+ipinfo+ip-api",
            "nodes": ai_geo_node_details,
        }
    else:
        if ai_geo_idx >= 0 and not progress.is_completed(ai_geo_idx):
            progress.finish_stage(ai_geo_idx, f"[ai-geo] пропущен (перепроверка с {start_stage})")

    # ---------------------------------------------------------------------
    # ROUTE-этап УДАЛЁН в v11. Раньше трассировал маршрут (RTT, jitter, loss)
    # и обогащал отчёт — но НЕ фильтровал узлы. На 14000 нод это 14000 лишних
    # батарей по 4 пробы. Пользы ноль, времени — часы. Если нужны метрики
    # маршрута — есть initial_check latency_ms и resilience ping_avg.
    # ---------------------------------------------------------------------
    route_report: dict[str, Any] = {"enabled": False, "note": "удалён в v11"}

    # NOTE: отдельный Zapret-этап и dpi_suite УДАЛЕНЫ в v11. DPI-этап делает
    # только классическую проверку (alive + tcp 16-20 + siberian + CIDR).

    if args.limit > 0:
        working = working[: args.limit]

    # ---------------------------------------------------------------------
    # GEO-СТАДИЯ: переименование узлов (флаг страны + префикс, БЕЗ скорости
    # в имени). Идёт ДО финального спидтеста: замер скорости не меняет имена.
    # ---------------------------------------------------------------------
    last_call: list[float] = [0.0]
    geo_total = len(working)

    def progress_geo(index: int, total: int, name: str) -> None:
        if cancel_event and cancel_event.is_set():
            raise RuntimeError("refresh_cancelled")
        while pause_event and pause_event.is_set():
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            time.sleep(0.2)
        if total == 0:
            return
        if geo_idx >= 0:
            progress.update(index, name)

    if geo_idx >= 0:
        progress.start_stage(geo_idx, f"geo-тег {geo_total} узлов")
        progress.set_total(geo_idx, geo_total)

    rows = serialize_working(
        working,
        geo_cache,
        last_call,
        timeout=min(8.0, args.timeout),
        progress=progress_geo,
    )
    if geo_idx >= 0:
        progress.finish_stage(geo_idx, f"[geo] done: {len(rows)} nodes geo-tagged")

    # ---------------------------------------------------------------------
    # ФИНАЛЬНЫЙ СПИДТЕСТ (v10): САМЫЙ КОНЕЦ, ПОСЛЕ переименования.
    # ОТБРАКОВЫВАЮЩИЙ: узел ниже порога НЕ попадает в подписку.
    # Порог: effective_min_speed_kbps = min(args.min_speed, baseline*0.6),
    # где baseline — прямой замер канала ДО тестов (см. этап baseline выше).
    # На мобильной раздаче (5-15 Мбит/с) порог 5000 КБ/с физически недостижим,
    # поэтому baseline адаптирует его под реальный канал.
    #
    # Вердикты по узлу:
    #   PASS  — speed >= порога → узел в подписке.
    #   SLOW  — 0 < speed < порога → узел НЕ в подписке (отбракован как
    #           «полудохлый» — именно это пользователь просил исправить).
    #   DEAD  — speed не измерилась (None) → узел НЕ в подписке, независимо
    #           от alive_probe. Раньше «alive=True, speed=None» оставался в
    #           подписке как SKIP — это и были «полудохлые» узлы, которые
    #           проходят HEAD, но не тянут реальный трафик.
    # Только скорость: tg-медиа уже проверено на этапе telegram_pro.
    # ---------------------------------------------------------------------
    recheck_report: dict[str, Any] = {}
    if not args.no_stress and rows:
        recheck_orig_count = len(working)
        # Адаптивный порог: если baseline измерил канал, используем min(пользовательский, 60% канала).
        # Если baseline не измерял (no-stress, перепроверка) — порог из args.min_speed.
        # Это исправляет инцидент «на мобильной раздаче все ноды отбракованы»:
        # канал 10 Мбит/с = 1280 КБ/с, порог 5000 КБ/с физически недостижим.
        recheck_min_speed = float(effective_min_speed_kbps)
        # Если порог меньше 100 КБ/с — это явно ошибка/нуль, ставим минимум 100.
        recheck_min_speed = max(100.0, recheck_min_speed)
        log(
            f"[sub] Финальный спидтест (отсеивающий, после переименования), "
            f"порог={recheck_min_speed:.0f} Kbps"
            + (
                f" (адаптирован под канал: args.min_speed={args.min_speed}, baseline*0.6)"
                if recheck_min_speed < float(args.min_speed)
                else f" (из args.min_speed)"
            )
            + f", checking {recheck_orig_count} nodes..."
        )
        log(f"[sub] recheck: параллельно, {min(args.workers, max(1, recheck_orig_count))} потоков")
        if recheck_idx >= 0:
            progress.start_stage(recheck_idx, f"финальный спидтест {recheck_orig_count} узлов")
            progress.set_total(recheck_idx, recheck_orig_count)

        # Источники замера скорости загрузки (пробуем по порядку, первый
        # успешный результат берём). speed.cloudflare.com не работает через
        # Cloudflare Worker-прокси (даёт None/0), поэтому нужны fallback-хосты.
        _SPEED_TIMEOUT = min(8.0, args.timeout)

        # У Cloudflare Worker-узлов есть ramp-up: короткий замер (512KB/2.5s)
        # замеряет начальный медленный участок и сильно занижает скорость
        # (проверено: 1.8→7.6 MB/s на том же узле). Поэтому финальный замер
        # использует большой объём (16MB) и более длинный sample-период (8s).
        _BIG_TIMEOUT = max(8.0, _SPEED_TIMEOUT)

        def _probe_download(socks_host: str, socks_port: int) -> float | None:
            # Единый замер скорости (NDT7 → speed.cloudflare.com → proof.ovh.net
            # → speedtest.tele2.net, 16MB/8s) — тот же, что раньше в стресс-тесте.
            return _download_speed_probe(socks_host, socks_port, _BIG_TIMEOUT)

        def _speed_probe(socks_host: str, socks_port: int) -> float | None:
            # 3 полные попытки (без раннего выхода), берём максимум.
            # На заново поднятом core-процессе первый замер сильно занижен
            # (холодный старт TCP/TLS, ramp-up у Worker-узлов).
            samples: list[float] = []
            for _ in range(3):
                val = _probe_download(socks_host, socks_port)
                if val is not None and val > 0:
                    samples.append(val)
            return max(samples) if samples else None

        def _alive_probe(socks_host: str, socks_port: int) -> bool:
            # Проверка живости через простой HEAD на несколько хостов.
            # Если ни один не отвечает — узел мёртв (прокси поднялся, но
            # реальный трафик не проходит). Проверено: у "мёртвых" worker-узлов
            # замер скорости даёт None, и HEAD тоже не отвечает.
            for host in ("api.telegram.org", "example.com", "www.google.com"):
                try:
                    res = _socks_https_head_status(socks_host, socks_port, host, 443, host, min(8.0, args.timeout), "/")
                except Exception:  # noqa: BLE001
                    res = None
                if res is not None and res[0] < 500:
                    return True
            return False

        # Большой замер (16MB/8s на каждый источник, до 3 попыток) может занять
        # дольше дефолтного budget — даём явный запас.
        _RECHECK_BUDGET = max(150.0, min(8.0, args.timeout) * 6.0)

        def _check_speed_node(w: Any) -> tuple[float | None, bool | None]:
            speed_kbps = run_with_node(
                w.node.raw_url,
                _speed_probe,
                timeout=min(8.0, args.timeout),
                budget=_RECHECK_BUDGET,
            )
            if speed_kbps is not None:
                return (float(speed_kbps), None)
            # Скорость не измерилась — проверяем живость для информативности
            # отчёта. В новом (отсеивающем) режиме узел всё равно отбраковывается,
            # но alive=True в отчёте поможет диагностике («узел отвечает, но
            # не тянет трафик» — это и есть «полудохлая» нода).
            alive = run_with_node(
                w.node.raw_url,
                _alive_probe,
                timeout=min(8.0, args.timeout),
                budget=max(60.0, min(8.0, args.timeout) * 4.0),
            )
            return (None, bool(alive))

        # Скорость нельзя мерить толпой: при 32 параллельных замерах один
        # канал делится на 32 — все узлы «медленные» (требование пользователя:
        # «учитывай, что в 1 сети параллельно тестируется туча конфигураций»).
        # Спидтест — максимум 4 параллельных замера.
        # Если baseline измерил канал, дополнительно ограничиваем параллелизм
        # на медленных сетях (полоса < 2 Мбит/с → только 1-2 замера).
        speed_workers = min(int(args.workers), 4)
        if baseline_report.get("enabled") and baseline_report.get("measurement", {}).get("download_kbps"):
            baseline_dl = float(baseline_report["measurement"]["download_kbps"])
            baseline_mbits = baseline_dl * 8 / 1000.0
            if baseline_mbits < 2.0:
                speed_workers = 1
                log(f"[sub] спидтест: 1 поток (канал < 2 Мбит/с — замеры последовательны)")
            elif baseline_mbits < 10.0:
                speed_workers = min(speed_workers, 2)
                log(f"[sub] спидтест: {speed_workers} потока (канал < 10 Мбит/с)")
            else:
                log(f"[sub] спидтест: параллельно, {speed_workers} потоков (полоса не делится на толпу)")
        else:
            log(f"[sub] спидтест: параллельно, {speed_workers} потоков (полоса не делится на толпу)")

        pairs = _parallel_map_nodes(
            working,
            _check_speed_node,
            workers=speed_workers,
            stage_idx=recheck_idx,
            progress=progress,
            label="recheck",
            cancel_event=cancel_event,
            pause_event=pause_event,
        )

        # rows соответствуют working по индексу (serialize_working сохраняет
        # порядок) — отбрасываем мёртвые/медленные из обоих списков согласованно.
        kept_working: list[Any] = []
        kept_rows: list[dict[str, Any]] = []
        failed_recheck = 0      # DEAD — speed=None (полностью мёртвый)
        slow_recheck = 0        # SLOW — 0<speed<порога (полудохлый, отбракован)
        skip_recheck = 0        # SKIP — speed=None, но alive=True (тоже отбракован,
                                #   но причина — «не измерилось», а не «мёртв»)
        recheck_speeds: dict[str, dict[str, Any]] = {}
        for idx, ((w, outcome), row) in enumerate(zip(pairs, rows), 1):
            speed_kbps, alive = outcome if outcome else (None, None)
            if speed_kbps is not None:
                w.download_kbps = speed_kbps
                row["download_kbps"] = round(float(speed_kbps), 1)
            recheck_speeds[row.get("name") or w.node.title()] = {
                "speed_kbps": None if speed_kbps is None else round(float(speed_kbps), 1),
                "alive": alive,
                "passed": bool(speed_kbps is not None and speed_kbps >= recheck_min_speed),
                "threshold_kbps": round(recheck_min_speed, 1),
            }
            if speed_kbps is None:
                # Скорость не измерилась — узел не тянет реальный трафик.
                # Раньше (v9) такой узел оставался в подписке как SKIP, если
                # alive_probe проходил. Это и были «полудохлые» ноды, которые
                # пользователь видит в финальной подписке. Теперь отбраковываем.
                if alive is True:
                    skip_recheck += 1
                    log(
                        f"[recheck] SKIP→FAIL {idx}/{recheck_orig_count}: {row.get('name') or w.node.title()} "
                        f"(скорость не измерилась, узел отвечает HEAD, но не тянет трафик — отбракован)"
                    )
                else:
                    failed_recheck += 1
                    log(f"[recheck] DEAD {idx}/{recheck_orig_count}: {row.get('name') or w.node.title()} (скорость не измерилась, узел не отвечает)")
            elif speed_kbps >= recheck_min_speed:
                kept_working.append(w)
                kept_rows.append(row)
                log(f"[recheck] PASS {idx}/{recheck_orig_count}: {row.get('name') or w.node.title()} ({speed_kbps:.1f} Kbps ≥ {recheck_min_speed:.0f})")
            else:
                # SLOW — узел медленный, ниже порога. Отбраковываем.
                slow_recheck += 1
                log(
                    f"[recheck] SLOW→FAIL {idx}/{recheck_orig_count}: {row.get('name') or w.node.title()} "
                    f"({speed_kbps:.1f} Kbps < {recheck_min_speed:.0f} — отбракован как полудохлый)"
                )

        if recheck_idx >= 0:
            progress.finish_stage(
                recheck_idx,
                f"[recheck] done: {len(kept_working)} passed, {slow_recheck} slow (отбракованы), "
                f"{skip_recheck} skip (отбракованы), {failed_recheck} dead",
            )

        working = kept_working
        rows = kept_rows
        total_dropped = failed_recheck + slow_recheck + skip_recheck
        if total_dropped > 0:
            log(
                f"[sub] filtered out {total_dropped} nodes (final speed re-check): "
                f"{failed_recheck} dead, {skip_recheck} skip (no-speed-but-alive), {slow_recheck} slow (<{recheck_min_speed:.0f} Kbps)"
            )

        recheck_report = {
            "enabled": True,
            "checked": recheck_orig_count,
            "passed": len(kept_working),
            "slow": slow_recheck,
            "skip": skip_recheck,
            "failed": failed_recheck,
            "min_speed_kbps": recheck_min_speed,
            "user_min_speed_kbps": float(args.min_speed),
            "baseline_applied": bool(recheck_min_speed < float(args.min_speed)),
            "informative": False,
            "mode": "filtering",
            "note": "спидтест ОТБРАКОВЫВАЮЩИЙ: slow-узлы (<порога) и skip-узлы (speed=None, alive=True) НЕ попадают в подписку. "
                    "Порог адаптирован под канал: min(args.min_speed, baseline*0.6).",
            "speeds": recheck_speeds,
        }

        # Финальный набор в DPI-файлах: перезаписываем их узлами, которые
        # прошли ВЕСЬ конвейер + финальную проверку живости (раньше туда
        # попадали узлы до DPI-ACTIVE, из-за чего в подписке user'а оказывались
        # «уже умершие» конфиги — инцидент лог6, сентябрь 2026).
        if args.dpi_check:
            final_urls = urls_text(working)
            write_file(_resolve_path(args.working_dpi), final_urls)
            write_file(_resolve_path(args.out_dpi), base64.b64encode(final_urls.encode("utf-8")).decode("ascii"))
            log(f"[sub] финальный набор (после спидтеста) записан в DPI-файлы: {len(working)} nodes")
            # v11: Zapret-suite удалён из конвейера; блок `if run_suite:` убран —
            # переменная не существовала, NameError при --dpi-check.

    progress.close()

    subscription_b64 = write_subscription_files(
        rows,
        working_path=working_path,
        out_path=out_path,
        plain=False,
    )

    # WARP генерация удалена — обычные warp:// URL блокируются на
    # мобильных сетях РФ и бесполезны.

    # Отчёт.
    report: dict[str, Any] = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": sources,
        "dedup_mode": getattr(args, "dedup_mode", "normal"),
        "discovered": len(discovered),
        "working": len(working),
        "rejected": len(rejected),
        "exported": len(rows),
        "geo_unknown": sum(1 for r in rows if r["country_code"] == GEOIP_FALLBACK_CODE),
        # Сетевой профиль прогона (v8.2): p50 initial_check, slow_mode —
        # видно, какой сетью шёл прогон и почему таймауты адаптированы.
        "network": network_report,
        "baseline": baseline_report,
        "initial_check": initial_check_report,
        "telegram_pro": telegram_pro_report,
        "services": services_report,
        "dpi": dpi_report,
        "dpi_active": dpi_active_report,
        "ai_geo": ai_geo_report,
        "route": route_report,
        # Совместимость: зеркало suite-части DPI-этапа под старым ключом
        # "zapret" (раньше был отдельный этап — теперь suite внутри dpi).
        "zapret": dpi_report.get("suite", {"enabled": False}) if dpi_report else {"enabled": False},
        "resilience": resilience_report,
        "recheck": recheck_report,
        "nodes": rows,
    }

    write_report(report_path, report)

    # Сохранить geo-кеш.
    write_geo_cache(geo_cache_path, geo_cache)

    log(f"[sub] done: exported {len(rows)} nodes")
    log(f"[sub] subscription: {out_path} ({len(subscription_b64)} bytes)")
    log(f"[sub] working:      {working_path}")
    log(f"[sub] report:       {report_path}")
    log(f"[sub] geo-cache:    {geo_cache_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(argv)
