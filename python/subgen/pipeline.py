"""Основной конвейер: сборка узлов -> проверки -> подписка -> отчёт."""
from __future__ import annotations

import argparse
import base64
import contextlib
import socket
import ssl
import threading
import time
import urllib.request

from pathlib import Path
from typing import Any

from checkers import DPI_DEFAULT_TARGET, check_node_dpi_detailed
from checkers.net_diagnostic import run_network_diagnostic
from checkers.base import run_with_node
from checkers.initial_check import run_initial_check, format_result as format_initial_check_result
from checkers.dpi_active import DPI_ACTIVE_MIN_SCORE, DpiActiveResult, check_node_dpi_active_detailed

from checkers.telegram_pro import TG_TIMEOUT, TelegramProResult, check_node_telegram_pro_detailed
from checkers.route import (
    ROUTE_PROBE_TIMEOUT,
    ROUTE_PROBES,
    RouteCheckResult,
    check_node_route_detailed,
)

from checkers.zapret import (
    SLOW_NETWORK_RTT_MS,
    effective_suite_params,
    load_dpi_suite,
)
from xray_runtime import _download_speed_probe, _socks_https_head_status


from subgen.config import DEFAULT_SOURCES_FILE, DATA_DIR, GEOIP_FALLBACK_CODE, ROOT
from subgen.geo import load_geo_cache, serialize_working
from subgen.logging import log
from subgen.output import (
    append_text,
    build_subscription,
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
    parser.add_argument("--no-telegram", action="store_true", help="Отключить ВСЕ Telegram-проверки, включая обязательный медиа-фильтр (t.me/s/): каждый узел в финале обязан реально качать видео из Telegram (>= 512 КБ/с), иначе — отбраковка (tg_media_failed). С флагом узлы принимаются только по спид-тесту.")
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
    parser.add_argument("--initial-check-timeout", type=float, default=3.0, help="Таймаут начальной проверки доступности (TCP+HTTP HEAD), сек (по умолчанию 3).")
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
        "--start-stage",
        choices=["ping", "initial", "telegram_pro", "dpi", "dpi_active", "ai_geo", "route", "resilience", "recheck", "zapret"],
        default="ping",
        help="С какого этапа начать перепроверку. 'ping' — полный прогон с нуля; "
        "остальные — пропустить распинговку и стресс-тест и начать с указанного "
        "этапа, используя сохранённые рабочие конфиги (data/.runtime_cache). "
        "'zapret' — устаревший алиас 'dpi'.",
    )
    # NOTE: --tun-check и WARP-аргументы (--add-warp/--warp-preset/--warp-dns)
    # удалены вместе со всей TUN/WARP-функциональностью.

    # --- Пост-обработка алиасов (после parse_args, в run()) ---
    return parser


# Порядок этапов перепроверки (--start-stage). Синхронизирован с
# ui/pages/recheck_page.py (STAGES) — регрессионный тест сверяет.
# 'zapret' сюда НЕ входит: функционал тестирования Zapret объединён с
# этапом 'dpi' (алиас 'zapret' ремапится на 'dpi').
# v8.2: telegram_pro стоит ДО dpi — Telegram-проверка (голосовые) —
# главный критерий пользователя и должна отмеряться раньше жёсткого
# DPI-гейта (инцидент 2026-09-02: на мобильной сети DPI забраковал все
# 106 узлов до того, как Telegram-проверка вообще началась).
STAGE_ORDER: tuple[str, ...] = (
    "ping",
    "initial",
    "telegram_pro",
    "dpi",
    "dpi_active",
    "ai_geo",
    "route",
    "resilience",
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
    custom = str(args.custom_file or "").strip()
    if custom:
        path = Path(custom).expanduser().resolve()
        log(f"[sub] custom config file: {path}")
        return [str(path)]
    if args.sources is not None:
        return [str(u).strip() for u in args.sources if str(u).strip()]
    try:
        return [
            line.strip()
            for line in DEFAULT_SOURCES_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError:
        log(f"[sub] WARNING: не найден {DEFAULT_SOURCES_FILE}, используем --sources или пустой список")
        return []



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
    except Exception:
        pass
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
    except Exception:
        pass

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


def run(
    argv: list[str] | None = None,
    cancel_event: threading.Event | None = None,
    pause_event: threading.Event | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Ремап устаревших флагов/этапов (zapret→dpi, ai-strict→ai-check).
    args = _apply_stage_aliases(args)


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
    # Zapret-этап УДАЛЁН: функционал тестирования Zapret (DPI suite tcp 16-20
    # + HTTP-тест) — ЧАСТЬ этапа 'dpi': один core-процесс на узел, без дубля
    # tcp 16-20. Suite выполняется при каждом включённом --dpi-check
    # (v8: отдельных тумблеров/флагов больше нет). Вес dpi это учитывает.
    run_suite = bool(getattr(args, "dpi_check", False))
    progress = _PowerShellProgress()
    progress.add_stage("load", 0.05, total=len(sources))
    progress.add_stage("ping", 0.25, total=1)
    if not args.no_stress:
        progress.add_stage("stress", 0.35, total=1)
    progress.add_stage("initial_check", 0.10, total=1)
    if not args.no_telegram:
        progress.add_stage("telegram_pro", 0.10, total=1)
    if args.dpi_check:
        progress.add_stage("dpi", 0.15 + (0.15 if run_suite else 0.0), total=1)
    if args.dpi_active:
        progress.add_stage("dpi_active", 0.10, total=1)
    if getattr(args, "ai_check", False):
        progress.add_stage("ai_geo", 0.08, total=1)
    progress.add_stage("route", 0.10, total=1)
    # Resilience check теперь всегда включён (по умолчанию), но можно отключить через --no-resilience-check
    resilience_enabled = getattr(args, 'resilience_check', True)

    if resilience_enabled:
        progress.add_stage("resilience", 0.10, total=1)
    progress.add_stage("recheck", 0.05, total=1)
    progress.add_stage("geo", 0.10, total=1)

    ping_idx = progress.stage_index("ping")
    stress_idx = progress.stage_index("stress")
    initial_idx = progress.stage_index("initial_check")
    dpi_idx = progress.stage_index("dpi")
    dpi_active_idx = progress.stage_index("dpi_active")
    telegram_pro_idx = progress.stage_index("telegram_pro")
    ai_geo_idx = progress.stage_index("ai_geo")
    route_idx = progress.stage_index("route")
    resilience_idx = progress.stage_index("resilience") if resilience_enabled else -1
    recheck_idx = progress.stage_index("recheck")
    geo_idx = progress.stage_index("geo")



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

        # Фильтр по скорости для 1080p (только при стресс-тесте).
        # Telegram-медиа фильтр (обязательный, v7) уже отработал в стресс-тесте:
        # узлы, не качающие видео из t.me/s/, отбракованы там (tg_media_failed).
        # Исключений больше нет — порог скорости един для всех.
        if not args.no_stress:
            min_speed = args.min_speed
            orig_count = len(working)
            working = [
                w
                for w in working
                if w.download_kbps is None
                or w.download_kbps >= min_speed
            ]
            if len(working) < orig_count:
                log(f"[sub] filtered out {orig_count - len(working)} nodes with speed < {min_speed} Kbps")
    else:
        # Перепроверка с этапа: распинговка и стресс-тест уже выполнены ранее,
        # их результаты сохранены в кеше. Загружаем рабочие конфиги и начинаем
        # с указанного этапа (initial/dpi/dpi_active/telegram_pro/ai_geo/
        # route/resilience/recheck).
        log(f"[sub] перепроверка с этапа '{start_stage}' (пропуск распинговки и стресс-теста)")
        working = _load_cached_working()
        rejected: list[Any] = []
        discovered: list[Any] = []
        if not working:
            log("[sub] ERROR: нет сохранённых рабочих конфигов для перепроверки. Сначала выполните полный прогон.")
            progress.close()
            return 1

        # Отмечаем этапы load/ping/stress как завершённые (они пропущены).
        load_idx = progress.stage_index("load")
        if load_idx >= 0:
            progress.finish_stage(load_idx, f"[load] пропущен (перепроверка с {start_stage})")
        if ping_idx >= 0 and not progress.is_completed(ping_idx):
            progress.finish_stage(ping_idx, f"[ping] пропущен (перепроверка с {start_stage})")
        if stress_idx >= 0 and not progress.is_completed(stress_idx):
            progress.finish_stage(stress_idx, f"[stress] пропущен (перепроверка с {start_stage})")

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
        if not _stage_enabled_from(start_stage, "route"):
            if route_idx >= 0 and not progress.is_completed(route_idx):
                progress.finish_stage(route_idx, f"[route] пропущен (перепроверка с {start_stage})")
        if not _stage_enabled_from(start_stage, "resilience"):
            resilience_enabled = False
            if resilience_idx >= 0 and not progress.is_completed(resilience_idx):
                progress.finish_stage(resilience_idx, f"[resilience] пропущен (перепроверка с {start_stage})")

    # ---------------------------------------------------------------------
    # Initial Check: быстрая проверка доступности (TCP + HTTP HEAD).
    # Обязательный системный этап первичного отсева (Fail Fast): отсеивает
    # мёртвые узлы за 2-3 сек ДО дорогих проверок. Выполняется при полном
    # прогоне; при перепроверке с этапа узлы уже проверены — пропускаем.
    # ---------------------------------------------------------------------
    initial_check_report: dict[str, Any] = {}
    if start_stage == "ping":
        initial_orig_count = len(working)
        log(f"[sub] Initial check enabled, timeout={args.initial_check_timeout}s, checking {initial_orig_count} nodes...")
        if initial_idx >= 0:
            progress.start_stage(initial_idx, f"Initial check {initial_orig_count} узлов")
            progress.set_total(initial_idx, initial_orig_count)

        checked_initial: list[Any] = []
        failed_initial = 0
        initial_node_details: dict[str, Any] = {}
        for idx, w in enumerate(working, 1):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                time.sleep(0.2)
            if initial_idx >= 0:
                progress.update(idx, f"Initial {w.node.title()}")

            proxy_url = w.node.raw_url
            res = run_initial_check({}, proxy_url, timeout=args.initial_check_timeout)
            initial_node_details[w.node.title()] = res
            if res["passed"]:
                checked_initial.append(w)
                log(f"[initial] PASS {idx}/{initial_orig_count}: {w.node.title()} ({format_initial_check_result(res)})")
            else:
                failed_initial += 1
                log(f"[initial] FAIL {idx}/{initial_orig_count}: {w.node.title()} ({format_initial_check_result(res)})")

        if initial_idx >= 0:
            progress.finish_stage(
                initial_idx,
                f"[initial] done: {len(checked_initial)} passed, {failed_initial} failed",
            )

        working = checked_initial
        if failed_initial > 0:
            log(f"[sub] filtered out {failed_initial} nodes that failed initial check")

        initial_check_report = {
            "enabled": True,
            "checked": initial_orig_count,
            "passed": len(checked_initial),
            "failed": failed_initial,
            "nodes": initial_node_details,
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

    # Продвинутая Telegram-проверка (MTProto connect/auth, upload)
    # с расчётом telegram_score. Ставится ДО DPI-этапа: Telegram — главный
    # критерий пользователя (голосовые должны грузиться и отправляться), и
    # узлы должны отмеряться им раньше, чем жёстким DPI-гейтом,
    # откалиброванным под широкополосный доступ (инцидент 2026-09-02: на
    # мобильной сети DPI убил все 106 нод до того, как Telegram-проверка
    # вообще началась — 0 нод проверено).
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
        if telegram_pro_idx >= 0:
            progress.start_stage(telegram_pro_idx, f"Telegram-проверка {telegram_pro_orig_count} узлов")
            progress.set_total(telegram_pro_idx, telegram_pro_orig_count)

        checked_telegram_pro: list[Any] = []
        failed_telegram_pro = 0
        telegram_pro_node_details: dict[str, Any] = {}
        for idx, w in enumerate(working, 1):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                time.sleep(0.2)
            if telegram_pro_idx >= 0:
                progress.update(idx, f"Telegram {w.node.title()}")

            res: TelegramProResult = check_node_telegram_pro_detailed(
                w.node.raw_url,
                timeout=tg_timeout,
            )
            telegram_pro_node_details[w.node.title()] = res.row()
            if res.accepted:
                checked_telegram_pro.append(w)
                log(
                    f"[telegram-pro] PASS {idx}/{telegram_pro_orig_count}: {w.node.title()} "
                    f"(score={res.telegram_score} connect={res.connect}({res.connect_ms}ms) "
                    f"auth={res.auth} up={res.upload_kbps}KB/s)"
                )
            else:
                failed_telegram_pro += 1
                log(
                    f"[telegram-pro] FAIL {idx}/{telegram_pro_orig_count}: {w.node.title()} "
                    f"(score={res.telegram_score} connect={res.connect} auth={res.auth} "
                    f"up={res.upload_kbps}KB/s reason={res.reason})"
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
            "nodes": telegram_pro_node_details,
        }

    # DPI-проверка (обход блокировок) через XrayCoreRuntime.
    # СЛИЯНИЕ: Zapret-функционал (DPI suite tcp 16-20: POST 64KB на цели
    # suite.v2.json по 3 протоколам + HTTP-тест) выполняется ВНУТРИ этого же
    # этапа при включённом --dpi-suite — один core-процесс на узел, без
    # дубля tcp 16-20. Отдельный zapret-этап удалён.
    dpi_report: dict[str, Any] = {}
    if args.dpi_check:
        timeout = get_threshold("dpi", "timeout", 10.0)
        require_siberian = args.dpi_siberian or get_threshold("dpi", "require_siberian", False)
        require_cidr = args.dpi_cidr or get_threshold("dpi", "require_cidr", False)

        # --- Suite (Zapret-методика) внутри DPI-этапа ---
        # Параметры сьюта адаптируются под измеренный RTT сети
        # (effective_suite_params): таймаут RTT*8 (до 20с), на медленных сетях
        # 4 цели / без HTTP-теста / порог 0.5. Без адаптации «медленный канал»
        # неотличим от «DPI-фриз» и сьют бракует все узлы подряд (инцидент
        # 2026-09-02, мобильная сеть: 106/106 FAIL при suite=0-1/24 за 3 часа;
        # те же узлы на WiFi — 23/24).
        suite_params: dict[str, Any] = {}
        suite_targets = None
        suite_timeout = max(2.0, float(getattr(args, "dpi_suite_timeout", 5.0)))
        suite_min_score = max(0.0, min(1.0, float(getattr(args, "dpi_suite_min_score", 0.75))))
        suite_http = not bool(getattr(args, "dpi_suite_no_http", False))
        if run_suite:
            suite_max_targets = max(1, int(getattr(args, "dpi_suite_targets", 8)))
            suite_params = effective_suite_params(
                network_rtt_ms,
                timeout=suite_timeout,
                min_score=suite_min_score,
                max_targets=suite_max_targets,
                run_http_test=suite_http,
            )
            suite_timeout = suite_params["timeout"]
            suite_min_score = suite_params["min_score"]
            suite_http = suite_params["run_http_test"]
            suite_targets = load_dpi_suite(max_targets=suite_params["max_targets"])

        orig_dpi_count = len(working)
        target = args.dpi_target or DPI_DEFAULT_TARGET
        log(
            f"[sub] DPI check enabled, target={target}, siberian={'on' if require_siberian else 'info'} "
            f"cidr={'on' if require_cidr else 'info'}"
            + (
                f", suite=on (zapret-методика, {len(suite_targets)} целей, timeout={suite_timeout:.0f}с, "
                f"min_score={suite_min_score:.2f}, http_test={'on' if suite_http else 'off'}"
                + (", slow-mode: канал медленный" if suite_params.get("slow_mode") else "")
                + ")"
                if run_suite
                else ", suite=off"
            )
            + f", checking {orig_dpi_count} nodes..."
        )
        if dpi_idx >= 0:
            progress.start_stage(dpi_idx, f"DPI-проверка {orig_dpi_count} узлов")
            progress.set_total(dpi_idx, orig_dpi_count)
        working_dpi_path = _resolve_path(args.working_dpi)
        out_dpi_path = _resolve_path(args.out_dpi)
        write_file(working_dpi_path, "")
        write_file(out_dpi_path, "")
        checked: list[Any] = []
        failed = 0
        slow_network_passed = 0  # узлы, принятые с suite_slow_network (сеть, не узел)
        _tcp_labels = {
            "not_detected": "not detected ✅",
            "possible": "possible detected ⚠️",
            "probably": "probably detected ⚠️",
            "unlikely": "unlikely ⚠️",
            "detected": "detected ❗️",
        }

        # Проверяем кэш если включён
        cache_enabled = get_threshold("cache", "enabled", True)

        for idx, w in enumerate(working, 1):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                time.sleep(0.2)
            if dpi_idx >= 0:
                progress.update(idx, f"DPI {w.node.title()}")

            # Проверка кэша
            cached_passed = None
            if cache_enabled:
                cached_passed, _ = check_cached(w.node.raw_url, "dpi")

            if cached_passed is not None:
                # Используем кэшированный результат
                res = None  # заглушка, т.к. нет детального результата из кэша
                passed = cached_passed
                log(f"[dpi] CACHED {'PASS' if passed else 'FAIL'} {idx}/{orig_dpi_count}: {w.node.title()}")
            else:
                # Выполняем реальную проверку (классика DPI + suite, если включён)
                res = check_node_dpi_detailed(
                    w.node.raw_url,
                    target_host=target,
                    timeout=timeout,
                    require_siberian=require_siberian,
                    require_cidr=require_cidr,
                    run_suite=run_suite,
                    suite_targets=suite_targets,
                    suite_timeout=suite_timeout,
                    suite_min_score=suite_min_score,
                    suite_http_test=suite_http,
                    rtt_hint_ms=network_rtt_ms,
                )
                passed = res.accepted

                # Сохраняем в кэш
                if cache_enabled:
                    cache_result(w.node.raw_url, "dpi", passed, res.row() if res else {})

            tcp_label = _tcp_labels.get(res.tcp1620_level, res.tcp1620_level) if res else "cached"
            suite_label = ""
            if res is not None and res.suite_run:
                suite_label = f" suite={res.suite_score_text}"
            slow_net_label = ""
            if res is not None and res.reason == "suite_slow_network":
                # Фикс «dpi уронил всё на мобильной сети»: классика прошла, а
                # suite завален таймаутами на медленном канале — вердикт по
                # классике, маркер в логе/отчёте.
                slow_net_label = " ⚠️ сеть медленная — suite не вето, вердикт по классике"
                slow_network_passed += 1
            if passed:
                checked.append(w)
                append_text(working_dpi_path, w.node.raw_url + "\n")
                log(f"[dpi] PASS {idx}/{orig_dpi_count}: {w.node.title()} (tcp 16-20: {tcp_label}{suite_label}{slow_net_label})")
            else:
                failed += 1
                reason = res.reason if res else "cached_fail"
                log(f"[dpi] FAIL {idx}/{orig_dpi_count}: {w.node.title()} (reason={reason}{suite_label})")
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

        # Совместимость: при включённом suite пишем и старые zapret-файлы
        # (тот же набор узлов — подписки/скрипты, завязанные на имена файлов,
        # продолжают работать).
        if run_suite:
            working_zapret_path = _resolve_path(args.zapret_working)
            out_zapret_path = _resolve_path(args.zapret_out)
            zap_urls = urls_text(working)
            write_file(working_zapret_path, zap_urls)
            write_file(out_zapret_path, base64.b64encode(zap_urls.encode("utf-8")).decode("ascii"))
            log(f"[sub] saved {len(working)} DPI+suite-passed nodes -> {working_zapret_path} / {out_zapret_path}")

        dpi_report = {
            "enabled": True,
            "checked": orig_dpi_count,
            "passed": len(checked),
            "failed": failed,
            "slow_network_passed": slow_network_passed,
            "target": target,
            "suite": {
                "enabled": run_suite,
                "targets": [
                    {"id": t.id, "provider": t.provider, "country": t.country, "host": t.host}
                    for t in (suite_targets or [])
                ],
                "timeout_sec": suite_timeout,
                "adaptive_timeout_max": 20.0,
                "http_test": suite_http,
                "min_score": suite_min_score,
                "rtt_hint_ms": suite_params.get("rtt_hint_ms"),
                "slow_mode": suite_params.get("slow_mode"),
            }
            if run_suite
            else {"enabled": False},
        }

    # Активная DPI-проверка ПРОТОКОЛА узла (SNI-варианты, фрагментация/большой
    # ClientHello, ECH, TLS 1.2/1.3). Отвечает на вопрос: сможет ли узел обходить
    # конкретные DPI-механизмы, а не просто работает ли интернет через него.
    dpi_active_report: dict[str, Any] = {}
    if args.dpi_active:
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
        for idx, w in enumerate(working, 1):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                time.sleep(0.2)
            if dpi_active_idx >= 0:
                progress.update(idx, f"DPI-active {w.node.title()}")

            res: DpiActiveResult = check_node_dpi_active_detailed(
                w.node.raw_url,
                timeout=dpi_active_timeout,
            )
            dpi_active_node_details[w.node.title()] = res.row()
            if res.accepted:
                checked_dpi_active.append(w)
                log(
                    f"[dpi-active] PASS {idx}/{dpi_active_orig_count}: {w.node.title()} "
                    f"(score={res.score} reason={res.reason})"
                )
            else:
                failed_dpi_active += 1
                log(
                    f"[dpi-active] FAIL {idx}/{dpi_active_orig_count}: {w.node.title()} "
                    f"(score={res.score} reason={res.reason})"
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

    # ---------------------------------------------------------------------
    # ИИ-гео слепок (Gemini/OpenAI): под какой страной exit-IP видят
    # ИИ-сервисы. Метод: Cloudflare trace (chatgpt.com/claude.ai, loc=XX —
    # машиночитаемый гео-вердикт Cloudflare перед OpenAI/Anthropic) +
    # страна из футера Google (<div class="O3yKUb">Россия</div> — тот же
    # гео-движок, что у Gemini) + досягаемость gemini.google.com.
    # Все запросы через прокси узла: домен резолвит выход узла, системный
    # hosts-файл не участвует — подмены «разблокирующих» записей не влияют.
    # v8: этап ОБЯЗАТЕЛЬНЫЙ — слепок CF (loc=) становится источником флага
    # страны в подписке; --ai-strict (единственная опция) отсеивает слепок-РФ.
    # ---------------------------------------------------------------------
    ai_geo_report: dict[str, Any] = {}
    if getattr(args, "ai_check", False):
        from checkers.ai_geo import AI_GEO_TIMEOUT, AiGeoResult, check_node_ai_geo_detailed

        ai_geo_orig_count = len(working)
        ai_strict = bool(getattr(args, "ai_strict", False))
        ai_timeout = max(3.0, float(getattr(args, "ai_timeout", AI_GEO_TIMEOUT)))
        log(
            f"[sub] AI-geo (обязательный этап: страна для флага по CF-слепку OpenAI, "
            f"strict={'on (слепок РФ -> FAIL)' if ai_strict else 'off'}), timeout={ai_timeout}s, "
            f"checking {ai_geo_orig_count} nodes..."
        )
        if ai_geo_idx >= 0:
            progress.start_stage(ai_geo_idx, f"ИИ-гео слепок {ai_geo_orig_count} узлов")
            progress.set_total(ai_geo_idx, ai_geo_orig_count)

        checked_ai: list[Any] = []
        failed_ai = 0
        ai_geo_node_details: dict[str, Any] = {}
        for idx, w in enumerate(working, 1):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                time.sleep(0.2)
            if ai_geo_idx >= 0:
                progress.update(idx, f"AI-geo {w.node.title()}")

            res: AiGeoResult = check_node_ai_geo_detailed(
                w.node.raw_url,
                timeout=ai_timeout,
            )
            ai_geo_node_details[w.node.title()] = res.row()
            # v8: ISO-код страны из CF-слепка — источник флага в подписке
            # (сохраняется в узле; пусто = слепок недоступен -> обычная
            # цепочка pyip/egress/geoip в subgen.geo.serialize_working).
            w.ai_geo_country = (res.cf_loc or "").strip().upper()
            # Фильтрация только в strict-режиме и только при ДОСТУПНОМ
            # слепке: ai_unblocked=False (слепок РФ). None (сигналы не
            # получены) и node_start_failed — узел НЕ отсеивается.
            node_rejected = bool(ai_strict and res.ai_unblocked is False)
            if not node_rejected:
                checked_ai.append(w)
                log(
                    f"[ai-geo] {idx}/{ai_geo_orig_count}: {w.node.title()} "
                    f"(cf={res.cf_loc or '-'} via {res.cf_source or '-'} "
                    f"google={res.google_country or '-'} gemini={res.gemini_reachable} "
                    f"verdict={res.ai_unblocked} reason={res.reason})"
                )
            else:
                failed_ai += 1
                log(
                    f"[ai-geo] FAIL {idx}/{ai_geo_orig_count}: {w.node.title()} "
                    f"(слепок РФ: cf={res.cf_loc or '-'} google={res.google_country or '-'} "
                    f"reason={res.reason})"
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
            "nodes": ai_geo_node_details,
        }

    # ---------------------------------------------------------------------
    # Проверка стабильности маршрута (RTT: ping_avg/ping_p95/jitter/loss).
    # Системный этап: не фильтрует узлы (Pass/Fail), а только обогащает отчёт
    # метаданными маршрута (для geo-тегирования и диагностики).
    # ---------------------------------------------------------------------
    route_report: dict[str, Any] = {}
    if _stage_enabled_from(start_stage, "route"):
        route_orig_count = len(working)
        log(
            f"[sub] ROUTE trace enabled, probes={ROUTE_PROBES}, checking {route_orig_count} nodes..."
        )
        if route_idx >= 0:
            progress.start_stage(route_idx, f"трассировка маршрута {route_orig_count} узлов")
            progress.set_total(route_idx, route_orig_count)

        route_node_details: dict[str, Any] = {}
        for idx, w in enumerate(working, 1):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                time.sleep(0.2)
            if route_idx >= 0:
                progress.update(idx, f"Route {w.node.title()}")

            res: RouteCheckResult = check_node_route_detailed(
                w.node.raw_url,
                timeout=ROUTE_PROBE_TIMEOUT,
            )
            route_node_details[w.node.title()] = res.row()
            log(
                f"[route] {idx}/{route_orig_count}: {w.node.title()} "
                f"(avg={res.ping_avg}ms p95={res.ping_p95}ms jitter={res.jitter}ms "
                f"loss={res.loss} {res.probes_ok}/{res.probes_total} reason={res.reason})"
            )
        if route_idx >= 0:
            progress.finish_stage(
                route_idx,
                f"[route] done: {route_orig_count} nodes traced",
            )

        route_report = {
            "enabled": True,
            "checked": route_orig_count,
            "nodes": route_node_details,
        }
    else:
        if route_idx >= 0 and not progress.is_completed(route_idx):
            progress.finish_stage(route_idx, f"[route] пропущен (перепроверка с {start_stage})")

    # NOTE: отдельный Zapret-этап УДАЛЁН. Функционал тестирования Zapret
    # (DPI suite tcp 16-20: POST 64KB на цели suite.v2.json по трём
    # протоколам + HTTP-тест, score-логика) выполняется ВНУТРИ DPI-этапа
    # (см. блок выше, --dpi-suite). Старый флаг --zapret-check работает
    # как алиас (--dpi-check --dpi-suite), файлы subs_zapret.txt /
    # working_zapret.txt по-прежнему пишутся при включённом suite.

    # Resilience check: проверка живучести узлов в условиях блокировок (теперь всегда включена по умолчанию).
    # Выполняется ПЕРЕД стресс-тестом для отсеивания мёртвых узлов до дорогих проверок.
    resilience_report: dict[str, Any] = {}

    resilience_enabled = getattr(args, 'resilience_check', True)
    if resilience_enabled:
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
            f"[sub] Resilience check enabled (default), timeout={resilience_timeout}s"
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
        for idx, w in enumerate(working, 1):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh-cancelled")
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh-cancelled")
                time.sleep(0.2)
            if resilience_idx >= 0:
                progress.update(idx, f"Resilience {w.node.title()}")

            res = check_node_resilience_detailed(
                w.node.raw_url,
                timeout=resilience_timeout,
                rtt_hint_ms=resilience_rtt_hint,
            )
            resilience_node_details[w.node.title()] = res.to_dict()

            if res.alive:
                checked_resilience.append(w)
                log(
                    f"[resilience] PASS {idx}/{resilience_orig_count}: {w.node.title()} "
                    f"(mode={res.recommended_mode}, tcp={res.tcp_works}, doh={res.doh_works}, tg={not res.telegram_blocked}, white_sni={res.white_sni_works})"
                )
            else:
                failed_resilience += 1
                # Честная причина отвала: ошибка запуска ядра/бюджета — это НЕ
                # «узел мёртв», раньше оба случая писались как completely_dead.
                fail_reason = (
                    "run_failed (ядро узла не поднялось/бюджет)"
                    if res.recommended_mode == "error"
                    else "completely_dead"
                )
                log(
                    f"[resilience] FAIL {idx}/{resilience_orig_count}: {w.node.title()} "
                    f"({fail_reason})"
                )

            if resilience_idx >= 0:
                progress.finish_stage(resilience_idx, f"[resilience] done: {len(checked_resilience)} passed, {failed_resilience} failed")

        working = checked_resilience
        resilience_urls = "\n".join(w.node.raw_url for w in working) + "\n"
        resilience_report = {
            "enabled": True,
            "checked": resilience_orig_count,
            "passed": len(checked_resilience),
            "failed": failed_resilience,
            "timeout_sec": resilience_timeout,
            "rtt_hint_ms": round(resilience_rtt_hint, 1) if resilience_rtt_hint else None,
            "nodes": resilience_node_details,
        }
    else:
        log("[sub] Resilience check disabled via --no-resilience-check")
        resilience_report = {"enabled": False}

    if args.limit > 0:
        working = working[: args.limit]

    # Финальный спидтест (после всех проверок):
    # поднимаем прокси узла и реально качаем с speed.cloudflare.com, чтобы
    # закрепить скорость и отсеять узлы, которые просели к этому моменту.
    recheck_report: dict[str, Any] = {}
    if not args.no_stress:
        recheck_orig_count = len(working)
        recheck_min_speed = args.min_speed
        log(
            f"[sub] Final speed re-check after all checks, min={recheck_min_speed} Kbps, "
            f"checking {recheck_orig_count} nodes..."
        )
        if recheck_idx >= 0:
            progress.start_stage(recheck_idx, f"финальный спидтест {recheck_orig_count} узлов")
            progress.set_total(recheck_idx, recheck_orig_count)

        rechecked: list[Any] = []
        failed_recheck = 0
        recheck_speeds: dict[str, dict[str, Any]] = {}

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
            # → speedtest.tele2.net, 16MB/8s) — тот же, что в стресс-тесте
            # xray_runtime._download_speed_probe. Стресс-тест и финальный recheck
            # теперь измеряют скорость одинаково, поэтому узел не может пройти
            # начальную проверку и вылететь на финале.
            return _download_speed_probe(socks_host, socks_port, _BIG_TIMEOUT)

        def _speed_probe(socks_host: str, socks_port: int) -> float | None:
            # 3 полные попытки (без раннего выхода), берём максимум.
            # На заново поднятом core-процессе первый замер сильно занижен
            # (холодный старт TCP/TLS, ramp-up у Worker-узлов) — ровно поэтому
            # узел проходит стресс-тест (там 3 раунда на прогретом core + медиана),
            # но вылетает на финальном recheck (там раньше бралось первое значение).
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

        # Большой замер (16MB/8s на каждый источник, до 2 попыток) может занять
        # дольше дефолтного budget (24с) — даём явный запас.
        _RECHECK_BUDGET = max(120.0, min(8.0, args.timeout) * 6.0)

        for idx, w in enumerate(working, 1):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                time.sleep(0.2)
            if recheck_idx >= 0:
                progress.update(idx, f"recheck {w.node.title()}")
            speed_kbps = run_with_node(

                w.node.raw_url,
                _speed_probe,
                timeout=min(8.0, args.timeout),
                budget=_RECHECK_BUDGET,
            )

            if speed_kbps is not None:
                w.download_kbps = speed_kbps

            # Скорость измерить не удалось — проверяем живость. Если узел мёртв
            # (прокси поднялся, но трафик не ходит) — отсеиваем, а не SKIP.
            # Исключений для медиа-узлов больше нет (v7): финальный порог
            # recheck един для всех, медиа-фильтр уже пройден в стресс-тесте.
            alive: bool | None = None
            if speed_kbps is None:
                alive = run_with_node(
                    w.node.raw_url,
                    _alive_probe,
                    timeout=min(8.0, args.timeout),
                    budget=max(60.0, min(8.0, args.timeout) * 4.0),
                )
                alive = bool(alive)

            recheck_speeds[w.node.title()] = {
                "speed_kbps": None if speed_kbps is None else round(speed_kbps, 1),
                "alive": alive,
                "passed": (speed_kbps is not None and speed_kbps >= recheck_min_speed)
                or (speed_kbps is None and alive is True),
            }
            if speed_kbps is None and alive is False:
                failed_recheck += 1
                log(f"[recheck] DEAD {idx}/{recheck_orig_count}: {w.node.title()} (скорость не измерилась, узел не отвечает)")
            elif speed_kbps is None:
                rechecked.append(w)
                log(f"[recheck] SKIP {idx}/{recheck_orig_count}: {w.node.title()} (не удалось измерить скорость, но узел жив)")
            elif speed_kbps >= recheck_min_speed:
                rechecked.append(w)
                log(f"[recheck] PASS {idx}/{recheck_orig_count}: {w.node.title()} ({speed_kbps:.1f} Kbps)")
            else:
                failed_recheck += 1
                log(f"[recheck] FAIL {idx}/{recheck_orig_count}: {w.node.title()} ({speed_kbps:.1f} Kbps < {recheck_min_speed})")


        if recheck_idx >= 0:
            progress.finish_stage(
                recheck_idx,
                f"[recheck] done: {len(rechecked)} passed, {failed_recheck} failed",
            )

        working = rechecked
        if failed_recheck > 0:
            log(f"[sub] filtered out {failed_recheck} nodes that failed final speed re-check")

        recheck_report = {
            "enabled": True,
            "checked": recheck_orig_count,
            "passed": len(rechecked),
            "failed": failed_recheck,
            "min_speed_kbps": recheck_min_speed,
            "speeds": recheck_speeds,
        }

    # Geo-стадия (последняя): определяет имена стран для узлов.
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

    if not args.no_stress:
        rows = serialize_working(
            working,
            geo_cache,
            last_call,
            timeout=min(8.0, args.timeout),
            progress=progress_geo,
        )
    else:
        candidates = [item for item in working if item.accepted]
        rows = serialize_working(
            candidates,
            geo_cache,
            last_call,
            timeout=min(8.0, args.timeout),
            progress=progress_geo,
        )
    if geo_idx >= 0:
        progress.finish_stage(geo_idx, f"[geo] done: {len(rows)} nodes geo-tagged")
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
        "discovered": len(discovered),
        "working": len(working),
        "rejected": len(rejected),
        "exported": len(rows),
        "geo_unknown": sum(1 for r in rows if r["country_code"] == GEOIP_FALLBACK_CODE),
        # Сетевой профиль прогона (v8.2): p50 initial_check, slow_mode —
        # видно, какой сетью шёл прогон и почему таймауты адаптированы.
        "network": network_report,
        "initial_check": initial_check_report,
        "telegram_pro": telegram_pro_report,
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
