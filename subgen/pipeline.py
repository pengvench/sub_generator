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

from checkers.zapret import ZapretCheckResult, check_node_zapret_detailed, load_dpi_suite
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
    parser.add_argument("--no-telegram", action="store_true", help="Отключить все Telegram-проверки: медиа-проверку (загрузку/выгрузку) в стресс-тесте и продвинутую MTProto-проверку (connect/auth, upload, telegram_score). Узлы принимаются только по спид-тесту.")
    parser.add_argument("--plain", action="store_true", help="Не кодировать подписку в base64.")
    parser.add_argument("--dpi-check", action="store_true", help="Включить DPI-проверку через Xray (обход блокировок).")
    parser.add_argument("--dpi-target", default=DPI_DEFAULT_TARGET, help="Целевой хост для DPI-проверки (по умолчанию instagram.com).")
    parser.add_argument("--dpi-siberian", action="store_true", help="DPI: siberian-проверка (множественные TLS-хендшейки с разными SNI) как обязательная отсеивающая.")
    parser.add_argument("--dpi-cidr", action="store_true", help="DPI: CIDR-whitelist проверка как обязательная отсеивающая.")
    parser.add_argument("--dpi-active", action="store_true", help="Включить активную DPI-проверку протокола узла (SNI-варианты, фрагментация/большой ClientHello, ECH, TLS 1.2/1.3).")
    parser.add_argument("--dpi-active-timeout", type=float, default=4.0, help="Таймаут одного варианта активной DPI-проверки, сек (по умолчанию 4).")
    parser.add_argument("--telegram-pro", action="store_true", help="УСТАРЕЛО: продвинутые Telegram-проверки (MTProto connect/auth, upload) и telegram_score теперь выполняются автоматически при включённом Telegram. Флаг оставлен для обратной совместимости (игнорируется, если не задан --no-telegram).")
    parser.add_argument("--zapret-check", action="store_true", help="Включить Zapret-проверку (DPI suite tcp 16-20 + HTTP test, методика C:\\Zapret).")
    parser.add_argument("--initial-check-timeout", type=float, default=3.0, help="Таймаут начальной проверки доступности (TCP+HTTP HEAD), сек (по умолчанию 3).")
    parser.add_argument("--resilience-check", action="store_true", default=True, help="Включить проверку живучести узлов в условиях блокировок (multi-target ping, WHITE-SNI, альтернативные цели). Включено по умолчанию для работы на заблокированных мобильных сетях.")
    parser.add_argument("--no-resilience-check", action="store_false", dest="resilience_check", help="Отключить проверку живучести (не рекомендуется для мобильных сетей РФ).")
    parser.add_argument("--resilience-timeout", type=float, default=4.0, help="Таймаут одного теста resilience-проверки, сек (по умолчанию 4).")

    parser.add_argument("--zapret-out", default="subs_zapret.txt", help="Подписка узлов, прошедших Zapret-проверку.")
    parser.add_argument("--zapret-working", default="working_zapret.txt", help="Рабочие конфиги, прошедшие Zapret-проверку.")
    parser.add_argument("--zapret-targets", type=int, default=8, help="Максимум целей DPI suite на узел (по умолчанию 8).")
    parser.add_argument("--zapret-timeout", type=float, default=5.0, help="Таймаут одного Zapret-теста, сек (по умолчанию 5).")
    parser.add_argument("--zapret-min-score", type=float, default=0.75, help="Мин. доля успешных тестов для принятия узла, 0..1 (по умолчанию 0.75 = ~45/60).")
    parser.add_argument("--zapret-no-http", action="store_true", help="Не выполнять стандартный HTTP-тест (только DPI suite).")
    parser.add_argument("--min-speed", type=int, default=5000, help="Минимальная скорость загрузки в КБ/с для 1080p (по умолчанию 5000).")
    parser.add_argument(
        "--start-stage",
        choices=["ping", "dpi", "zapret", "recheck"],
        default="ping",
        help="С какого этапа начать перепроверку. 'ping' — полный прогон с нуля; "
        "'dpi'/'zapret'/'recheck' — пропустить распинговку и стресс-тест и начать "
        "с указанного этапа, используя сохранённые рабочие конфиги (data/.runtime_cache).",
    )
    parser.add_argument(
        "--tun-check",
        action="store_true",
        help="Тестировать через TUN (Karing-стиль): весь трафик проверок идёт через "
        "виртуальный TUN-адаптер, системные настройки DNS/HTTP не влияют на результаты. "
        "DNS-резолвинг выполняет сам прокси-сервер узла (через outbound). "
        "Требует прав администратора на Windows и wintun.dll для xray-TUN "
        "(sing-box с gvisor работает без внешнего драйвера). "
        "При отсутствии пререквизитов — автоматический fallback на SOCKS-only.",
    )
    parser.add_argument(
        "--add-warp",
        action="store_true",
        help="После завершения тестирования добавить WARP-конфиг в конец подписки. "
        "Запрашивает конфиг у cyb-portal.com /api/warp, конвертирует в warp:// URL "
        "и добавляет в subs.txt/working.txt. WARP не тестируется (Cloudflare стабилен) — "
        "работает как fallback, если все vless-узлы упали.",
    )
    parser.add_argument(
        "--warp-preset",
        type=int,
        nargs="+",
        default=[0],
        help="Пресет(ы) генерации WARP (с --add-warp). Можно указать "
        "несколько через пробел — все выбранные добавятся в подписку. "
        "0 = Авто (1 конфиг от cyb-portal), "
        "1 = Мобильный интернет (3 конфига, порты 2408/500/4500), "
        "2 = Нейросети ChatGPT (2 конфига, WARP+ IP), "
        "3 = Максимальный обход (6 конфигов, все порты). "
        "По умолчанию 0 (Авто). Пример: --warp-preset 1 2 3."
    )
    parser.add_argument(
        "--warp-dns",
        type=str,
        default="",
        help="Кастомный DNS для WARP-конфигов (через запятую). "
        "Например: --warp-dns 111.88.96.50,111.88.96.51 (xbox-dns.ru). "
        "Если не указан — используется DNS из пресета.",
    )
    return parser



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
    try:
        url = "https://cloudflare-dns.com/dns-query?name=google.com&type=A"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/dns-json", "User-Agent": "SubGenerator/1.0"},
        )
        with urllib.request.urlopen(req, timeout=min(timeout, 5.0)) as resp:
            if resp.status == 200:
                result["doh"] = True
    except Exception:
        pass

    return result


def run(
    argv: list[str] | None = None,
    cancel_event: threading.Event | None = None,
    pause_event: threading.Event | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)


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
    progress = _PowerShellProgress()
    progress.add_stage("load", 0.05, total=len(sources))
    progress.add_stage("ping", 0.25, total=1)
    if not args.no_stress:
        progress.add_stage("stress", 0.35, total=1)
    progress.add_stage("initial_check", 0.10, total=1)
    if args.dpi_check:
        progress.add_stage("dpi", 0.15, total=1)
    if args.dpi_active:
        progress.add_stage("dpi_active", 0.10, total=1)
    if not args.no_telegram:
        progress.add_stage("telegram_pro", 0.10, total=1)
    progress.add_stage("route", 0.10, total=1)
    if args.zapret_check:
        progress.add_stage("zapret", 0.15, total=1)
    # Resilience check теперь всегда включён (по умолчанию), но можно отключить через --no-resilience-check
    resilience_enabled = getattr(args, 'resilience_check', True)
    # TUN-полная проверка: один core на узел, все проверки через TUN+SOCKS
    # (Karing-стиль). Включается через --tun-check (по умолчанию ON из UI).
    tun_full_enabled = bool(getattr(args, 'tun_check', False))

    # ---------------------------------------------------------------------
    # Когда включён --tun-check, probe_node_full внутри себя уже прогоняет
    # ВСЕ базовые проверки через один core с TUN+SOCKS:
    #   - ping (HTTPS к gstatic/cloudflare/google/microsoft/apple)
    #   - telegram (HEAD api.telegram.org + MTProto DC)
    #   - chatgpt (HTTPS HEAD chatgpt.com + chat.openai.com)
    #   - instagram (HTTPS HEAD instagram.com)
    #   - speed (download/upload через SOCKS)
    #   - TUN-связность (системный HTTPS/DNS через TUN)
    # Дублирующие SOCKS-only этапы ниже (initial_check, telegram_pro,
    # route, resilience, recheck) поднимали бы ОТДЕЛЬНЫЙ core на каждый
    # узел, повторяя ту же работу. На 100 узлах × 5 этапов = 500 лишних
    # старт-стопов xray.exe/sing-box.exe = ~8 минут чистого оверхеда.
    # Поэтому при --tun-check их пропускаем. DPI/DPI-active/Zapret — НЕ
    # дублируются (это отдельные проверки обхода блокировок), их оставляем.
    # ---------------------------------------------------------------------
    _skip_initial_when_tun = False
    _skip_telegram_pro_when_tun = False
    _skip_route_when_tun = False
    _skip_recheck_when_tun = False
    if tun_full_enabled:
        log("[sub] TUN-check включён: initial_check, telegram_pro, route, "
            "resilience и финальный recheck пропускаются — они дублируются "
            "внутри probe_node_full (один TUN+SOCKS core на узел, все "
            "базовые проверки через него).")
        resilience_enabled = False
        _skip_initial_when_tun = True
        _skip_telegram_pro_when_tun = True
        _skip_route_when_tun = True
        _skip_recheck_when_tun = True

    if resilience_enabled:
        progress.add_stage("resilience", 0.10, total=1)
    if tun_full_enabled:
        progress.add_stage("tun_full", 0.30, total=1)
    if not _skip_recheck_when_tun:
        progress.add_stage("recheck", 0.05, total=1)
    progress.add_stage("geo", 0.10, total=1)

    ping_idx = progress.stage_index("ping")
    stress_idx = progress.stage_index("stress")
    initial_idx = progress.stage_index("initial_check")
    dpi_idx = progress.stage_index("dpi")
    dpi_active_idx = progress.stage_index("dpi_active")
    telegram_pro_idx = progress.stage_index("telegram_pro")
    route_idx = progress.stage_index("route")
    zapret_idx = progress.stage_index("zapret")
    resilience_idx = progress.stage_index("resilience") if resilience_enabled else -1
    tun_full_idx = progress.stage_index("tun_full") if tun_full_enabled else -1
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
        # Если оба недоступны, останавливаемся до запуска тестов: иначе
        # системные настройки DNS испортят результаты проверок узлов.
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
        if not preflight.internet_ok:
            log(
                "[sub] ERROR: локальная сеть не готова (DNS/HTTPS недоступны). "
                "Проверьте подключение к сети и настройки DNS."
            )
            for err in preflight.errors:
                log(f"[sub] preflight error: {err}")
            progress.close()
            return 1

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
        if not args.no_stress:
            min_speed = args.min_speed
            orig_count = len(working)
            working = [w for w in working if w.download_kbps is None or w.download_kbps >= min_speed]
            if len(working) < orig_count:
                log(f"[sub] filtered out {orig_count - len(working)} nodes with speed < {min_speed} Kbps")
    else:
        # Перепроверка с этапа: распинговка и стресс-тест уже выполнены ранее,
        # их результаты сохранены в кеше. Загружаем рабочие конфиги и начинаем
        # с указанного этапа (dpi / zapret / recheck).
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

        # Если начинаем с zapret/recheck — пропускаем все предшествующие проверки
        # (обычную DPI, активную DPI, Telegram-pro).
        if start_stage in ("zapret", "recheck"):
            args.dpi_check = False
            args.dpi_active = False
            args.no_telegram = True
            for _stage_name, _stage_idx in (
                ("dpi", dpi_idx),
                ("dpi_active", dpi_active_idx),
                ("telegram_pro", telegram_pro_idx),
            ):
                if _stage_idx >= 0 and not progress.is_completed(_stage_idx):
                    progress.finish_stage(_stage_idx, f"[{_stage_name}] пропущен (перепроверка с {start_stage})")
        # Если начинаем с recheck — пропускаем также Zapret и TUN-full.
        if start_stage == "recheck":
            args.zapret_check = False
            if getattr(args, 'tun_check', False):
                args.tun_check = False
                if tun_full_idx >= 0 and not progress.is_completed(tun_full_idx):
                    progress.finish_stage(tun_full_idx, "[tun_full] пропущен (перепроверка с recheck)")

    # ---------------------------------------------------------------------
    # Initial Check: быстрая проверка доступности (TCP + HTTP HEAD).
    # Обязательный системный этап первичного отсева (Fail Fast): отсеивает
    # мёртвые узлы за 2-3 сек ДО дорогих проверок. Выполняется при полном
    # прогоне; при перепроверке с этапа узлы уже проверены — пропускаем.
    # ---------------------------------------------------------------------
    initial_check_report: dict[str, Any] = {}
    if start_stage == "ping" and not _skip_initial_when_tun:
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

    # DPI-проверка (обход блокировок) через XrayCoreRuntime.
    if args.dpi_check:
        timeout = get_threshold("dpi", "timeout", 10.0)
        require_siberian = args.dpi_siberian or get_threshold("dpi", "require_siberian", False)
        require_cidr = args.dpi_cidr or get_threshold("dpi", "require_cidr", False)
        
        orig_dpi_count = len(working)
        target = args.dpi_target or DPI_DEFAULT_TARGET
        log(
            f"[sub] DPI check enabled, target={target}, siberian={'on' if require_siberian else 'info'} "
            f"cidr={'on' if require_cidr else 'info'}, checking {orig_dpi_count} nodes..."
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
                # Выполняем реальную проверку
                res = check_node_dpi_detailed(
                    w.node.raw_url,
                    target_host=target,
                    timeout=timeout,
                    require_siberian=require_siberian,
                    require_cidr=require_cidr,
                )
                passed = res.accepted
                
                # Сохраняем в кэш
                if cache_enabled:
                    cache_result(w.node.raw_url, "dpi", passed, res.row() if res else {})
            
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

    # Продвинутая Telegram-проверка (MTProto connect/auth, upload)
    # с расчётом telegram_score.
    telegram_pro_report: dict[str, Any] = {}
    if not args.no_telegram and not _skip_telegram_pro_when_tun:
        telegram_pro_orig_count = len(working)
        log(
            f"[sub] Telegram-PRO check enabled, checking {telegram_pro_orig_count} nodes..."
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
                timeout=TG_TIMEOUT,
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
            "nodes": telegram_pro_node_details,
        }

    # ---------------------------------------------------------------------
    # Проверка стабильности маршрута (RTT: ping_avg/ping_p95/jitter/loss).
    # Системный этап: не фильтрует узлы (Pass/Fail), а только обогащает отчёт
    # метаданными маршрута (для geo-тегирования и диагностики). Всегда включён
    # при полном прогоне, скрыт из UI.
    # ---------------------------------------------------------------------
    route_report: dict[str, Any] = {}
    if start_stage == "ping" and not _skip_route_when_tun:
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
            progress.finish_stage(route_idx, f"[route] пропущен (TUN-check или перепроверка с {start_stage})")

    # Zapret-проверка (методика C:\Zapret: DPI suite tcp 16-20 + HTTP test).
    zapret_report: dict[str, Any] = {}

    if args.zapret_check:
        zapret_orig_count = len(working)
        max_targets = max(1, args.zapret_targets)
        zapret_timeout = max(2.0, args.zapret_timeout)
        run_http = not args.zapret_no_http
        min_score = max(0.0, min(1.0, args.zapret_min_score))

        log(
            f"[sub] Zapret check enabled, targets={max_targets} timeout={zapret_timeout}s "
            f"http_test={run_http} min_score={min_score:.2f}, checking {zapret_orig_count} nodes..."
        )
        if zapret_idx >= 0:
            progress.start_stage(zapret_idx, f"Zapret-проверка {zapret_orig_count} узлов")
            progress.set_total(zapret_idx, zapret_orig_count)

        suite_targets = load_dpi_suite(max_targets=max_targets)

        working_zapret_path = _resolve_path(args.zapret_working)
        out_zapret_path = _resolve_path(args.zapret_out)
        write_file(working_zapret_path, "")
        write_file(out_zapret_path, "")
        checked_zapret: list[Any] = []
        failed_zapret = 0
        zapret_node_details: dict[str, Any] = {}
        for idx, w in enumerate(working, 1):
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                time.sleep(0.2)
            if zapret_idx >= 0:
                progress.update(idx, f"Zapret {w.node.title()}")

            res: ZapretCheckResult = check_node_zapret_detailed(
                w.node.raw_url,
                targets=suite_targets,
                timeout=zapret_timeout,
                max_targets=max_targets,
                run_http_test=run_http,
                min_score=min_score,
            )
            blocked = res.blocked_targets
            probe_summary = ", ".join(
                f"{t['host']}:{t['blocked'] and 'LIKELY_BLOCKED' or 'ok'}"
                for t in res.targets[:5]
            )
            zapret_node_details[w.node.title()] = res.row()
            if res.accepted:
                checked_zapret.append(w)
                append_text(working_zapret_path, w.node.raw_url + "\n")
                log(
                    f"[zapret] PASS {idx}/{zapret_orig_count}: {w.node.title()} "
                    f"(score={res.score_text} ok={res.ok_targets}/{res.total_targets} "
                    f"blocked={blocked} blocked_probes={res.blocked_probes})"
                )
            else:
                failed_zapret += 1
                log(
                    f"[zapret] FAIL {idx}/{zapret_orig_count}: {w.node.title()} "
                    f"(score={res.score_text} below={min_score:.2f} blocked={blocked}/{res.total_targets} "
                    f"reason={res.reason} {probe_summary})"
                )
        if zapret_idx >= 0:
            progress.finish_stage(
                zapret_idx,
                f"[zapret] done: {len(checked_zapret)} passed, {failed_zapret} failed",
            )

        working = checked_zapret
        if failed_zapret > 0:
            log(f"[sub] filtered out {failed_zapret} nodes that failed Zapret check")

        zapret_urls = urls_text(working)
        write_file(working_zapret_path, zapret_urls)
        zapret_b64 = base64.b64encode(zapret_urls.encode("utf-8")).decode("ascii")
        write_file(out_zapret_path, zapret_b64)
        log(f"[sub] saved {len(working)} Zapret-passed nodes -> {working_zapret_path} / {out_zapret_path}")

        zapret_report = {
            "enabled": True,
            "suite_targets": [{"id": t.id, "provider": t.provider, "country": t.country, "host": t.host} for t in suite_targets],
            "checked": zapret_orig_count,
            "passed": len(checked_zapret),
            "failed": failed_zapret,
            "timeout_sec": zapret_timeout,
            "http_test": run_http,
            "min_score": min_score,
            "nodes": zapret_node_details,
        }

    # Resilience check: проверка живучести узлов в условиях блокировок (теперь всегда включена по умолчанию).
    # Выполняется ПЕРЕД стресс-тестом для отсеивания мёртвых узлов до дорогих проверок.
    # При включённом --tun-check resilience дублируется внутри probe_node_full,
    # поэтому пропускается (resilience_enabled = False выставлено выше).
    resilience_report: dict[str, Any] = {}

    if not tun_full_enabled:
        # Только если TUN-check не включён, читаем флаг из args. Иначе
        # оставляем значение False, выставленное выше (TUN-check дублирует
        # resilience внутри probe_node_full).
        resilience_enabled = getattr(args, 'resilience_check', True)
    if resilience_enabled:
        from checkers.resilience import check_node_resilience_detailed

        resilience_orig_count = len(working)
        resilience_timeout = max(3.0, args.resilience_timeout)

        log(
            f"[sub] Resilience check enabled (default), timeout={resilience_timeout}s, "
            f"checking {resilience_orig_count} nodes..."
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

            res = check_node_resilience_detailed(w.node.raw_url, timeout=resilience_timeout)
            resilience_node_details[w.node.title()] = res.to_dict()

            if res.alive:
                checked_resilience.append(w)
                log(
                    f"[resilience] PASS {idx}/{resilience_orig_count}: {w.node.title()} "
                    f"(mode={res.recommended_mode}, tcp={res.tcp_works}, doh={res.doh_works}, tg={not res.telegram_blocked}, white_sni={res.white_sni_works})"
                )
            else:
                failed_resilience += 1
                log(
                    f"[resilience] FAIL {idx}/{resilience_orig_count}: {w.node.title()} "
                    f"(completely_dead)"
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
            "nodes": resilience_node_details,
        }
    else:
        log("[sub] Resilience check disabled via --no-resilience-check")
        resilience_report = {"enabled": False}

    # ---------------------------------------------------------------------
    # TUN-полная проверка (Karing-стиль): один core на узел с TUN+SOCKS,
    # все проверки через один SOCKS-порт. Это ЗАМЕНЯЕТ множество отдельных
    # поднятий ядра (раньше: initial_check, dpi, telegram_pro, route, zapret,
    # resilience — каждое поднимало свой core). Теперь: один core, прогоняем
    # ping + telegram + chatgpt + instagram + speed + TUN-связность.
    #
    # DNS-резолвинг выполняет сам прокси-сервер (через outbound), а не
    # локальный резолвер — это критично для заблокированных сетей, где
    # локальный DNS режется провайдером.
    # ---------------------------------------------------------------------
    tun_full_report: dict[str, Any] = {"enabled": tun_full_enabled}
    if tun_full_enabled:
        from xray_runtime import XrayCoreRuntime, XrayRuntimeConfig

        tun_full_orig_count = len(working)
        log(f"[sub] TUN-full check enabled, checking {tun_full_orig_count} nodes through virtual TUN adapter...")
        if tun_full_idx >= 0:
            progress.start_stage(tun_full_idx, f"TUN-проверка {tun_full_orig_count} узлов")
            progress.set_total(tun_full_idx, tun_full_orig_count)

        tun_config = XrayRuntimeConfig(
            subscription_urls=[],
            probe_workers=1,
            probe_timeout_sec=max(2.0, args.timeout),
            min_speed_kbps=float(args.min_speed),
            telegram_media_check=not args.no_telegram,
        )
        tun_runtime = XrayCoreRuntime(
            tun_config,
            root_dir=ROOT,
            out_dir=DATA_DIR / ".runtime_cache" / "tun",
            log_sink=log,
        )
        tun_node_details: dict[str, Any] = {}
        tun_passed = 0
        tun_failed = 0
        # Результаты TUN-проверки обновляют поля в working (latency, chatgpt, etc).
        checked_tun: list[Any] = []
        try:
            for idx, w in enumerate(working, 1):
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                while pause_event and pause_event.is_set():
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    time.sleep(0.2)
                if tun_full_idx >= 0:
                    progress.update(idx, f"TUN {w.node.title()}")

                # probe_node_full: один core на узел, все проверки через него.
                # tun=True → поднимает TUN+SOCKS, гоняет системный трафик через TUN.
                # speed_test=not args.no_stress → спид-тест только если стресс включён.
                tun_res = tun_runtime.probe_node_full(
                    w.node,
                    tun=True,
                    speed_test=not args.no_stress,
                    karing_log=True,
                )
                tun_node_details[w.node.title()] = {
                    "title": w.node.title(),
                    "accepted": tun_res.accepted,
                    "reason": tun_res.reason,
                    "latency_ms": tun_res.latency_ms,
                    "dc_latency_ms": tun_res.dc_latency_ms,
                    "chatgpt_ok": not tun_res.chatgpt_blocked,
                    "chatgpt_latency_ms": tun_res.chatgpt_latency_ms,
                    "instagram_ok": not tun_res.instagram_blocked,
                    "instagram_latency_ms": tun_res.instagram_latency_ms,
                    "download_kbps": tun_res.download_kbps,
                    "upload_kbps": tun_res.upload_kbps,
                }
                if tun_res.accepted:
                    tun_passed += 1
                    checked_tun.append(w)
                    log(
                        f"[tun_full] PASS {idx}/{tun_full_orig_count}: {w.node.title()} "
                        f"(ping={tun_res.latency_ms:.0f}ms"
                        + (f", dl={tun_res.download_kbps:.0f}K" if tun_res.download_kbps else "")
                        + f", chatgpt={'ok' if not tun_res.chatgpt_blocked else 'blocked'}"
                        + f", instagram={'ok' if not tun_res.instagram_blocked else 'blocked'})"
                    )
                else:
                    tun_failed += 1
                    log(f"[tun_full] FAIL {idx}/{tun_full_orig_count}: {w.node.title()} ({tun_res.reason})")
        finally:
            with contextlib.suppress(Exception):
                tun_runtime.stop()

        if tun_full_idx >= 0:
            progress.finish_stage(
                tun_full_idx,
                f"[tun_full] done: {tun_passed} passed, {tun_failed} failed (out of {tun_full_orig_count})",
            )

        tun_full_report = {
            "enabled": True,
            "checked": tun_full_orig_count,
            "passed": tun_passed,
            "failed": tun_failed,
            "nodes": tun_node_details,
        }
        # TUN-проверка НЕ отбраковывает узлы (Karing-стиль: информационный
        # сигнал). Рабочие узлы остаются в working, чтобы последующие этапы
        # (recheck, geo) могли их обработать.

    if args.limit > 0:
        working = working[: args.limit]

    # Финальный спидтест (после всех проверок, включая zapret):
    # поднимаем прокси узла и реально качаем с speed.cloudflare.com, чтобы
    # закрепить скорость и отсеять узлы, которые просели к этому моменту.
    # При включённом --tun-check пропускается: спид-тест уже выполнен
    # внутри probe_node_full через тот же TUN+SOCKS core.
    recheck_report: dict[str, Any] = {}
    if not args.no_stress and not _skip_recheck_when_tun:
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
    elif _skip_recheck_when_tun:
        # TUN-check: recheck пропущен — спид-тест выполнен внутри probe_node_full.
        recheck_report = {"enabled": False, "reason": "skipped_by_tun_check"}
        if recheck_idx >= 0 and not progress.is_completed(recheck_idx):
            progress.finish_stage(recheck_idx, "[recheck] пропущен (TUN-check — спид-тест уже выполнен внутри probe_node_full)")

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
        plain=args.plain,
    )

    # ---------------------------------------------------------------------
    # WARP-резерв: если включён --add-warp, после завершения основного
    # пайплайна запрашиваем WARP-конфиг у cyb-portal и добавляем warp://
    # URL в конец subs.txt/working.txt как fallback. WARP не тестируется
    # (Cloudflare стабилен) — он работает как «последний рубеж», если все
    # vless-узлы упали.
    # ---------------------------------------------------------------------
    warp_report: dict[str, Any] = {"enabled": bool(getattr(args, "add_warp", False))}
    if getattr(args, "add_warp", False):
        # Список индексов пресетов (по умолчанию [0] = «Авто»).
        preset_indices = list(getattr(args, "warp_preset", [0]) or [0])
        if not isinstance(preset_indices, list):
            preset_indices = [preset_indices]
        preset_indices = [int(i) for i in preset_indices if i is not None]
        if not preset_indices:
            preset_indices = [0]

        # Кастомный DNS (если указан через --warp-dns).
        custom_dns_str = str(getattr(args, "warp_dns", "") or "").strip()
        custom_dns = None
        if custom_dns_str:
            custom_dns = [d.strip() for d in custom_dns_str.split(",") if d.strip()]
            log(f"[sub] WARP: кастомный DNS: {custom_dns}")

        log(f"[sub] WARP: запрашиваем конфиг у Cloudflare API (пресеты: {preset_indices}) ...")
        try:
            from subgen.warp import (
                WARP_PRESETS,
                generate_warp_uri,
                generate_warp_uris_for_presets,
                _build_uris_for_preset,
                fetch_warp_config_parsed,
                warp_config_to_uri,
            )
            from copy import deepcopy

            # Если выбран только пресет 0 (Авто) — один конфиг.
            # Если выбраны пресеты 1-4 — несколько URL с разными endpoint:port.
            if preset_indices == [0]:
                cfg = fetch_warp_config_parsed(timeout=45.0)
                if custom_dns:
                    cfg.dns = list(custom_dns)
                warp_uris = [warp_config_to_uri(cfg)]
                preset_names = ["Авто"]
            else:
                preset_names = []
                for idx in preset_indices:
                    if 0 <= idx < len(WARP_PRESETS):
                        preset_names.append(WARP_PRESETS[idx].user_facing)
                total_expected = sum(
                    WARP_PRESETS[idx].total for idx in preset_indices
                    if 0 <= idx < len(WARP_PRESETS)
                )
                log(f"[sub] WARP: пресеты: {', '.join(preset_names)} — ожидается до {total_expected} конфигов")
                # Если указан кастомный DNS — подменяем в пресетах.
                if custom_dns:
                    cfg = fetch_warp_config_parsed(timeout=45.0)
                    cfg.dns = list(custom_dns)
                    warp_uris = []
                    seen_ep: set[tuple[str, int]] = set()
                    import re
                    endpoint_re = re.compile(r"@([^:/?#]+):(\d+)\b")
                    for idx in preset_indices:
                        if 0 <= idx < len(WARP_PRESETS):
                            preset = WARP_PRESETS[idx]
                            for uri in _build_uris_for_preset(cfg, preset):
                                m = endpoint_re.search(uri)
                                if m:
                                    ep_key = (m.group(1).lower(), int(m.group(2)))
                                    if ep_key in seen_ep:
                                        continue
                                    seen_ep.add(ep_key)
                                warp_uris.append(uri)
                else:
                    warp_uris = generate_warp_uris_for_presets(preset_indices, timeout=45.0)

            log(f"[sub] WARP: получено {len(warp_uris)} конфиг(ов), добавляем в подписку")

            # Читаем текущий текст подписки и добавляем warp:// URL в конец.
            try:
                existing_text = working_path.read_text(encoding="utf-8") if working_path.exists() else ""
            except Exception:
                existing_text = ""
            if existing_text and not existing_text.endswith("\n"):
                existing_text += "\n"
            for uri in warp_uris:
                existing_text += uri + "\n"
                log(f"[sub] WARP: + {uri[:90]}...")
            write_file(working_path, existing_text)

            # Для base64-подписки (subs.txt) — пересобираем base64 из
            # обновлённого текста (если не --plain).
            if not args.plain:
                new_b64 = base64.b64encode(existing_text.encode("utf-8")).decode("ascii")
                write_file(out_path, new_b64)
                subscription_b64 = new_b64
            else:
                write_file(out_path, existing_text)
                subscription_b64 = existing_text

            warp_report["added"] = True
            warp_report["presets"] = preset_names
            warp_report["preset_indices"] = preset_indices
            warp_report["uris"] = warp_uris
            log(f"[sub] WARP: {len(warp_uris)} конфиг(ов) добавлено в подписку (пресеты: {', '.join(preset_names)})")
        except Exception as exc:
            warp_report["added"] = False
            warp_report["error"] = str(exc)
            log(f"[sub] WARP: ОШИБКА — не удалось добавить конфиг: {exc}")
    else:
        warp_report["added"] = False

    # Отчёт.
    report: dict[str, Any] = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": sources,
        "discovered": len(discovered),
        "working": len(working),
        "rejected": len(rejected),
        "exported": len(rows),
        "geo_unknown": sum(1 for r in rows if r["country_code"] == GEOIP_FALLBACK_CODE),
        "initial_check": initial_check_report,
        "dpi_active": dpi_active_report,
        "telegram_pro": telegram_pro_report,
        "route": route_report,
        "zapret": zapret_report,
        "resilience": resilience_report,
        "tun_full": tun_full_report,
        "recheck": recheck_report,
        "warp": warp_report,
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
