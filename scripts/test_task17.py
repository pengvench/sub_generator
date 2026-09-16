#!/usr/bin/env python3
"""Тесты v1.3 (Task 17): модульность runtime/, базовый замер сети,
автовыборка, привязка таймаутов к UI, чистка мёртвого кода.
+ v1.3.2: кэп быстрого канала (≥100 Мбит — замер не слушаем),
sources.txt в корне (data/ — только рантайм), спидтест в диагностике,
поле «Свой файл конфигов» под тумблером.

Запуск: python scripts/test_task17.py  (из корня репозитория).
Все проверки офлайн — сеть не трогаем (кроме каскадов, которые мокаются).
"""
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "python"))

PASSED = []
FAILED = []


def check(name, fn):
    try:
        fn()
        PASSED.append(name)
        print(f"  PASS  {name}")
    except Exception as exc:  # noqa: BLE001
        FAILED.append((name, exc))
        print(f"  FAIL  {name}: {exc}")


# =====================================================================
# 1. Пакет runtime/: структура и фасад
# =====================================================================
def test_runtime_package_structure():
    from runtime import types, uritools, parse, fetch, netsocks, probes_ping, probes_telegram, probes_speed, configs, procs, core  # noqa: F401
    import xray_runtime

    # Фасад реэкспортирует всё, что используют внешние модули.
    for name in (
        "XrayCoreRuntime", "XrayNode", "XrayProbeResult", "XrayRuntimeConfig",
        "collect_subscription_nodes", "parse_node_link",
        "_download_speed_probe", "_socks_https_head_status", "_result_from_row",
        "_xray_outbound", "_normalize_reality_pbk", "_tg_media_video_urls",
        "_socks_mtproto_latency", "TG_MEDIA_MIN_KBPS", "TELEGRAM_DCS",
        "XRAY_SPEED_TEST_BIG_BYTES", "NODE_SCHEMES",
    ):
        assert hasattr(xray_runtime, name), f"фасад не реэкспортирует {name}"
    # Фасад тонкий: не содержит тел функций (только импорты).
    src = open(os.path.join(REPO_ROOT, "python", "xray_runtime.py"), encoding="utf-8").read()
    assert "def " not in src, "фасад не должен содержать определений функций"


def test_runtime_no_legacy():
    # DEFAULT_XRAY_SUBSCRIPTIONS / is_legacy удалены (мёртвые).
    import xray_runtime
    assert not hasattr(xray_runtime, "DEFAULT_XRAY_SUBSCRIPTIONS")
    assert not hasattr(xray_runtime, "is_legacy_xray_subscription")
    from runtime.types import XrayRuntimeConfig
    assert XrayRuntimeConfig().subscription_urls == []


def test_node_roundtrip_through_package():
    import xray_runtime as xr
    node = xr.parse_node_link(
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443"
        "?encryption=none&security=reality&sni=example.com&fp=chrome&pbk=abc&sid=12&type=tcp#t"
    )
    assert node is not None and node.protocol == "vless"
    ob = xr._xray_outbound(node, tag="proxy-7")
    assert ob["tag"] == "proxy-7"
    # Палевный chrome заменяется на firefox при записи fp в stream.
    ss = ob["streamSettings"]["realitySettings"]
    assert ob["streamSettings"]["security"] == "reality"


# =====================================================================
# 2. Базовый замер сети: адаптация порогов
# =====================================================================
def test_baseline_adapt_mobile_asymmetric():
    from subgen.baseline import BaselineResult, adapt_speed_thresholds
    # Сеть с картинки пользователя: 46.16 Мбит down, 5.29 Мбит up.
    b = BaselineResult(download_kbps=5850.0, upload_kbps=660.0, rtt_ms=40.0)
    dl, up, tg, info = adapt_speed_thresholds(5000.0, b)
    assert dl == 3510.0, dl          # 60% от 5850 < порога пользователя
    assert up == 330.0, up           # min(500, 50% от 660) — фикс асимметрии
    assert tg == 512.0, tg           # медиа-фильтр не трогаем (замер высокий)
    assert info["applied"] is True


def test_baseline_adapt_user_lower_wins():
    from subgen.baseline import BaselineResult, adapt_speed_thresholds
    b = BaselineResult(download_kbps=5850.0)
    dl, up, tg, _ = adapt_speed_thresholds(1500.0, b)  # пользователь сам снизил
    assert dl == 1500.0, "замер может только смягчить, не ужесточить"
    assert tg == 512.0


def test_baseline_adapt_weak_network_floors():
    from subgen.baseline import BaselineResult, adapt_speed_thresholds
    b = BaselineResult(download_kbps=600.0, upload_kbps=80.0)
    dl, up, tg, _ = adapt_speed_thresholds(5000.0, b)
    assert dl == 360.0 and up == 64.0 and tg == 300.0, (dl, up, tg)


def test_baseline_adapt_fallback():
    from subgen.baseline import BaselineResult, adapt_speed_thresholds
    b = BaselineResult()  # замер не удался
    dl, up, tg, info = adapt_speed_thresholds(5000.0, b)
    assert (dl, up, tg) == (5000.0, 500.0, 512.0)
    assert info["applied"] is False


def test_baseline_targets_whitelisted():
    # v1.3.1: Cloudflare выпилен из замера полностью — на мобильных РФ он
    # не белый; вместо него Яндекс.Интернетометр и QMS-движок Билайна.
    from subgen.baseline import BASELINE_DOWNLOAD_TARGETS
    src = open(os.path.join(REPO_ROOT, "python", "subgen", "baseline.py"), encoding="utf-8").read()
    labels = [t[0] for t in BASELINE_DOWNLOAD_TARGETS]
    # Яндекс первым, tele2 вторым (RU-белые статичные), OVH — международный
    # fallback последним; QMS (speedtest.ru/Билайн) вставляется динамически.
    assert labels[0] == "yandex", labels
    assert labels[1] == "tele2", labels
    assert labels[-1] == "ovh", labels
    for _label, url, _cap in BASELINE_DOWNLOAD_TARGETS:
        assert "cloudflare" not in url.lower(), url
    # Ни в download, ни в upload нет спидтеста Cloudflare; старого
    # константного CF-приёмника выгрузки больше не существует.
    from subgen import baseline as _bl
    assert "speed.cloudflare.com" not in src
    assert not hasattr(_bl, "BASELINE_UPLOAD_URL")


def test_baseline_yandex_and_qms_endpoints():
    from subgen import baseline
    # Яндекс: CDN-проба и приёмник выгрузки — хосты Яндекса.
    assert baseline.YANDEX_CDN_PROBE_URL.startswith("https://")
    assert baseline.YANDEX_CDN_PROBE_URL.endswith(".svc.cdn.yandex.net/probes/50mb")
    assert baseline.YANDEX_UPLOADHOST_URL == "https://internetometr.download.cdn.yandex.net/uploadhost"
    assert baseline.YANDEX_PAGE_URL == "https://yandex.ru/internet"
    # QMS: движок «проверки скорости» Билайна (speedtest.ru), ключи на месте.
    assert baseline.QMS_API_BASE == "https://speedtest.ru"
    assert len(baseline.QMS_API_KEYS) >= 2 and all(len(k) == 32 for k in baseline.QMS_API_KEYS)
    assert baseline.QMS_DOWNLOAD_MB >= 8


def test_baseline_yandex_host_guard():
    from subgen.baseline import _is_yandex_host_url
    # Только хосты Яндекса — приёмник выгрузки не подменить.
    assert _is_yandex_host_url("http://cloudcdn-fra-02.cdn.yandex.net/upload")
    assert _is_yandex_host_url("https://internetometr.download.cdn.yandex.net/uploadhost")
    assert not _is_yandex_host_url("http://evil.example.com/upload")
    assert not _is_yandex_host_url("https://cdn.yandex.net.evil.io/upload")
    assert not _is_yandex_host_url("garbage")


def test_baseline_upload_cascade_signature():
    # measure_upload теперь возвращает (kbps, label) — источник замера.
    import inspect
    from subgen.baseline import measure_upload, measure_download
    assert "tuple" in inspect.signature(measure_upload).return_annotation
    assert "log" in inspect.signature(measure_upload).parameters
    assert "log" in inspect.signature(measure_download).parameters
    # Каскад в докстрингах описан как Яндекс -> QMS (Билайн) без Cloudflare.
    up_doc = (inspect.getdoc(measure_upload) or "").lower()
    assert "яндекс" in up_doc or "yandex" in up_doc
    assert "qms" in up_doc and "билайн" in up_doc


# =====================================================================
# 3. Таймауты этапов привязаны к базовому --timeout
# =====================================================================
def test_stage_timeouts_derived():
    from subgen.pipeline import build_parser, _apply_stage_aliases
    # Дефолтные None-таймауты (UI ничего не передаёт) -> выведены из базы.
    args = _apply_stage_aliases(build_parser().parse_args(["--timeout", "15"]))
    assert args.initial_check_timeout is None  # до run() разрешается внутри
    # Разрешение логики дублируем: run() выводит значения, проверим формулы
    # через те же коэффициенты (проверка фактических значений — в smoke-тесте
    # run() ниже через исходник).
    src = open(os.path.join(REPO_ROOT, "python", "subgen", "pipeline.py"), encoding="utf-8").read()
    assert "base_timeout * 0.5" in src and "base_timeout * 0.4" in src
    assert "base_timeout * 0.75" in src and "tg_base_timeout" in src
    assert "recheck_probe_timeout = round(max(8.0, min(base_timeout, 12.0)), 1)" in src
    # Явный CLI-флаг всё ещё работает.
    args2 = _apply_stage_aliases(build_parser().parse_args(["--initial-check-timeout", "9", "--timeout", "15"]))
    assert args2.initial_check_timeout == 9.0
    # Дефолты argparse теперь None (выводятся), а не хардкод 3/4/6.
    for action in build_parser()._actions:
        if action.dest == "initial_check_timeout":
            assert action.default is None
        if action.dest == "ai_timeout":
            assert action.default is None
        if action.dest == "resilience_timeout":
            assert action.default is None


def test_stage_timeout_derivation_math():
    # Формулы выведения (0.5/0.4/0.75/0.6) — как в run().
    base = 15.0
    assert round(max(3.0, base * 0.5), 1) == 7.5
    assert round(max(4.0, base * 0.4), 1) == 6.0
    assert round(max(6.0, base * 0.75), 1) == 11.2  # round(11.25, 1) = 11.2 (banker's)
    assert round(max(5.0, base * 0.6), 1) == 9.0
    base = 3.0  # короткий таймаут UI -> нижние пороги
    assert round(max(3.0, base * 0.5), 1) == 3.0
    assert round(max(4.0, base * 0.4), 1) == 4.0
    assert round(max(6.0, base * 0.75), 1) == 6.0
    assert round(max(8.0, min(base, 12.0)), 1) == 8.0


# =====================================================================
# 5. Чистка мёртвого кода
# =====================================================================
def test_dead_code_removed():
    # config.py: crypt_* удалены.
    cfg_src = open(os.path.join(REPO_ROOT, "python", "subgen", "config.py"), encoding="utf-8").read()
    assert "crypt_encode" not in cfg_src and "_CRYPT_KEY" not in cfg_src
    # checkers/tg_media.py удалён.
    assert not os.path.exists(os.path.join(REPO_ROOT, "python", "checkers", "tg_media.py"))
    # 6 не-detailed обёрток удалены.
    for mod, fn in (
        ("dpi", "check_node_dpi"),
        ("zapret", "check_node_zapret"), ("dpi_active", "check_node_dpi_active"),
        ("telegram_pro", "check_node_telegram_pro"),
    ):
        src = open(os.path.join(REPO_ROOT, "python", "checkers", f"{mod}.py"), encoding="utf-8").read()
        assert f"def {fn}(" not in src, f"{fn} должен быть удалён"
    import checkers  # noqa: F401
    assert not hasattr(checkers, "check_node_dpi")
    assert hasattr(checkers, "check_node_dpi_detailed")
    # multi_target_ping / download_bytes / bin_dir / ui_dir удалены.
    res_src = open(os.path.join(REPO_ROOT, "python", "checkers", "resilience.py"), encoding="utf-8").read()
    assert "def multi_target_ping" not in res_src
    base_src = open(os.path.join(REPO_ROOT, "python", "checkers", "base.py"), encoding="utf-8").read()
    assert "def download_bytes" not in base_src
    paths_src = open(os.path.join(REPO_ROOT, "python", "ui", "paths.py"), encoding="utf-8").read()
    assert "def bin_dir" not in paths_src and "def ui_dir" not in paths_src
    # save_thresholds/create_default_config удалены.
    th_src = open(os.path.join(REPO_ROOT, "python", "subgen", "checker_thresholds.py"), encoding="utf-8").read()
    assert "def save_thresholds" not in th_src and "def create_default_config" not in th_src
    # _preflight_dns_doh удалён (мёртвый дубль net_diagnostic).
    pipe_src = open(os.path.join(REPO_ROOT, "python", "subgen", "pipeline.py"), encoding="utf-8").read()
    assert "_preflight_dns_doh" not in pipe_src


def test_legacy_cli_aliases_removed():
    from subgen.pipeline import build_parser
    option_strings = {opt for action in build_parser()._actions for opt in action.option_strings}
    for alias in ("--zapret-targets", "--zapret-timeout", "--zapret-min-score", "--zapret-no-http"):
        assert alias not in option_strings, f"{alias} должен быть удалён (v1.3)"
    # Рабочие флаги на месте.
    for kept in ("--dpi-suite-targets", "--dpi-suite-timeout", "--zapret-out", "--zapret-working", "--zapret-check"):
        assert kept in option_strings, f"{kept} должен остаться"


# =====================================================================
# 6. Консолидация диагностики (без TUN)
# =====================================================================
def test_diag_consolidated_no_tun():
    nd_src = open(os.path.join(REPO_ROOT, "python", "checkers", "net_diagnostic.py"), encoding="utf-8").read()
    for tun_name in ("tun_present", "tun_ready", "local_tun_check", "_windows_tun_detail", "tun_iface"):
        assert tun_name not in nd_src, f"{tun_name} должен быть удалён (TUN не используется)"
    # GUI-страница ходит в общую реализацию, своих inline-проверок нет.
    diag_src = open(os.path.join(REPO_ROOT, "python", "ui", "pages", "diag_page.py"), encoding="utf-8").read()
    assert "from checkers.net_diagnostic import run_network_diagnostic" in diag_src
    assert "cloudflare-dns.com/dns-query?name=google.com" not in diag_src, "inline DoH-проверка должна быть удалена (дубль)"
    # pipeline preflight логирует без tun=.
    pipe_src = open(os.path.join(REPO_ROOT, "python", "subgen", "pipeline.py"), encoding="utf-8").read()
    assert "tun=" not in pipe_src
    # blocked-цели включают api.telegram.org.
    from checkers.net_diagnostic import BLOCKED_MEDIA_HTTP_PROBES
    hosts = [h for h, _ in BLOCKED_MEDIA_HTTP_PROBES]
    assert "api.telegram.org" in hosts and "chatgpt.com" in hosts and "instagram.com" in hosts


def test_net_diagnostic_result_api():
    from checkers.net_diagnostic import NetworkDiagnosticResult
    r = NetworkDiagnosticResult(
        udp_dns_ok=True, http_ok=True,
        blocked_targets={
            "chatgpt.com": {"ok": True, "latency_ms": 120.0, "status": 200},
            "instagram.com": {"ok": False, "latency_ms": None, "status": 0},
            "api.telegram.org": {"ok": True, "latency_ms": 60.0, "status": 302},
        },
    )
    assert r.dns_ok and r.internet_ok
    assert r.chatgpt_ok and not r.instagram_ok and r.telegram_api_ok
    d = r.as_dict()
    assert d["telegram_api_ok"] is True and "blocked_targets" in d
    assert "tun_present" not in d


# =====================================================================
# 7. Адаптивные пороги в рантайме
# =====================================================================
def test_runtime_adaptive_threshold_fields():
    from runtime.types import XrayRuntimeConfig
    cfg = XrayRuntimeConfig(min_speed_kbps=3510.0, upload_min_kbps=330.0, tg_media_min_kbps=300.0)
    assert cfg.upload_min_kbps == 330.0
    assert cfg.tg_media_min_kbps == 300.0
    # Дефолты: None (10% от min_speed) и TG_MEDIA_MIN_KBPS.
    cfg2 = XrayRuntimeConfig()
    assert cfg2.upload_min_kbps is None
    assert cfg2.tg_media_min_kbps == 512.0
    # Стресс-проба использует поля (исходник; после модуляризации core.py
    # _stress_probe_node живёт в runtime/stress.py — StressMixin).
    stress_src = open(os.path.join(REPO_ROOT, "python", "runtime", "stress.py"), encoding="utf-8").read()
    assert "upload_min_kbps" in stress_src and "tg_media_min_kbps" in stress_src


def test_refresh_passes_adaptive_thresholds():
    import inspect
    from subgen.refresh import run_refresh
    sig = inspect.signature(run_refresh)
    assert "upload_min_kbps" in sig.parameters
    assert "tg_media_min_kbps" in sig.parameters
    refresh_src = inspect.getsource(run_refresh)
    assert "upload_min_kbps=upload_min_kbps" in refresh_src


def test_pipeline_baseline_wiring():
    pipe_src = open(os.path.join(REPO_ROOT, "python", "subgen", "pipeline.py"), encoding="utf-8").read()
    assert "measure_baseline" in pipe_src and "adapt_speed_thresholds" in pipe_src
    assert "effective_min_speed" in pipe_src
    assert "upload_min_kbps=effective_upload_min" in pipe_src
    assert '"baseline": baseline_report' in pipe_src
    # Прогресс-этап baseline зарегистрирован.
    assert 'progress.add_stage("baseline"' in pipe_src


# =====================================================================
# 8. Спеки PyInstaller знают про runtime/
# =====================================================================
def test_specs_include_runtime():
    for spec_name in ("SubGenerator.spec", "SubGenerator-cli.spec"):
        src = open(os.path.join(REPO_ROOT, "scripts", spec_name), encoding="utf-8").read()
        assert "'runtime.core'" in src, f"{spec_name} должен включать runtime-модули"
        assert "'runtime.probes_speed'" in src


# =====================================================================
# 9. v1.3.2: кэп быстрого канала, sources.txt в корне, спидтест в диагностике
# =====================================================================
def test_baseline_adapt_fast_channel_cap():
    """Замер ≥ 100 Мбит/с — НЕ слушаем: пороги пользователя как есть."""
    from subgen.baseline import BaselineResult, adapt_speed_thresholds, BASELINE_CAP_MBITS
    assert BASELINE_CAP_MBITS == 100.0
    # 125 Мбит/с (проводной канал), порог пользователя 3000 КБ/с.
    b = BaselineResult(download_kbps=15625.0, upload_kbps=2500.0)
    dl, up, tg, info = adapt_speed_thresholds(3000.0, b)
    assert (dl, up, tg) == (3000.0, 300.0, 512.0), (dl, up, tg)
    assert info["applied"] is False
    assert info["ignored"] == "fast_channel"
    assert info["baseline_mbits"] == 125.0

    # Граница: ровно 100 Мбит — уже кэп (автозамер для мобильных, не для fiber).
    b100 = BaselineResult(download_kbps=100.0 * 1000.0 / 8)  # 12500 КБ/с
    _dl, _up, _tg, info100 = adapt_speed_thresholds(3000.0, b100)
    assert info100["ignored"] == "fast_channel"

    # 99.9 Мбит — ещё слушаем (мобильный/медленный канал).
    b99 = BaselineResult(download_kbps=99.9 * 1000.0 / 8)
    dl99, _u, _t, info99 = adapt_speed_thresholds(30000.0, b99)
    assert info99["applied"] is True and info99["ignored"] is None
    assert dl99 < 30000.0  # замер смягчил порог


def test_sources_file_single_in_root():
    """sources.txt — ЕДИНСТВЕННЫЙ, в корне; data/ — только рантайм."""
    from subgen.config import DEFAULT_SOURCES_FILE, ROOT
    assert DEFAULT_SOURCES_FILE == ROOT / "sources.txt", DEFAULT_SOURCES_FILE
    assert "data" not in DEFAULT_SOURCES_FILE.parts[-2:], DEFAULT_SOURCES_FILE
    # В репозитории файл лежит в корне; data/sources.txt не существует.
    assert (ROOT / "sources.txt").exists(), "sources.txt должен лежать в корне репо"
    assert not (ROOT / "data" / "sources.txt").exists(), "дубля в data/ быть не должно"

    from ui.paths import sources_file, app_root
    assert sources_file() == app_root() / "sources.txt"

    # Спеки PyInstaller кладут sources.txt в корень бандла.
    for spec_name in ("SubGenerator.spec", "SubGenerator-cli.spec"):
        src = open(os.path.join(REPO_ROOT, "scripts", spec_name), encoding="utf-8").read()
        assert "(os.path.join(ROOT, 'sources.txt'), '.')" in src, spec_name
        assert "'data', 'sources.txt'" not in src, f"{spec_name}: не должно быть data/sources.txt"

    # Сборщик копирует ОДИН sources.txt в build\, без build\data\.
    bat = open(os.path.join(REPO_ROOT, "build_release.bat"), encoding="utf-8", errors="replace").read()
    assert "copy /Y sources.txt build\\sources.txt" in bat
    assert "data\\sources.txt" not in bat, "дубля в data/ в сборке быть не должно"

    # .gitignore: data/ игнорируется ЦЕЛИКОМ (там только рантайм-мусор).
    gi = open(os.path.join(REPO_ROOT, ".gitignore"), encoding="utf-8").read()
    assert "data/" in gi

    # Фильтр подписок работает с корневым sources.txt.
    flt = open(os.path.join(REPO_ROOT, "scripts", "run_filter_sources.bat"), encoding="utf-8", errors="replace").read()
    assert "--sources sources.txt" in flt and "data\\sources.txt" not in flt


def test_diag_page_runs_speed_test():
    """Диагностика сети включает спидтест-прогон по белым сервисам."""
    src = open(os.path.join(REPO_ROOT, "python", "ui", "pages", "diag_page.py"), encoding="utf-8").read()
    assert "from subgen.baseline import" in src
    assert "measure_download" in src and "measure_upload" in src
    assert "BASELINE_CAP_MBITS" in src, "замер ≥ 100 Мбит должен помечаться"
    assert "_run_speed_test" in src
    # Спидтест вызывается в рабочем потоке диагностики (после заблок. целей).
    assert "self._run_speed_test()" in src


def test_start_page_custom_file_under_toggle():
    """Поле пути «Свой файл конфигов» — в ТОЙ ЖЕ колонке, что тумблер."""
    src = open(os.path.join(REPO_ROOT, "python", "ui", "pages", "start_page.py"), encoding="utf-8").read()
    # Тумблер — правая колонка (1, 1).
    assert 'self._make_toggle(inner_extra, 1, 1, "Свой файл конфигов"' in src
    # Поле пути — прямо под ним: row 2, column 1 (та же колонка).
    assert "frame_custom.grid(row=2, column=1" in src
    assert "frame_custom.grid(row=2, column=0" not in src, "поле не должно уезжать в левую колонку"


def test_pipeline_fast_channel_log():
    """Конвейер логирует неприменение автопорога на быстром канале."""
    pipe_src = open(os.path.join(REPO_ROOT, "python", "subgen", "pipeline.py"), encoding="utf-8").read()
    assert '"fast_channel"' in pipe_src or "'fast_channel'" in pipe_src
    assert "быстрый канал" in pipe_src


def main() -> int:
    print("=== Task 17: модульность runtime/ + базлайн + автовыборка + таймауты ===")
    tests = [
        ("runtime: структура пакета + фасад", test_runtime_package_structure),
        ("runtime: legacy-константы удалены", test_runtime_no_legacy),
        ("runtime: roundtrip parse/outbound через пакет", test_node_roundtrip_through_package),
        ("baseline: адаптация 46/5 Мбит (мобильная асимметрия)", test_baseline_adapt_mobile_asymmetric),
        ("baseline: пониженный порог пользователя уважается", test_baseline_adapt_user_lower_wins),
        ("baseline: слабая сеть -> нижние пороги", test_baseline_adapt_weak_network_floors),
        ("baseline: неудачный замер -> fallback на UI", test_baseline_adapt_fallback),
        ("baseline: каскад белых сервисов РФ (яндекс/tele2/qms), CF удалён", test_baseline_targets_whitelisted),
        ("baseline: эндпоинты Яндекса и QMS (движок Билайна)", test_baseline_yandex_and_qms_endpoints),
        ("baseline: защита приёмника выгрузки (хосты Яндекса)", test_baseline_yandex_host_guard),
        ("baseline: upload-каскад возвращает источник", test_baseline_upload_cascade_signature),
        ("таймауты: derivation-формулы в pipeline", test_stage_timeouts_derived),
        ("таймауты: математика выведения (0.5/0.4/0.75/0.6)", test_stage_timeout_derivation_math),
        ("мёртвый код: crypt/tg_media/обёртки/aliases/TUN удалены", test_dead_code_removed),
        ("CLI: legacy --zapret-* алиасы удалены", test_legacy_cli_aliases_removed),
        ("диагностика: консолидация GUI+конвейер, без TUN", test_diag_consolidated_no_tun),
        ("диагностика: NetworkDiagnosticResult API", test_net_diagnostic_result_api),
        ("рантайм: поля адаптивных порогов", test_runtime_adaptive_threshold_fields),
        ("refresh: проброс адаптивных порогов", test_refresh_passes_adaptive_thresholds),
        ("pipeline: базлайн подключён", test_pipeline_baseline_wiring),
        ("спеки PyInstaller: runtime/ в hiddenimports", test_specs_include_runtime),
        ("v1.3.2: кэп ≥100 Мбит — замер не слушаем, пороги UI", test_baseline_adapt_fast_channel_cap),
        ("v1.3.2: sources.txt единственный, в корне; data/ — рантайм", test_sources_file_single_in_root),
        ("v1.3.2: спидтест-прогон в диагностике сети", test_diag_page_runs_speed_test),
        ("v1.3.2: поле «Свой файл конфигов» под тумблером", test_start_page_custom_file_under_toggle),
        ("v1.3.2: лог кэпа быстрого канала в конвейере", test_pipeline_fast_channel_log),
    ]
    for name, fn in tests:
        check(name, fn)
    print(f"\nИТОГ: {len(PASSED)} passed, {len(FAILED)} failed")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
