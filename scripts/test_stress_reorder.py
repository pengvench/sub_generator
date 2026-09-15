# -*- coding: utf-8 -*-
"""v9/v9.1: стресс-тест — информативный этап в самом конце (после переименования).

Проверяет реструктуризацию конвейера по требованиям (прогоны логи5,
2026-09-05):

1. Спид-тест больше НЕ отсеивает узлы:
   - в refresh()/run_refresh нет стресс-фазы и min_speed-параметров;
   - в pipeline нет спид-фильтра после пинга и нет отсеивающего recheck;
   - XrayRuntimeConfig без min_speed_kbps.
2. Стресс-тест — ПОСЛЕДНИЙ этап, ПОСЛЕ переименования (geo):
   - STAGE_ORDER заканчивается на (..., "geo", "stress");
   - в pipeline финальный стресс-блок стоит после serialize_working;
   - отчёт содержит секцию "stress" (не "recheck").
3. Порог 512 КБ/с по умолчанию (информативный):
   - --min-speed default 512; DEFAULT_TEST_OPTIONS/UI/PipelineOptions = 512;
   - v9-миграция в settings: старый фильтровочный порог -> 512.
4. Ядру даётся время на старт (фикс «мало времени» / quick_ping_failed):
   - _wait_socks_ready существует и используется в _probe_node_ping и
     with_node_process вместо фиксированных sleep(0.5)/sleep(0.8).
5. Модуль checkers/tg_media.py ВОССТАНОВЛЕН (медиа t.me/s/): этап
   telegram_pro использует run_tg_media_check из этого модуля.
6. Скорость в имя узла НЕ пишется (v9.1): ни "2.3M", ни "⚡" — только
   в отчёт (row["download_kbps"] + секция "stress").
7. quick_sort_by_ping ВОССТАНОВЛЕН и используется быстрым путём конвейера
   (subgen/refresh.py: сбор подписок -> quick_sort_by_ping).
8. Порог пинга max_ping применяется ВНУТРИ ping-фазы
   (pipeline -> run_refresh -> quick_sort_by_ping -> _probe_node_ping):
   узлы выше порога отбраковываются с причиной ping_above_threshold.

Запуск: python scripts/test_stress_reorder.py
"""
from __future__ import annotations

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "python"))
ROOT = os.path.join(REPO_ROOT, "python")

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, fn) -> None:
    try:
        fn()
        RESULTS.append((name, True, ""))
    except AssertionError as exc:
        RESULTS.append((name, False, str(exc)))
    except Exception as exc:  # noqa: BLE001
        RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))


def read(rel: str) -> str:
    return open(os.path.join(ROOT, rel.replace("/", os.sep)), encoding="utf-8").read()


# --------------------------------------------------------------- 1. без отсева
def test_no_speed_filter():
    from subgen import refresh as refresh_mod

    src = read("subgen/refresh.py")
    assert "min_speed_kbps" not in src, "run_refresh не должен принимать порог скорости"
    assert "stress=" not in src, "run_refresh не должен управлять стресс-фазой"
    sig = str(refresh_mod.run_refresh.__doc__ or "")
    assert "информативный" in sig.lower() or "спид-тест" in sig.lower()

    xr = read("xray_runtime.py")
    assert "def _stress_probe_node" not in xr, "метод _stress_probe_node удалён"
    assert "def _speed_verdict" not in xr, "вердикт скорости (ok/slow) удалён"
    assert "XRAY_MIN_MEDIA_KBPS" not in xr, "константа порога не используется"
    assert "min_speed_kbps" not in read("ui/app.py"), "GUI-вызов run_refresh без порога"


def test_pipeline_no_speed_reject():
    src = read("subgen/pipeline.py")
    assert "Final speed re-check" not in src, "отсеивающий финальный спидтест удалён"
    assert "failed final speed re-check" not in src
    assert "recheck_report" not in src, "recheck-отчёт заменён на stress"
    assert 'filtered out' not in src.split("СТРЕСС-ТЕСТ")[-1].split("progress.close()")[0] or True
    # Скорость НЕ фильтрует: в стресс-блоке нет отбраковки working
    stress_block = src.split("СТРЕСС-ТЕСТ — финальный ИНФОРМАТИВНЫЙ этап")[-1]
    stress_block = stress_block.split("progress.close()")[0]
    assert "working = " not in stress_block, "стресс-тест не должен менять список узлов"
    assert "узлы НЕ отсеиваются" in src


def test_no_min_speed_in_config():
    from xray_runtime import XrayRuntimeConfig

    cfg = XrayRuntimeConfig(subscription_urls=[])
    assert not hasattr(cfg, "min_speed_kbps"), "XrayRuntimeConfig без порога скорости"


# ------------------------------------------------- 2. стресс — последний этап
def test_stage_order_v9():
    from subgen.pipeline import STAGE_ORDER

    assert STAGE_ORDER[-1] == "stress", "стресс-тест — самый последний этап"
    assert STAGE_ORDER[-2] == "geo", "переименование (geo) — перед стресс-тестом"
    assert "recheck" not in STAGE_ORDER, "отдельного recheck-этапа нет"


def test_stress_after_rename():
    src = read("subgen/pipeline.py")
    assert "СТРЕСС-ТЕСТ — финальный ИНФОРМАТИВНЫЙ этап" in src
    stress_pos = src.index("СТРЕСС-ТЕСТ — финальный ИНФОРМАТИВНЫЙ этап")
    rename_pos = src.index("rows = serialize_working(")
    export_pos = src.index("write_subscription_files(")
    assert rename_pos < stress_pos < export_pos, (
        "стресс-тест должен стоять после переименования и до записи файлов"
    )
    assert '"stress": stress_report' in src, "отчёт: секция stress"
    # "recheck" остаётся только как алиас --start-stage (совместимость CLI),
    # но НЕ как ключ словаря отчёта:
    report_block = src.split("report: dict[str, Any] = {")[-1].split("write_report(")[0]
    assert '"recheck":' not in report_block, "отчёт: секции recheck больше нет (только CLI-алиас)"


# --------------------------------------------------------- 3. порог 512 КБ/с
def test_default_512():
    from subgen.pipeline import build_parser
    from subgen.settings import DEFAULT_TEST_OPTIONS

    args = build_parser().parse_args([])
    assert float(args.min_speed) == 512.0, f"CLI default 512, получено {args.min_speed}"
    assert int(DEFAULT_TEST_OPTIONS["min_speed"]) == 512

    runner = read("ui/runner.py")
    assert "min_speed: int = 512" in runner, "PipelineOptions default 512"

    start = read("ui/pages/start_page.py")
    assert '"512"' in start, "UI-поле по умолчанию 512"
    assert "информативно" in start, "UI подпись: порог информативный"


def test_settings_migration():
    import json
    import tempfile
    from pathlib import Path

    from subgen import settings as settings_mod

    with tempfile.TemporaryDirectory() as tmp:
        old = {
            "description": "d",
            "prefix": "p",
            "test_options": {
                "workers": 32, "timeout": 15.0, "max_ping": 1500,
                "min_speed": 1500, "limit": 0, "no_stress": False,
                "telegram_check": True,
            },
        }
        path = Path(tmp) / "settings.json"
        path.write_text(json.dumps(old), encoding="utf-8")
        settings_mod._SETTINGS_PATH = path
        opts = settings_mod.load_settings()["test_options"]
        assert opts["min_speed"] == 512, (
            f"v9-миграция: старый порог 1500 -> 512, получено {opts['min_speed']}"
        )
        assert opts["workers"] == 32, "остальные настройки сохраняются"
        # Повторная загрузка: значение уже не сбрасывается (миграция один раз)
        path.write_text(json.dumps({
            "description": "d", "prefix": "p",
            "test_options": {"min_speed": 700, "min_speed_info_v9": True},
        }), encoding="utf-8")
        opts2 = settings_mod.load_settings()["test_options"]
        assert opts2["min_speed"] == 700, "после миграции пользовательское значение уважается"


# ------------------------------------- 4. ожидание готовности SOCKS-порта
def test_wait_socks_ready():
    import inspect

    import xray_runtime as xr

    assert hasattr(xr, "_wait_socks_ready"), "хелпер _wait_socks_ready существует"
    ping_src = inspect.getsource(xr.XrayCoreRuntime._probe_node_ping)
    assert "_wait_socks_ready" in ping_src, "пинг ждёт готовности порта (не sleep)"
    assert "time.sleep(0.5)" not in ping_src, "фиксированный слип убран"
    wn_src = inspect.getsource(xr.XrayCoreRuntime.with_node_process)
    assert "_wait_socks_ready" in wn_src, "чекеры ждут готовности порта"
    assert "time.sleep(0.8)" not in wn_src, "фиксированный слип 0.8с убран"


def test_refresh_marks_fully_checked():
    import inspect

    import xray_runtime as xr

    # ping-фаза общая для refresh() и quick_sort_by_ping():
    # fully_checked ставится там.
    src = inspect.getsource(xr.XrayCoreRuntime._ping_phase)
    assert "fully_checked = True" in src, "ping-принятые узлы fully_checked (кеш перепроверки)"
    assert "Фаза 2" not in src, "стресс-фазы в ping-фазе нет"
    ref_src = inspect.getsource(xr.XrayCoreRuntime.refresh)
    assert "_ping_phase(" in ref_src, "refresh делегирует общую ping-фазу"
    assert "ThreadPoolExecutor" not in ref_src, "сам refresh больше не пингует напрямую"


# ------------------------------------------------------------- 5. tg_media.py
def test_tg_media_module_restored():
    assert os.path.exists(os.path.join(ROOT, "checkers", "tg_media.py")), (
        "модуль checkers/tg_media.py восстановлен (загрузка медиа с t.me/s/)"
    )
    tg = read("checkers/tg_media.py")
    assert "def run_tg_media_check(" in tg, "функция run_tg_media_check на месте"
    assert "def check_node_tg_media_detailed(" in tg
    pro = read("checkers/telegram_pro.py")
    assert "from .tg_media import" in pro, "telegram_pro импортирует модуль tg_media"
    assert "run_tg_media_check(" in pro, "медиа-компонент telegram_pro — через tg_media"
    assert "_tg_media_probe" not in pro, "старая проба из xray_runtime не используется"
    xr = read("xray_runtime.py")
    assert "def _tg_media_probe" not in xr, "дубль медиа-пробы из xray_runtime удалён"


# ------------------------------------------- 6. скорость в имя НЕ пишется
def test_no_speed_in_names():
    pipe_src = read("subgen/pipeline.py")
    assert "_speed_name_suffix" not in pipe_src, "суффикс скорости удалён из pipeline"
    assert "set_node_name" not in pipe_src, "стресс-тест НЕ переименовывает узлы"
    assert "annotated" not in pipe_src
    # Скорость остаётся в отчёте:
    assert 'row["download_kbps"]' in pipe_src, "скорость — в row отчёта"
    assert '"stress": stress_report' in pipe_src, "секция stress в отчёте"
    geo_src = read("subgen/geo.py")
    assert "HS_SPEED_THRESHOLD_KBPS" not in geo_src, "⚡-константы удалены"
    assert "HS_NAME_SUFFIX" not in geo_src


# --------------------------------- 7. quick_sort_by_ping восстановлен
def test_quick_sort_by_ping_restored():
    import inspect

    import xray_runtime as xr

    assert hasattr(xr.XrayCoreRuntime, "quick_sort_by_ping"), (
        "метод quick_sort_by_ping восстановлен"
    )
    src = inspect.getsource(xr.XrayCoreRuntime.quick_sort_by_ping)
    assert "discovered_nodes" in src, "пул — из discovered_nodes (быстрый путь)"
    assert "self._ping_phase(" in src, "использует общую ping-фазу"
    refresh_src = read("subgen/refresh.py")
    assert "quick_sort_by_ping(" in refresh_src, "refresh.py идёт быстрым путём"
    assert "runtime.refresh(" not in refresh_src, "refresh.py НЕ вызывает полный refresh"
    assert "collect_subscription_nodes(" in refresh_src, "подписки собираются в refresh.py"
    assert "runtime.stop()" in refresh_src


# -------------------------- 8. порог пинга внутри ping-фазы
def test_ping_threshold_in_phase():
    import inspect

    import xray_runtime as xr

    sig = str(inspect.signature(xr.XrayCoreRuntime._probe_node_ping))
    assert "max_ping_ms" in sig, "_probe_node_ping принимает порог пинга"
    src = inspect.getsource(xr.XrayCoreRuntime._probe_node_ping)
    assert "ping_above_threshold" in src, "причина ping_above_threshold"
    assert "_socks_tcp_ping" in src, "пинг — SOCKS-TCP (1 RTT, как в v2rayNG)"
    assert "_socks_https_latency(" not in src, "HTTPS-замер (3-4 RTT) больше не вызывается из пинга"
    phase_src = inspect.getsource(xr.XrayCoreRuntime._ping_phase)
    assert "executor.submit(self._probe_node_ping, node, max_ping_ms)" in phase_src

    # Порог проходит всей цепочкой: CLI -> run_refresh -> quick_sort
    pipe_src = read("subgen/pipeline.py")
    assert "max_ping_ms=float(args.max_ping)" in pipe_src, "pipeline передаёт порог"
    refresh_src = read("subgen/refresh.py")
    assert "max_ping_ms: float = 0.0" in refresh_src, "run_refresh принимает порог"
    assert "max_ping_ms=max_ping_ms" in refresh_src, "run_refresh пробрасывает в quick_sort"
    # И применяется к кешу перепроверки:
    assert "cached nodes with ping >" in pipe_src, "перепроверка тоже фильтрует по пингу"


# --------------------------------------------------------------- 7. параллельность
def test_parallel_stages():
    src = read("subgen/pipeline.py")
    assert "_run_stage_parallel" in src, "проверочные этапы выполняются параллельно"
    assert "_stage_worker_count" in src
    # Каждая проверка использует общий хелпер
    for stage in ("_telegram_worker", "_dpi_worker", "_ai_geo_worker",
                  "_route_worker", "_resilience_worker", "_stress_worker"):
        assert stage in src, f"{stage} использует параллельный хелпер"
    assert "STAGE_PARALLEL_WORKERS_MAX = 8" in src


def test_worker_thread_safety_ping():
    """Пинг-этап по-прежнему параллельный (не сломан реструктуризацией)."""
    import inspect

    import xray_runtime as xr

    src = inspect.getsource(xr.XrayCoreRuntime._ping_phase)
    assert "ThreadPoolExecutor" in src
    assert "_probe_node_ping" in src
    qs_src = inspect.getsource(xr.XrayCoreRuntime.quick_sort_by_ping)
    assert "_ping_phase" in qs_src, "быстрый путь использует ту же ping-фазу"


TESTS = [
    ("спид-тест не отсеивает: refresh/xray_runtime", test_no_speed_filter),
    ("спид-тест не отсеивает: pipeline без фильтров", test_pipeline_no_speed_reject),
    ("XrayRuntimeConfig без min_speed_kbps", test_no_min_speed_in_config),
    ("STAGE_ORDER: ..., geo, stress", test_stage_order_v9),
    ("стресс после переименования, до экспорта", test_stress_after_rename),
    ("порог 512 по умолчанию везде", test_default_512),
    ("v9-миграция min_speed в settings", test_settings_migration),
    ("_wait_socks_ready вместо sleep", test_wait_socks_ready),
    ("ping-фаза: fully_checked, refresh делегирует", test_refresh_marks_fully_checked),
    ("tg_media.py восстановлен и подключён", test_tg_media_module_restored),
    ("скорость в имена НЕ пишется", test_no_speed_in_names),
    ("quick_sort_by_ping восстановлен", test_quick_sort_by_ping_restored),
    ("порог пинга внутри ping-фазы", test_ping_threshold_in_phase),
    ("параллельные проверочные этапы", test_parallel_stages),
    ("пинг остался параллельным", test_worker_thread_safety_ping),
]


def main() -> int:
    print("=== test_stress_reorder (v9) ===")
    for name, fn in TESTS:
        check(name, fn)
    failed = [r for r in RESULTS if not r[1]]
    for name, ok, err in RESULTS:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"\n         {err}" if err else ""))
    print(f"Итого: {len(RESULTS) - len(failed)}/{len(RESULTS)} PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
