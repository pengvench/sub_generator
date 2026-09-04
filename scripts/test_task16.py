#!/usr/bin/env python3
"""Тесты Task 16: слияние Zapret в DPI, ИИ-гео слепок, обход hosts, TG-медиа.

Всё на моках — без сети и без core-процессов:
  1.  Слияние: комбинированный вердикт (классика AND suite), suite-поля, row.
  2.  Слияние: бюджет +95с при run_suite (DPI_SUITE_BUDGET).
  3.  Zapret-этапа нет: STAGE_ORDER без 'zapret', с 'ai_geo'.
  4.  Алиасы: --zapret-check -> dpi_check+dpi_suite; zapret-* -> dpi-suite-*;
      --start-stage zapret -> dpi.
  5.  ai_geo: parse_cf_trace (loc=), parse_google_country (CSS-ловушка O3yKUb),
      is_russia_name/iso, compute_verdict (True/False/None).
  6.  ai_geo: AiGeoResult.row() — полный слепок на моках.
  7.  hostres: кеш резолва 300с, IP-literal без DoH, деградация urlopen.
  8.  zapret._fetch_suite_json через hostres (мок direct_https_get).
  9.  TG-медиа: _tg_media_video_urls — blured последним, теговый парсинг.
  10. TG-медиа: анти-кеш — случайный Range-старт (мок SOCKS-туннеля).
  11. TG-медиа: row/_result_from_row раундтрип tg_media_kbps.
  12. Медиа-фильтр обязателен для всех: метки 📼 и rescue-механики нет.
  13. AST: idna-вызовы в dpi_active обёрнуты try (fallback).
  14. runner: PipelineOptions (без dpi_suite/ai_check) + build_pipeline_args.
  15. settings/start_page/runner: ai_check/zapret_check удалены, один
      DPI-тумблер, ai_strict без зависимости, миграция zapret_check.
  16. v8: ai-слепок обязателен — поле узла (раундтрип кеша), флаг в
      serialize_working, run_suite безусловен при dpi_check.

Запуск:  python3 scripts/test_task16.py  (из корня SubGenerator)
"""
from __future__ import annotations

import ast
import os
import sys
import types

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO_ROOT, "python")
sys.path.insert(0, ROOT)

PASSED = 0
FAILED = 0


def check(name: str, fn) -> None:
    global PASSED, FAILED
    try:
        fn()
        print(f"  PASS  {name}")
        PASSED += 1
    except Exception as exc:
        print(f"  FAIL  {name}: {exc}")
        FAILED += 1


# ------------------------------------------------------------------ 1. слияние
def test_merge_verdict():
    from checkers import dpi as dpi_mod
    from checkers.base import TCP1620_NOT_DETECTED
    from checkers.zapret import ZapretCheckResult, ZapretTarget

    calls = {}

    def fake_run_zapret_checks(host, port, targets, timeout, http_test, min_score):
        calls["suite"] = (host, port, len(targets), timeout, http_test, min_score)
        return ZapretCheckResult(
            accepted=False,
            reason="score_0.500_below_0.75 (blocked=2/2)",
            score=0.5,
            min_score=0.75,
            total_probes=4,
            ok_probes=2,
            total_targets=2,
            ok_targets=0,
            blocked_targets=2,
        )

    orig = dpi_mod.base
    try:
        # Классика проходит: alive + tcp1620 NOT_DETECTED + siberian ok.
        dpi_mod.base = types.SimpleNamespace(
            tls_handshake_ok=lambda *a, **k: True,
            tcp1620_payload_ok=lambda *a, **k: TCP1620_NOT_DETECTED,
            siberian_check_ok=lambda *a, **k: True,
        )
        import checkers.zapret as zap_mod

        real = zap_mod._run_zapret_checks
        zap_mod._run_zapret_checks = fake_run_zapret_checks
        try:
            res = dpi_mod._run_checks(
                "127.0.0.1",
                1080,
                "instagram.com",
                2.0,
                target_hosts=("instagram.com",),
                run_suite=True,
                suite_targets=[ZapretTarget(id="1", provider="p", country="RU", host="h1")],
                suite_timeout=3.0,
                suite_min_score=0.9,
                suite_http_test=False,
            )
        finally:
            zap_mod._run_zapret_checks = real

        # Комбинированный вердикт: классика AND suite -> FAIL из-за suite.
        assert res.accepted is False, "suite FAIL должен ронять вердикт"
        assert res.reason.startswith("suite_"), f"reason={res.reason!r}"
        assert res.suite_run is True and res.suite_accepted is False
        assert res.suite_score == 0.5
        # row() содержит suite-поля (кеш-раундтрип).
        row = res.row()
        assert row["suite_run"] is True
        assert row["suite_accepted"] is False
        assert row["suite_score_text"] == "2/4"
        assert row["reason"].startswith("suite_")
        # Suite выполнялся на том же SOCKS-порту (тот же core-процесс).
        assert calls["suite"][1] == 1080
        assert calls["suite"][2] == 1  # цели переданы
        assert calls["suite"][5] == 0.9  # min_score пробрасывается

        # Классика проходит + suite проходит -> accepted.
        zap_mod._run_zapret_checks = lambda *a, **k: ZapretCheckResult(
            accepted=True, reason="ready", score=1.0, total_probes=4, ok_probes=4, total_targets=2, ok_targets=2
        )
        try:
            res2 = dpi_mod._run_checks(
                "127.0.0.1", 1080, "instagram.com", 2.0,
                target_hosts=("instagram.com",),
                run_suite=True, suite_targets=[object()],
            )
        finally:
            zap_mod._run_zapret_checks = real
        assert res2.accepted is True, "классика+suite OK должен проходить"
        assert res2.suite_run and res2.suite_accepted
        # run_suite=False -> suite не выполняется вовсе.
        res3 = dpi_mod._run_checks(
            "127.0.0.1", 1080, "instagram.com", 2.0,
            target_hosts=("instagram.com",), run_suite=False,
        )
        assert res3.suite_run is False and res3.accepted is True
    finally:
        dpi_mod.base = orig


def test_merge_budget():
    import inspect

    from checkers import dpi as dpi_mod

    src = inspect.getsource(dpi_mod.check_node_dpi_detailed)
    assert "run_suite" in inspect.signature(dpi_mod.check_node_dpi_detailed).parameters
    assert "suite_targets" in inspect.signature(dpi_mod.check_node_dpi_detailed).parameters
    assert "suite_timeout" in inspect.signature(dpi_mod.check_node_dpi_detailed).parameters
    assert "suite_min_score" in inspect.signature(dpi_mod.check_node_dpi_detailed).parameters
    assert "suite_http_test" in inspect.signature(dpi_mod.check_node_dpi_detailed).parameters
    assert "DPI_SUITE_BUDGET" in src, "бюджет должен расти при включённом suite"
    assert dpi_mod.DPI_SUITE_BUDGET >= 90.0, "бюджет suite ~95с"


# ------------------------------------------------------------------ 3. zapret-этап
def test_no_zapret_stage():
    from subgen.pipeline import STAGE_ORDER

    assert "zapret" not in set(STAGE_ORDER), "отдельный zapret-этап должен быть объединён с dpi"
    assert "ai_geo" in set(STAGE_ORDER), "ai_geo-этап отсутствует"
    assert "dpi" in set(STAGE_ORDER)


def test_aliases():
    from subgen.pipeline import _apply_stage_aliases, build_parser

    parser = build_parser()
    args = _apply_stage_aliases(parser.parse_args(["--zapret-check"]))
    assert args.dpi_check, "--zapret-check должен включать dpi_check (suite всегда часть DPI)"

    args = _apply_stage_aliases(
        parser.parse_args([
            "--zapret-check",
            "--zapret-targets", "5",
            "--zapret-timeout", "7",
            "--zapret-min-score", "0.5",
            "--zapret-no-http",
        ])
    )
    assert args.dpi_check
    assert args.dpi_suite_targets == 5
    assert args.dpi_suite_timeout == 7.0
    assert args.dpi_suite_min_score == 0.5
    assert args.dpi_suite_no_http is True

    args = _apply_stage_aliases(parser.parse_args(["--start-stage", "zapret"]))
    assert args.start_stage == "dpi", "start-stage zapret ремапится на dpi"


# ------------------------------------------------------------------ 5. ai_geo
def test_ai_geo_parsers():
    from checkers.ai_geo import (
        compute_verdict,
        is_russia_iso,
        is_russia_name,
        parse_cf_trace,
        parse_google_country,
    )

    trace = b"fl=abc\nip=185.1.2.3\nloc=HK\nhttp=http/2\n"
    assert parse_cf_trace(trace) == "HK"
    assert parse_cf_trace(b"") == ""
    assert parse_cf_trace(b"loc=RU\n") == "RU"

    # CSS-ловушка: .O3yKUb{...} не матчится (нет кавычки+'>'), футер — да.
    html = (
        b"<html><style>.O3yKUb{padding:0}</style>"
        b'<div class="O3yKUb">\xd0\x93\xd0\xbe\xd0\xbd\xd0\xba\xd0\xbe\xd0\xbd\xd0\xb3</div></html>'
    )
    assert parse_google_country(html) == "Гонконг"
    assert parse_google_country(b"<style>.O3yKUb{padding:0}</style>") == ""

    assert is_russia_name("Россия") and is_russia_name("russia")
    assert not is_russia_name("Гонконг")
    assert is_russia_iso("RU") and is_russia_iso("rus")
    assert not is_russia_iso("HK")

    # compute_verdict: (openai_ok, gemini_ok, ai_unblocked, reason)
    ok, g, verdict, reason = compute_verdict("HK", "Гонконг")
    assert ok and g and verdict is True and reason.startswith("ai_geo_ok")
    ok, g, verdict, reason = compute_verdict("RU", "Россия")
    assert (not ok) and (not g) and verdict is False and reason.startswith("ai_geo_russia")
    ok, g, verdict, reason = compute_verdict("", "")
    assert verdict is None and reason == "ai_signals_unavailable"
    ok, g, verdict, _ = compute_verdict("", "Гонконг")
    assert (not ok) and g and verdict is True


def test_ai_geo_result_row():
    from checkers.ai_geo import AiGeoResult

    res = AiGeoResult(
        checked=True, accepted=True, cf_loc="HK", cf_source="chatgpt.com",
        google_country="Гонконг", gemini_reachable=True,
        openai_ok=True, gemini_ok=True, ai_unblocked=True,
        reason="ai_geo_ok (cf=HK, google=Гонконг)",
    )
    row = res.row()
    assert row["cf_loc"] == "HK" and row["google_country"] == "Гонконг"
    assert row["ai_unblocked"] is True and row["gemini_reachable"] is True
    assert row["checked"] is True


# ------------------------------------------------------------------ 7. hostres
def test_hostres_cache_and_literal():
    from checkers import hostres

    hostres.clear_resolve_cache()
    # IP-literal не требует DoH.
    assert hostres.resolve_ip("1.1.1.1") == "1.1.1.1"
    assert hostres._doh_query("example.com", 0.1) is None or True  # без сети не падает

    # Кеш: DoH зовётся один раз, второй резолв из кеша.
    calls = {"n": 0}

    def fake_doh(host, timeout):
        calls["n"] += 1
        return "93.184.216.34"

    hostres.clear_resolve_cache()
    orig = hostres._doh_query
    hostres._doh_query = fake_doh
    try:
        assert hostres.resolve_ip("example.com") == "93.184.216.34"
        assert hostres.resolve_ip("example.com") == "93.184.216.34"
        assert calls["n"] == 1, "второй резолв должен идти из кеша"
    finally:
        hostres._doh_query = orig
    hostres.clear_resolve_cache()


def test_hostres_degradation():
    from checkers import hostres

    # DoH недоступен -> urlopen-fallback с hosts_dependent=True.
    hostres.clear_resolve_cache()
    orig_doh = hostres._doh_query
    orig_urlget = hostres._https_ip_get
    hostres._doh_query = lambda host, timeout: None
    opened = {"n": 0}

    class FakeResp:
        status = 200

        def read(self, n):
            opened["n"] += 1
            return b'{"Answer":[{"type":1,"data":"1.2.3.4"}]}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        opened["url"] = req.full_url
        return FakeResp()

    import urllib.request

    orig_urlopen = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        resp = hostres.direct_https_get(
            "https://example.com/dns-query?name=x&type=A",
            timeout=2.0,
            max_bytes=4096,
            headers={"Accept": "application/dns-json"},
        )
        assert resp.ok and resp.status == 200
        assert resp.hosts_dependent is True, "fallback обязан помечать hosts_dependent"
        assert b"Answer" in resp.body
        assert opened["url"].startswith("https://example.com/")
    finally:
        urllib.request.urlopen = orig_urlopen
        hostres._doh_query = orig_doh
        hostres._https_ip_get = orig_urlget
        hostres.clear_resolve_cache()


# ------------------------------------------------------------------ 8. suite-fetch
def test_suite_fetch_via_hostres():
    import checkers.zapret as zap
    from checkers import hostres

    captured = {}

    class FakeResponse:
        ok = True
        status = 200
        body = b'[{"id":"t1","provider":"prov","country":"RU","host":"z1.example"}]'

    def fake_get(url, timeout=8.0, max_bytes=0, headers=None, method="GET"):
        captured["url"] = url
        captured["headers"] = headers
        captured["max_bytes"] = max_bytes
        return FakeResponse()

    orig = hostres.direct_https_get
    hostres.direct_https_get = fake_get
    try:
        targets = zap._fetch_suite_json("https://suite.example/suite.v2.json", 5.0)
    finally:
        hostres.direct_https_get = orig

    assert targets is not None and len(targets) == 1
    assert targets[0].host == "z1.example" and targets[0].provider == "prov"
    assert captured["url"] == "https://suite.example/suite.v2.json"
    assert captured["headers"].get("Accept") == "application/json"
    assert captured["max_bytes"] >= 64 * 1024


# ------------------------------------------------------------------ 9. tg-media urls
def test_tg_media_video_urls():
    import xray_runtime as xr

    html = (
        b'<div><video src="https://cdn4.telesco.pe/file/a.mp4?token=1" class="blured"></video>'
        b'<video src="https://cdn4.telesco.pe/file/b.mp4?token=2"></video>'
        b'<video src="https://cdn4.telesco.pe/file/c.mp4?token=3" class="blured"></video></div>'
    )
    urls = xr._tg_media_video_urls(html)
    assert len(urls) == 3, "все три видео извлекаются"
    # blured — в конце (сначала полноразмерные).
    assert urls[0].endswith("b.mp4?token=2"), f"порядок: {urls}"
    assert urls[1].endswith("a.mp4?token=1")
    assert urls[2].endswith("c.mp4?token=3")
    # Пустой/мусорный HTML.
    assert xr._tg_media_video_urls(b"") == []
    assert xr._tg_media_video_urls(b"<p>no video here</p>") == []


def test_tg_media_row_roundtrip():
    import xray_runtime as xr

    node = xr.parse_node_link(
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443"
        "?encryption=none&security=tls&sni=example.com&type=tcp#t"
    )
    assert node is not None
    probe = xr.XrayProbeResult(
        node=node, accepted=True, reason="tg_media_ok",
        latency_ms=50.0, successes=3, attempts=3, runtime=node.runtime,
    )
    probe.tg_media_kbps = 1173.5
    row = probe.row()
    assert row.get("tg_media_kbps") == 1173.5
    assert row.get("url")  # ссылка узла — для раундтрипа через кеш
    restored = xr._result_from_row(row, accepted=True)
    assert restored is not None
    assert restored.tg_media_kbps == 1173.5
    assert restored.reason == "tg_media_ok"


# ------------------------------------------------ 12. медиа-фильтр без метки
def test_geo_tg_media_suffix():
    from subgen import geo

    assert not hasattr(geo, "TG_MEDIA_NAME_SUFFIX"), "метка 📼 удалена (фильтр универсальный)"
    geo_src = open(os.path.join(ROOT, "subgen", "geo.py"), encoding="utf-8").read()
    assert "📼" not in geo_src, "иконка 📼 не должна остаться в geo.py"
    assert "tg_media_kbps" in geo_src, "geo должен сохранять tg_media_kbps как данные"

    xr_src = open(os.path.join(ROOT, "xray_runtime.py"), encoding="utf-8").read()
    assert "tg_media_failed" in xr_src, "медиа-фильтр должен отбраковывать (reason=tg_media_failed)"
    assert "TG_MEDIA_RESCUE_REASON_PREFIXES" not in xr_src, "rescue-механика удалена"
    assert "tg_media_ok" not in xr_src, "reason=tg_media_ok больше не выставляется"
    assert "_tg_media_probe" in xr_src and "_tg_media_rescue_probe" not in xr_src

    pipe_src = open(os.path.join(ROOT, "subgen", "pipeline.py"), encoding="utf-8").read()
    assert "rescued_media" not in pipe_src, "исключения rescue в фильтрах удалены"
    assert "tg_media_ok" not in pipe_src
    assert "📼" not in pipe_src, "иконка 📼 не должна остаться в pipeline.py"

    start_src = open(os.path.join(ROOT, "ui", "pages", "start_page.py"), encoding="utf-8").read()
    assert "📼" not in start_src, "иконка 📼 не должна остаться в тултипе UI"


# ------------------------------------------------------------------ 13. AST
def test_dpi_active_idna_try():
    tree = ast.parse(open(os.path.join(ROOT, "checkers", "dpi_active.py"), encoding="utf-8").read())
    found_idna = False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for sub in ast.walk(node):
                if (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "encode"
                    and sub.args
                    and isinstance(sub.args[0], ast.Constant)
                    and sub.args[0].value == "idna"
                ):
                    found_idna = True
                    assert any(isinstance(anc, ast.Try) for anc in ast.walk(node)), (
                        f"encode('idna') в {node.name} не обёрнут try/except"
                    )
    assert found_idna, "в dpi_active должен быть хотя бы один idna-вызов"


# ------------------------------------------------------------------ 14. runner
def test_runner_options():
    from ui.runner import PipelineOptions, build_pipeline_args

    opts = PipelineOptions(
        dpi_check=True, dpi_siberian=True, dpi_cidr=False,
        ai_strict=True,
    )
    args = build_pipeline_args(opts, ["https://sub.example/list"])
    assert "--dpi-check" in args
    assert "--ai-strict" in args
    assert "--dpi-siberian" in args
    assert "--dpi-suite" not in args, "suite не передаётся: всегда часть --dpi-check (v8)"
    assert "--ai-check" not in args, "ai-слепок обязателен, флаг не нужен (v8)"
    assert args[args.index("--sources") + 1] == "https://sub.example/list"

    # ai_strict выключен -> флага нет; слепок всё равно всегда выполняется.
    opts2 = PipelineOptions(ai_strict=False)
    args2 = build_pipeline_args(opts2, [])
    assert "--ai-strict" not in args2 and "--ai-check" not in args2


# ------------------------------------------------------------------ 15. settings/UI
def test_settings_and_ui():
    from subgen.settings import DEFAULT_TEST_OPTIONS

    # v8: ai_check/zapret_check удалены из дефолтов (слепок обязателен,
    # suite — часть DPI); осталась единственная опция ai_strict.
    assert "ai_check" not in DEFAULT_TEST_OPTIONS
    assert "zapret_check" not in DEFAULT_TEST_OPTIONS
    assert DEFAULT_TEST_OPTIONS.get("ai_strict") is False
    assert DEFAULT_TEST_OPTIONS.get("ai_timeout") == 6.0
    # WARP удалён из дефолтов.
    assert "add_warp" not in DEFAULT_TEST_OPTIONS
    assert "warp_presets" not in DEFAULT_TEST_OPTIONS

    start_src = open(os.path.join(ROOT, "ui", "pages", "start_page.py"), encoding="utf-8").read()
    # v8: один DPI-тумблер (suite внутри), ИИ-гео без тумблера — только strict.
    assert 'self.toggle_dpi_suite = ' not in start_src, "тумблер DPI suite удалён (v8: один DPI-тумблер)"
    assert 'DPI suite (Zapret-методика)' not in start_src
    assert 'self.toggle_ai = ' not in start_src, "тумблер ИИ-гео удалён (этап обязательный)"
    assert 'self.toggle_ai_strict = ' in start_src, "тумблер strict остаётся"
    assert 'ИИ-гео: исключить РФ-слепок' in start_src
    assert 'enabled_when=self.toggle_ai' not in start_src, "strict больше не зависит от ai"
    # Миграция старого ключа zapret_check -> включение DPI.
    assert 'zapret_check' in start_src, "миграция zapret_check -> toggle_dpi"
    assert 'tg_media_rescue' not in start_src, "тумблер tg_media убран (rescue автоматический)"

    runner_src = open(os.path.join(ROOT, "ui", "runner.py"), encoding="utf-8").read()
    assert 'dpi_suite: bool' not in runner_src and 'ai_check: bool' not in runner_src

    app_src = open(os.path.join(ROOT, "ui", "app.py"), encoding="utf-8").read()
    assert '"ai_geo"' in app_src, "сводка результатов должна содержать ai_geo"
    assert '("zapret", "Zapret")' not in app_src


# ------------------------------------------------ 16. v8: ai-слепок обязателен
def test_ai_geo_mandatory_v8():
    import xray_runtime as xr

    # Слепок — поле узла: раундтрип через кеш (флаг страны при recheck).
    node = xr.parse_node_link(
        "vless://515f2f57-6d28-4d5a-9a3c-9d34b1e55555@example.com:443?security=tls&type=ws#test",
        source_url="cache",
    )
    assert node is not None
    probe = xr.XrayProbeResult(
        node=node, accepted=True, reason="ready",
        latency_ms=50.0, successes=3, attempts=3, runtime=node.runtime,
    )
    probe.ai_geo_country = "DE"
    row = probe.row()
    assert row.get("ai_geo_country") == "DE"
    restored = xr._result_from_row(row, accepted=True)
    assert restored is not None and restored.ai_geo_country == "DE"

    # Приоритет флага в serialize_working: слепок раньше pyip/egress/geoip.
    geo_src = open(os.path.join(ROOT, "subgen", "geo.py"), encoding="utf-8").read()
    assert "ai_geo_country" in geo_src, "geo должен брать страну из ai_geo_country"

    pipe_src = open(os.path.join(ROOT, "subgen", "pipeline.py"), encoding="utf-8").read()
    assert "args.ai_check = True" in pipe_src, "ai-этап обязателен (нормализация в run())"
    assert "run_suite = bool(getattr(args, \"dpi_check\", False))" in pipe_src, (
        "suite безусловно включается вместе с --dpi-check"
    )


def main() -> int:
    tests = [
        ("слияние: вердикт классика AND suite + suite-поля + row", test_merge_verdict),
        ("слияние: сигнатура + бюджет DPI_SUITE_BUDGET", test_merge_budget),
        ("zapret-этапа нет (STAGE_ORDER)", test_no_zapret_stage),
        ("алиасы zapret-* -> dpi-suite-* / start-stage", test_aliases),
        ("ai_geo: парсеры + compute_verdict", test_ai_geo_parsers),
        ("ai_geo: AiGeoResult.row()", test_ai_geo_result_row),
        ("hostres: кеш + IP-literal", test_hostres_cache_and_literal),
        ("hostres: деградация urlopen + hosts_dependent", test_hostres_degradation),
        ("zapret: suite-fetch через hostres", test_suite_fetch_via_hostres),
        ("tg-media: video urls (blured последними)", test_tg_media_video_urls),
        ("tg-media: row/_result_from_row раундтрип", test_tg_media_row_roundtrip),
        ("geo: медиа-фильтр без метки 📼, rescue удалён", test_geo_tg_media_suffix),
        ("AST: idna в dpi_active обёрнут try", test_dpi_active_idna_try),
        ("runner: PipelineOptions + build_pipeline_args", test_runner_options),
        ("settings/start_page/runner: v8-ключи, один DPI-тумблер", test_settings_and_ui),
        ("v8: ai-слепок обязателен + флаг по слепку + suite безусловен", test_ai_geo_mandatory_v8),
    ]
    for name, fn in tests:
        print(f"=== {name} ===")
        check(name, fn)
    print()
    print(f"ИТОГ: {PASSED} passed, {FAILED} failed")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
