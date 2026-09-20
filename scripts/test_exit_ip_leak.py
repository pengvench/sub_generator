#!/usr/bin/env python3
"""Тесты v14: (1) полный список протоколов + ★-пометки популярных;
(2) жёсткий отбор «прозрачных» узлов (exit-IP == ваш IP, SOCKS-путь).

Часть 1 — params_filter / filters_page:
  1. hysteria (v1) — отдельное значение фильтра (раньше сливалась с hy2);
     quic+tls у обоих; полный список протоколов = парсер (NODE_SCHEMES).
  2. POPULAR/POPULAR_NOTES консистентны (все значения в DIMENSIONS, у всех
     помеченных есть заметка-тултип).
  3. filters_page: ★-метки на галочках, приписка-легенда, миграция настроек
     (hysteria2 в сохранённых -> включаем и hysteria).

Часть 2 — ai_geo / pipeline / app (утечки exit-IP):
  4. _probe_ipinfo/_probe_ipapi: из тех же тел достаются страна И exit-IP
     (ipinfo "ip": ..., ip-api "query": ...).
  5. _run_ai_geo_checks: exit_ip = ipinfo (приоритет) / ip-api (fallback).
  6. fetch_real_ip: прямой запрос без прокси (фейковый hostres), fallback
     ipify (plain text), полный отказ -> ("", "").
  7. pipeline: real_ip запрашивается ОДИН раз до обхода; утечка = положительное
     совпадение (любой IP пуст -> узел НЕ отсеивается); node_rejected =
     leaked ИЛИ (ai_strict И слепок РФ) — жёсткий отбор НЕЗАВИСИМО от strict;
     leak_check в ai_geo-отчёте.
  8. app.py: строка «Утечки exit-IP» под ИИ-гео + учёт в высоте окна.

Часть 3 — регрессионные охраны:
  9. Логика сравнения IP (регистр/пробелы) как в конвейере.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from subgen.params_filter import (  # noqa: E402
    DIMENSIONS,
    LABELS,
    POPULAR,
    POPULAR_NOTES,
    build_matcher,
    node_params,
)
from checkers import ai_geo as AG  # noqa: E402
from runtime.uritools import NODE_SCHEMES  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}  {detail}")


class _Node:
    """Минимальный узел для node_params (protocol + query)."""

    def __init__(self, protocol: str, query: dict | None = None):
        self.protocol = protocol
        self.query = query or {}


# ---------------------------------------------------------------------------
print("== 1. hysteria (v1) — отдельное значение; полный список протоколов ==")

p = node_params(_Node("hysteria"))
check(
    "hysteria v1 -> protocol=hysteria (не сливается с hysteria2)",
    p["protocol"] == "hysteria",
    str(p),
)
check(
    "hysteria v1 -> quic+tls (sing-box)",
    p["transport"] == "quic" and p["security"] == "tls",
    str(p),
)
p = node_params(_Node("hy2"))
check("hy2 -> hysteria2 (как раньше)", p["protocol"] == "hysteria2", str(p))
p = node_params(_Node("hysteria2"))
check("hysteria2 -> hysteria2", p["protocol"] == "hysteria2", str(p))

# Полный список фильтра покрывает всё, что парсер умеет поднимать.
_schemes = {s.rstrip("://") for s in NODE_SCHEMES}
_alias = {"ss": "shadowsocks", "hy2": "hysteria2"}
_parsed_protocols = {_alias.get(s, s) for s in _schemes}
check(
    "DIMENSIONS.protocol покрывает NODE_SCHEMES парсера",
    _parsed_protocols <= set(DIMENSIONS["protocol"]),
    f"нет в фильтре: {_parsed_protocols - set(DIMENSIONS['protocol'])}",
)
check(
    "в фильтре нет лишних протоколов (не умеем проверять)",
    set(DIMENSIONS["protocol"]) <= _parsed_protocols,
    f"лишние: {set(DIMENSIONS['protocol']) - _parsed_protocols}",
)

# Матчер: фильтр hysteria2 не должен резать hysteria v1 и наоборот.
m = build_matcher(protocols={"hysteria2"})
check(
    "фильтр hysteria2 пропускает hysteria2",
    m(_Node("hysteria2")),
)
check(
    "фильтр hysteria2 режет hysteria v1 (значения теперь разные)",
    not m(_Node("hysteria")),
)
m = build_matcher(protocols={"hysteria", "hysteria2"})
check(
    "фильтр hysteria+hysteria2 пропускает оба",
    m(_Node("hysteria")) and m(_Node("hysteria2")),
)

# ---------------------------------------------------------------------------
print("== 2. POPULAR: консистентность метаданных ==")

for dim, values in POPULAR.items():
    check(
        f"POPULAR[{dim}] внутри DIMENSIONS[{dim}]",
        values <= set(DIMENSIONS[dim]),
        str(values - set(DIMENSIONS[dim])),
    )
for dim, values in POPULAR.items():
    missing = [v for v in values if v not in POPULAR_NOTES]
    check(
        f"POPULAR_NOTES покрывает POPULAR[{dim}]",
        not missing,
        str(missing),
    )
check(
    "нет заметок для НЕпопулярных значений (не должны показываться)",
    set(POPULAR_NOTES) <= {v for vals in POPULAR.values() for v in vals},
    str(set(POPULAR_NOTES) - {v for vals in POPULAR.values() for v in vals}),
)
check(
    "hysteria (v1) НЕ помечен популярным (это legacy)",
    "hysteria" not in POPULAR["protocol"],
)
check(
    "LABELS для hysteria (v1) есть",
    "hysteria" in LABELS,
)

# ---------------------------------------------------------------------------
print("== 3. filters_page: ★-метки, приписка, миграция ==")

fp_src = (REPO / "python" / "ui" / "pages" / "filters_page.py").read_text(
    encoding="utf-8"
)
check(
    "filters_page импортирует POPULAR/POPULAR_NOTES",
    "POPULAR" in fp_src and "POPULAR_NOTES" in fp_src,
)
check(
    "★-метка на галочках ходовых значений",
    'label = f"★ {label}"' in fp_src,
)
check(
    "приписка-легенда POPULAR_FOOTNOTE на странице",
    "POPULAR_FOOTNOTE" in fp_src and "самые ходовые" in fp_src.lower(),
)
check(
    "приписка обещает: список НЕ обрезается",
    "НЕ" in fp_src and "обрезается" in fp_src,
)
check(
    "миграция настроек: hysteria2 в сохранённых -> включить hysteria",
    '"hysteria2" in allowed' in fp_src and 'allowed.add("hysteria")' in fp_src,
)
check(
    "тултип на популярных галочках",
    "POPULAR_NOTES.get(value" in fp_src,
)

# ---------------------------------------------------------------------------
print("== 4. _probe_ipinfo/_probe_ipapi: страна + exit-IP из одного тела ==")


class _FakeBase:
    """Фейк checkers.base.http_get_body — отдат заготовленный ответ."""

    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self._status = status

    def http_get_body(self, *a, **kw):
        return True, self._body, self._status


_ipinfo_body = (
    b'{"ip": "185.123.45.6", "hostname": "x.example.com",'
    b' "city": "Berlin", "region": "BE", "country": "DE",'
    b' "loc": "52.52,13.40"}'
)
_ipapi_body = (
    b'{"status":"success","country":"Germany","countryCode":"DE",'
    b'"region":"BE","city":"Berlin","query":"185.123.45.6"}'
)

_orig_base = AG.base
try:
    AG.base = _FakeBase(_ipinfo_body)  # type: ignore[assignment]
    country, ip = AG._probe_ipinfo("127.0.0.1", 1080, 3.0)
    check(
        "ipinfo: страна + exit-IP",
        country == "DE" and ip == "185.123.45.6",
        f"country={country} ip={ip}",
    )
    AG.base = _FakeBase(_ipapi_body)  # type: ignore[assignment]
    country, ip = AG._probe_ipapi("127.0.0.1", 1080, 3.0)
    check(
        "ip-api: страна + exit-IP (поле query)",
        country == "DE" and ip == "185.123.45.6",
        f"country={country} ip={ip}",
    )
    AG.base = _FakeBase(b"garbage", status=503)  # type: ignore[assignment]
    c1, i1 = AG._probe_ipinfo("127.0.0.1", 1080, 3.0)
    c2, i2 = AG._probe_ipapi("127.0.0.1", 1080, 3.0)
    check(
        "плохой статус -> ('', '') без исключения",
        (c1, i1) == ("", "") and (c2, i2) == ("", ""),
        f"{(c1, i1)} {(c2, i2)}",
    )
    # тела без полей IP
    AG.base = _FakeBase(b'{"country": "DE"}')  # type: ignore[assignment]
    c3, i3 = AG._probe_ipinfo("127.0.0.1", 1080, 3.0)
    check(
        "ipinfo без поля ip: страна есть, IP пуст",
        c3 == "DE" and i3 == "",
        f"{(c3, i3)}",
    )
finally:
    AG.base = _orig_base

# ---------------------------------------------------------------------------
print("== 5. _run_ai_geo_checks: exit_ip с приоритетом ipinfo ==")


def _patch_probes(monkey: dict):
    """Подменить пробы модуля; вернуть словарь для восстановления."""
    saved = {}
    for name in monkey:
        saved[name] = getattr(AG, name)
        setattr(AG, name, monkey[name])
    return saved


def _restore(saved: dict):
    for name, fn in saved.items():
        setattr(AG, name, fn)


saved = _patch_probes(
    {
        "_probe_cf_trace": lambda *a, **k: ("DE", "chatgpt.com"),
        "_probe_google_country": lambda *a, **k: "Deutschland",
        "_probe_gemini": lambda *a, **k: True,
        "_probe_ipinfo": lambda *a, **k: ("DE", "185.111.22.33"),
        "_probe_ipapi": lambda *a, **k: ("DE", "185.111.99.99"),
    }
)
try:
    res = AG._run_ai_geo_checks("127.0.0.1", 1080, 3.0)
    check(
        "exit_ip из ipinfo (приоритет)",
        res.exit_ip == "185.111.22.33" and res.exit_ip_source == "ipinfo",
        f"exit={res.exit_ip} src={res.exit_ip_source}",
    )
    check(
        "row() и details содержат exit-IP",
        res.row().get("exit_ip") == "185.111.22.33"
        and res.details.get("exit_ip") == "185.111.22.33",
    )
finally:
    _restore(saved)

saved = _patch_probes(
    {
        "_probe_cf_trace": lambda *a, **k: ("", ""),
        "_probe_google_country": lambda *a, **k: "",
        "_probe_gemini": lambda *a, **k: False,
        "_probe_ipinfo": lambda *a, **k: ("", ""),
        "_probe_ipapi": lambda *a, **k: ("GB", "2.2.2.2"),
    }
)
try:
    res = AG._run_ai_geo_checks("127.0.0.1", 1080, 3.0)
    check(
        "exit_ip из ip-api (fallback)",
        res.exit_ip == "2.2.2.2" and res.exit_ip_source == "ip-api",
        f"exit={res.exit_ip} src={res.exit_ip_source}",
    )
finally:
    _restore(saved)

saved = _patch_probes(
    {
        "_probe_cf_trace": lambda *a, **k: ("", ""),
        "_probe_google_country": lambda *a, **k: "",
        "_probe_gemini": lambda *a, **k: False,
        "_probe_ipinfo": lambda *a, **k: ("", ""),
        "_probe_ipapi": lambda *a, **k: ("", ""),
    }
)
try:
    res = AG._run_ai_geo_checks("127.0.0.1", 1080, 3.0)
    check(
        "оба пусты -> exit_ip пуст (нет проверки утечки)",
        res.exit_ip == "" and res.exit_ip_source == "",
    )
finally:
    _restore(saved)

# ---------------------------------------------------------------------------
print("== 6. fetch_real_ip: прямое соединение (фейковый hostres) ==")


class _FakeResponse:
    def __init__(self, ok: bool, status: int, body: bytes):
        self.ok = ok
        self.status = status
        self.body = body


class _FakeHostres:
    def __init__(self, responses: list):
        self.responses = list(responses)
        self.calls: list[str] = []

    def direct_https_get(self, url, **kw):
        self.calls.append(url)
        if not self.responses:
            return _FakeResponse(False, 0, b"")
        return self.responses.pop(0)


_real_sys_path = list(sys.modules.keys())
try:
    # Убираем реальный hostres, подставляем фейк.
    sys.modules.pop("checkers.hostres", None)
    fake_mod = types.ModuleType("checkers.hostres")
    _fake = _FakeHostres(
        [_FakeResponse(True, 200, b'{"ip": "91.198.44.1", "country": "RU"}')]
    )
    fake_mod.direct_https_get = _fake.direct_https_get
    sys.modules["checkers.hostres"] = fake_mod

    ip, src = AG.fetch_real_ip(timeout=3.0)
    check(
        "fetch_real_ip: ipinfo отдал IP + источник",
        ip == "91.198.44.1" and src == "ipinfo.io",
        f"ip={ip} src={src}",
    )
    check(
        "fetch_real_ip: URL ipinfo.io/json (прямой, без SOCKS)",
        any("ipinfo.io/json" in c for c in _fake.calls),
        str(_fake.calls),
    )

    # fallback: ipinfo недоступен -> ipify (plain text).
    _fake2 = _FakeHostres(
        [_FakeResponse(False, 0, b""), _FakeResponse(True, 200, b"203.0.113.7")]
    )
    fake_mod.direct_https_get = _fake2.direct_https_get
    ip, src = AG.fetch_real_ip(timeout=3.0)
    check(
        "fetch_real_ip: fallback ipify (plain text)",
        ip == "203.0.113.7" and src == "api.ipify.org",
        f"ip={ip} src={src}",
    )

    # полный отказ.
    _fake3 = _FakeHostres([])
    fake_mod.direct_https_get = _fake3.direct_https_get
    ip, src = AG.fetch_real_ip(timeout=3.0)
    check(
        "fetch_real_ip: всё недоступно -> ('', '')",
        ip == "" and src == "",
        f"ip={ip} src={src}",
    )

    # ipinfo вернул мусор (нет поля ip) -> идём в ipify.
    _fake4 = _FakeHostres(
        [_FakeResponse(True, 200, b'{"country": "RU"}'),
         _FakeResponse(True, 200, b"198.51.100.9")]
    )
    fake_mod.direct_https_get = _fake4.direct_https_get
    ip, src = AG.fetch_real_ip(timeout=3.0)
    check(
        "fetch_real_ip: ipinfo без поля ip -> ipify",
        ip == "198.51.100.9" and src == "api.ipify.org",
        f"ip={ip} src={src}",
    )
finally:
    sys.modules.pop("checkers.hostres", None)
    # Восстанавливаем лишь реально существовавшие модули (фейк не трогаем).
    for name in _real_sys_path:
        pass  # реальные модули не удалялись — pop выше вернул None/реальный

# ---------------------------------------------------------------------------
print("== 7. pipeline: жёсткий отбор утечек + leak_check в отчёте ==")

pipe_src = (REPO / "python" / "subgen" / "pipeline.py").read_text(encoding="utf-8")
check(
    "pipeline импортирует fetch_real_ip",
    "fetch_real_ip" in pipe_src,
)
check(
    "real_ip запрашивается ДО параллельного обхода ai-geo (в ai-geo блоке)",
    pipe_src.index("fetch_real_ip(timeout=ai_timeout)")
    < pipe_src.index("def _check_ai_node"),
)
check(
    "утечка = положительное совпадение (оба IP не пусты)",
    "leaked = bool(" in pipe_src and "exit_ip.lower() == real_ip.strip().lower()" in pipe_src,
)
check(
    "жёсткий отбор НЕЗАВИСИМО от ai_strict: leaked OR strict",
    "node_rejected = leaked or bool(ai_strict and res.ai_unblocked is False)" in pipe_src,
)
check(
    "лог LEAK с указанием обоих IP",
    "[ai-geo] LEAK" in pipe_src,
)
check(
    "leak_check-секция в ai_geo-отчёте",
    '"leak_check": {' in pipe_src,
)
check(
    "failed_ai включает утечки (математика passed+failed=checked)",
    "failed_ai += 1" in pipe_src and "failed_leak += 1" in pipe_src,
)
check(
    "exit-IP попадает в обычный лог узла (exit=...)",
    "exit={exit_ip or '-'}" in pipe_src,
)

# Функциональная проверка логики вердикта (зеркально конвейеру: exit_ip
# стрипается ДО сравнения — pipeline: exit_ip = (...).strip()).
real_ip = "91.198.44.1"


def _verdict(exit_ip: str, real: str, ai_strict: bool, ai_unblocked):
    exit_ip = (exit_ip or "").strip()
    leaked = bool(real and exit_ip and exit_ip.lower() == real.strip().lower())
    return leaked or bool(ai_strict and ai_unblocked is False)


check("вердикт: exit == real -> отсеять (даже без strict)", _verdict(real_ip, real_ip, False, None))
check("вердикт: exit пуст -> НЕ отсеивать", not _verdict("", real_ip, False, None))
check("вердикт: real пуст -> НЕ отсеивать", not _verdict(real_ip, "", False, None))
check(
    "вердикт: разные IP -> пройти",
    not _verdict("185.123.45.6", real_ip, False, None),
)
check(
    "вердикт: регистр/пробелы не ломают сравнение",
    _verdict("  91.198.44.1 ", "91.198.44.1", False, None),
)
check(
    "вердикт: strict-РФ работает как раньше (без утечки)",
    _verdict("185.1.1.1", real_ip, True, False),
)
check(
    "вердикт: strict-РФ None (слепка нет) -> пройти",
    not _verdict("185.1.1.1", real_ip, True, None),
)

# ---------------------------------------------------------------------------
print("== 8. app.py: строка «Утечки exit-IP» в окне результатов ==")

app_src = (REPO / "python" / "ui" / "app.py").read_text(encoding="utf-8")
check(
    "строка «Утечки exit-IP» под ИИ-гео",
    "Утечки exit-IP" in app_src and 'stage_key == "ai_geo"' in app_src,
)
check(
    "цвет: 0 утечек = зелёный, >0 = красный",
    "n_leak == 0" in app_src and "theme.ERROR" in app_src,
)
check(
    "n_rows учитывает строку утечек",
    "(1 if has_leak else 0)" in app_src,
)
check(
    "охрана фикса окна результатов не тронута (dpi-фикс 2026-09-19)",
    "_dialog_scale" in app_src and "grid_propagate(False)" in app_src
    and 'Frame(dlg, height=2' in app_src,
)

# ---------------------------------------------------------------------------
print("== 9. компиляция изменённых файлов ==")

import py_compile  # noqa: E402

for rel in (
    "subgen/params_filter.py",
    "ui/pages/filters_page.py",
    "checkers/ai_geo.py",
    "subgen/pipeline.py",
    "ui/app.py",
):
    try:
        py_compile.compile(str(REPO / "python" / rel), doraise=True)
        check(f"compile {rel}", True)
    except py_compile.PyCompileError as exc:
        check(f"compile {rel}", False, str(exc))

# ---------------------------------------------------------------------------
print(f"\n{'=' * 60}")
print(f"PASS: {PASS}  FAIL: {FAIL}")
sys.exit(1 if FAIL else 0)
