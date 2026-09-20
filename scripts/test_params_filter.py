#!/usr/bin/env python3
"""Тесты фичи «фильтр конфигов по параметрам» (v12) + верификация ai_geo.

Часть 1 — subgen/params_filter.py:
  1. node_params(): нормализация (vless reality xhttp / vmess net=ws / hy2 /
     ss / h2→http / security=xtls→tls / flow=xtls-rprx-vision→vision /
     неизвестное → other).
  2. build_matcher(): белый список, пустое множество и {"*"} = без фильтра,
     корзина other.
  3. parse_csv_spec(): CSV → set, пусто → None.
  4. apply_params_filter(): счётчик отвала по измерению, элементы без .node
     проходят как есть.
  5. Реальные конфиги юзера (userlogs working.txt + report.json nodes):
     node_params разбирает живые ссылки; фильтр «vless+reality+xhttp»
     оставляет только их.

Часть 2 — проводка конвейера/UI (AST/функционально):
  6. pipeline: 4 CLI-аргумента, импорт params_filter, применение ДО
     initial-check (в обоих режимах — полный и перепроверка), params_filter
     в итоговом отчёте.
  7. runner: build_pipeline_args передаёт непустые фильтры в CLI.
  8. UI: app.py регистрирует вкладку «Фильтры»; filters_page: группы галочек
     из DIMENSIONS + other, ai_strict перенесён; start_page: тумблер РФ-слепка
     удалён, опции тянутся с filters page; settings: merge вместо replace.

Часть 3 — ai_geo («пускают ли нейросети», просьба юзера):
  9. Герметичные тесты логики: parse_cf_trace, parse_google_country,
     is_russia_name, compute_verdict, _consensus_country (кейс CF-Worker:
     cf=US при exit=GB).
  10. Реальные данные юзера (report.json от 2026-09-17): ai_geo по 54 нодам,
      все вердикты openai_ok/gemini_ok, ни одного RU-слепка.
"""
from __future__ import annotations

import ast
import json
import py_compile
import sys
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from subgen.params_filter import (  # noqa: E402
    DIMENSIONS,
    OTHER,
    apply_params_filter,
    build_matcher,
    node_params,
    parse_csv_spec,
)
from checkers import ai_geo as AG  # noqa: E402
from runtime.parse import parse_node_link  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


print("== T1. node_params: нормализация ==")


def _np(url: str) -> dict:
    node = parse_node_link(url)
    return node_params(node)


# vless reality xhttp — точный сценарий юзера.
url = (
    "vless://uuid@1.2.3.4:443?encryption=none&security=reality&sni=www.tesla.com"
    "&fp=chrome&pbk=KEY&sid=abcd&type=xhttp&path=%2Fx&flow=xtls-rprx-vision#Test"
)
p = _np(url)
check("T1 vless+reality+xhttp+vision",
      p == {"protocol": "vless", "security": "reality", "transport": "xhttp", "flow": "vision"}, str(p))

# vless tcp без tls.
p = _np("vless://uuid@1.2.3.4:8080?encryption=none&type=tcp#plain")
check("T2 vless+tcp без security -> none",
      p["security"] == "none" and p["transport"] == "tcp", str(p))

# security=xtls (устаревший) -> tls; type=h2 -> http.
p = _np("vless://uuid@1.2.3.4:443?security=xtls&type=h2#old")
check("T3 security=xtls -> tls; type=h2 -> http",
      p["security"] == "tls" and p["transport"] == "http", str(p))

# trojan — security обязателен (URI без security=tls для trojan нет, но парсер
# не додумывает: пусто -> none).
p = _np("trojan://pass@1.2.3.4:443?sni=x.com&type=grpc&serviceName=s#tr")
check("T4 trojan+grpc", p["protocol"] == "trojan" and p["transport"] == "grpc", str(p))

# vmess: JSON-модель (net/path/tls).
import base64  # noqa: E402

vmess_json = {"add": "5.6.7.8", "port": "443", "id": "uu-id", "ps": "vm", "net": "ws", "tls": ""}
vmess_url = "vmess://" + base64.b64encode(json.dumps(vmess_json).encode()).decode()
p = _np(vmess_url)
check("T5 vmess net=ws tls='' -> transport=ws security=none",
      p["protocol"] == "vmess" and p["transport"] == "ws" and p["security"] == "none", str(p))

vmess_json["tls"] = "tls"
vmess_json["net"] = "tcp"
vmess_url = "vmess://" + base64.b64encode(json.dumps(vmess_json).encode()).decode()
p = _np(vmess_url)
check("T6 vmess tls=tls net=tcp", p["security"] == "tls" and p["transport"] == "tcp", str(p))

# hy2 — всегда quic+tls (маскировка не в URI).
p = _np("hy2://pass@1.2.3.4:8443?sni=a.com#hy")
check("T7 hy2 -> hysteria2/quic/tls", 
      p["protocol"] == "hysteria2" and p["transport"] == "quic" and p["security"] == "tls", str(p))

# ss — метод в credential, security none.
p = _np("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss")
check("T8 ss -> shadowsocks/none", p["protocol"] == "shadowsocks" and p["security"] == "none", str(p))

# Неизвестный транспорт -> other (открытый список конфигураций).
p = _np("vless://uuid@1.2.3.4:443?type=meow-new-transport&security=reality#x")
check("T9 неизвестный транспорт -> other", p["transport"] == OTHER, str(p))

# splithttp — синоним xhttp, но в DIMENSIONS отдельная галочка; канонизация
# НЕ схлопывает (юзер может выбрать только splithttp).
p = _np("vless://uuid@1.2.3.4:443?type=splithttp&security=tls#sp")
check("T10 splithttp остаётся splithttp", p["transport"] == "splithttp", str(p))

print("== T2. build_matcher / parse_csv_spec ==")
check("T11 parse_csv_spec 'VLESS, trojan' -> {vless, trojan}",
      parse_csv_spec("VLESS, trojan") == {"vless", "trojan"}, str(parse_csv_spec("VLESS, trojan")))
check("T12 parse_csv_spec '' -> None", parse_csv_spec("") is None and parse_csv_spec(None) is None)

node = parse_node_link(url)
m_all = build_matcher()
check("T13 пустой матчер пропускает всё", m_all(node) is True)
m_vless = build_matcher(protocols={"vless"})
check("T14 protocols={vless}: vless проходит", m_vless(node) is True)
vm_node = parse_node_link(vmess_url)
check("T15 protocols={vless}: vmess отсекается", m_vless(vm_node) is False)
m_star = build_matcher(protocols={"*"})
check("T16 {'*'} = без фильтра", m_star(vm_node) is True)
m_xhttp = build_matcher(transports={"xhttp"})
check("T17 transports={xhttp}: xhttp проходит", m_xhttp(node) is True)
m_other = build_matcher(transports={OTHER})
check("T18 transports={other}: неизвестный проходит, xhttp нет",
      m_other(parse_node_link("vless://u@1.2.3.4:1?type=meow#n")) is True and m_other(node) is False)

print("== T3. apply_params_filter ==")
nodes = [node, vm_node]
kept, dropped = apply_params_filter(nodes, m_vless)
check("T19 отсеян vmess, счётчик protocol=1",
      len(kept) == 1 and dropped == {"protocol": 1}, f"kept={len(kept)} dropped={dropped}")
kept, dropped = apply_params_filter([], m_vless)
check("T20 пустой список — без паники", kept == [] and dropped == {})
kept, dropped = apply_params_filter([{"no_node": True}], m_vless)
check("T21 элемент без .node проходит как есть", len(kept) == 1 and dropped == {})

# Эмуляция элемента w (как в конвейере: w.node).
class _W:
    def __init__(self, node):
        self.node = node


ws = [_W(node), _W(vm_node)]
kept, dropped = apply_params_filter(ws, build_matcher(protocols={"vless"}, transports={"xhttp"}))
check("T22 w.node-обёртки: vless+xhttp остался, vmess ушёл по protocol",
      len(kept) == 1 and dropped.get("protocol") == 1, str(dropped))

print("== T4. Реальные конфиги юзера (working.txt из логов 2026-09-17) ==")
WORKING = Path("/home/z/my-project/userlogs/extracted/data/working.txt")
REPORT = Path("/home/z/my-project/userlogs/extracted/data/report.json")
if WORKING.exists():
    lines = [ln.strip() for ln in WORKING.read_text(encoding="utf-8").splitlines() if ln.strip()]
    real_nodes = [n for n in (parse_node_link(ln) for ln in lines) if n]
    check("T23 рабочие конфиги юзера парсятся (>40)", len(real_nodes) > 40, str(len(real_nodes)))
    from collections import Counter
    proto_c = Counter(node_params(n)["protocol"] for n in real_nodes)
    sec_c = Counter(node_params(n)["security"] for n in real_nodes)
    tr_c = Counter(node_params(n)["transport"] for n in real_nodes)
    print(f"       протоколы: {dict(proto_c)}")
    print(f"       шифрование: {dict(sec_c)}")
    print(f"       транспорт: {dict(tr_c)}")
    # Фильтр «vless reality» на реальных данных: все оставшиеся — vless+reality.
    m = build_matcher(protocols={"vless"}, security={"reality"})
    kept_nodes = [n for n in real_nodes if m(n)]
    ok = all(node_params(n)["protocol"] == "vless" and node_params(n)["security"] == "reality" for n in kept_nodes)
    check("T24 фильтр vless+reality на данных юзера: все оставшиеся им и являются", ok,
          f"kept={len(kept_nodes)}/{len(real_nodes)}")
    # Фильтр «xhttp» — сколько бы осталось (у юзера xhttp-нод может не быть —
    # проверяем только корректность результата, не количество).
    m_x = build_matcher(transports={"xhttp"})
    kept_x = [n for n in real_nodes if m_x(n)]
    ok = all(node_params(n)["transport"] == "xhttp" for n in kept_x)
    check("T25 фильтр xhttp: все оставшиеся — xhttp", ok, f"kept={len(kept_x)}")
else:
    print("  SKIP  T23-T25: логи юзера недоступны")

print("== T5. Проводка конвейера (AST) ==")
pipe_src = (REPO / "python" / "subgen" / "pipeline.py").read_text(encoding="utf-8")
runner_src = (REPO / "python" / "ui" / "runner.py").read_text(encoding="utf-8")
app_src = (REPO / "python" / "ui" / "app.py").read_text(encoding="utf-8")
start_src = (REPO / "python" / "ui" / "pages" / "start_page.py").read_text(encoding="utf-8")
filters_src = (REPO / "python" / "ui" / "pages" / "filters_page.py").read_text(encoding="utf-8")
settings_src = (REPO / "python" / "subgen" / "settings.py").read_text(encoding="utf-8")

for arg in ("--proto-filter", "--security-filter", "--transport-filter", "--flow-filter"):
    check(f"T26 pipeline: аргумент {arg}", arg in pipe_src)
check("T27 pipeline: импорт params_filter",
      "from subgen.params_filter import apply_params_filter, build_matcher, parse_csv_spec" in pipe_src)
check("T28 pipeline: params_filter в итоговом отчёте", '"params_filter": params_filter_report' in pipe_src)

# Фильтр должен стоять ДО initial-check (экономит пинг по ненужным нодам).
pipe_tree = ast.parse(pipe_src)
run_fn = next(n for n in pipe_tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
init_pos = pipe_src.find("# Initial Check: быстрая проверка")
params_pos = pipe_src.find("# ФИЛЬТР ПО ПАРАМЕТРАМ КОНФИГОВ")
check("T29 фильтр применяется ДО initial-check", 0 < params_pos < init_pos,
      f"params@{params_pos} init@{init_pos}")
# ...и ПОСЛЕ загрузки кеша перепроверки (работает в обоих режимах).
cache_pos = pipe_src.find("_load_cached_working()")
check("T30 фильтр после загрузки кеша перепроверки (оба режима)", params_pos > cache_pos > 0)

# Функционально: build_pipeline_args передаёт фильтры.
from ui.runner import PipelineOptions, build_pipeline_args  # noqa: E402

opts = PipelineOptions(proto_filter="vless", transport_filter="xhttp,ws")
args = build_pipeline_args(opts, [])
check("T31 runner: --proto-filter vless в CLI", "--proto-filter" in args and args[args.index("--proto-filter") + 1] == "vless")
check("T32 runner: --transport-filter xhttp,ws", 
      "--transport-filter" in args and args[args.index("--transport-filter") + 1] == "xhttp,ws")
check("T33 runner: пустые фильтры не попадают в CLI",
      "--security-filter" not in build_pipeline_args(PipelineOptions(), []) 
      and "--flow-filter" not in build_pipeline_args(PipelineOptions(), []))
# ai_strict по-прежнему доезжает (перенос на вкладку «Фильтры» его не сломал).
check("T34 runner: --ai-strict передаётся", "--ai-strict" in build_pipeline_args(PipelineOptions(ai_strict=True), []))

print("== T6. UI: вкладка «Фильтры» (AST — customtkinter в песочнице нет) ==")
# v17: «Фильтры» — вкладка страницы «Мои подписки» (не пункт сайдбара).
check("T35 app.py: FiltersPage живёт во вкладке «Мои подписки»",
      "from .pages.filters_page import FiltersPage" in app_src
      and "self.page_filters = self.page_mysubs.filters_tab" in app_src)
check("T36 mysubs_page: вкладка «Фильтры» + алиас навигации",
      '"filters": "Фильтры"' in (REPO / "python" / "ui" / "pages" / "mysubs_page.py").read_text(encoding="utf-8")
      and '"filters": ("sources", "filters")' in app_src)
check("T37 app.py: on_start_clicked сохраняет настройки filters",
      "self.page_filters.save_current_settings()" in app_src)

f_tree = ast.parse(filters_src)
f_class = next((n for n in f_tree.body if isinstance(n, ast.ClassDef) and n.name == "FiltersPage"), None)
check("T38 filters_page: класс FiltersPage существует", f_class is not None)
f_methods = {n.name for n in f_class.body if isinstance(n, ast.FunctionDef)} if f_class else set()
for method in ("get_filter_options", "save_current_settings", "_restore_settings", "_group_csv"):
    check(f"T39 filters_page: метод {method}", method in f_methods)
check("T40 filters_page: галочки из DIMENSIONS + other",
      "from subgen.params_filter import DIMENSIONS, LABELS, OTHER" in filters_src)
check("T41 filters_page: ai_strict перенесён сюда",
      "self.toggle_ai_strict" in filters_src and "Исключить РФ-слепок" in filters_src)
check("T42 filters_page: пустая группа CSV = без фильтра (защита от нулевого результата)",
      'if not selected or len(selected) == len(group):' in filters_src)

check("T43 start_page: тумблер РФ-слепка удалён с главной (виджет и HELP)",
      "self.toggle_ai_strict" not in start_src and 'HELP["ai_strict"]' not in start_src,
      "— в тексте допустимы только комментарии о переносе")
check("T44 start_page: опции тянутся со вкладки «Фильтры»",
      'getattr(self.app, "page_filters", None)' in start_src)
check("T45 start_page: proto_filter в PipelineOptions", "proto_filter=" in start_src)
check("T46 settings: save_test_options MERGE (не затирает чужие ключи)",
      "merged.update(test_options)" in settings_src and "merged = dict(existing)" in settings_src)
check("T47 settings: дефолты params-ключей", '"params_filter_enabled": False' in settings_src)

print("== T7. ai_geo: «пускают ли нейросети» (просьба юзера) ==")
body = b"fl=abc\nip=1.2.3.4\nloc=DE\nhttp=http/2\n"
check("T48 parse_cf_trace: loc=DE", AG.parse_cf_trace(body) == "DE")
check("T49 parse_cf_trace: пустое тело", AG.parse_cf_trace(b"") == "")
html = b'<html><style>.O3yKUb{padding:4px}</style><div class="O3yKUb">\xd0\xa0\xd0\xbe\xd1\x81\xd1\x81\xd0\xb8\xd1\x8f</div></html>'
check("T50 parse_google_country: Россия (CSS-правило не матчится)",
      AG.parse_google_country(html) == "Россия")
html_de = b'<div class="O3yKUb">Deutschland</div>'
check("T51 parse_google_country: Deutschland", AG.parse_google_country(html_de) == "Deutschland")
check("T52 is_russia_name: Россия/Russia", AG.is_russia_name("Россия") and AG.is_russia_name("russia"))
check("T53 is_russia_iso: RU/RUS", AG.is_russia_iso("RU") and AG.is_russia_iso("RUS") and not AG.is_russia_iso("DE"))

# compute_verdict: не-РФ слепок -> True (нейросети пускают).
o, g, v, r = AG.compute_verdict("DE", "Deutschland")
check("T54 verdict: DE+Deutschland -> ai_unblocked=True", o and g and v is True, f"{o},{g},{v},{r}")
# РФ слепок -> False.
o, g, v, r = AG.compute_verdict("RU", "Россия")
check("T55 verdict: RU+Россия -> ai_unblocked=False", (not o) and (not g) and v is False, f"{o},{g},{v},{r}")
# Сигналы недоступны -> None (не фильтрует).
o, g, v, r = AG.compute_verdict("", "")
check("T56 verdict: нет сигналов -> None", v is None and r == "ai_signals_unavailable")
# Один сигнал не-РФ перекрывает второй недоступный.
o, g, v, _ = AG.compute_verdict("", "Deutschland")
check("T57 verdict: только google=DE -> True", v is True)

# Консенсус v11 — кейс CF-Worker: CF trace показывает гео кеша (US),
# реальный exit — GB (ipinfo/ip-api).
c = AG._consensus_country("US", "GB", "GB")
check("T58 консенсус CF-Worker: cf=US, ipinfo=GB, ipapi=GB -> GB", c == "GB", c)
c = AG._consensus_country("DE", "DE", "FR")
check("T59 консенсус 2-of-3: DE,DE,FR -> DE", c == "DE", c)
c = AG._consensus_country("", "", "TR")
check("T60 консенсус один источник: TR", c == "TR", c)
c = AG._consensus_country("", "", "")
check("T61 консенсус без источников: ''", c == "")

print("== T8. ai_geo на реальных данных юзера (report.json 2026-09-17) ==")
if REPORT.exists():
    rep = json.loads(REPORT.read_text(encoding="utf-8"))
    ai = rep.get("ai_geo") or {}
    nodes_ai = ai.get("nodes") or {}
    # Прогон 17.09 (старый формат, ключи по title): checked=54, записей 52 —
    # одноимённые ноды перезаписали друг друга (починено в c122936 ключованием
    # по host:port/digest). Допуск на дубли — не наша тема.
    check("T62 ai_geo в отчёте: >=50 узлов (прогон 2026-09-17)",
          len(nodes_ai) >= 50, str(len(nodes_ai)))
    consensus = [v.get("consensus_country") for v in nodes_ai.values() if isinstance(v, dict)]
    ru = [c for c in consensus if c in ("RU", "RUS")]
    check("T63 ни одного RU-слепка у юзера (нейросети пускают)",
          len(ru) == 0 and all(consensus), f"RU={len(ru)}, пустых={sum(1 for c in consensus if not c)}")
    # ai_unblocked (вердикт v11 по консенсусу) — истина у всех записей.
    unb_false = [k for k, v in nodes_ai.items() if isinstance(v, dict) and v.get("ai_unblocked") is False]
    check("T64 ai_unblocked=True у всех узлов (консенсус не-РФ)",
          not unb_false, str(unb_false[:3]))
    # Семантика сигналов: openai_ok=False допустим ТОЛЬКО при недоступном
    # CF-сигнале (cf_loc='') — как у «Финляндия 13»: консенсус FI от ipinfo.
    bad_openai = [k for k, v in nodes_ai.items()
                  if isinstance(v, dict) and not v.get("openai_ok") and v.get("cf_loc")]
    check("T65 openai_ok=False только при пустом cf_loc (сигнал недоступен)",
          not bad_openai, str(bad_openai[:3]))
    # Особенность на данных юзера: Google-футер показывал «Россия» у 27 узлов
    # при консенсусе не-РФ (Google-гео расходится с CF/ipinfo/ip-api) — ровно
    # тот случай, который чинит консенсус v11: старая логика gemini_ok
    # забраковала бы 27 РАБОЧИХ узлов. gemini_ok=False допустим только при
    # google_country='Россия' (или пустом — сигнал недоступен).
    bad_gemini = [k for k, v in nodes_ai.items()
                  if isinstance(v, dict) and not v.get("gemini_ok")
                  and v.get("google_country") not in ("", "Россия")]
    check("T66 gemini_ok=False только при google=Россия/пусто (консенсус v11 переопределяет)",
          not bad_gemini, str(bad_gemini[:3]))
    n_google_ru = sum(1 for v in nodes_ai.values()
                      if isinstance(v, dict) and v.get("google_country") == "Россия")
    print(f"       google-футер «Россия» у {n_google_ru} узлов при консенсусе не-РФ — консенсус v11 вернул их в подписку")
else:
    print("  SKIP  T62-T66: report.json недоступен")

print("== T9. Компиляция ==")
for f in (
    "python/subgen/params_filter.py",
    "python/subgen/pipeline.py",
    "python/subgen/settings.py",
    "python/ui/runner.py",
    "python/ui/app.py",
    "python/ui/pages/filters_page.py",
    "python/ui/pages/start_page.py",
    "python/checkers/ai_geo.py",
):
    try:
        py_compile.compile(str(REPO / f), doraise=True)
        check(f"T66 {f} компилируется", True)
    except py_compile.PyCompileError as exc:
        check(f"T66 {f} компилируется", False, str(exc))

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
