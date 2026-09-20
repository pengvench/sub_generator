#!/usr/bin/env python3
"""v17: XrayBatchPool (групповой тест через ядро xray) + UI «как в браузере».

Часть 1 (юнит): сборка конфига xray-пула — N inbound / N outbound /
routing-правила / порты / reality / unsupported-протоколы.
Часть 2 (текст): pipeline --pool-engine + фабрика; runner опции.
Часть 3 (текст): сайдбар 4 пункта, вкладки, resilience в «Что тестировать»,
dedup в одной ячейке, отсутствие приписок.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(f"{name} {detail}")
    print(("  ok   " if cond else "  FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))


print("=== 1. XrayBatchPool: сборка конфига ===")
import xray_runtime as xr  # noqa: E402
from runtime.xray_pool import XrayBatchPool  # noqa: E402


def make_node(url: str):
    node = xr.parse_node_link(url)
    assert node is not None, f"не распарсился: {url}"
    return node


nodes = [
    make_node(
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443"
        "?encryption=none&security=reality&sni=example.com&fp=chrome"
        "&pbk=abc&sid=12&type=tcp&flow=xtls-rprx-vision#reality-node"
    ),
    make_node(
        "vmess://eyJhZGQiOiJleGFtcGxlLmNldCIsInBvcnQiOjQ0MywiaWQiOiIwMTIzNDU2Ny04OWFiLWNkZWYtMDEyMy00NTY3ODlhYmNkZWYiLCJhaWQiOjAsIm5ldCI6IndzIiwicGF0aCI6Ii93cyIsInRscyI6InRscyJ9"
    ),
    make_node("trojan://secretpass@example.net:443?security=tls&sni=example.net&type=tcp#trojan-node"),
    make_node("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.org:8388#ss-node"),
    make_node("hysteria2://pass@example.io:443?sni=example.io#hy2-node"),
]

pool = XrayBatchPool(nodes, root_dir=REPO, base_port=20000, batch_id=7)
cfg = pool._config

check("конфиг построен", cfg is not None)
check("4 узла поддерживаются (hy2 — нет)", pool.supported_count == 4, str(pool.supported_count))
hy2 = nodes[4]
check("hysteria2 → unsupported", hy2.key in pool.unsupported_keys)
check("unsupported_keys — только hy2", len(pool.unsupported_keys) == 1, str(len(pool.unsupported_keys)))

inbounds = cfg["inbounds"]
outbounds = [o for o in cfg["outbounds"] if o.get("tag", "").startswith("proxy-")]
check("inbound'ов столько же, сколько прокси-outbound'ов", len(inbounds) == len(outbounds) == 4,
      f"{len(inbounds)}/{len(outbounds)}")

ports = [i["port"] for i in inbounds]
check("порты последовательны от base", ports == [20000, 20001, 20002, 20003], str(ports))
tags_in = [i["tag"] for i in inbounds]
tags_out = [o["tag"] for o in outbounds]
check("теги уникальны", len(set(tags_in)) == len(tags_in) and len(set(tags_out)) == len(tags_out))

rules = cfg["routing"]["rules"]
block_rule = rules[0]
check("первое правило — block локальных IP", block_rule["outboundTag"] == "block" and "127.0.0.0/8" in block_rule["ip"])
pair_rules = rules[1:]
check("routing-правил «inbound→outbound» — 4", len(pair_rules) == 4, str(len(pair_rules)))
mapping_ok = all(
    r["inboundTag"] == [f"socks-in-{i}"] and r["outboundTag"] == f"proxy-{i}"
    for i, r in enumerate(pair_rules, 1)
)
check("правила связывают socks-in-K → proxy-K", mapping_ok)

# reality-узел: outbound содержит realitySettings с public_key и utls
reality_ob = outbounds[0]
ss = reality_ob["streamSettings"]
reality = ss.get("realitySettings", {})
check("reality: public_key присутствует", bool(reality.get("publicKey") or reality.get("public_key")))
tls = ss.get("tlsSettings", {})
check("reality: uTLS включён", bool(tls.get("utls", {}).get("fingerprint") or reality.get("fingerprint")),
      str(ss.get("tlsSettings", {}).keys()))

# blackhole в outbounds
check("blackhole «block» в конфиге", any(o.get("tag") == "block" for o in cfg["outbounds"]))

# select/endpoint
check("select(reality) → True", pool.select(nodes[0]))
check("endpoint = (127.0.0.1, 20000)", pool.endpoint == ("127.0.0.1", 20000), str(pool.endpoint))
check("select(hy2) → False", not pool.select(nodes[4]))
check("select(несуществующий узел) → False", not pool.select(make_node("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@other.org:8388#other")))
check("select(vmess) → endpoint меняется", pool.select(nodes[1]) and pool.endpoint == ("127.0.0.1", 20001),
      str(pool.endpoint))

# дроп-подстановка: битый узел (unknown protocol) не рушит конфиг
try:
    bad = make_node("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@bad.org:8388#bad")
    bad.protocol = "wat"
    pool2 = XrayBatchPool([nodes[0], bad], root_dir=REPO, base_port=21000, batch_id=8)
    check("битый протокол → unsupported, пул жив", pool2.supported_count == 1 and bad.key in pool2.unsupported_keys)
except Exception as exc:
    check("битый протокол → unsupported, пул жив", False, str(exc)[:80])

# пустой пул
pool3 = XrayBatchPool([], root_dir=REPO, base_port=22000, batch_id=9)
check("пустой батч → конфиг None", pool3._config is None and pool3.start() is False)

print("=== 2. pipeline: --pool-engine ===")
pipe_src = (REPO / "python" / "subgen" / "pipeline.py").read_text(encoding="utf-8")
check("аргумент --pool-engine", '"--pool-engine"' in pipe_src)
check("дефолт xray", 'default="xray"' in pipe_src)
check("фабрика _make_batch_pool", "def _make_batch_pool" in pipe_src)
check("выбор движка с учётом форса", "def _pool_engine_choice" in pipe_src)
check("initial: групповой тест через движок", "групповой тест через {pool_engine}" in pipe_src)
check("XrayBatchPool импортируется в фабрике", "from runtime.xray_pool import XrayBatchPool" in pipe_src)
check("отчёт: engine в singbox_pool", '"engine": str(getattr(args, "pool_engine"' in pipe_src)

print("=== 3. runner: опции ===")
run_src = (REPO / "python" / "ui" / "runner.py").read_text(encoding="utf-8")
check("PipelineOptions.pool_engine", "pool_engine: str = \"xray\"" in run_src)
check("--pool-engine передаётся", '"--pool-engine", engine' in run_src)

from ui.runner import PipelineOptions, build_pipeline_args  # noqa: E402

opts = PipelineOptions()
args = build_pipeline_args(opts, [])
check("дефолт xray: аргумент не передаётся", "--pool-engine" not in args, str(args[-4:]))
opts_singbox = PipelineOptions(pool_engine="singbox")
args2 = build_pipeline_args(opts_singbox, [])
check("singbox: --pool-engine singbox", "--pool-engine" in args2 and "singbox" in args2)

print("=== 4. UI: сайдбар и вкладки ===")
app_src = (REPO / "python" / "ui" / "app.py").read_text(encoding="utf-8")
check("4 кнопки меню", 'self._nav_button(3, "🚀 Запуск", "start")' in app_src
      and 'self._nav_button(4, "📚 Мои подписки", "sources")' in app_src
      and 'self._nav_button(5, "🔁 Перепроверка", "recheck")' in app_src
      and 'self._nav_button(6, "⚙ Настройки", "settings")' in app_src)
check("нет кнопки «Добавить подписки»", "➕ Добавить подписки" not in app_src)
check("нет кнопок Фильтры/Журнал/Диагностика в меню", "🧲 Фильтры" not in app_src and "📋 Журнал" not in app_src and "🔬 Диагностика" not in app_src)
check("футер «Результаты — в папке» удалён", "Результаты — в папке" not in app_src)
check("алиасы вкладок", '"import": ("sources", "import")' in app_src and '"log": ("settings", "log")' in app_src)
check("MySubsPage строится", "MySubsPage(self.pages_frame, self)" in app_src)
check("SettingsRootPage строится", "SettingsRootPage(self.pages_frame, self)" in app_src)
check("ссылки на дочерние вкладки", "self.page_sources = self.page_mysubs.list_tab" in app_src
      and "self.page_log = self.page_settings_root.log_tab" in app_src)

mysubs_src = (REPO / "python" / "ui" / "pages" / "mysubs_page.py").read_text(encoding="utf-8")
check("вкладки mysubs: Список/Импорт/Фильтры",
      '"sources": "Список"' in mysubs_src and '"import": "Импорт"' in mysubs_src and '"filters": "Фильтры"' in mysubs_src)

settings_src = (REPO / "python" / "ui" / "pages" / "settings_page.py").read_text(encoding="utf-8")
check("вкладки настроек: Основные/Диагностика/Журнал",
      '"basic": "Основные"' in settings_src and '"diag": "Диагностика"' in settings_src and '"log": "Журнал"' in settings_src)

print("=== 5. UI: старт-страница ===")
sp_src = (REPO / "python" / "ui" / "pages" / "start_page.py").read_text(encoding="utf-8")
check("resilience в «Что тестировать»", "inner_what, 3, 0" in sp_src and "Стабильность соединения" in sp_src)
check("resilience убран из «Дополнительно»", "Стабильность (resilience)" not in sp_src
      and 'inner_extra, 2, 1,\n            "Стабильность' not in sp_src)
check("приписка «Фильтры параметров и РФ-слепок» удалена", "Фильтры параметров и РФ-слепок" not in sp_src and "params_hint" not in sp_src)
check("dedup в одной ячейке (без columnspan=2)", 'dedup_frame.grid(row=4, column=0, padx=6, pady=4, sticky="w")' in sp_src)
check("dedup columnspan=2 отсутствует", 'dedup_frame.grid(row=4, column=0, columnspan=2' not in sp_src)
check("движок пула: меню xray/singbox", 'values=["xray", "singbox"]' in sp_src and "pool_engine_var" in sp_src)
check("тумблер «Групповой тест (пачкой узлов)»", "Групповой тест (пачкой узлов)" in sp_src)
check("восстановление pool_engine", "opts.get(\"pool_engine\", \"xray\")" in sp_src)
check("сохранение pool_engine", '"pool_engine": str(self.pool_engine_var.get()' in sp_src)
check("novice: кнопка «⬇ Импорт…»", "⬇ Импорт…" in sp_src)
check("novice: нет «Добавить ссылку…»", "Добавить ссылку…" not in sp_src)

print("=== 6. компиляция ===")
import py_compile  # noqa: E402

for f in ["runtime/xray_pool.py", "subgen/pipeline.py", "ui/runner.py", "ui/app.py",
          "ui/pages/mysubs_page.py", "ui/pages/settings_page.py", "ui/pages/start_page.py",
          "ui/pages/sources_page.py", "ui/pages/filters_page.py", "ui/pages/log_page.py",
          "ui/pages/diag_page.py", "ui/pages/import_page.py"]:
    try:
        py_compile.compile(str(REPO / "python" / f), doraise=True)
        check(f"компиляция {f}", True)
    except Exception as e:
        check(f"компиляция {f}", False, str(e)[:80])

print()
print(f"=== v17 xray-pool + UI: {len(PASS)} PASS, {len(FAIL)} FAIL ===")
if FAIL:
    print("ПРОВАЛЫ:")
    for f in FAIL:
        print("  -", f)
    sys.exit(1)
