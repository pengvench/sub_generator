#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты отчёта «из каких подписок собрана итоговая подписка»:

- _build_sources_report / _log_sources_report — функционально (AST-извлечение
  из pipeline.py + изолированный exec, как test_route_ping_fixes T20-T23:
  pipeline импортирует чекеры/движок, тащить его в тест дорого);
- проводка в pipeline.py (final + pending отчёт) и в UI app.py — AST;
- поле source в serialize_working (geo.py) — AST.
"""
import ast
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, "/home/z/my-project/sub_generator/python")

PIPELINE_SRC = Path("/home/z/my-project/sub_generator/python/subgen/pipeline.py").read_text(encoding="utf-8")
APP_SRC = Path("/home/z/my-project/sub_generator/python/ui/app.py").read_text(encoding="utf-8")
GEO_SRC = Path("/home/z/my-project/sub_generator/python/subgen/geo.py").read_text(encoding="utf-8")

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {detail}")


# ------------------------------- AST-извлечение тестируемых функций pipeline

def extract_functions(source: str, names: list[str]) -> str:
    tree = ast.parse(source)
    parts = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            parts.append(ast.get_source_segment(source, node))
    assert len(parts) == len(names), f"не все функции найдены: {len(parts)}/{len(names)}"
    return "\n\n".join(parts)


code = extract_functions(PIPELINE_SRC, ["_node_source_url", "_build_sources_report", "_log_sources_report"])
ns: dict = {"Any": object, "__builtins__": __builtins__}
exec(compile(code, "<pipeline-extract>", "exec"), ns)
_build_sources_report = ns["_build_sources_report"]
_log_sources_report = ns["_log_sources_report"]
_node_source_url = ns["_node_source_url"]


def mk(source_url: str):
    """Псевдо-XrayProbeResult: только то, что читает отчёт."""
    return SimpleNamespace(node=SimpleNamespace(source_url=source_url))


print("== _build_sources_report ==")

# Базовый сценарий: 4 источника, узлы распределены неравномерно.
sources = ["https://a.example/1", "https://b.example/2", "https://c.example/3", "https://d.example/4"]
discovered = (
    [mk(sources[0])] * 30 + [mk(sources[1])] * 10 + [mk(sources[2])] * 5
)  # d.example не дал НИЧЕГО (мёртвый)
working = [mk(sources[0])] * 6 + [mk(sources[1])] * 3 + [mk(sources[2])]  # 10 узлов в итоге
rep = _build_sources_report(sources, discovered, working)

check("enabled", rep.get("enabled") is True)
check("sources_total = 4", rep.get("sources_total") == 4)
check("contributed = 3", rep.get("contributed") == 3)
check("dead = 1 (d.example)", rep.get("dead") == 1)
check("nodes_total = 10", rep.get("nodes_total") == 10)
check("checked_no_result = 0", rep.get("checked_no_result") == 0)
entries = {e["source"]: e for e in rep["nodes"]}
check("a.example: discovered=30 exported=6 share=60.0",
      entries[sources[0]]["discovered"] == 30 and entries[sources[0]]["exported"] == 6
      and entries[sources[0]]["share_pct"] == 60.0, str(entries[sources[0]]))
check("b.example: 10→3, 30.0%",
      entries[sources[1]]["exported"] == 3 and entries[sources[1]]["share_pct"] == 30.0)
check("c.example: 5→1, 10.0%",
      entries[sources[2]]["exported"] == 1 and entries[sources[2]]["share_pct"] == 10.0)
check("d.example: пустой, empty=True",
      entries[sources[3]]["exported"] == 0 and entries[sources[3]]["discovered"] == 0
      and entries[sources[3]]["empty"] is True)
check("сортировка nodes по вкладу",
      [e["source"] for e in rep["nodes"]] == [sources[0], sources[1], sources[2], sources[3]])
check("top-3 без пустых",
      len(rep["top"]) == 3 and rep["top"][0]["source"] == sources[0])
check("доля в сумме = 100%", abs(sum(e["share_pct"] for e in rep["nodes"]) - 100.0) < 0.01)

# Проверенные, но отвалившиеся (discovered>0, exported=0).
working2 = [mk(sources[0])] * 4
rep2 = _build_sources_report(sources, discovered, working2)
check("checked_no_result = 2 (b, c проверены, не дошли)",
      rep2.get("checked_no_result") == 2)
check("в nodes у b.example empty=False при discovered=10",
      {e["source"]: e for e in rep2["nodes"]}[sources[1]]["empty"] is False)

# Режим перепроверки: discovered пуст (кеш), exported считаются.
rep3 = _build_sources_report(sources, [], working)
check("перепроверка: exported считаются (nodes_total=10)", rep3.get("nodes_total") == 10)
check("перепроверка: note про кеш",
      "перепроверка" in str(rep3.get("note", "")))

# Источник «сбоку» (saved_subs) — не в sources.txt, но узлы от него есть.
side = "file://saved_subs/test.txt"
rep4 = _build_sources_report(sources, [mk(side)] * 3, [mk(side)] * 2 + [mk(sources[0])] * 8)
entries4 = {e["source"]: e for e in rep4["nodes"]}
check("боковой источник посчитан (file://...)",
      entries4.get(side, {}).get("exported") == 2)
check("sources_total = 5 (включая боковой)", rep4["sources_total"] == 5)

# Узлы без source_url (старый кеш) — не теряются, попадают в «неизвестный».
rep5 = _build_sources_report(sources, [mk("")], [mk(""), mk(sources[0])])
check("пустой source -> «(источник неизвестен)»",
      any(e["source"] == "(источник неизвестен)" and e["exported"] == 1 for e in rep5["nodes"]))

# Пустой прогон: 0 узлов.
rep6 = _build_sources_report(sources, [], [])
check("пустой прогон: contributed=0, доли 0.0",
      rep6["contributed"] == 0 and all(e["share_pct"] == 0.0 for e in rep6["nodes"]))

print("== _log_sources_report ==")
lines: list[str] = []
_log_sources_report(rep, log=lines.append)
check("веха «итоговая подписка собрана из N подписок»",
      any("итоговая подписка собрана из 3 подписок" in s for s in lines), str(lines[:1]))
check("топ-строки с вкладом",
      any("6 узлов (60.0%)" in s and sources[0] in s for s in lines))
check("disabled-отчёт не логируется",
      _log_sources_report({"enabled": False}) is None and lines[-1].startswith("[sub] sources"))

print("== проводка pipeline.py ==")
check("final-отчёт содержит sources_report",
      '"sources_report": sources_report' in PIPELINE_SRC)
check("final: _build_sources_report вызывается с (sources, discovered, working)",
      "_build_sources_report(sources, discovered, working)" in PIPELINE_SRC)
check("final: веха логируется",
      "_log_sources_report(sources_report, log=log)" in PIPELINE_SRC)
check("pending-отчёт содержит sources_report",
      '"sources_report": {"enabled": False}' in PIPELINE_SRC)
check("порядок: отчёт по источникам после экспорта подписки",
      PIPELINE_SRC.index("write_subscription_files(") < PIPELINE_SRC.index("_build_sources_report(sources"))

print("== проводка UI app.py ==")
check("диалог читает sources_report",
      'report.get("sources_report")' in APP_SRC)
check("строка «Подписок дали узлы»",
      "Подписок дали узлы:" in APP_SRC)
check("кнопка «Из каких подписок собрано»",
      "Из каких подписок собрано" in APP_SRC)
check("метод _show_sources_dialog определён",
      "def _show_sources_dialog" in APP_SRC)
check("детализация цветовая: 3 тега (ok/mid/dead)",
      APP_SRC.count('text.tag_configure("') >= 3)
check("таблица выводит discovered→exported",
      "→" in APP_SRC and "share_pct" in APP_SRC)

print("== проводка geo.py ==")
check("serialize_working пишет source в строку узла",
      '"source": str(node.source_url or "")' in GEO_SRC)

# --------------------------------------------------------------------- итог
print(f"\n=== sources report: {PASS} PASS, {FAIL} FAIL ===")
sys.exit(1 if FAIL else 0)
