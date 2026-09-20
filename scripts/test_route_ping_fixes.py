#!/usr/bin/env python3
"""Тесты фиксов анализа лога 2026-09-17 («пинг откидывает рабочие»):

1. route_thresholds(): адаптивные пороги от rtt_hint (медленный канал не
   бракует живые ноды), базовые — без hint.
2. _run_route(rtt_hint_ms=...): поведение на фейковых пробах — нода юзера
   «Игровой 2» (avg=525, jitter=68) с hint=614 проходит, без hint — нет.
3. violations в details: какой именно порог пробит (вместо тавтологии
   «route_unstable (route_unstable)»).
4. resilience передаёт rtt_hint_ms в _run_route (AST).
5. pipeline: ключование per-node деталей по _detail_key (host:port/digest),
   а не по title (дубликаты имён больше не перезаписывают записи).
6. pipeline: сводная веха «[sub] filtered out N that failed resilience»
   с разбивкой по причинам.
7. Воспроизведение данных юзера: 61 отклонённый route — счётчик причин
   (avg>500 у 51) и сколько вернётся при адаптивных порогах.
8. Краш 2026-09-18 (KeyError: 'route_unstable', pipeline.py:1641): счётчик
   причин был пустым plain dict с инкрементом `+=` — первый же отвал ронял
   ВЕСЬ конвейер при разборе результатов (16 PASS-строк, затем смерть
   процесса без итогового файла). Фикс: _bump_reason (.get-инкремент);
   тест исполняет НАСТОЯЩУЮ функцию, извлечённую из исходника AST-ом
   (импорт subgen.pipeline тянет xray_runtime — тяжело и с побочными
   эффектами), + source-охрана от возвращения минированного паттерна.
"""
from __future__ import annotations

import ast
import json
import py_compile
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from checkers import route as R  # noqa: E402

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


print("== T1. route_thresholds: адаптивные пороги ==")
base = R.route_thresholds(None)
check("T1 без hint -> базовые 500/800/80", base == {"avg_ms": 500.0, "p95_ms": 800.0, "jitter_ms": 80.0, "loss": 0.05}, str(base))
slow = R.route_thresholds(614.3)
check("T2 hint=614.3 (канал юзера) -> 614/921/154", 
      abs(slow["avg_ms"] - 614.3) < 0.1 and abs(slow["p95_ms"] - 921.45) < 0.1 and abs(slow["jitter_ms"] - 153.58) < 0.1,
      str(slow))
fast = R.route_thresholds(300.0)
check("T3 hint=300 (быстрый канал) -> базовые (не ужесточаем)", fast["avg_ms"] == 500.0 and fast["p95_ms"] == 800.0, str(fast))
vfast = R.route_thresholds(2000.0)
check("T4 hint=2000 -> 2000/3000/500", vfast["avg_ms"] == 2000.0 and vfast["p95_ms"] == 3000.0 and vfast["jitter_ms"] == 500.0, str(vfast))
check("T5 loss не масштабируется", slow["loss"] == 0.05 and vfast["loss"] == 0.05)

print("== T2. _run_route на фейковых пробах (сценарий юзера) ==")

real_probe = R._rtt_probe
try:
    # «Игровой 2» юзера: avg=525, p95=620, jitter=68, loss=0 (из report.json).
    # Фейковые пробы: 5 успешных замеров, дающие avg≈525.
    rtts = [500.0, 510.0, 530.0, 540.0, 545.0]  # avg=525, jitter≈18
    R._rtt_probe = lambda h, p, t: rtts.pop(0) if rtts else 500.0

    res_no_hint = R._run_route("127.0.0.1", 1080, 4.0, probes=5)
    check("T6 без hint: avg=525 > 500 -> отклонён (старое поведение)",
          res_no_hint.accepted is False and res_no_hint.reason == "route_unstable",
          f"accepted={res_no_hint.accepted} reason={res_no_hint.reason}")
    check("T6b violations называет точный порог",
          any("avg" in v and "525" in v for v in res_no_hint.details.get("violations", [])),
          str(res_no_hint.details.get("violations")))

    rtts = [500.0, 510.0, 530.0, 540.0, 545.0]
    res_hint = R._run_route("127.0.0.1", 1080, 4.0, probes=5, rtt_hint_ms=614.3)
    check("T7 с hint=614.3: тот же узел ПРОХОДИТ (главный фикс)",
          res_hint.accepted is True and res_hint.reason == "ready",
          f"accepted={res_hint.accepted} reason={res_hint.reason}")
    check("T7b применённые пороги в details",
          res_hint.details.get("max_avg_ms") == 614.3 and res_hint.details.get("rtt_hint_ms") == 614.3,
          str(res_hint.details))

    # Потери: 1 из 5 проб потеряна -> loss=0.2 > 5% -> high_loss независимо от hint.
    rtts = [500.0, 510.0]
    R._rtt_probe = lambda h, p, t: (rtts.pop(0) if rtts else None)
    res_loss = R._run_route("127.0.0.1", 1080, 4.0, probes=5, rtt_hint_ms=614.3)
    check("T8 loss=0.2 -> high_loss даже с hint (потери не от канала)",
          res_loss.accepted is False and res_loss.reason == "high_loss"
          and any("loss" in v for v in res_loss.details.get("violations", [])),
          f"reason={res_loss.reason} viol={res_loss.details.get('violations')}")

    # not_measured не наказывается (меньше 3 проб) — регресс-охрана.
    res_nm = R._run_route("127.0.0.1", 1080, 4.0, probes=5, rtt_hint_ms=614.3, deadline=0.0)
    # deadline в прошлом: ни одной пробы не началось
    check("T9 0 проб -> not_measured", res_nm.reason == "not_measured" and res_nm.probes_total == 0, res_nm.reason)
finally:
    R._rtt_probe = real_probe

print("== T3. Данные юзера из report.json (воспроизведение инцидента) ==")
LOGS = Path("/home/z/my-project/userlogs/extracted/data/report.json")
if LOGS.exists():
    rep = json.loads(LOGS.read_text(encoding="utf-8"))
    rz = rep["resilience"]["nodes"]
    rtt_hint = rep["network"]["initial_p50_ms"]

    def count_pass(a, p, j, loss_cap=0.05):
        n = 0
        for v in rz.values():
            r = v.get("route") or {}
            if isinstance(r, dict) and r.get("ping_avg") is not None:
                if (r.get("loss") or 0) <= loss_cap and r["ping_avg"] <= a and r["ping_p95"] <= p and r["jitter"] <= j:
                    n += 1
        return n

    cur = count_pass(500, 800, 80)
    th = R.route_thresholds(rtt_hint)
    adapted = count_pass(th["avg_ms"], th["p95_ms"], th["jitter_ms"])
    check("T10 воспроизведён срез юзера: 50/111 при базовых порогах", cur == 50, str(cur))
    check("T11 адаптивные пороги возвращают ноды (>=70)", adapted >= 70, str(adapted))
    print(f"       (базовые: {cur}/111 -> адаптивные: {adapted}/111, hint={rtt_hint:.0f}мс)")

    # «Игровой 2» юзера: узел, прошедший initial+tg+services, убитый route.
    g2 = rz.get("🇪🇪 🎮 Игровой 2")
    if g2:
        r = g2["route"]
        ok = (r["loss"] <= 0.05 and r["ping_avg"] <= th["avg_ms"]
              and r["ping_p95"] <= th["p95_ms"] and r["jitter"] <= th["jitter_ms"])
        check("T12 юзеров «Игровой 2» (avg=525, jit=68) возвращается фиксом", ok,
              f"avg={r['ping_avg']} jit={r['jitter']}")
else:
    print("  SKIP  T10-T12: логи юзера недоступны в песочнице")

print("== T4. AST: resilience передаёт hint; pipeline ключи/лог ==")
route_src = (REPO / "python" / "checkers" / "route.py").read_text(encoding="utf-8")
res_src = (REPO / "python" / "checkers" / "resilience.py").read_text(encoding="utf-8")
pipe_src = (REPO / "python" / "subgen" / "pipeline.py").read_text(encoding="utf-8")

check("T13 resilience: rtt_hint_ms=rtt_hint_ms в вызове _run_route",
      "rtt_hint_ms=rtt_hint_ms" in res_src)

tree = ast.parse(pipe_src)
calls = [ast.unparse(n.func) if isinstance(n.func, ast.Name) else ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)]
check("T14 pipeline: _detail_key(w) используется в местах деталей (>=7)",
      sum(1 for c in calls if c == "_detail_key") >= 7, str(sum(1 for c in calls if c == "_detail_key")))
check("T15 pipeline: нет ключования по w.node.title() в деталях",
      "initial_node_details[w.node.title()]" not in pipe_src
      and "resilience_node_details[w.node.title()]" not in pipe_src
      and "telegram_pro_node_details[w.node.title()]" not in pipe_src
      and "services_node_details[w.node.title()]" not in pipe_src
      and "ai_geo_node_details[w.node.title()]" not in pipe_src)
check("T16 pipeline: сводная веха resilience с причинами",
      "filtered out\" + \" nodes that failed resilience check" in pipe_src.replace(f"{{failed_resilience}}", "filtered out\" + \"")
      or "nodes that failed resilience check" in pipe_src)
check("T17 pipeline: тавтология route_unstable убрана",
      "f\"route_unstable ({route_row.get('reason')})\"" not in pipe_src
      and "violations = (route_row.get(\"details\") or {}).get(\"violations\")" in pipe_src)
check("T18 pipeline: recheck speeds по _detail_key + name в значении",
      "recheck_speeds[_detail_key(w)]" in pipe_src)

print("== T6. Краш 2026-09-18: счётчик причин отвала (KeyError: 'route_unstable') ==")

# Функциональный тест НАСТОЯЩЕГО _bump_reason: извлекаем функцию из
# исходника pipeline.py через AST и исполняем изолированно.
_tree = ast.parse(pipe_src)
_fn = next((n for n in _tree.body if isinstance(n, ast.FunctionDef) and n.name == "_bump_reason"), None)
check("T20 _bump_reason существует в pipeline.py", _fn is not None)
if _fn is not None:
    _ns: dict = {}
    exec(compile(ast.Module(body=[_fn], type_ignores=[]), "<_bump_reason>", "exec"), _ns)
    _bump = _ns["_bump_reason"]

    # Точный сценарий краша 2026-09-18: пустой счётчик, первый же отвал —
    # раньше `resilience_fail_reasons['route_unstable'] += 1` -> KeyError,
    # и весь конвейер умирал до записи итогового файла.
    _reasons: dict = {}
    try:
        _bump(_reasons, "route_unstable")  # раньше: KeyError: 'route_unstable'
        _bump(_reasons, "route_unstable")
        _bump(_reasons, "high_loss")
        _bump(_reasons, "run_failed")
        _bump(_reasons, "completely_dead")
        check("T21 счёт с нуля: все причины посчитаны, без KeyError",
              _reasons == {"route_unstable": 2, "high_loss": 1, "run_failed": 1, "completely_dead": 1},
              str(_reasons))
    except KeyError as exc:
        check("T21 счёт с нуля: все причины посчитаны, без KeyError", False, f"KeyError: {exc}")

# Source-охрана: минированный паттерн dict[key] += 1 на этом счётчике не
# должен возвращаться ни при ребейзе, ни при «оптимизации» обратно.
check("T22 в pipeline.py нет 'resilience_fail_reasons[...] += 1'",
      "resilience_fail_reasons[reason] += 1" not in pipe_src
      and 'resilience_fail_reasons["run_failed"] += 1' not in pipe_src
      and 'resilience_fail_reasons["completely_dead"] += 1' not in pipe_src)
check("T23 все три ветки отвала используют _bump_reason",
      pipe_src.count("_bump_reason(resilience_fail_reasons,") == 3,
      str(pipe_src.count("_bump_reason(resilience_fail_reasons,")))

print("== T5. Компиляция ==")
for f in ("python/checkers/route.py", "python/checkers/resilience.py", "python/subgen/pipeline.py"):
    try:
        py_compile.compile(str(REPO / f), doraise=True)
        check(f"T19 {f} компилируется", True)
    except py_compile.PyCompileError as exc:
        check(f"T19 {f} компилируется", False, str(exc))

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
