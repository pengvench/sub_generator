# -*- coding: utf-8 -*-
"""v16: стадия dpi_active в трейсе + причины prefilter-потерь + чистка мёртвых подписок.

Инцидент из лог2 юзера (2026-09-20):
  * 35 узлов, убитых dpi_active (control_failed/dpi_signature_unstable),
    приписывались ai_geo с безликим «—»;
  * 16537 узлов, убитых TCP/UDP-предфильтром до xray-ping, значились «—»
    на стадии quick («потерялись хрен пойми где»).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

PASS = []
FAIL = []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  ok  " if cond else "  FAIL") + " " + name + (f" {extra}" if extra else ""))


print("=== 1. STAGES: dpi_active между resilience и ai_geo ===")
from subgen.trace import STAGES, FunnelTracker, trace_key, node_source

check("dpi_active в STAGES", "dpi_active" in STAGES)
check("порядок resilience < dpi_active < ai_geo",
      STAGES.index("resilience") < STAGES.index("dpi_active") < STAGES.index("ai_geo"))

print("=== 2. pipeline: чекпойнт dpi_active с причинами ===")
pipe_src = (ROOT / "python" / "subgen" / "pipeline.py").read_text(encoding="utf-8")
check("checkpoint dpi_active вызывается",
      'tracker.checkpoint("dpi_active", working, _dpi_active_drop_reasons)' in pipe_src)
check("причины dpi-active с префиксом dpi-active:",
      '"dpi-active: {res.reason}"' in pipe_src)
check("summary_line dpi_active", 'tracker.summary_line("dpi_active")' in pipe_src)

print("=== 3. sorting: prefilter-мёртвые получают причины ===")
sort_src = (ROOT / "python" / "runtime" / "sorting.py").read_text(encoding="utf-8")
check("tcp_prefilter_dead создаётся",
      '"tcp_prefilter_dead"' in sort_src)
check("tcp_prefilter_slow с латентностью",
      'f"tcp_prefilter_slow ({latency:.0f}мс > 3000мс)"' in sort_src)
check("prefilter_dead попадает в last_rejected",
      "old_rejected\n                    + prefilter_dead" in sort_src)
check("старые prefilter-записи не дублируются",
      'startswith("tcp_prefilter_")' in sort_src)

print("=== 4. FunnelTracker функционально: отввал на dpi_active виден с причиной ===")


class _Node:
    def __init__(self, host, port, src):
        self.key = ("vless", host, port, "x" * 16)
        self.host = host
        self.port = port
        self.source_url = src


nodes = [_Node(f"10.0.0.{i}", 443, "https://sub.example") for i in range(1, 11)]
tr = FunnelTracker()
tr.register(nodes)
# quick прошли все 10 → max_ping 10 → initial 8 → telegram 7 → services 6 → resilience 5
alive = nodes[:]
for stage, keep in [("quick", 10), ("max_ping", 10), ("initial", 8),
                    ("telegram", 7), ("services", 6), ("resilience", 5)]:
    alive = alive[:keep]
    tr.checkpoint(stage, alive)
# dpi_active: выживают 3, двое отвалились с причинами
dpi_alive = alive[:3]
dpi_reasons = {
    trace_key(alive[3]): "dpi-active: control_failed",
    trace_key(alive[4]): "dpi-active: dpi_signature_unstable",
}
tr.checkpoint("dpi_active", dpi_alive, dpi_reasons)
tr.checkpoint("ai_geo", dpi_alive)
tr.checkpoint("recheck", dpi_alive)
tr.checkpoint("exported", dpi_alive)

lost = tr.lost_at("https://sub.example")
check("два узла отвалились на dpi_active",
      sum(lost.get("dpi_active", {}).values()) == 2)
check("причина control_failed записана",
      "dpi-active: control_failed" in lost.get("dpi_active", {}))
check("причина dpi_signature_unstable записана",
      "dpi-active: dpi_signature_unstable" in lost.get("dpi_active", {}))
check("на ai_geo НИКТО не отвалился (раньше вешались сюда)",
      "ai_geo" not in lost or sum(lost["ai_geo"].values()) == 0)
funnel = tr.funnel_for_source("https://sub.example")
# funnel[stage] = «дожил до ВХОДА в стадию»: упавшие на dpi_active (2) тоже входили
check("funnel dpi_active=5 (3 выжило + 2 упало там)", funnel["dpi_active"] == 5)
check("funnel ai_geo=3", funnel["ai_geo"] == 3)
check("funnel exported=3", funnel["exported"] == 3)

print("=== 5. write_log: стадия dpi_active в человекочитаемом логе ===")
import tempfile
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "trace.log"
    tr.write_log(p, header="test")
    text = p.read_text(encoding="utf-8")
    check("trace.log: dpi_active в строке стадий", "dpi_active" in text)
    check("trace.log: причина dpi-active видна", "dpi-active: control_failed" in text)

print("=== 6. sources_page: классификация мёртвых (текстовая проверка) ===")
sp_src = (ROOT / "python" / "ui" / "pages" / "sources_page.py").read_text(encoding="utf-8")
check("порог: quick >= 10", "quick >= 10" in sp_src)
check("порог: пинг-проходимость < 5%", "(max_ping / quick) < 0.05" in sp_src)
check("условие: 0 экспорта", "exported == 0" in sp_src)
check("кнопка «Убрать мёртвые» есть", "Убрать мёртвые" in sp_src)
check("сохранение после удаления", "_save_all" in sp_src)

print("=== 7. start_page: пресеты и режимы ===")
spg_src = (ROOT / "python" / "ui" / "pages" / "start_page.py").read_text(encoding="utf-8")
check("PRESETS определены", '"Мягкий"' in spg_src and '"Строгий"' in spg_src)
check("Строгий включает dpi_active", '"dpi_active": True' in spg_src)
check("режим сохраняется ui_mode", '"ui_mode"' in spg_src)
check("novice get_options", "novice = self.ui_mode_var.get()" in spg_src)
check("set_running блокирует обе кнопки", "btn_run_novice" in spg_src)

print("=== 8. компиляция ===")
import py_compile
for f in ["subgen/trace.py", "subgen/pipeline.py", "runtime/sorting.py",
          "ui/pages/sources_page.py", "ui/pages/start_page.py", "ui/app.py"]:
    try:
        py_compile.compile(str(ROOT / "python" / f), doraise=True)
        check(f"компиляция {f}", True)
    except Exception as e:
        check(f"компиляция {f}", False, str(e)[:80])

print()
print(f"=== v16 dead/trace/ui: {len(PASS)} PASS, {len(FAIL)} FAIL ===")
if FAIL:
    print("ПРОВАЛЫ:")
    for f in FAIL:
        print("  -", f)
    sys.exit(1)
