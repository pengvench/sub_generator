#!/usr/bin/env python3
"""Смоук: строка «Утечки exit-IP» в окне 📊 Результаты (v14).

Строит фейковый отчёт с ai_geo.leak_check (enabled, rejected=2) и
проверяет, что в диалоге появилась строка «Утечки exit-IP (прозрачные):»
со значением «2 узлов», и что высота окна учла её (n_rows).
Запуск: DISPLAY=:99 python scripts/test_results_leak_row.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

import tkinter as tk  # noqa: E402

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


report = {
    "generated_at_utc": "2026-09-19T12:00:00Z",
    "sources": ["a", "b"],
    "discovered": 100,
    "working": 40,
    "rejected": 60,
    "exported": 38,
    "ai_geo": {
        "enabled": True,
        "checked": 45,
        "passed": 42,
        "failed": 3,
        "leak_check": {
            "enabled": True,
            "real_ip": "91.198.44.1",
            "real_ip_source": "ipinfo.io",
            "rejected": 2,
        },
    },
    "sources_report": {"enabled": False},
}


class _FakeApp(tk.Tk):
    """Только enough Tk для диалога."""

    def _dialog_scale(self):
        return 1.0

    def tk_call(self, *a):
        return self.tk.call(*a)


from ui import theme  # noqa: E402  (нужен диалогу)

app = _FakeApp()
app.withdraw()

# Метод _show_results_dialog живёт в ui/app.py на классе SubGeneratorApp.
# Извлекаем его как несвязанную функцию (нужны только tk-виджеты + theme).
import ui.app as appmod  # noqa: E402

cls_candidates = [
    c for c in vars(appmod).values()
    if isinstance(c, type) and hasattr(c, "_show_results_dialog")
]
check("класс с _show_results_dialog найден", bool(cls_candidates))
if cls_candidates:
    fn = cls_candidates[0].__dict__["_show_results_dialog"]

    class _Host(_FakeApp):
        pass

    host = _Host()
    host.withdraw()
    fn(host, report)
    dlg = host.winfo_children()[-1]
    labels = [
        w.cget("text")
        for w in dlg.winfo_children()
        if isinstance(w, tk.Label)
    ]
    values = [
        w.cget("text")
        for w in dlg.winfo_children()
        if isinstance(w, tk.Label) and w.cget("text") == "2 узлов"
    ]
    check(
        "строка «Утечки exit-IP (прозрачные):» отрисована",
        any("Утечки exit-IP" in t for t in labels),
        str(labels),
    )
    check("значение «2 узлов» отрисовано", bool(values))
    dlg.update_idletasks()
    dlg.update()
    geom = dlg.winfo_geometry()
    check(
        "окно построено с разумной геометрией",
        dlg.winfo_width() >= 420 and dlg.winfo_height() >= 200,
        geom,
    )
    # Высота: n_rows = 6 + 1(ai_geo) + 1(leak) = 8 -> 185+26*8 = 393.
    h = dlg.winfo_height()
    check("высота учитывает строку утечек (~393)", 380 <= h <= 410, str(h))
    dlg.destroy()
    host.destroy()

app.destroy()
print(f"\n{'=' * 60}")
print(f"PASS: {PASS}  FAIL: {FAIL}")
sys.exit(1 if FAIL else 0)
