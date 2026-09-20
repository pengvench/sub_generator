#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты фикса окна «📊 Результаты» (инцидент 2026-09-19: «заголовки есть,
цифр нет»).

Причина бага: диалог — чистый tk с геометрией в физических пикселях и
шрифтами в пунктах; при DPI > 100% (или подстановке широкого шрифта вместо
Segoe UI) текстовый разделитель «─»×60 раздувал grid-таблицу шире окна, и
значения со sticky="e" улетали за правый край.

Фикс: _dialog_scale (масштаб окна по tk scaling), разделитель Frame
height=2 (ширина не зависит от шрифта), grid_propagate(False) +
columnconfigure(0, weight=1) (значения всегда внутри окна), высота окна
зависит от числа строк, геометрия второго диалога тоже масштабируется.

Здесь: source-охраны (нельзя вернуть хрупкую вёрстку), функциональный
тест _dialog_scale (AST-извлечение + фейковый tk) и опциональный GUI-смоук
(если есть дисплей): все значения внутри окна, в т.ч. при форс-масштабе 2.0
(эквивалент 150% DPI).
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, "/home/z/my-project/sub_generator/python")

APP_SRC = Path("/home/z/my-project/sub_generator/python/ui/app.py").read_text(encoding="utf-8")

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


# ----------------------------------------------------------- source-охраны

print("== source: хрупкая вёрстка не должна вернуться ==")
check("жёсткая геометрия 560x680 отсутствует", "560x680" not in APP_SRC)
check("жёсткая геометрия 760x560 отсутствует", "760x560" not in APP_SRC)
check(
    "текстовый разделитель-Label «─» отсутствует",
    'Label(dlg, text="─"' not in APP_SRC,
    "(«─» внутри скроллящегося Text второго диалога — контентная строка, не layout)",
)
check("разделитель — Frame высотой 2px", "Frame(dlg, height=2" in APP_SRC)
check("grid замкнут на окно (propagate off)", "grid_propagate(False)" in APP_SRC)
check("колонке подписей отдан вес", "columnconfigure(0, weight=1)" in APP_SRC)
check("скроллы — orient строками (tk8.6+tk9)", 'orient="vertical"' in APP_SRC and 'orient="horizontal"' in APP_SRC)
check("orient=Y (запрещён в tk9) отсутствует", "orient=Y" not in APP_SRC)

print("== source: DPI-масштаб и динамика ==")
check("есть метод _dialog_scale", "def _dialog_scale" in APP_SRC)
check("_dialog_scale читает tk scaling", '"tk", "scaling"' in APP_SRC)
check("эталон 96/72 DPI", "96.0 / 72.0" in APP_SRC)
check("масштаб не меньше 1.0", "max(1.0," in APP_SRC)
check("высота окна зависит от числа строк", "26 * n_rows" in APP_SRC)
check("окно вписывается в экран (clamp)", "min(W, sw - 80)" in APP_SRC and "min(H, sh - 80)" in APP_SRC)

# ------------------------------------- функциональный тест _dialog_scale

print("== функционально: _dialog_scale (AST-извлечение) ==")


def extract_method(source: str, class_name: str, method: str) -> str:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for sub in node.body:
                if isinstance(sub, ast.FunctionDef) and sub.name == method:
                    return ast.get_source_segment(source, sub)
    raise AssertionError(f"метод {class_name}.{method} не найден")


code = extract_method(APP_SRC, "SubGenApp", "_dialog_scale")
ns: dict = {}
exec(compile(code, "<dialog-scale-extract>", "exec"), ns)
_dialog_scale = ns["_dialog_scale"]


class FakeTk:
    def __init__(self, value=None, raise_=False):
        self.value = value
        self.raise_ = raise_

    def call(self, *a):
        if self.raise_ or self.value is None:
            raise RuntimeError("no tk")
        return self.value


class FakeSelf:
    def __init__(self, scaling):
        self.tk = FakeTk(scaling)


cases = [
    # (tk scaling, ожидаемый k, пояснение)
    (96.0 / 72.0, 1.0, "Windows 96 DPI (100%) -> окно как было"),
    (120.0 / 72.0, 1.25, "Windows 120 DPI (125%) -> окно x1.25"),
    (144.0 / 72.0, 1.5, "Windows 144 DPI (150%) -> окно x1.5"),
    (1.0, 1.0, "X11 bitmap-шрифты (~72 dpi) -> не сжимаем"),
    (None, 1.0, "tk scaling недоступен -> эталон"),
]
for scaling, expected, why in cases:
    got = _dialog_scale(FakeSelf(scaling))
    check(f"k={expected} ({why})", abs(got - expected) < 0.02, f"got {got:.4f}")

# ------------------------------------------------- GUI-смоук (если дисплей)

print("== GUI-смоук (пропуск без дисплея) ==")
gui_done = False
try:
    import tkinter  # noqa: F401

    tkinter.Tk()
    tkinter._default_root.destroy()
except Exception as exc:  # нет дисплея / нет tkinter
    print(f"  skip (нет дисплея: {type(exc).__name__})")
else:
    import customtkinter as ctk
    from ui import theme
    from ui.app import SubGenApp

    theme.apply_theme()
    root = ctk.CTk()
    root.geometry("980x620+0+0")
    root._dialog_scale = lambda: SubGenApp._dialog_scale(root)
    root.update()

    report = {
        "generated_at_utc": "2026-09-19T06:12:34Z",
        "sources": ["https://a", "https://b"],
        "discovered": 168,
        "working": 53,
        "rejected": 115,
        "exported": 53,
        "initial_check": {"enabled": True, "passed": 111, "failed": 57, "checked": 168},
        "route": {"enabled": True, "passed": 53, "failed": 1, "checked": 54},
        "sources_report": {
            "enabled": True, "contributed": 2, "sources_total": 2,
            "dead": 0, "nodes": [],
        },
    }

    def run_case(tag: str):
        global gui_done
        SubGenApp._show_results_dialog(root, report)
        root.update_idletasks()
        root.update()
        dlg = None
        for ch in root.winfo_children():
            if isinstance(ch, tkinter.Toplevel):
                dlg = ch
        assert dlg is not None, "диалог не создан"
        dw = dlg.winfo_width()
        # Значения — это Label с жирным шрифтом (по вёрстке _add_row).
        bad = []
        for w in dlg.winfo_children():
            if w.winfo_class() == "Label":
                try:
                    font = str(w.cget("font"))
                except Exception:
                    continue
                if font.endswith("bold"):
                    right = w.winfo_x() + w.winfo_width()
                    if right > dw:
                        bad.append((w.cget("text")[:20], right))
        check(f"[{tag}] все значения внутри окна (правый край <= {dw})", not bad, f"вылезли: {bad}")
        # Разделитель — Frame высотой <= 4px.
        seps = [w for w in dlg.winfo_children()
                if w.winfo_class() == "Frame" and w.winfo_height() <= 4]
        check(f"[{tag}] разделитель — плоский Frame", bool(seps))
        # Кнопки внутри окна по ширине.
        btns = [w for w in dlg.winfo_children() if w.winfo_class() == "TButton" or w.winfo_class() == "Button"]
        ok_btn = all(w.winfo_x() + w.winfo_width() <= dw for w in btns)
        check(f"[{tag}] кнопки внутри окна", ok_btn and len(btns) >= 1)
        dlg.destroy()
        gui_done = True

    run_case("нативный масштаб")
    root.tk.call("tk", "scaling", 2.0)  # эквивалент 150% DPI
    run_case("150% DPI (scaling 2.0)")
    root.destroy()

if not gui_done:
    print("  (GUI-смоук пропущен — source-охраны и функциональные тесты выше обязательны)")

# ------------------------------------------------------------------- итог
print(f"\n{'=' * 60}")
print(f"PASS: {PASS}  FAIL: {FAIL}")
sys.exit(1 if FAIL else 0)
