#!/usr/bin/env python3
"""GUI-смоук вкладки «Фильтры» после v14 (полный список протоколов + ★).

Под Xvfb: строим окно приложения, открываем вкладку «Фильтры» и проверяем:
  1. галочка «hysteria (v1)» существует и выбрана по умолчанию;
  2. на ходовых значениях — «★ » в подписи (vless/hysteria2/ss/reality/
     tcp/ws/grpc/vision);
  3. приписка-легенда отрисована (текст со «★» и «НЕ обрезается»);
  4. все галочки по-прежнему выбираются/снимаются (мастер-тумблер жив).
Запуск: xvfb-run -a python scripts/test_filters_gui_smoke.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

import customtkinter as ctk  # noqa: E402

from subgen.params_filter import DIMENSIONS, POPULAR  # noqa: E402

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


ctk.set_appearance_mode("dark")
app = ctk.CTk()
app.geometry("900x700")
app.withdraw()  # невидимо — нам нужен только виджет-дерево

# Строим страницу напрямую (без полного ui.app — он тянет runner и т.п.).
from ui.pages import filters_page  # noqa: E402

page = filters_page.FiltersPage(app, app)

boxes = page._checkboxes
check("группа protocol построена", "protocol" in boxes)

# 1. hysteria (v1) присутствует и выбрана.
proto = boxes.get("protocol", {})
check(
    "галочка hysteria (v1) построена",
    "hysteria" in proto,
    str(list(proto)),
)
if "hysteria" in proto:
    check(
        "hysteria (v1) выбрана по умолчанию",
        bool(proto["hysteria"].get()),
    )
    check(
        "подпись hysteria (v1) читаемая",
        "hysteria (v1)" in (proto["hysteria"].cget("text") or ""),
        str(proto["hysteria"].cget("text")),
    )

# 2. ★-метки на ходовых значениях каждой группы.
for dim, values in POPULAR.items():
    for v in sorted(values):
        chk = boxes.get(dim, {}).get(v)
        text = (chk.cget("text") if chk is not None else "") or ""
        check(
            f"★ на ходовом {dim}:{v}",
            text.startswith("★ "),
            f"text={text!r}",
        )

# 3. НЕпопулярные — без звезды (не палим всё подряд).
vm = boxes.get("protocol", {}).get("vmess")
check(
    "vmess без ★ (не ходовой)",
    vm is not None and not (vm.cget("text") or "").startswith("★"),
    str(vm.cget("text") if vm else None),
)

# 4. Все значения всех измерений на месте (полный список).
total_expected = sum(len(v) for v in DIMENSIONS.values()) + len(DIMENSIONS)
total_built = sum(len(g) for g in boxes.values())
check(
    "все галочки построены (значения + «прочие»)",
    total_built == total_expected,
    f"{total_built} vs {total_expected}",
)

# 5. Приписка-легенда отрисована — ищем CTkLabel с текстом легенды.
legend_found = False


def _text_of(widget) -> str:
    try:
        value = widget.cget("text")
    except Exception:
        return ""
    return value if isinstance(value, str) else ""


def _walk(widget, depth: int = 0):
    global legend_found
    if depth > 6:
        return
    if "★" in _text_of(widget) and "обрезается" in _text_of(widget):
        legend_found = True
    for child in widget.winfo_children():
        _walk(child, depth + 1)


_walk(page.scroll)
check("приписка-легенда (★ + «НЕ обрезается») отрисована", legend_found)

# 6. select_all / deselect_all живы.
page._deselect_all()
check(
    "снять всё работает",
    all(not chk.get() for g in boxes.values() for chk in g.values()),
)
page._select_all()
check(
    "выбрать всё работает",
    all(chk.get() for g in boxes.values() for chk in g.values()),
)

# 7. get_filter_options: выбранные протоколы уходят в конвейер.
# a) мастер-тумблер выключен (дефолт) -> фильтры пустые, тестируется всё.
opts = page.get_filter_options()
check(
    "мастер выключен -> proto_filter пуст (всё тестируется)",
    opts.get("proto_filter", "x") == "" and not opts.get("params_filter_enabled"),
)

# b) мастер включен + снят vmess -> CSV из остальных протоколов (вкл. hysteria).
page.toggle_params_master.select()
page._checkboxes["protocol"]["vmess"].deselect()
opts = page.get_filter_options()
csv = opts.get("proto_filter", "")
check("мастер включен -> params_filter_enabled", bool(opts.get("params_filter_enabled")))
for proto_name in DIMENSIONS["protocol"]:
    if proto_name == "vmess":
        continue
    check(f"proto_filter отдаёт {proto_name}", proto_name in csv, csv)
check("proto_filter НЕ отдаёт снятый vmess", "vmess" not in csv, csv)

app.destroy()
print(f"\n{'=' * 60}")
print(f"PASS: {PASS}  FAIL: {FAIL}")
sys.exit(1 if FAIL else 0)
