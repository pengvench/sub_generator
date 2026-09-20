#!/usr/bin/env python3
"""v17 GUI-смоук: сайдбар 4 пункта, вкладки «как в браузере», resilience,
dedup в одной ячейке, движок пула, кнопки «Импорт…» в режиме «Просто».

Запуск (Xvfb должен быть поднят тем же вызовом bash):
    Xvfb :99 ... & DISPLAY=:99 /home/z/.venv/bin/python scripts/test_v17_ui_smoke.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

import customtkinter as ctk  # noqa: E402

ctk.set_appearance_mode("dark")

from ui.app import SubGenApp  # noqa: E402

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(f"{name} {detail}")


app = SubGenApp()
app.update_idletasks()

# --- 1. Сайдбар: 4 кнопки ---
btns = dict(app._nav_buttons)
check("sidebar: ровно 4 кнопки", set(btns) == {"start", "sources", "recheck", "settings"},
      str(set(btns)))
labels = [b.cget("text") for b in btns.values()]
check("sidebar: подписи", labels == ["🚀 Запуск", "📚 Мои подписки", "🔁 Перепроверка", "⚙ Настройки"],
      str(labels))
check("sidebar: нет «Добавить подписки»", not any("Добавить подписки" in l for l in labels))
check("sidebar: нет футера «Результаты — в папке»",
      "Результаты — в папке" not in Path(REPO / "python" / "ui" / "app.py").read_text(encoding="utf-8"))

# --- 2. Страницы и вкладки ---
check("pages: 4 ключа", set(app.pages) == {"start", "sources", "recheck", "settings"}, str(set(app.pages)))
check("page_sources = вкладка Список", app.page_sources is app.page_mysubs.list_tab)
check("page_import = вкладка Импорт", app.page_import is app.page_mysubs.import_tab)
check("page_filters = вкладка Фильтры", app.page_filters is app.page_mysubs.filters_tab)
check("page_settings = вкладка Основные", app.page_settings is app.page_settings_root.basic_tab)
check("page_diag = вкладка Диагностика", app.page_diag is app.page_settings_root.diag_tab)
check("page_log = вкладка Журнал", app.page_log is app.page_settings_root.log_tab)

def tab_names(tabview):
    """Имена вкладок, совместимо с ctk 5.x и 6.x."""
    if hasattr(tabview, "_name_list"):
        return list(tabview._name_list)
    return list(getattr(tabview, "_name_index_dict", {}))


tv = app.page_mysubs.tabview
names = tab_names(tv)
check("вкладки «Мои подписки»", names == ["Список", "Импорт", "Фильтры"], str(names))
tvs = app.page_settings_root.tabview
names2 = tab_names(tvs)
check("вкладки «Настройки»", names2 == ["Основные", "Диагностика", "Журнал"], str(names2))

# --- 3. Навигация алиасами (старые ключи) ---
app._show_page("import"); app.update_idletasks()
check("алиас import → вкладка «Импорт»", tv.get() == "Импорт", tv.get())
app._show_page("log"); app.update_idletasks()
check("алиас log → вкладка «Журнал»", tvs.get() == "Журнал", tvs.get())
app._show_page("diag"); app.update_idletasks()
check("алиас diag → вкладка «Диагностика»", tvs.get() == "Диагностика", tvs.get())
app._show_page("filters"); app.update_idletasks()
check("алиас filters → вкладка «Фильтры»", tv.get() == "Фильтры", tv.get())
app._show_page("sources"); app.update_idletasks()
check("sources → вкладка «Список»", tv.get() == "Список", tv.get())

# --- 4. Старт-страница ---
check("toggle_resilience_check существует", hasattr(app.page_start, "toggle_resilience_check"))
check("pool_engine_menu существует", hasattr(app.page_start, "pool_engine_menu"))
opts = app.page_start.get_options()
check("get_options: pool_engine=xray", getattr(opts, "pool_engine", None) == "xray",
      str(getattr(opts, "pool_engine", None)))
check("get_options: resilience_check=True", bool(getattr(opts, "resilience_check", False)))

# resilience теперь в карточке «Что тестировать» (ряд 3)
inner_what = app.page_start.card_what.inner
res_grid = app.page_start.toggle_resilience_check.master.grid_info()
check("resilience: внутри карточки «Что тестировать»",
      app.page_start.toggle_resilience_check.master.master is inner_what)
check("resilience: ряд 3", str(res_grid.get("row")) == "3", str(res_grid))

# dedup — ОДНА ячейка (колонка 0, ряд 4), columnspan=1
inner_extra = app.page_start.card_extra.inner
dedup_frame = app.page_start.dedup_mode_menu.master
gi = dedup_frame.grid_info()
check("dedup: колонка 0", str(gi.get("column")) == "0", str(gi))
check("dedup: columnspan не 2 (одна ячейка)", str(gi.get("columnspan", "1")) != "2", str(gi))

# --- 5. Режим «Просто»: кнопки «Импорт…» / «Список» ---
app.page_start.set_ui_mode("novice"); app.update_idletasks()
btn_texts: list[str] = []


def walk(w):
    for c in w.winfo_children():
        if isinstance(c, ctk.CTkButton):
            btn_texts.append(str(c.cget("text")))
        walk(c)


walk(app.page_start.novice)
check("novice: кнопка «⬇ Импорт…»", any("Импорт…" in t for t in btn_texts), str(btn_texts))
check("novice: кнопка «Список»", any(t == "Список" for t in btn_texts), str(btn_texts))
check("novice: нет «Добавить ссылку…»", not any("Добавить ссылку" in t for t in btn_texts))

# клик по «Импорт…» открывает страницу вкладок с вкладкой «Импорт»
# (кнопка лежит на 3 уровня вложенности — ищем рекурсивно).
def find_button(w, needle):
    for c in w.winfo_children():
        if isinstance(c, ctk.CTkButton) and needle in str(c.cget("text")):
            return c
        found = find_button(c, needle)
        if found is not None:
            return found
    return None


btn_import = find_button(app.page_start.novice, "Импорт…")
check("novice: кнопка «Импорт…» найдена рекурсивно", btn_import is not None)
if btn_import is not None:
    btn_import.invoke()
app.update_idletasks()
check("клик «Импорт…» → вкладка «Импорт» открыта", tv.get() == "Импорт", tv.get())

# --- 6. set_busy прокидывается во вкладки ---
app._set_busy(True); app.update_idletasks()
app._set_busy(False); app.update_idletasks()
check("set_busy не падает", True)

app.destroy()

print(f"\n=== v17 UI-смоук: {len(PASS)} ok, {len(FAIL)} FAIL ===")
for f in FAIL:
    print("  FAIL:", f)
sys.exit(0 if not FAIL else 1)
