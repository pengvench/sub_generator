#!/usr/bin/env python3
"""v19 GUI-тесты: (1) вкладка «Основные» без скролла, кнопка видна целиком;
(2) умное скрытие скроллбаров; (3) Ctrl+C/V/A/X в РУССКОЙ раскладке
(диспетчер по keycode — ui/hotkeys.py).

Запуск (Xvfb тем же вызовом bash):
    Xvfb :99 ... & DISPLAY=:99 /home/z/.venv/bin/python scripts/test_v19_ui_fixes.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

import tkinter as tk  # noqa: E402

import customtkinter as ctk  # noqa: E402

ctk.set_appearance_mode("dark")

from ui.app import SubGenApp  # noqa: E402

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(f"{name}{(' | ' + detail) if detail and not cond else ''}")
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  [{detail}]"))


def en_key(widget: object, latin: str) -> None:
    """Синтетическое нажатие Ctrl+<латинская клавиша> (английская раскладка).

    Под Xvfb X-сервер пересчитывает keysym из keycode по us-раскладке,
    так что событие всегда «английское». Русскую раскладку эмулируем
    юнит-вызовами обработчика (FakeEvent) — см. п. 3.6.
    """
    widget.event_generate(f"<Control-KeyPress-{latin}>")


# Таблицы клавиш: символ на RU-раскладке, VK-код и keysym-имя Windows
# (для юнит-вызовов с FakeEvent — точная форма события на Windows).
RU_CHAR = {"a": "ф", "c": "с", "v": "м", "x": "ч"}
VK = {"a": 65, "c": 67, "v": 86, "x": 88}
WIN_KEYSYM = {"a": "cyrillic_ef", "c": "cyrillic_es", "v": "cyrillic_em", "x": "cyrillic_che"}

app = SubGenApp()
app.update_idletasks()

# ===========================================================================
# 1. Вкладка «Основные»: без скролл-фрейма, кнопка сохранения видна целиком
# ===========================================================================
ps = app.page_settings  # SettingsPage (вкладка «Основные»)
app._show_page("settings")
app.update_idletasks()

check("settings: CTkScrollableFrame убран", not hasattr(ps, "scroll"))
check("settings: entry префикса на месте", hasattr(ps, "entry_prefix"))
check("settings: кнопка сохранения на месте", hasattr(ps, "btn_save"))

app_win_bottom = app.winfo_rooty() + app.winfo_height()
btn_bottom = ps.btn_save.winfo_rooty() + ps.btn_save.winfo_height()
check("settings: кнопка «Сохранить» видна ЦЕЛИКОМ", btn_bottom <= app_win_bottom,
      f"btn_bottom={btn_bottom} > win_bottom={app_win_bottom}")
lbl_bottom = ps.lbl_saved.winfo_rooty() + ps.lbl_saved.winfo_height()
check("settings: статус «сохранено» тоже внутри окна", lbl_bottom <= app_win_bottom,
      f"lbl_bottom={lbl_bottom} > win_bottom={app_win_bottom}")

# Скроллбаров внутри вкладки «Основные» не осталось вообще.
scrollbars = []
def _collect(w):
    for ch in w.winfo_children():
        if ch.winfo_class() in ("Scrollbar", "CTkScrollbar"):
            scrollbars.append(ch)
        _collect(ch)
_collect(ps)
check("settings: внутри вкладки нет ни одного скроллбара", not scrollbars,
      str(scrollbars))

# ===========================================================================
# 2. Умное скрытие скроллбаров (патч CTkScrollbar.set в theme.py)
# ===========================================================================
top = ctk.CTkToplevel(app)
top.geometry("400x300")
sf = ctk.CTkScrollableFrame(top, width=380, height=260)
sf.pack(fill="both", expand=True)
lbl = ctk.CTkLabel(sf, text="small")
lbl.pack()
top.update_idletasks()
app.update()

sb_small = sf._scrollbar
check("smart-scroll: маленький контент — скроллбар скрыт",
      not sb_small.grid_info() and getattr(sb_small, "_smart_hidden", False),
      f"grid_info={sb_small.grid_info()}")

for i in range(40):
    ctk.CTkLabel(sf, text=f"line {i}" * 3).pack()
app.update()
check("smart-scroll: большой контент — скроллбар вернулся",
      bool(sb_small.grid_info()) and not getattr(sb_small, "_smart_hidden", False),
      f"grid_info={sb_small.grid_info()}")

top.destroy()

# ===========================================================================
# 3. Хоткеи копирования/вставки
# ===========================================================================
# Интеграционные X-события под Xvfb всегда дают ЛАТИНСКИЙ keysym (X-сервер
# пересчитывает keysym из keycode по us-раскладке), поэтому реальную РУССКУЮ
# раскладку эмулируем юнит-вызовами обработчика (FakeEvent, как на Windows)
# в п. 3.6. Здесь — реальные события диспетчера: EN-путь и закрытый нами
# пробел x11 (Ctrl+A без <<SelectAll>> на <Control-a>).

# --- 3.1. Обычная CTkEntry (настройки — префикс) ---
entry = ps.entry_prefix._entry  # внутренний tk.Entry
entry.focus_force()
app.update()
check("фокус на поле настроек", app.focus_get() is entry, str(app.focus_get()))

entry.delete(0, "end")
entry.insert(0, "PREFIX-123")
entry.icursor(0)
app.update()

# Ctrl+A: на x11 классового биндинга нет — выделяет НАШ обработчик
# (диспетчер реально срабатывает на живых X-событиях).
en_key(entry, "a")
app.update()
check("Ctrl+A (X-событие): выделился ВЕСЬ текст поля",
      entry.selection_present() and str(entry.index("sel.first")) == "0"
      and str(entry.index("sel.last")) == "10",
      f"sel={entry.index('sel.first') if entry.selection_present() else None}.."
      f"{entry.index('sel.last') if entry.selection_present() else None}")

# Ctrl+C с выделением — классовый биндинг (наш скип не мешает).
app.clipboard_clear()
app.clipboard_append("OLD")
en_key(entry, "c")
app.update()
check("Ctrl+C (X-событие): выделенное попало в буфер",
      app.clipboard_get() == "PREFIX-123", repr(app.clipboard_get()))

# Ctrl+V: вставка классовым биндингом ровно один раз (скип не даёт задвоить).
entry.icursor("end")
app.clipboard_clear()
app.clipboard_append("ВСТАВЛЕНО")
en_key(entry, "v")
app.update()
check("Ctrl+V (X-событие): вставилось в поле один раз",
      entry.get() == "PREFIX-123ВСТАВЛЕНО", repr(entry.get()))

# Ctrl+X с выделением — вырезание.
entry.delete(0, "end")
entry.insert(0, "CUT-ME")
en_key(entry, "a")
en_key(entry, "x")
app.update()
check("Ctrl+X (X-событие): вырезано в буфер", app.clipboard_get() == "CUT-ME"
      and entry.get() == "", f"buf={app.clipboard_get()!r} field={entry.get()!r}")

# --- 3.2. Поле вставки «Импорт»: Ctrl+V = вставка с заменой ---
# Цепочка виртуальных событий: физический <Control-v> матчится с <<Paste>>,
# виджетный биндинг импорта срабатывает ПЕРВЫМ (до классового) и ставит
# 'break' — замена ровно один раз.
app.page_mysubs.show_tab("import")
app.update_idletasks()
imp = app.page_import
txt = imp.txt_input._textbox  # внутренний tk.Text
txt.focus_force()
app.update()

txt.delete("1.0", "end")
txt.insert("1.0", "junk")
app.clipboard_clear()
app.clipboard_append("vless://en-1")
en_key(txt, "v")
app.update()
body = txt.get("1.0", "end").strip()
check("Импорт Ctrl+V: замена, ровно один раз", body == "vless://en-1",
      repr(body[:120]))

# Ctrl+A в текстовом поле — наш обработчик (пробел x11).
en_key(txt, "a")
app.update()
sel = None
try:
    sel = (txt.index("sel.first"), txt.index("sel.last"))
    ok_sel = sel[0] == "1.0"
except tk.TclError:
    ok_sel = False
check("Импорт Ctrl+A: выделение от начала текста", ok_sel, str(sel))

# Ctrl+C из текстового поля с выделением (Text всегда имеет хвостовой \n).
app.clipboard_clear()
app.clipboard_append("STALE")
en_key(txt, "c")
app.update()
check("Импорт Ctrl+C: буфер обновился",
      app.clipboard_get().rstrip("\n") == "vless://en-1",
      repr(app.clipboard_get()))

# --- 3.4. Существующие кастомные обработчики не сломаны ---
# sources: Ctrl+V в поле URL — вставка на курс (без замены) по VK-коду:
# кастомный обработчик срабатывает на уровне ВИДЖЕТА (раньше нашего) и
# ставит 'break' — Windows-путь при любой раскладке.
app.page_mysubs.show_tab("sources")
app.update_idletasks()
src = app.page_sources
sentry = src.entry_url._entry
sentry.focus_force()
app.update()
sentry.delete(0, "end")
sentry.insert(0, "https://base/")
sentry.icursor("end")
app.clipboard_clear()
app.clipboard_append("tail")
sentry.event_generate(f"<Control-KeyPress-{RU_CHAR['v']}>", keycode=86)
app.update()
check("Список Ctrl+V (кастом): вставка на курсор",
      sentry.get() == "https://base/tail", repr(sentry.get()))

# --- 3.5. Глобальное покрытие: произвольная CTkEntry ---
top2 = ctk.CTkToplevel(app)
top2.geometry("300x120")
e2 = ctk.CTkEntry(top2)
e2.pack(fill="x", padx=10, pady=10)
e2_inner = e2._entry
e2_inner.focus_force()
top2.update()
app.update()
e2_inner.delete(0, "end")
e2_inner.insert(0, "ANY-ENTRY")
en_key(e2_inner, "a")
app.update()
check("Любая CTkEntry: Ctrl+A работает (глобальный перехватчик)",
      e2_inner.selection_present()
      and str(e2_inner.index("sel.last")) == "9",
      f"sel..{e2_inner.index('sel.last') if e2_inner.selection_present() else None}")
top2.destroy()

# --- 3.6. Юнит-вызовы обработчика: события «как на Windows» ---
# На реальной Windows с русской раскладкой event.keysym = 'cyrillic_ef'
# (кириллическое имя), event.keycode = VK-код, оконная система 'win32'.
# В Xvfb такое событие не сгенерировать (X-сервер не знает ru-раскладки и
# выдаёт искажённый keysym), поэтому вызываем обработчик напрямую с фейковым
# событием точной Windows-формы, подменив _WINDOWINGSYSTEM на 'win32'.

from ui import hotkeys  # noqa: E402


class FakeEvent:
    def __init__(self, widget, keysym, keycode, char, state=0x4):
        self.widget = widget
        self.keysym = keysym
        self.keycode = keycode
        self.char = char
        self.state = state


_saved_ws = hotkeys._WINDOWINGSYSTEM
hotkeys._WINDOWINGSYSTEM = "win32"

entry.delete(0, "end")
entry.insert(0, "WIN-RU-TEST")
entry.select_clear()
entry.focus_force()
app.update()
app.clipboard_clear()
app.clipboard_append("FAKE-CLIP")

# Ctrl+A: keysym 'cyrillic_ef' (не латиница -> не пропущен), VK 65.
res = hotkeys._on_ctrl_key(FakeEvent(entry, WIN_KEYSYM["a"], VK["a"], "\x13"))
app.update()
check("win-ru fake Ctrl+A: обработчик сработал и выделил всё",
      res == "break" and entry.selection_present()
      and str(entry.index("sel.last")) == "11",
      f"res={res} sel_last={entry.index('sel.last') if entry.selection_present() else None}")

# Ctrl+C: keysym 'cyrillic_es', VK 67.
res = hotkeys._on_ctrl_key(FakeEvent(entry, WIN_KEYSYM["c"], VK["c"], "\x13"))
app.update()
check("win-ru fake Ctrl+C: буфер получил текст",
      app.clipboard_get() == "WIN-RU-TEST", repr(app.clipboard_get()))

# Ctrl+V: keysym 'cyrillic_em', VK 86 (выделение предварительно снято,
# буфер выставляем ПОСЛЕ шага C — C перезаписывает буфер выделенным).
entry.select_clear()
entry.icursor(0)
app.clipboard_clear()
app.clipboard_append("FAKE-CLIP")
res = hotkeys._on_ctrl_key(FakeEvent(entry, WIN_KEYSYM["v"], VK["v"], "\x13"))
app.update()
check("win-ru fake Ctrl+V: вставка в поле",
      entry.get() == "FAKE-CLIPWIN-RU-TEST", repr(entry.get()))

# То же — на текстовом поле «Импорт»: вставка с заменой (виджетный
# биндинг <<Paste>> срабатывает от синтезированного нами события).
app.clipboard_clear()
app.clipboard_append("vless://win-ru")
res = hotkeys._on_ctrl_key(FakeEvent(txt, WIN_KEYSYM["v"], VK["v"], "\x13"))
app.update()
check("Импорт win-ru fake Ctrl+V: замена контента буфером",
      txt.get("1.0", "end").strip() == "vless://win-ru",
      repr(txt.get("1.0", "end")[:120]))

# Английская раскладка: keysym 'v' (одиночный латинский символ) ->
# обработчик ПРОПУСКАЕТ (классовые биндинги Tk уже всё сделали).
res = hotkeys._on_ctrl_key(FakeEvent(entry, "v", VK["v"], "v"))
check("win-en fake Ctrl+V: латинский keysym пропущен (нет задвоения)",
      res is None, f"res={res}")

# Keysym-ИМЯ из латинских букв ('space') — НЕ латинская буква: не пропускать
# (регрессия: раньше 'space'.isalpha()==True ложно скипал событие).
res = hotkeys._on_ctrl_key(FakeEvent(entry, "space", VK["a"], "\x00"))
check("fake keysym='space'+VK_A: срабатывает SelectAll (не скип)",
      res == "break", f"res={res}")

# Ctrl без буквенной клавиши (например, Ctrl+Insert): не наш матч.
res = hotkeys._on_ctrl_key(FakeEvent(entry, "Insert", 45, ""))
check("fake Ctrl+Insert: вне нашей таблицы — пропуск", res is None, f"res={res}")

# Фокус не на текстовом виджете (кнопка): перехватчик не мешает.
res = hotkeys._on_ctrl_key(FakeEvent(ps.btn_save, WIN_KEYSYM["a"], VK["a"], "\x13"))
check("fake Ctrl+A на кнопке: игнор (не текстовый виджет)", res is None, f"res={res}")

hotkeys._WINDOWINGSYSTEM = _saved_ws

# ===========================================================================
# 4. Регрессия: вкладки и навигация живы
# ===========================================================================
app.page_settings_root.show_tab("diag")
app.update_idletasks()
check("regress: вкладка «Диагностика» переключается",
      app.page_settings_root.tabview.get() == "Диагностика")
app.page_settings_root.show_tab("log")
app.update_idletasks()
check("regress: вкладка «Журнал» переключается",
      app.page_settings_root.tabview.get() == "Журнал")
app.page_mysubs.show_tab("filters")
app.update_idletasks()
check("regress: вкладка «Фильтры» переключается",
      app.page_mysubs.tabview.get() == "Фильтры")

# ===========================================================================
print()
print(f"ИТОГО: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("ПРОВАЛЫ:")
    for f in FAIL:
        print("  -", f)
    sys.exit(1)
app.destroy()
