#!/usr/bin/env python3
"""Скриншоты v17-интерфейса под Xvfb (для визуальной проверки)."""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))
OUT = REPO.parent / "download"

import customtkinter as ctk  # noqa: E402

ctk.set_appearance_mode("dark")

from ui.app import SubGenApp  # noqa: E402

app = SubGenApp()
app.update_idletasks()

shots = [
    ("start", "ui17_start_novice.png"),
    ("sources", "ui17_mysubs_list.png"),
    ("import", "ui17_mysubs_import.png"),
    ("filters", "ui17_mysubs_filters.png"),
    ("settings", "ui17_settings_basic.png"),
    ("diag", "ui17_settings_diag.png"),
    ("log", "ui17_settings_log.png"),
    ("recheck", "ui17_recheck.png"),
]

# экспертный режим стартовой — отдельным кадром
for page, fname in shots:
    app._show_page(page)
    if page == "start":
        app.page_start.set_ui_mode("novice")
    app.update_idletasks()
    # Реально ждём отрисовки: цикл update() ~600мс (after-колбэк сам
    # отработает внутри цикла — прошлый вариант снимал кадр до рендера).
    import time as _t
    _deadline = _t.monotonic() + 0.6
    while _t.monotonic() < _deadline:
        app.update()
        _t.sleep(0.03)
    try:
        from PIL import ImageGrab
    except ImportError:
        break
    img = ImageGrab.grab()
    img.save(OUT / fname)
    print("saved", fname)

# экспертный режим стартовой страницы
app._show_page("start")
app.page_start.set_ui_mode("expert")
app.update_idletasks()
import time as _t
_deadline = _t.monotonic() + 0.6
while _t.monotonic() < _deadline:
    app.update()
    _t.sleep(0.03)
try:
    from PIL import ImageGrab
    img = ImageGrab.grab()
    img.save(OUT / "ui17_start_expert.png")
    print("saved ui17_start_expert.png")
except ImportError:
    pass

app.destroy()
print("done")
