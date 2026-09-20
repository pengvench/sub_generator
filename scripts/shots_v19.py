#!/usr/bin/env python3
"""Скриншоты v19: вкладка «Основные» без скролла + страницы после фиксов."""
from __future__ import annotations

import sys
import time as _t
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
    ("settings", "ui19_settings_basic.png"),
    ("diag", "ui19_settings_diag.png"),
    ("log", "ui19_settings_log.png"),
    ("sources", "ui19_mysubs_list.png"),
    ("import", "ui19_mysubs_import.png"),
]

for page, fname in shots:
    app._show_page(page)
    app.update_idletasks()
    _deadline = _t.monotonic() + 0.7
    while _t.monotonic() < _deadline:
        app.update()
        _t.sleep(0.03)
    try:
        from PIL import ImageGrab
    except ImportError:
        print("нет PIL — скриншоты пропущены")
        break
    img = ImageGrab.grab()
    img.save(OUT / fname)
    print("saved", fname)

app.destroy()
