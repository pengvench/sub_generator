#!/usr/bin/env python3
"""Скриншоты v18: страницы «Мои подписки» и «Настройки» после чистки приписок."""
from __future__ import annotations

import sys
import time as _t
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))
OUT = REPO.parent / "download"
OUT.mkdir(exist_ok=True)

import customtkinter as ctk  # noqa: E402

ctk.set_appearance_mode("dark")

from ui.app import SubGenApp  # noqa: E402

app = SubGenApp()
app.geometry("1180x780+0+0")
app.update_idletasks()

shots = [
    ("sources", "ui18_mysubs_list.png"),
    ("import", "ui18_mysubs_import.png"),
    ("settings", "ui18_settings.png"),
]

for page, fname in shots:
    app._show_page(page)
    app.update_idletasks()
    _deadline = _t.monotonic() + 0.8
    while _t.monotonic() < _deadline:
        app.update()
        _t.sleep(0.03)
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        # кроп по окну приложения
        x = app.winfo_rootx(); y = app.winfo_rooty()
        w = app.winfo_width(); h = app.winfo_height()
        img = img.crop((x, y, x + w, y + h))
        img.save(OUT / fname)
        print("saved", fname)
    except Exception as e:
        print("grab failed:", e)

app.destroy()
