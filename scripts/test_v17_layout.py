#!/usr/bin/env python3
"""v17: проверка геометрии раскладки (Xvfb)."""
from __future__ import annotations

import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

import customtkinter as ctk  # noqa: E402

ctk.set_appearance_mode("dark")

from ui.app import SubGenApp  # noqa: E402

app = SubGenApp()


def pump(sec: float = 0.4) -> None:
    deadline = time.monotonic() + sec
    while time.monotonic() < deadline:
        app.update()
        time.sleep(0.03)


pump(0.8)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(f"{name} {detail}")


# 1. Низ кнопки запуска (новичок) в пределах окна 620px
app.page_start.set_ui_mode("novice")
pump()
btn = app.page_start.btn_run_novice
bottom = btn.winfo_rooty() - app.winfo_rooty() + btn.winfo_height()
check(f"novice: кнопка запуска влезает (низ {bottom} < 620)", bottom < 620)

# 2. Эксперт: кнопка запуска существует и в скролле
app.page_start.set_ui_mode("expert")
pump()
btn2 = app.page_start.btn_run
bottom2 = btn2.winfo_rooty() - app.winfo_rooty() + btn2.winfo_height()
check(f"expert: кнопка запуска отрисована (низ {bottom2})", bottom2 > 0)

# 3. Оба tabview отрисованы
for name, tv in [("mysubs", app.page_mysubs.tabview), ("settings", app.page_settings_root.tabview)]:
    check(f"{name}: tabview отрисован", tv.winfo_ismapped() and tv.winfo_width() > 100,
          f"mapped={tv.winfo_ismapped()} w={tv.winfo_width()}")

# 4. Меню dedup/engine не схлопнулись
check("dedup_menu ширина >= 100", app.page_start.dedup_mode_menu.winfo_width() >= 100,
      str(app.page_start.dedup_mode_menu.winfo_width()))
check("engine_menu ширина >= 100", app.page_start.pool_engine_menu.winfo_width() >= 100,
      str(app.page_start.pool_engine_menu.winfo_width()))

# 5. dedup-фрейм не шире одной колонки (~половина карточки)
dw = app.page_start.dedup_mode_menu.master.winfo_width()
check(f"dedup-фрейм в пределах колонки ({dw}px < 360)", dw < 360)

# 6. resilience-тумблер замаплен в карточке «Что тестировать»
res = app.page_start.toggle_resilience_check
check("resilience замаплен", bool(res.winfo_ismapped()))

# 7. Заголовок карточки «Что тестировать» на месте
head = app.page_start.card_what.winfo_children()[0].winfo_children()[0]
check("карточка «Что тестировать»", "Что тестировать" in str(head.cget("text")))

app.destroy()
print(f"=== v17 геометрия: {len(PASS)} ok, {len(FAIL)} FAIL ===")
for f in FAIL:
    print("  FAIL:", f)
sys.exit(0 if not FAIL else 1)
