"""Тёмная Material-палитра (3 тона: фон / акцент / текст) по образцу ZapretUI.

Тона ZapretUI:
  - фон:      #0C1014 .. #17212B (градиент), сайдбар #0D1319, карточки #121A22
  - акцент:   градиент #075985 -> #0891B2, hover #22C7E8
  - текст:    #E7EDF3, muted #8D9AA7
"""
from __future__ import annotations

import customtkinter as ctk

# ---------------------------------------------------------------------------
# Палитра (Material 3 тона)
# ---------------------------------------------------------------------------
BG = "#0C1014"              # фон окна (тёмный)
BG_ALT = "#101820"          # альтернативный фон
BG_GRAD_END = "#17212B"     # конец фонового градиента
SIDEBAR = "#0D1319"         # сайдбар
CARD = "#121A22"            # карточки
CARD_ALT = "#151F29"        # альтернативная карточка / hover
BORDER = "#263543"          # рамки
BORDER_SOFT = "#1B2733"     # мягкая рамка
INPUT = "#0C1218"           # поля ввода
INPUT_BORDER = "#314555"    # рамка полей
TEXT = "#E7EDF3"            # основной текст
MUTED = "#8D9AA7"           # вторичный текст
SUCCESS = "#2ECF8F"         # успех
WARNING = "#F3C969"         # предупреждение
ERROR = "#F2777A"           # ошибка
INFO = "#65B7FF"            # информация
ACCENT = "#0891B2"          # акцент
ACCENT_DEEP = "#075985"     # глубокий акцент (начало градиента)
ACCENT_HOVER = "#22C7E8"    # акцент hover
ACCENT_SOFT = "#0E2A35"     # мягкая подложка акцента (активные элементы)
SWITCH_TRACK = "#26323D"    # трек выключенного тумблера
SWITCH_ON = "#087B92"       # трек включённого тумблера
SWITCH_BORDER = "#22C7E8"   # рамка включённого тумблера
BTN_BG = "#18232D"          # фон кнопки
BTN_BORDER = "#314555"      # рамка кнопки
BTN_HOVER = "#1E2E3B"       # hover кнопки
DANGER = "#A8403F"          # красная кнопка (удаление)
DANGER_HOVER = "#C0524F"
DANGER_SOFT = "#2E1518"     # мягкая красная подложка

WARNING_BTN = "#9A6B1F"     # оранжевая кнопка
WARNING_BTN_HOVER = "#B87F2B"
FONT = "Segoe UI"
FONT_MONO = "Consolas"

# ---------------------------------------------------------------------------
# Применение к customtkinter
# ---------------------------------------------------------------------------
def apply_theme() -> None:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    t = ctk.ThemeManager.theme

    t["CTkFrame"]["fg_color"] = BG
    t["CTkFrame"]["top_fg_color"] = BG
    t["CTkFrame"]["border_color"] = BORDER

    t["CTkButton"]["fg_color"] = BTN_BG
    t["CTkButton"]["hover_color"] = BTN_HOVER
    t["CTkButton"]["border_color"] = BTN_BORDER
    t["CTkButton"]["border_width"] = 1
    t["CTkButton"]["text_color"] = TEXT
    t["CTkButton"]["text_color_disabled"] = "#5B6673"

    t["CTkLabel"]["text_color"] = TEXT

    t["CTkEntry"]["fg_color"] = INPUT
    t["CTkEntry"]["border_color"] = INPUT_BORDER
    t["CTkEntry"]["text_color"] = TEXT
    t["CTkEntry"]["placeholder_text_color"] = MUTED

    t["CTkTextbox"]["fg_color"] = CARD
    t["CTkTextbox"]["border_color"] = BORDER
    t["CTkTextbox"]["text_color"] = TEXT
    t["CTkTextbox"]["scrollbar_button_color"] = ACCENT
    t["CTkTextbox"]["scrollbar_button_hover_color"] = ACCENT_HOVER

    # Тумблеры (Switch) в стиле ZapretUI: трек 42x22, включён #087B92 + border #22C7E8
    t["CTkSwitch"]["fg_color"] = SWITCH_TRACK
    t["CTkSwitch"]["progress_color"] = SWITCH_ON
    t["CTkSwitch"]["button_color"] = TEXT
    t["CTkSwitch"]["button_hover_color"] = "#FFFFFF"
    t["CTkSwitch"]["text_color"] = TEXT

    t["CTkCheckBox"]["fg_color"] = SWITCH_ON
    t["CTkCheckBox"]["hover_color"] = ACCENT
    t["CTkCheckBox"]["border_color"] = INPUT_BORDER
    t["CTkCheckBox"]["checkmark_color"] = TEXT
    t["CTkCheckBox"]["text_color"] = TEXT

    t["CTkRadioButton"]["fg_color"] = SWITCH_ON
    t["CTkRadioButton"]["hover_color"] = ACCENT
    t["CTkRadioButton"]["border_color"] = INPUT_BORDER
    t["CTkRadioButton"]["text_color"] = TEXT

    t["CTkProgressBar"]["fg_color"] = "#1B2733"
    t["CTkProgressBar"]["progress_color"] = ACCENT
    t["CTkProgressBar"]["border_color"] = BORDER

    t["CTkScrollbar"]["button_color"] = "#26323D"
    t["CTkScrollbar"]["button_hover_color"] = ACCENT

    t["CTkOptionMenu"]["fg_color"] = INPUT
    t["CTkOptionMenu"]["button_color"] = ACCENT
    t["CTkOptionMenu"]["button_hover_color"] = ACCENT_HOVER
    t["CTkOptionMenu"]["text_color"] = TEXT
    t["CTkOptionMenu"]["dropdown_fg_color"] = CARD
    t["CTkOptionMenu"]["dropdown_hover_color"] = CARD_ALT
    t["CTkOptionMenu"]["dropdown_text_color"] = TEXT

    t["CTkComboBox"]["fg_color"] = INPUT
    t["CTkComboBox"]["border_color"] = INPUT_BORDER
    t["CTkComboBox"]["button_color"] = ACCENT
    t["CTkComboBox"]["button_hover_color"] = ACCENT_HOVER
    t["CTkComboBox"]["text_color"] = TEXT
    t["CTkComboBox"]["dropdown_fg_color"] = CARD
    t["CTkComboBox"]["dropdown_hover_color"] = CARD_ALT
    t["CTkComboBox"]["dropdown_text_color"] = TEXT
