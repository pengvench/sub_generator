"""Страница «Настройки» — вкладки как в браузере (v17).

Запрос юзера 2026-09-20: «таким же образом давай в "настройки" добавим
"Диагностику" и "Журнал"». Три бывших пункта сайдбара стали вкладками:

  * «Основные»    — описание/префикс итоговой подписки (прежняя страница);
  * «Диагностика» — пошаговая проверка сети (DiagPage);
  * «Журнал»      — статистика по подпискам + лог выполнения (LogPage).

Сама страница настроек (SettingsPage) не изменилась — она лишь встроена во
вкладку; app.page_settings / page_diag / page_log по-прежнему указывают на
дочерние страницы, весь существующий код (append_log, set_stats, set_busy)
работает без правок.
"""
from __future__ import annotations

import customtkinter as ctk

from .. import theme
from ..tooltip import CTkToolTip, info_label
from subgen.settings import load_settings, save_settings

# Внутренний ключ вкладки -> заголовок.
_TAB_TITLES = {
    "basic": "Основные",
    "diag": "Диагностика",
    "log": "Журнал",
}
_TAB_ORDER = ["basic", "diag", "log"]


class SettingsRootPage(ctk.CTkFrame):
    """«Настройки»: вкладки Основные / Диагностика / Журнал (как в браузере)."""

    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkLabel(
            self, text="Настройки",
            font=ctk.CTkFont(size=22, weight="bold"), text_color=theme.TEXT,
        )
        header.grid(row=0, column=0, padx=20, pady=(16, 4), sticky="w")

        self.tabview = ctk.CTkTabview(
            self,
            fg_color=theme.CARD,
            segmented_button_selected_color=theme.ACCENT,
            segmented_button_selected_hover_color=theme.ACCENT_HOVER,
            segmented_button_unselected_color=theme.BG_ALT,
            segmented_button_unselected_hover_color=theme.CARD_ALT,
            text_color=theme.TEXT,
        )
        # Шрифт ярлыков вкладок — через configure: аргумент конструктора
        # segmented_button_font есть только в customtkinter 6.x, а configure
        # работает и в 5.2.2, и в 6.x.
        try:
            self.tabview._segmented_button.configure(font=ctk.CTkFont(size=13))
        except Exception:
            pass
        self.tabview.grid(row=1, column=0, padx=16, pady=(0, 12), sticky="nsew")

        # Дочерние страницы (создаются ПОСЛЕ tabview, чтобы исключить
        # циклические импорты: diag/log импортируем лениво).
        self.basic_tab = None
        self.diag_tab = None
        self.log_tab = None

        from .diag_page import DiagPage
        from .log_page import LogPage

        for key in _TAB_ORDER:
            title = _TAB_TITLES[key]
            frame = self.tabview.add(title)
            frame.grid_columnconfigure(0, weight=1)
            frame.grid_rowconfigure(0, weight=1)
            if key == "basic":
                self.basic_tab = SettingsPage(frame, app)
                self.basic_tab.grid(row=0, column=0, sticky="nsew")
            elif key == "diag":
                self.diag_tab = DiagPage(frame, app)
                self.diag_tab.grid(row=0, column=0, sticky="nsew")
            elif key == "log":
                self.log_tab = LogPage(frame, app)
                self.log_tab.grid(row=0, column=0, sticky="nsew")

        self.tabview.set("Основные")

    # ------------------------------------------------------------ API

    def show_tab(self, key: str) -> None:
        """Показать вкладку по внутреннему ключу (basic/diag/log)."""
        title = _TAB_TITLES.get(key)
        if title:
            try:
                self.tabview.set(title)
            except Exception:
                pass

    def set_busy(self, busy: bool) -> None:
        """Блокировка на время прогона — во все вкладки."""
        for page in (self.basic_tab, self.diag_tab, self.log_tab):
            setter = getattr(page, "set_busy", None)
            if setter is not None:
                try:
                    setter(busy)
                except Exception:
                    pass


class SettingsPage(ctk.CTkFrame):
    """Вкладка «Основные» — описание/префикс итоговой подписки.

    Контент маленький (одна карточка + кнопка), поэтому никакого
    CTkScrollableFrame: скроллбар на пустом месте только мешал
    (жалоба юзера 2026-09-20: «маленький блок обрезается и скрол —
    че пара строчек не помещается?»).
    """

    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)

        self.grid_columnconfigure(0, weight=1)

        # ---------------- Карточка: описание и префикс ----------------
        card_desc = self._make_card(self, 0, "Описание и префикс конфигов")
        inner = card_desc.inner
        inner.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(
            inner, text="Префикс (первая строка подписки)",
            anchor="w", text_color=theme.TEXT,
        )
        lbl.grid(row=0, column=0, padx=6, pady=(6, 0), sticky="w")
        info = info_label(inner, "Строка, добавляемая в начало подписки перед описанием. "
                                  "Автоматически комментируется '#', чтобы не ломать парсеры happ/Hiddify.")
        info.grid(row=0, column=1, padx=(4, 0), pady=(6, 0), sticky="w")

        self.entry_prefix = ctk.CTkEntry(inner, height=34)
        self.entry_prefix.grid(row=1, column=0, columnspan=2, padx=6, pady=(4, 8), sticky="ew")

        lbl2 = ctk.CTkLabel(
            inner, text="Описание (вторая строка подписки)",
            anchor="w", text_color=theme.TEXT,
        )
        lbl2.grid(row=2, column=0, padx=6, pady=(6, 0), sticky="w")
        info2 = info_label(inner, "Описание, добавляемое в подписку после префикса. "
                                  "Используйте '#', чтобы клиент игнорировал строку.")
        info2.grid(row=2, column=1, padx=(4, 0), pady=(6, 0), sticky="w")

        self.text_desc = ctk.CTkTextbox(inner, height=70, wrap="word")
        self.text_desc.grid(row=3, column=0, columnspan=2, padx=6, pady=(4, 8), sticky="ew")

        # ---------------- Кнопка сохранения ----------------
        self.btn_save = ctk.CTkButton(
            self,
            text="💾 Сохранить настройки",
            height=44,
            corner_radius=8,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color="#0C1014",
            command=self._save,
        )
        self.btn_save.grid(row=1, column=0, padx=12, pady=(8, 6), sticky="ew")
        CTkToolTip(self.btn_save, "Сохранить.")

        self.lbl_saved = ctk.CTkLabel(
            self, text="", text_color=theme.SUCCESS,
            font=ctk.CTkFont(size=12),
        )
        self.lbl_saved.grid(row=2, column=0, padx=12, pady=(0, 6), sticky="w")

        self._load()

    # ------------------------------------------------------------ helpers

    def _make_card(self, parent, row, title) -> ctk.CTkFrame:
        card = ctk.CTkFrame(
            parent, fg_color=theme.CARD, corner_radius=10,
            border_width=1, border_color=theme.BORDER,
        )
        card.grid(row=row, column=0, padx=8, pady=6, sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            card, text=title,
            font=ctk.CTkFont(size=14, weight="bold"), text_color=theme.TEXT,
        )
        header.grid(row=0, column=0, padx=10, pady=(8, 2), sticky="w")

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.grid(row=1, column=0, padx=6, pady=(2, 8), sticky="ew")

        card.inner = inner  # type: ignore[attr-defined]
        return card

    def _load(self) -> None:
        settings = load_settings()
        self.entry_prefix.delete(0, "end")
        self.entry_prefix.insert(0, str(settings.get("prefix", "")))
        self.text_desc.delete("1.0", "end")
        desc = settings.get("description", "")
        self.text_desc.insert("1.0", str(desc))

    def _save(self) -> None:
        settings = load_settings()
        settings["prefix"] = self.entry_prefix.get().strip()
        settings["description"] = self.text_desc.get("1.0", "end").strip()
        save_settings(settings)
        self.lbl_saved.configure(text="✓ Настройки сохранены.")
        self.app.show_status("Настройки сохранены.")

    # ------------------------------------------------------------ API
    def set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.btn_save.configure(state=state)
