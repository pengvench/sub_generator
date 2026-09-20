"""Страница «Мои подписки» — вкладки как в браузере (v17).

Запрос юзера 2026-09-20: «объединим пункты "Мои подписки" и "Импорт", а так
же "Фильтры" — сделай там вкладки как в браузере». Три бывших пункта
сайдбара стали тремя вкладками одной страницы:

  * «Список»   — SourcesPage (управление sources.txt, отсев мёртвых);
  * «Импорт»   — ImportPage (вставка конфигов / URL / файл, saved_subs);
  * «Фильтры»  — FiltersPage (параметры конфигов, РФ-слепок).

Вкладки — CTkTabview (сегмент сверху, как вкладки браузера). Сами страницы
не тронуты: они лишь встроены во вкладки и по-прежнему живут как
app.page_sources / app.page_import / app.page_filters — весь существующий
код (get_sources, save_current_settings, set_busy) работает как раньше.
"""
from __future__ import annotations

import customtkinter as ctk

from .. import theme
from .sources_page import SourcesPage
from .import_page import ImportPage
from .filters_page import FiltersPage

# Отображение внутренних ключей (используются show_tab/_show_page) на
# заголовки вкладок.
_TAB_TITLES = {
    "sources": "Список",
    "import": "Импорт",
    "filters": "Фильтры",
}
_TAB_ORDER = ["sources", "import", "filters"]


class MySubsPage(ctk.CTkFrame):
    """«Мои подписки»: вкладки Список / Импорт / Фильтры (как в браузере)."""

    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ---------------- Шапка ----------------
        header = ctk.CTkLabel(
            self, text="Мои подписки",
            font=ctk.CTkFont(size=22, weight="bold"), text_color=theme.TEXT,
        )
        header.grid(row=0, column=0, padx=20, pady=(16, 4), sticky="w")

        # ---------------- Вкладки (как в браузере) ----------------
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

        # Дочерние страницы живут ВНУТРИ вкладок (мастер — фрейм вкладки).
        # app.page_sources / page_import / page_filters указывают на них —
        # весь существующий код продолжает работать без правок.
        self.list_tab = None
        self.import_tab = None
        self.filters_tab = None

        for key in _TAB_ORDER:
            title = _TAB_TITLES[key]
            frame = self.tabview.add(title)
            frame.grid_columnconfigure(0, weight=1)
            frame.grid_rowconfigure(0, weight=1)
            if key == "sources":
                self.list_tab = SourcesPage(frame, app)
                self.list_tab.grid(row=0, column=0, sticky="nsew")
            elif key == "import":
                self.import_tab = ImportPage(frame, app)
                self.import_tab.grid(row=0, column=0, sticky="nsew")
            elif key == "filters":
                self.filters_tab = FiltersPage(frame, app)
                self.filters_tab.grid(row=0, column=0, sticky="nsew")

        # Первая вкладка — «Список».
        self.tabview.set("Список")

    # ------------------------------------------------------------ API

    def show_tab(self, key: str) -> None:
        """Показать вкладку по внутреннему ключу (sources/import/filters)."""
        title = _TAB_TITLES.get(key)
        if title:
            try:
                self.tabview.set(title)
            except Exception:
                pass

    def current_tab(self) -> str:
        """Внутренний ключ активной вкладки."""
        title = self.tabview.get()
        for key, t in _TAB_TITLES.items():
            if t == title:
                return key
        return "sources"

    def set_busy(self, busy: bool) -> None:
        """Блокировка на время прогона — во все вкладки."""
        for page in (self.list_tab, self.import_tab, self.filters_tab):
            setter = getattr(page, "set_busy", None)
            if setter is not None:
                try:
                    setter(busy)
                except Exception:
                    pass

    def on_shown(self) -> None:
        """Обновить счётчики при показе страницы (например, список файлов импорта)."""
        refresher = getattr(self.import_tab, "_refresh_saved_list", None)
        if refresher is not None:
            try:
                refresher()
            except Exception:
                pass
