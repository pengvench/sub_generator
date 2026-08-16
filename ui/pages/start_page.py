"""Страница «Тестирование» — настройки и запуск (Material, тумблеры ZapretUI).

Компоновка:
  - три карточки СТОЛБИКОМ (одна под другой): «Что тестировать»,
    «Скорость тестирования», «Дополнительно»;
  - каждая карточка скрываемая (заголовок-аккордеон с чекбоксом видимости);
  - внутри карточки пункты располагаются в 2 столбика;
  - если содержимое не помещается — появляется слайдер (прокрутка).
"""
from __future__ import annotations

import customtkinter as ctk

from .. import theme
from ..runner import PipelineOptions
from ..tooltip import CTkToolTip, info_label

HELP = {
    "workers": "Потоков для параллельного тестирования узлов.",
    "timeout": "Таймаут на один узел (сек).",
    "max_ping": "Узлы с пингом выше этого значения отбрасываются (мс).",
    "min_speed": "Минимальная скорость для признания узла рабочим (КБ/с).",
    "limit": "Ограничение количества тестируемых узлов (0 = без лимита).",
    "no_stress": "Отключить нагрузочное (скоростное) тестирование.",
    "plain": "Тестировать только обычные (не TLS) подключения.",
    "dpi": "Проверка обхода DPI-блокировок (через Xray).",
    "siberian": "Проверка на сибирские блокировки.",
    "cidr": "Проверка узлов по CIDR-спискам запрещённых сетей.",
    "zapret": "Проверка обхода блокировок по методу zapret.",
    "telegram": "Проверка Telegram: медиа, MTProto, скорость. Узлы без Telegram отбрасываются.",
    "dpi_active": "Активная DPI-проверка протокола узла (SNI, ClientHello, ECH, TLS 1.2/1.3).",
    "use_cache": "Запустить проверку с сохранённого кеша прошлого прогона "
                 "(data/.runtime_cache): пинг и стресс-тест не повторяются, "
                 "проверки запускаются с выбранного в «Настройках» этапа. "
                 "Если сохранённых конфигов нет — тумблер выключен.",
    "custom_file": "Загрузить конфиги из локального файла (например, сохранённый "
                   "кеш с прошлого прогона). Base64 декодируется, берутся только "
                   "ссылки-конфиги (vless/vmess/trojan/ss/hy2), остальной текст "
                   "игнорируется.",
}






class StartPage(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)
        # Зависимые тумблеры: родитель -> [зависимые]. Когда родитель выключен,
        # зависимые визуально блокируются и принудительно выключаются.
        self._toggle_dependents: dict[ctk.CTkSwitch, list[ctk.CTkSwitch]] = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkLabel(
            self, text="Тестирование",
            font=ctk.CTkFont(size=22, weight="bold"), text_color=theme.TEXT,
        )
        header.grid(row=0, column=0, padx=20, pady=(16, 10), sticky="w")

        # ---------------- Слайдер (прокрутка, если не помещается) ----------------
        self.scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=theme.ACCENT,
            scrollbar_button_hover_color=theme.ACCENT_HOVER,
        )
        self.scroll.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")
        self.scroll.grid_columnconfigure(0, weight=1)

        # ---------------- Три карточки СТОЛБИКОМ ----------------
        self.card_what = self._make_card(self.scroll, 0, "Что тестировать", visible=True)
        self.card_speed = self._make_card(self.scroll, 1, "Скорость тестирования", visible=True)
        self.card_extra = self._make_card(self.scroll, 2, "Дополнительно", visible=True)

        # --- содержимое: «Что тестировать» (2 столбика) ---
        inner_what = self.card_what.inner
        for c in range(2):
            inner_what.grid_columnconfigure(c, weight=1)
        self.toggle_dpi = self._make_toggle(inner_what, 0, 0, "DPI-проверка (обход блокировок)", HELP["dpi"], default=False)
        self.toggle_siberian = self._make_toggle(inner_what, 0, 1, "Siberian (сибирские блокировки)", HELP["siberian"], default=True, enabled_when=self.toggle_dpi)
        self.toggle_cidr = self._make_toggle(inner_what, 1, 0, "CIDR (запрещённые сети)", HELP["cidr"], default=False, enabled_when=self.toggle_dpi)
        self.toggle_zapret = self._make_toggle(inner_what, 1, 1, "Zapret (обход DPI)", HELP["zapret"], default=False)
        self.toggle_telegram = self._make_toggle(inner_what, 2, 0, "Telegram (загрузка/выгрузка)", HELP["telegram"], default=True)
        self.toggle_dpi_active = self._make_toggle(inner_what, 2, 1, "DPI-актив (SNI/ECH/TLS)", HELP["dpi_active"], default=False)


        # --- содержимое: «Скорость тестирования» (2 столбика) ---
        inner_speed = self.card_speed.inner
        for c in range(2):
            inner_speed.grid_columnconfigure(c, weight=1)
        self.min_speed = self._make_entry(inner_speed, 0, 0, "Мин. скорость (КБ/с)", "5000", help=HELP["min_speed"])
        self.max_ping = self._make_entry(inner_speed, 0, 1, "Макс. пинг (мс)", "1500", help=HELP["max_ping"])
        self.timeout = self._make_entry(inner_speed, 1, 0, "Таймаут (сек)", "15", help=HELP["timeout"])
        self.workers = self._make_entry(inner_speed, 1, 1, "Потоков", "32", help=HELP["workers"])

        # --- содержимое: «Дополнительно» (2 столбика) ---
        inner_extra = self.card_extra.inner
        for c in range(2):
            inner_extra.grid_columnconfigure(c, weight=1)
        self.toggle_no_stress = self._make_toggle(inner_extra, 0, 0, "Без нагрузочного теста", HELP["no_stress"], default=False)
        self.toggle_plain = self._make_toggle(inner_extra, 0, 1, "Только обычные подключения", HELP["plain"], default=False)
        self.toggle_use_cache = self._make_toggle(inner_extra, 1, 0, "С сохранённого кеша", HELP["use_cache"], default=False)
        self.toggle_custom_file = self._make_toggle(inner_extra, 1, 1, "Свой файл конфигов", HELP["custom_file"], default=False)
        self.limit = self._make_entry(inner_extra, 2, 0, "Лимит узлов (0 = без лимита)", "0", help=HELP["limit"])

        # Строка выбора файла (столбец 2, строка 2): label + entry + «Обзор…» + «✕».
        # Entry доступен только при включённом toggle_custom_file.
        frame_custom = ctk.CTkFrame(inner_extra, fg_color="transparent")
        frame_custom.grid(row=2, column=1, padx=6, pady=4, sticky="ew")
        frame_custom.grid_columnconfigure(0, weight=1)

        self.custom_file_entry = ctk.CTkEntry(frame_custom, width=110, justify="left", placeholder_text="путь к файлу")
        self.custom_file_entry.grid(row=0, column=0, padx=(0, 4), sticky="ew")

        self.btn_custom_browse = ctk.CTkButton(
            frame_custom, text="Обзор…", width=70, height=26,
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, text_color="#0C1014",
            font=ctk.CTkFont(size=11),
            command=self._browse_custom_file,
        )
        self.btn_custom_browse.grid(row=0, column=1, padx=(0, 4))

        self.btn_custom_clear = ctk.CTkButton(
            frame_custom, text="✕", width=28, height=26,
            fg_color="transparent", hover_color=theme.BORDER, text_color=theme.MUTED,
            font=ctk.CTkFont(size=12),
            command=self._clear_custom_file,
        )
        self.btn_custom_clear.grid(row=0, column=2)

        self.toggle_custom_file.configure(
            command=lambda _=None: self._sync_custom_file_controls()
        )
        self._sync_custom_file_controls()



        # ---------------- Кнопка запуска ----------------
        self.btn_run = ctk.CTkButton(
            self.scroll,
            text="▶ Запустить тестирование",
            height=44,
            corner_radius=8,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color="#0C1014",
            command=self.app.on_start_clicked,
        )
        self.btn_run.grid(row=3, column=0, padx=12, pady=(8, 14), sticky="ew")
        CTkToolTip(self.btn_run, "Запустить сборку и проверку конфигов из всех подписок.")

    # ------------------------------------------------------------ helpers
    def _make_card(self, parent, row, title, *, visible) -> ctk.CTkFrame:
        """Карточка-аккордеон: заголовок с чекбоксом «скрыть/показать» + содержимое."""
        card = ctk.CTkFrame(
            parent, fg_color=theme.CARD, corner_radius=10,
            border_width=1, border_color=theme.BORDER,
        )
        card.grid(row=row, column=0, padx=8, pady=6, sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        # Заголовок
        head = ctk.CTkFrame(card, fg_color="transparent")
        head.grid(row=0, column=0, padx=10, pady=(8, 2), sticky="ew")
        head.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            head, text=title,
            font=ctk.CTkFont(size=14, weight="bold"), text_color=theme.TEXT,
        )
        header.grid(row=0, column=0, sticky="w")

        chk = ctk.CTkCheckBox(
            head, text="скрыть", width=80,
            text_color=theme.MUTED, font=ctk.CTkFont(size=11),
        )
        chk.grid(row=0, column=1, sticky="e")
        CTkToolTip(chk, "Показывать или скрывать блок. Скрытые блоки экономят место.")

        # Контейнер содержимого (2 столбика)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.grid(row=1, column=0, padx=6, pady=(2, 8), sticky="ew")

        if not visible:
            chk.select()
            inner.grid_remove()

        def _toggle():
            if chk.get():
                inner.grid_remove()
            else:
                inner.grid()
        chk.configure(command=_toggle)

        card.inner = inner  # type: ignore[attr-defined]
        return card

    def _make_toggle(self, parent, row, col, label, help_text, *, default, enabled_when=None):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=row, column=col, padx=6, pady=4, sticky="ew")
        frame.grid_columnconfigure(0, weight=1)

        text_label = ctk.CTkLabel(frame, text=label, anchor="w", text_color=theme.TEXT)
        text_label.grid(row=0, column=0, sticky="w")

        info = info_label(frame, help_text)
        info.grid(row=0, column=1, padx=(4, 0), sticky="w")

        switch = ctk.CTkSwitch(frame, text="", width=42)
        switch.grid(row=0, column=2, padx=(10, 0), sticky="e")
        if default:
            switch.select()
        CTkToolTip(switch, help_text)

        if enabled_when is not None:
            self._toggle_dependents.setdefault(enabled_when, []).append(switch)
            # Команду синхронизации на родителя вешаем только один раз,
            # чтобы не затирать её при регистрации нескольких зависимых.
            if not getattr(enabled_when, "_subgen_deps_synced", False):
                enabled_when._subgen_deps_synced = True
                enabled_when.configure(command=lambda _=None: self._sync_toggle_dependents(enabled_when))
            switch.configure(command=lambda _=None: self._sync_toggle_dependents(enabled_when))
            self._sync_toggle_dependents(enabled_when)

        return switch

    def _sync_toggle_dependents(self, parent_switch) -> None:
        """Синхронизировать зависимые тумблеры с состоянием родителя.

        Если родительский тумблер выключен — зависимые блокируются
        (state="disabled") и принудительно выключаются. Это делает зависимость
        наглядной: тумблер нельзя «включить впустую», он визуально недоступен.
        """
        for dep in self._toggle_dependents.get(parent_switch, ()):
            if parent_switch.get():
                dep.configure(state="normal")
            else:
                dep.configure(state="disabled")
                if dep.get():
                    dep.deselect()

    def _make_entry(self, parent, row, col, label, default, *, help=""):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=row, column=col, padx=6, pady=4, sticky="ew")
        frame.grid_columnconfigure(0, weight=1)

        text_label = ctk.CTkLabel(frame, text=label, anchor="w", text_color=theme.TEXT)
        text_label.grid(row=0, column=0, sticky="w")

        info = info_label(frame, help)
        info.grid(row=0, column=1, padx=(4, 0), sticky="w")

        entry = ctk.CTkEntry(frame, width=110, justify="right")
        entry.grid(row=0, column=2, padx=(10, 0), sticky="e")
        entry.insert(0, default)
        return entry

    # ------------------------------------------------------------ custom file
    def _browse_custom_file(self) -> None:
        """Открыть диалог выбора файла с конфигами и подставить путь в entry."""
        from tkinter import filedialog


        path = filedialog.askopenfilename(
            title="Выберите файл с конфигами",
            filetypes=[
                ("Все файлы", "*.*"),
                ("Текстовые файлы", "*.txt"),
                ("Подписки", "*.txt;*.conf;*.list"),
            ],
        )
        if path:
            self.custom_file_entry.delete(0, "end")
            self.custom_file_entry.insert(0, path)

    def _clear_custom_file(self) -> None:
        """Очистить путь к файлу и выключить тумблер."""
        self.custom_file_entry.delete(0, "end")
        if self.toggle_custom_file.get():
            self.toggle_custom_file.deselect()
        self._sync_custom_file_controls()

    def _sync_custom_file_controls(self) -> None:
        """Включать/блокировать элементы выбора файла по состоянию тумблера."""
        enabled = bool(self.toggle_custom_file.get())
        state = "normal" if enabled else "disabled"
        self.custom_file_entry.configure(state=state)
        self.btn_custom_browse.configure(state=state)
        self.btn_custom_clear.configure(state=state)

    # ------------------------------------------------------------ options
    @staticmethod
    def _int_value(entry, default: int) -> int:
        try:
            return int(entry.get().strip())
        except (ValueError, AttributeError):
            return default

    @staticmethod
    def _float_value(entry, default: float) -> float:
        try:
            return float(entry.get().strip())
        except (ValueError, AttributeError):
            return default

    def get_options(self) -> PipelineOptions:
        dpi_check = bool(self.toggle_dpi.get())
        # Страховка: siberian/cidr учитываются только при включённой DPI-проверке
        # (тумблеры физически заблокированы, но защищаемся от программных select).
        custom_file = ""
        if self.toggle_custom_file.get():
            custom_file = self.custom_file_entry.get().strip()
        return PipelineOptions(
            workers=self._int_value(self.workers, 32),
            timeout=self._float_value(self.timeout, 15.0),
            limit=self._int_value(self.limit, 0),
            max_ping=self._int_value(self.max_ping, 1500),
            min_speed=self._int_value(self.min_speed, 3000),
            no_stress=self.toggle_no_stress.get(),
            plain=self.toggle_plain.get(),
            telegram_check=self.toggle_telegram.get(),
            dpi_check=dpi_check,
            dpi_siberian=bool(self.toggle_siberian.get()) if dpi_check else False,
            dpi_cidr=bool(self.toggle_cidr.get()) if dpi_check else False,
            zapret_check=self.toggle_zapret.get(),
            dpi_active=bool(self.toggle_dpi_active.get()),
            use_cache=bool(self.toggle_use_cache.get()),
            custom_file=custom_file,
        )


    def refresh_cache_toggle(self) -> None:
        """Включить/выключить тумблер запуска с сохранённого кеша.

        Если сохранённых рабочих конфигов (data/.runtime_cache/xray_working.json)
        нет — тумблер выключается и блокируется. После полного прогона кеш
        появляется, и тумблер становится доступен.
        """
        import json as _json

        available = False
        path = self.app.data_dir / ".runtime_cache" / "xray_working.json"
        try:
            if path.exists():
                data = _json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    available = any(row.get("fully_checked") for row in data)
        except Exception:
            available = False
        self.toggle_use_cache.configure(state="normal" if available else "disabled")
        if not available and self.toggle_use_cache.get():
            self.toggle_use_cache.deselect()

    def set_running(self, running: bool) -> None:
        self.btn_run.configure(state="disabled" if running else "normal")

