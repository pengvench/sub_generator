"""Страница «Тестирование» — настройки и запуск (Material, тумблеры ZapretUI).

v16: ДВА РЕЖИМА (запрос юзера 2026-09-20: «сделаем интерфейс юзер-френдли,
прям как для младенца — интуитивно понятный»):
  * «Просто» (новичок, по умолчанию): 3 понятных шага — откуда брать VPN,
    что проверить и насколько строгий отбор + большая кнопка запуска.
    Все технические параметры (потоки, таймауты, пулы, дедупликация)
    скрыты и выставляются автоматически по пресету строгости.
  * «Тонкая настройка» (эксперт): прежние три карточки со всеми параметрами.

Режим сохраняется в settings.json (ui_mode) и переживает перезапуск.
Экспертная компоновка (как раньше):
  - три карточки СТОЛБИКОМ (одна под другой): «Что тестировать»,
    «Скорость тестирования», «Дополнительно»;
  - каждая карточка скрываемая (заголовок-аккордеон с чекбоксом видимости);
  - внутри карточки пункты располагаются в 2 столбика;
  - если содержимое не помещается — появляется слайдер (прокрутка).

Настройки (workers, timeout, max_ping, min_speed, limit и тумблеры)
сохраняются в data/settings.json и восстанавливаются при следующем
запуске. Тумблер «С сохранённого кеша» удалён — он дублировал отдельную
страницу «Перепроверка» в сайдбаре.
"""
from __future__ import annotations

import logging

import customtkinter as ctk

from .. import theme
from ..runner import PipelineOptions
from ..tooltip import CTkToolTip, info_label
from subgen.settings import get_test_options, save_test_options

_logger = logging.getLogger(__name__)

HELP = {
    "workers": "Параллельных потоков. 32 — норма.",
    "timeout": "Таймаут на узел, сек.",
    "max_ping": "Отбраковка по пингу, мс. 0 = без лимита.",
    "min_speed": "Мин. скорость, КБ/с. Адаптируется под канал.",
    "limit": "Лимит узлов. 0 = без лимита.",
    "no_stress": "Пропустить финальный спидтест.",
    "sing_box_only": "Все узлы через sing-box (вместо xray).",
    "dpi": "Проверка обхода DPI-блокировок провайдера.",
    "siberian": "Строгий DPI-профиль для сибирских сетей.",
    "cidr": "Сверка с реестром заблокированных сетей (CIDR).",
    "services": "Проверка доступа к Instagram / YouTube / Discord.",
    "telegram": "Telegram (MTProto + медиа). Узлы без ТГ отбраковываются.",
    "dpi_active": "Глубокая проверка устойчивости к DPI (SNI/ECH/TLS-фаззинг, медленнее).",
    "custom_file": "Загрузить конфиги из локального файла.",
    "dedup_mode": "Убирать дубликаты конфигов: strict — все параметры; normal — без uTLS-фингерпринтов; aggressive — только сервер+порт+SNI.",
    "use_singbox_pool": "Групповой тест: одно ядро на пачку узлов — в разы быстрее, чем старт ядра на каждый узел.",
    "singbox_pool_batch": "Узлов на один процесс ядра.",
    "pool_engine": (
        "Ядро группового теста. xray — то же ядро, что в клиентах (Happ/v2rayN), "
        "поддержка xhttp/kcp/quic. sing-box — прежний вариант (эти транспорты "
        "проверяются по одному узлу)."
    ),
    "resilience_check": "Стабильность соединения (серия TCP/DoH/UDP-проб).",
}

# v16: пресеты строгости для режима «Просто» — человеческие слова вместо
# чисел. Пресет записывается в скрытые экспертные поля, поэтому при
# переключении в «Тонкую настройку» юзер видит те же значения.
PRESETS = {
    "Мягкий": {"max_ping": 3000, "min_speed": 300, "dpi_active": False},
    "Обычный": {"max_ping": 2000, "min_speed": 500, "dpi_active": False},
    "Строгий": {"max_ping": 1500, "min_speed": 1500, "dpi_active": True},
}
PRESET_ORDER = ["Мягкий", "Обычный", "Строгий"]


class StartPage(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)
        # Зависимые тумблеры: родитель -> [зависимые]. Когда родитель выключен,
        # зависимые визуально блокируются и принудительно выключаются.
        self._toggle_dependents: dict[ctk.CTkSwitch, list[ctk.CTkSwitch]] = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)  # и экспертный скролл, и новичок

        # ---------------- Шапка + переключатель режима ----------------
        header_row = ctk.CTkFrame(self, fg_color="transparent")
        header_row.grid(row=0, column=0, padx=20, pady=(16, 6), sticky="ew")
        header_row.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            header_row, text="Тестирование",
            font=ctk.CTkFont(size=22, weight="bold"), text_color=theme.TEXT,
        )
        header.grid(row=0, column=0, sticky="w")

        # v16: «Просто» / «Тонкая настройка» — режим интерфейса.
        # (Сегмент-кнопка не поддерживает bind -> тултип на фрейме-обёртке.)
        self.ui_mode_var = ctk.StringVar(value="novice")
        mode_holder = ctk.CTkFrame(header_row, fg_color="transparent")
        mode_holder.grid(row=0, column=1, padx=(0, 4), sticky="e")
        self.mode_switch = ctk.CTkSegmentedButton(
            mode_holder,
            values=["Просто", "Тонкая настройка"],
            variable=self.ui_mode_var,
            command=self._on_mode_changed,
            selected_color=theme.ACCENT,
            selected_hover_color=theme.ACCENT_HOVER,
            font=ctk.CTkFont(size=12),
        )
        self.mode_switch.grid(row=0, column=0, sticky="e")
        CTkToolTip(
            mode_holder,
            "«Просто» — минимум настроек, всё по умолчанию разумно. "
            "«Тонкая настройка» — все параметры (потоки, таймауты, пулы).",
        )

        sub_hint = ctk.CTkLabel(
            self,
            text="Нажмите «Запустить проверку» — остальное сделается само.",
            text_color=theme.MUTED, font=ctk.CTkFont(size=11),
        )
        sub_hint.grid(row=1, column=0, padx=20, pady=(0, 0), sticky="w")

        # ---------------- Режим «Просто» (новичок) ----------------
        # Скроллируемый: если на машине юзера шрифты шире (иные метрики/DPI) —
        # контент прокручивается, а не обрезается. Когда всё влезает —
        # скроллбара нет. Фрейм создаётся здесь (порядок в grid), наполняется
        # ПОСЛЕ экспертных виджетов — пресеты пишут в max_ping/min_speed/dpi_active.
        self.novice = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=theme.ACCENT,
            scrollbar_button_hover_color=theme.ACCENT_HOVER,
        )
        self.novice.grid(row=2, column=0, padx=8, pady=(0, 8), sticky="nsew")
        self.novice.grid_columnconfigure(0, weight=1)

        # ---------------- Слайдер (эксперт: прокрутка, если не помещается) ----------------
        self.scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=theme.ACCENT,
            scrollbar_button_hover_color=theme.ACCENT_HOVER,
        )
        self.scroll.grid(row=2, column=0, padx=8, pady=(0, 8), sticky="nsew")
        self.scroll.grid_columnconfigure(0, weight=1)

        # ---------------- Три карточки СТОЛБИКОМ ----------------
        self.card_what = self._make_card(self.scroll, 0, "Что тестировать", visible=True)
        self.card_speed = self._make_card(self.scroll, 1, "Скорость тестирования", visible=True)
        self.card_extra = self._make_card(self.scroll, 2, "Дополнительно", visible=True)

        # --- содержимое: «Что тестировать» (2 столбика, БЕЗ дыр: 3+3+подсказка) ---
        inner_what = self.card_what.inner
        for c in range(2):
            inner_what.grid_columnconfigure(c, weight=1)
        # Колонка 0: DPI-проверка и её зависимые. Колонка 1: независимые проверки.
        # Раньше было 4+2: последний ряд справа пустовал («дыра» в интерфейсе).
        self.toggle_dpi = self._make_toggle(inner_what, 0, 0, "Обход блокировок (DPI)", HELP["dpi"], default=False)
        self.toggle_dpi_active = self._make_toggle(inner_what, 0, 1, "Глубокая проверка DPI (медленнее)", HELP["dpi_active"], default=False)
        self.toggle_siberian = self._make_toggle(inner_what, 1, 0, "Siberian (строгий DPI-профиль)", HELP["siberian"], default=True, enabled_when=self.toggle_dpi)
        self.toggle_cidr = self._make_toggle(inner_what, 1, 1, "Реестр блокировок (CIDR)", HELP["cidr"], default=False, enabled_when=self.toggle_dpi)
        self.toggle_telegram = self._make_toggle(inner_what, 2, 0, "Telegram (медиа и звонки)", HELP["telegram"], default=True)
        self.toggle_services = self._make_toggle(inner_what, 2, 1, "YouTube / Instagram / Discord", HELP["services"], default=True)
        self.toggle_services2 = None
        # v17 (запрос юзера): «пункт Resilience стабильность можно поднять к
        # "Что тестировать"» — перенесён из карточки «Дополнительно». Ряд
        # 3, колонка 0. Приписка-ссылка на вкладку «Фильтры» из карточки
        # убрана совсем (запрос юзера — не загромождать главный экран).
        self.toggle_resilience_check = self._make_toggle(
            inner_what, 3, 0,
            "Стабильность соединения",
            HELP["resilience_check"], default=True,
        )


        # --- содержимое: «Скорость тестирования» (2 столбика) ---
        inner_speed = self.card_speed.inner
        for c in range(2):
            inner_speed.grid_columnconfigure(c, weight=1)
        self.min_speed = self._make_entry(inner_speed, 0, 0, "Мин. скорость (КБ/с)", "5000", help=HELP["min_speed"])
        self.max_ping = self._make_entry(inner_speed, 0, 1, "Макс. пинг (мс)", "1500", help=HELP["max_ping"])
        self.timeout = self._make_entry(inner_speed, 1, 0, "Таймаут на узел (сек)", "15", help=HELP["timeout"])
        self.workers = self._make_entry(inner_speed, 1, 1, "Потоков (параллельно)", "32", help=HELP["workers"])

        # --- содержимое: «Дополнительно» (2 столбика) ---
        inner_extra = self.card_extra.inner
        for c in range(2):
            inner_extra.grid_columnconfigure(c, weight=1)
        # Row 0: Без стресс-теста | Свой файл конфигов
        self.toggle_no_stress = self._make_toggle(inner_extra, 0, 0, "Без финального спидтеста", HELP["no_stress"], default=False)
        self.toggle_custom_file = self._make_toggle(inner_extra, 0, 1, "Свой файл конфигов", HELP["custom_file"], default=False)
        # Row 1: Лимит узлов | Выбор файла (поле пути — под тумблером
        # «Свой файл конфигов», в правой колонке: пустых ячеек нет)
        self.limit = self._make_entry(inner_extra, 1, 0, "Лимит узлов (0 = без лимита)", "0", help=HELP["limit"])
        frame_custom = ctk.CTkFrame(inner_extra, fg_color="transparent")
        frame_custom.grid(row=1, column=1, padx=6, pady=4, sticky="ew")
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
        # Синхронизация состояния custom_file: включение тумблера активирует
        # поле пути и кнопки (строка была случайно потеряна при вычистке TUN —
        # из-за этого поля файла навсегда оставались заблокированными).
        self.toggle_custom_file.configure(command=lambda _=None: self._sync_custom_file_controls())
        self._sync_custom_file_controls()
        # Row 2: Групповой тест | Только sing-box (пары без пустых ячеек).
        # v17: resilience перенесён в карточку «Что тестировать».
        self.toggle_sing_box_only = self._make_toggle(inner_extra, 2, 0, "Только sing-box", HELP["sing_box_only"], default=False)
        self.toggle_use_singbox_pool = self._make_toggle(
            inner_extra, 2, 1,
            "Групповой тест (пачкой узлов)",
            HELP["use_singbox_pool"], default=True,
        )
        # Row 3: Узлов в группе | Ядро группового теста.
        self.singbox_pool_batch = self._make_entry(
            inner_extra, 3, 0,
            "Узлов в группе",
            "200", help=HELP["singbox_pool_batch"],
        )
        engine_frame = ctk.CTkFrame(inner_extra, fg_color="transparent")
        engine_frame.grid(row=3, column=1, padx=6, pady=4, sticky="ew")
        engine_frame.grid_columnconfigure(1, weight=1)
        engine_label = ctk.CTkLabel(
            engine_frame, text="Ядро группового теста:",
            font=ctk.CTkFont(size=12), text_color=theme.MUTED, anchor="w",
        )
        engine_label.grid(row=0, column=0, padx=(0, 6), sticky="w")
        self.pool_engine_var = ctk.StringVar(value="xray")
        self.pool_engine_menu = ctk.CTkOptionMenu(
            engine_frame,
            values=["xray", "singbox"],
            variable=self.pool_engine_var,
            width=110, height=26,
            fg_color=theme.CARD, button_color=theme.ACCENT,
            button_hover_color=theme.ACCENT_HOVER,
            text_color=theme.TEXT,
            font=ctk.CTkFont(size=11),
        )
        self.pool_engine_menu.grid(row=0, column=1, sticky="e")
        CTkToolTip(self.pool_engine_menu, HELP["pool_engine"])
        CTkToolTip(engine_label, HELP["pool_engine"])
        # v17 (запрос юзера: «убрать дубликаты — у тебя щас вообще на два
        # столбца — это ужас»): дедупликация живёт в ОДНОЙ ячейке (колонка 0),
        # НЕ растягиваясь на оба столбца. Ширина фиксирована, метка прижата
        # влево — как обычный пункт карточки.
        import customtkinter as _ctk
        dedup_frame = _ctk.CTkFrame(inner_extra, fg_color="transparent")
        dedup_frame.grid(row=4, column=0, padx=6, pady=4, sticky="w")
        dedup_label = _ctk.CTkLabel(
            dedup_frame, text="Убирать дубликаты:",
            font=_ctk.CTkFont(size=12), text_color=theme.MUTED,
            anchor="w",
        )
        dedup_label.grid(row=0, column=0, padx=(0, 6), sticky="w")
        self.dedup_mode_var = _ctk.StringVar(value="normal")
        self.dedup_mode_menu = _ctk.CTkOptionMenu(
            dedup_frame,
            values=["strict", "normal", "aggressive"],
            variable=self.dedup_mode_var,
            width=120, height=26,
            fg_color=theme.CARD, button_color=theme.ACCENT,
            button_hover_color=theme.ACCENT_HOVER,
            text_color=theme.TEXT,
            font=_ctk.CTkFont(size=11),
        )
        self.dedup_mode_menu.grid(row=0, column=1, sticky="w")
        CTkToolTip(self.dedup_mode_menu, HELP["dedup_mode"])



        # ---------------- Кнопка запуска (эксперт) ----------------
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
        CTkToolTip(self.btn_run, "Запуск тестирования.")

        # v16: сначала строим простой интерфейс (тумблеры/пресет нужны
        # _restore_settings), потом восстанавливаем настройки и режим.
        self._build_novice_ui()
        self._restore_settings()
        self._apply_saved_ui_mode()

    # ------------------------------------------------------------ режим «Просто»
    def _build_novice_ui(self) -> None:
        """Максимально простая раскладка: 3 шага + кнопка запуска.

        Каждый шаг — отдельная карточка с крупным заголовком и человеческим
        описанием. Технические термины полностью спрятаны в тултипы.
        Геометрия подобрана под фиксированное окно 980x620: компактные
        отступы, кнопки 28px, тумблеры с pady=2 (см. test_novice_ui.py:
        низ кнопки запуска обязан влезать в окно).
        """

        def card(row: int, title: str, subtitle: str) -> ctk.CTkFrame:
            c = ctk.CTkFrame(
                self.novice, fg_color=theme.CARD, corner_radius=10,
                border_width=1, border_color=theme.BORDER,
            )
            c.grid(row=row, column=0, padx=8, pady=3, sticky="ew")
            c.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(
                c, text=title, font=ctk.CTkFont(size=14, weight="bold"),
                text_color=theme.TEXT, anchor="w",
            ).grid(row=0, column=0, padx=14, pady=(7, 0), sticky="w")
            ctk.CTkLabel(
                c, text=subtitle, font=ctk.CTkFont(size=10),
                text_color=theme.MUTED, anchor="w", wraplength=660, justify="left",
            ).grid(row=1, column=0, padx=14, pady=(0, 3), sticky="w")
            return c

        # --- Шаг 1: откуда брать VPN ---
        c1 = card(0, "1. Откуда брать VPN", "Сайты, откуда программа скачает конфиги.")
        row1 = ctk.CTkFrame(c1, fg_color="transparent")
        row1.grid(row=2, column=0, padx=14, pady=(0, 8), sticky="ew")
        row1.grid_columnconfigure(0, weight=1)
        self.lbl_sources_count = ctk.CTkLabel(
            row1, text="Подписок в списке: …", font=ctk.CTkFont(size=12),
            text_color=theme.TEXT, anchor="w",
        )
        self.lbl_sources_count.grid(row=0, column=0, sticky="w")
        ctk.CTkButton(
            row1, text="⬇ Импорт…", width=130, height=28,
            command=lambda: self.app._show_page("import"),
        ).grid(row=0, column=1, padx=(8, 0))
        ctk.CTkButton(
            row1, text="Список", width=100, height=28,
            fg_color="transparent", hover_color=theme.BORDER, text_color=theme.TEXT,
            command=lambda: self.app._show_page("sources"),
        ).grid(row=0, column=2, padx=(8, 0))

        # --- Шаг 2: что проверять ---
        c2 = card(1, "2. Что проверить", "Включённое должно работать — иначе конфиг отбрасывается.")
        self.novice_toggle_telegram = ctk.CTkSwitch(
            c2, text="Telegram (сообщения, видео, звонки)", width=44,
        )
        self.novice_toggle_telegram.grid(row=2, column=0, padx=14, pady=2, sticky="w")
        self.novice_toggle_telegram.select()
        CTkToolTip(
            self.novice_toggle_telegram,
            "Проверка Telegram через конфиг: MTProto-пинг до дата-центров ТГ "
            "и загрузка медиа. Узлы без рабочего Telegram отбрасываются.",
        )
        self.novice_toggle_services = ctk.CTkSwitch(
            c2, text="YouTube, Instagram, Discord", width=44,
        )
        self.novice_toggle_services.grid(row=3, column=0, padx=14, pady=2, sticky="w")
        self.novice_toggle_services.select()
        CTkToolTip(
            self.novice_toggle_services,
            "Проверка доступа к заблокированным сервисам через конфиг. "
            "Если сервис из списка недоступен — конфиг отбрасывается.",
        )
        self.novice_toggle_dpi = ctk.CTkSwitch(
            c2, text="Обход блокировок провайдера (DPI)", width=44,
        )
        self.novice_toggle_dpi.grid(row=4, column=0, padx=14, pady=(2, 8), sticky="w")
        CTkToolTip(
            self.novice_toggle_dpi,
            "Проверка конфигов на обход DPI-подмен (страницы-заглушки "
            "провайдера). Медленнее, но честнее.",
        )

        # --- Шаг 3: строгость ---
        c3 = card(
            2, "3. Насколько строгий отбор",
            "Строже — меньше конфигов, но каждый быстрее и стабильнее.",
        )
        self.preset_var = ctk.StringVar(value="Обычный")
        preset_holder = ctk.CTkFrame(c3, fg_color="transparent")
        preset_holder.grid(row=2, column=0, padx=14, pady=(0, 4), sticky="ew")
        preset_holder.grid_columnconfigure(0, weight=1)
        self.preset_switch = ctk.CTkSegmentedButton(
            preset_holder, values=PRESET_ORDER, variable=self.preset_var,
            command=self._on_preset_changed,
            selected_color=theme.ACCENT,
            selected_hover_color=theme.ACCENT_HOVER,
            font=ctk.CTkFont(size=13),
        )
        self.preset_switch.grid(row=0, column=0, sticky="ew")
        CTkToolTip(
            preset_holder,
            "Мягкий — оставить почти всё отвечающее (медленный интернет). "
            "Обычный — золотая середина. Строгий — только быстрые и стабильные "
            "(+глубокая DPI-проверка, дольше).",
        )
        preset_hint = {
            "Мягкий": "Оставить почти всё, что вообще отвечает. Для медного интернета.",
            "Обычный": "Золотая середина — подходит в 95% случаев.",
            "Строгий": "Только быстрые и стабильные. Для комфортного видео.",
        }
        self.lbl_preset_hint = ctk.CTkLabel(
            c3, text=preset_hint["Обычный"], font=ctk.CTkFont(size=10),
            text_color=theme.MUTED, anchor="w", wraplength=660, justify="left",
        )
        self.lbl_preset_hint.grid(row=3, column=0, padx=14, pady=(0, 8), sticky="w")
        self._preset_hint_map = preset_hint

        # --- Большая кнопка запуска ---
        self.btn_run_novice = ctk.CTkButton(
            self.novice,
            text="▶ Запустить проверку",
            height=48,
            corner_radius=10,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color="#0C1014",
            command=self.app.on_start_clicked,
        )
        self.btn_run_novice.grid(row=3, column=0, padx=8, pady=(6, 2), sticky="ew")
        CTkToolTip(
            self.btn_run_novice,
            "Проверка идёт в отдельном окне консоли — не закрывайте его. "
            "Когда закончится, откроется окно с результатами.",
        )

    def _on_preset_changed(self, value: str) -> None:
        """Пресет строгости → скрытые экспертные поля (пинг/скорость/dpi-актив)."""
        preset = PRESETS.get(value, PRESETS["Обычный"])
        self.lbl_preset_hint.configure(text=self._preset_hint_map.get(value, ""))
        # Пишем в экспертные виджеты: при переключении в «Тонкую настройку»
        # юзер увидит числа, соответствующие выбранному пресету.
        self.max_ping.delete(0, "end")
        self.max_ping.insert(0, str(preset["max_ping"]))
        self.min_speed.delete(0, "end")
        self.min_speed.insert(0, str(preset["min_speed"]))
        self._set_toggle(self.toggle_dpi_active, bool(preset["dpi_active"]))

    def _on_mode_changed(self, value: str) -> None:
        self.set_ui_mode("novice" if value == "Просто" else "expert", save=True)

    def set_ui_mode(self, mode: str, *, save: bool = False) -> None:
        """Показать режим «Просто» или «Тонкая настройка»."""
        mode = "expert" if mode == "expert" else "novice"
        if mode == "novice":
            self.scroll.grid_remove()
            self.novice.grid()
            self.refresh_novice()
        else:
            self.novice.grid_remove()
            self.scroll.grid()
        self.ui_mode_var.set("Просто" if mode == "novice" else "Тонкая настройка")
        if save:
            try:
                save_test_options({"ui_mode": mode})
            except Exception as exc:
                _logger.debug("ui_mode не сохранён: %s", exc)

    def _apply_saved_ui_mode(self) -> None:
        try:
            opts = get_test_options()
            mode = str(opts.get("ui_mode", "novice"))
        except Exception:
            mode = "novice"
        self.set_ui_mode("expert" if mode == "expert" else "novice")

    def refresh_novice(self) -> None:
        """Обновить счётчик подписок в режиме «Просто» (вызывается при показе страницы)."""
        try:
            sources_page = getattr(self.app, "page_sources", None)
            count = len(sources_page.get_sources()) if sources_page is not None else 0
        except Exception:
            count = 0
        word = "подписка" if count % 10 == 1 and count % 100 != 11 else (
            "подписки" if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14 else "подписок"
        )
        if self.lbl_sources_count is not None:
            if count:
                self.lbl_sources_count.configure(text=f"Подписок в списке: {count} {word}")
            else:
                self.lbl_sources_count.configure(
                    text="Подписок нет — нажмите «⬇ Импорт…», иначе проверять нечего.",
                    text_color=theme.WARNING if hasattr(theme, "WARNING") else theme.MUTED,
                )

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
        CTkToolTip(chk, "Скрыть/показать блок.")

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
        # Tooltip на само поле ввода — пользователь видит подсказку при наведении.
        if help:
            CTkToolTip(entry, help)
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

    # ------------------------------------------------------------ сохранение настроек
    def _restore_settings(self) -> None:
        """Восстановить сохранённые настройки тестирования из data/settings.json.

        Применяет workers/timeout/max_ping/min_speed/limit и тумблеры,
        которые пользователь установил в прошлый раз. Если файла нет —
        используются дефолты из DEFAULT_TEST_OPTIONS.
        """
        opts = get_test_options()
        # Числовые поля.
        self.workers.delete(0, "end")
        self.workers.insert(0, str(opts.get("workers", 32)))
        self.timeout.delete(0, "end")
        self.timeout.insert(0, str(opts.get("timeout", 15.0)))
        self.max_ping.delete(0, "end")
        self.max_ping.insert(0, str(opts.get("max_ping", 1500)))
        self.min_speed.delete(0, "end")
        self.min_speed.insert(0, str(opts.get("min_speed", 3000)))
        self.limit.delete(0, "end")
        self.limit.insert(0, str(opts.get("limit", 0)))
        # Тумблеры.
        self._set_toggle(self.toggle_no_stress, bool(opts.get("no_stress", False)))
        self._set_toggle(self.toggle_sing_box_only, bool(opts.get("sing_box_only", False)))

        self._set_toggle(self.toggle_telegram, bool(opts.get("telegram_check", True)))
        self._set_toggle(self.toggle_services, bool(opts.get("services_check", True)))
        self._set_toggle(self.toggle_dpi, bool(opts.get("dpi_check", False)))
        self._set_toggle(self.toggle_siberian, bool(opts.get("dpi_siberian", False)))
        self._set_toggle(self.toggle_cidr, bool(opts.get("dpi_cidr", False)))
        self._set_toggle(self.toggle_dpi_active, bool(opts.get("dpi_active", False)))
        # v8: ИИ-гео слепок — обязательный этап, тумблер только для strict.
        # Миграция: раньше suite был отдельным тумблером (ключ zapret_check)
        # и слепок — тумблером ai_check; теперь включаем DPI, если юзер
        # включал suite (намерение не теряется).
        if bool(opts.get("zapret_check", False)):
            self._set_toggle(self.toggle_dpi, True)
        # v12: ai_strict восстанавливается на вкладке «Фильтры» (тумблер
        # перенесён туда); здесь ключ больше не читаем.
        # v11: новые опции.
        self._set_toggle(self.toggle_use_singbox_pool, bool(opts.get("use_singbox_pool", True)))
        self._set_toggle(self.toggle_resilience_check, bool(opts.get("resilience_check", True)))
        dedup_mode = str(opts.get("dedup_mode", "normal"))
        if dedup_mode not in ("strict", "normal", "aggressive"):
            dedup_mode = "normal"
        self.dedup_mode_var.set(dedup_mode)
        # v17: ядро группового теста (xray/singbox).
        pool_engine = str(opts.get("pool_engine", "xray") or "xray").lower()
        if pool_engine not in ("xray", "singbox"):
            pool_engine = "xray"
        self.pool_engine_var.set(pool_engine)
        self.singbox_pool_batch.delete(0, "end")
        self.singbox_pool_batch.insert(0, str(opts.get("singbox_pool_batch", 200)))
        # Синхронизация зависимых тумблеров с восстановленными состояниями.
        self._sync_toggle_dependents(self.toggle_dpi)
        self._sync_toggle_dependents(self.toggle_telegram)
        # v16: режим «Просто» — тумблеры и пресет из сохранённых настроек.
        self._set_toggle(self.novice_toggle_telegram, bool(opts.get("telegram_check", True)))
        self._set_toggle(self.novice_toggle_services, bool(opts.get("services_check", True)))
        self._set_toggle(self.novice_toggle_dpi, bool(opts.get("dpi_check", False)))
        # Пресет восстанавливаем из сохранённых чисел (обратная карта).
        max_ping_saved = int(opts.get("max_ping", 2000) or 0)
        min_speed_saved = int(opts.get("min_speed", 500) or 0)
        dpi_active_saved = bool(opts.get("dpi_active", False))
        if dpi_active_saved and max_ping_saved <= 1500:
            preset = "Строгий"
        elif max_ping_saved >= 3000 and min_speed_saved <= 300:
            preset = "Мягкий"
        else:
            preset = "Обычный"
        self.preset_var.set(preset)
        self.lbl_preset_hint.configure(text=self._preset_hint_map.get(preset, ""))

    @staticmethod
    def _set_toggle(toggle: ctk.CTkSwitch, value: bool) -> None:
        if value:
            toggle.select()
        else:
            toggle.deselect()

    def save_current_settings(self) -> None:
        """Сохранить текущие настройки тестирования в data/settings.json.

        Вызывается перед запуском тестирования (app.on_start_clicked),
        чтобы при следующем запуске пользователя ждали те же значения.
        v16: в режиме «Просто» сохраняются значения простого интерфейса
        (тумблеры + пресет), в «Тонкой настройке» — как раньше, все поля.
        """
        novice = self.ui_mode_var.get() == "Просто"
        if novice:
            preset = PRESETS.get(self.preset_var.get(), PRESETS["Обычный"])
            opts = {
                "ui_mode": "novice",
                "telegram_check": bool(self.novice_toggle_telegram.get()),
                "services_check": bool(self.novice_toggle_services.get()),
                "dpi_check": bool(self.novice_toggle_dpi.get()),
                "max_ping": int(preset["max_ping"]),
                "min_speed": int(preset["min_speed"]),
                "dpi_active": bool(preset["dpi_active"]),
            }
        else:
            opts = {
                "ui_mode": "expert",
                "workers": self._int_value(self.workers, 32),
                "timeout": self._float_value(self.timeout, 15.0),
                "max_ping": self._int_value(self.max_ping, 1500),
                "min_speed": self._int_value(self.min_speed, 3000),
                "limit": self._int_value(self.limit, 0),
                "no_stress": bool(self.toggle_no_stress.get()),
                "sing_box_only": bool(self.toggle_sing_box_only.get()),

                "telegram_check": bool(self.toggle_telegram.get()),
                "services_check": bool(self.toggle_services.get()),
                "dpi_check": bool(self.toggle_dpi.get()),
                "dpi_siberian": bool(self.toggle_siberian.get()),
                "dpi_cidr": bool(self.toggle_cidr.get()),
                "dpi_active": bool(self.toggle_dpi_active.get()),
                # v8: ai-слепок обязателен — ключа ai_check больше нет;
                # zapret_check не сохраняем (suite — часть DPI-проверки).
                # v12: ai_strict сохраняет вкладка «Фильтры» (merge в settings —
                # ключ не теряется).
                # v11: новые опции.
                "dedup_mode": str(self.dedup_mode_var.get() or "normal"),
                "use_singbox_pool": bool(self.toggle_use_singbox_pool.get()),
                "singbox_pool_batch": self._int_value(self.singbox_pool_batch, 200),
                "pool_engine": str(self.pool_engine_var.get() or "xray"),
                "resilience_check": bool(self.toggle_resilience_check.get()),
            }
        try:
            save_test_options(opts)
        except Exception as exc:
            # Настройки теста не сохранились — запуск НЕ срываем, но
            # пользователь должен понять, почему тумблеры «откатились».
            _logger.warning("настройки теста не сохранены: %s", exc)

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
        # v16: режим «Просто» — опции из простого интерфейса, технические
        # параметры — разумные константы. Пресет перед стартом уже применён
        # к скрытым экспертным полям (_on_preset_changed), поэтому числа
        # пинга/скорости берутся оттуда же.
        novice = self.ui_mode_var.get() == "Просто"
        if novice:
            preset = PRESETS.get(self.preset_var.get(), PRESETS["Обычный"])
            # Синхронизируем скрытые экспертные поля с пресетом — на случай,
            # если пресет переключили, а command не отработал.
            self._on_preset_changed(self.preset_var.get())
            telegram_check = bool(self.novice_toggle_telegram.get())
            services_check = bool(self.novice_toggle_services.get())
            dpi_check = bool(self.novice_toggle_dpi.get())
            filters_page = getattr(self.app, "page_filters", None)
            filter_opts = filters_page.get_filter_options() if filters_page is not None else {}
            return PipelineOptions(
                workers=32,
                timeout=15.0,
                limit=0,
                max_ping=int(preset["max_ping"]),
                min_speed=int(preset["min_speed"]),
                no_stress=False,
                sing_box_only=False,
                telegram_check=telegram_check,
                services_check=services_check,
                dpi_check=dpi_check,
                dpi_siberian=False,
                dpi_cidr=False,
                dpi_active=bool(preset["dpi_active"]),
                ai_strict=bool(filter_opts.get("ai_strict", False)),
                ai_timeout=float(filter_opts.get("ai_timeout", 6.0)),
                custom_file="",
                dedup_mode="normal",
                use_singbox_pool=True,
                singbox_pool_batch=200,
                pool_engine="xray",
                resilience_check=True,
                proto_filter=str(filter_opts.get("proto_filter", "")),
                security_filter=str(filter_opts.get("security_filter", "")),
                transport_filter=str(filter_opts.get("transport_filter", "")),
                flow_filter=str(filter_opts.get("flow_filter", "")),
            )
        dpi_check = bool(self.toggle_dpi.get())
        # v8: suite — часть DPI-проверки (безусловна); ИИ-гео слепок —
        # обязательный этап (ai_check в опциях больше нет).
        custom_file = ""
        if self.toggle_custom_file.get():
            custom_file = self.custom_file_entry.get().strip()
        # v12: фильтр параметров конфигов + ai_strict/ai_timeout — со вкладки
        # «Фильтры» (тумблер РФ-слепка перенесён туда). get_options зовётся
        # по кнопке «Запустить», когда все страницы уже построены; guard на
        # getattr — на случай запуска старой сборки без page_filters.
        filters_page = getattr(self.app, "page_filters", None)
        filter_opts = filters_page.get_filter_options() if filters_page is not None else {}
        return PipelineOptions(
            workers=self._int_value(self.workers, 32),
            timeout=self._float_value(self.timeout, 15.0),
            limit=self._int_value(self.limit, 0),
            max_ping=self._int_value(self.max_ping, 1500),
            min_speed=self._int_value(self.min_speed, 3000),
            no_stress=self.toggle_no_stress.get(),
            sing_box_only=self.toggle_sing_box_only.get(),

            telegram_check=self.toggle_telegram.get(),
            services_check=self.toggle_services.get(),
            dpi_check=dpi_check,
            dpi_siberian=bool(self.toggle_siberian.get()) if dpi_check else False,
            dpi_cidr=bool(self.toggle_cidr.get()) if dpi_check else False,
            dpi_active=bool(self.toggle_dpi_active.get()),
            ai_strict=bool(filter_opts.get("ai_strict", False)),
            ai_timeout=float(filter_opts.get("ai_timeout", 6.0)),
            custom_file=custom_file,
            # v11: новые опции.
            dedup_mode=str(self.dedup_mode_var.get() or "normal"),
            use_singbox_pool=bool(self.toggle_use_singbox_pool.get()),
            singbox_pool_batch=self._int_value(self.singbox_pool_batch, 200),
            resilience_check=bool(self.toggle_resilience_check.get()),
            # v12: фильтр по параметрам конфигов (вкладка «Фильтры»).
            proto_filter=str(filter_opts.get("proto_filter", "")),
            security_filter=str(filter_opts.get("security_filter", "")),
            transport_filter=str(filter_opts.get("transport_filter", "")),
            flow_filter=str(filter_opts.get("flow_filter", "")),
        )



    def set_running(self, running: bool) -> None:
        """Блокировать/разблокировать кнопки запуска в обоих режимах."""
        state = "disabled" if running else "normal"
        self.btn_run.configure(state=state)
        if getattr(self, "btn_run_novice", None) is not None:
            self.btn_run_novice.configure(state=state)

