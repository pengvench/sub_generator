"""Страница «Фильтры» — отбор конфигов по параметрам протокола + гео-исключение.

Просьба пользователя (v14): «выписать ВСЕ возможные протоколы, что мы
проверяем, оставить галочки на нужных и пометить в приписке какие сейчас
самые ходовые». Поэтому:

  - галочки по 4 независимым измерениям (протокол / шифрование / транспорт /
    flow) — значения берутся из subgen/params_filter.py:DIMENSIONS (канон
    единый с конвертером конфигов): ВСЕ протоколы, которые поднимает парсер
    (vless/vmess/trojan/ss/hysteria2/hysteria), ничего не вырезается;
  - ★-пометки на «самых ходовых» значениях (params_filter.POPULAR) +
    приписка-легенда внизу карточки: НИЧЕГО не убирается и не пресетуется —
    звёздочка только подсказка, разнообразие остаётся за юзером;
  - мастер-тумблер: выключен — конвейер гоняет всё как раньше; включен —
    остаются только отмеченные комбинации. Снятие ВСЕХ галочек группы
    означает «по этому измерению не фильтровать» (один клик не должен
    обнулять результат прогона);
  - фильтр применяется ДО распинговки (зачем TCP-пинг по 17к vmess-нод,
    если нужны только vless+reality+xhttp).

Сюда же со страницы «Тестирование» перенесено гео-исключение РФ-слепка
(ai_strict) — тематически это фильтр результата, а не настройка проверки.
ИИ-гео слепок (CF trace chatgpt/claude + Google-футер + ipinfo/ip-api
консенсус) выполняется всегда: его вердикты openai_ok/gemini_ok попадают в
report.json — «пускают ли нейросети» видно по каждому узлу.
"""
from __future__ import annotations

import logging

import customtkinter as ctk

from .. import theme
from ..tooltip import CTkToolTip, info_label
from subgen.params_filter import DIMENSIONS, LABELS, OTHER, POPULAR, POPULAR_NOTES
from subgen.settings import get_test_options, save_test_options

_logger = logging.getLogger(__name__)

# Приписка-легенда под галочками (просьба юзера: пометить самые ходовые).
POPULAR_FOOTNOTE = (
    "★ — самые ходовые сейчас (РФ-обход, осень 2026): vless + reality + vision, "
    "hysteria2, ss (ss-2022); за CDN — vless/trojan + ws + tls. Список НЕ "
    "обрезается: все протоколы остаются с галочками — фильтр ничего не "
    "убирает, звёздочки лишь подсказывают лидеров. Снимайте/ставьте галочки "
    "под свою задачу."
)

HELP = {
    "params_master": (
        "Фильтр конфигов по параметрам протокола. Выключен — тестируются все "
        "конфиги. Включён — остаются только отмеченные ниже комбинации "
        "(например, только vless + reality + xhttp)."
    ),
    "params_group": (
        "Снятие всех галочек группы = по этому измерению не фильтровать. "
        "«Прочие/неизв.» — значения, которых нет в списке (новые транспорты "
        "и т.п.): они не теряются молча, а попадают в отдельную корзину."
    ),
    "params_popular": (
        "★ — самое ходовое значение сейчас (по практике РФ-обхода и статье "
        "Amnezia). Пометка информативная: галочку вы ставите сами."
    ),
    "ai_strict": (
        "Отбраковать узлы, чей ИИ-гео слепок — РФ (Gemini/OpenAI блокируют "
        "РФ по exit-IP). Слепок недоступен — узел НЕ отсеивается. Сам слепок "
        "выполняется всегда и попадает в отчёт (openai_ok/gemini_ok)."
    ),
    "ai_timeout": "Таймаут одного ИИ-гео запроса, сек.",
    # v22: SNI-категоризация для ограниченных сетей РФ (мобильные операторы).
    "sort_by_sni": (
        "Отсортировать итоговый список так, что БС-узлы (SNI в белом списке: "
        "sberbank.ru, vk.com, gosuslugi.ru, github.com, cloudflare.com ...) "
        "идут ПЕРВЫМИ в подписке. Полезно клиентам, которые подключаются к "
        "узлу по порядку из списка — на мобильной сети РФ первый БС-узел "
        "пройдёт DPI-блок. Без фильтрации, только переупорядочивание."
    ),
    "bs_only": (
        "Оставить в финальной подписке только БС-узлы (SNI в белом списке). "
        "Для ограниченных сетей РФ (МТС/МегаФон/Билайн/Tele2), где ЧС-узлы "
        "(instagram.com, chatgpt.com, twitter.com ...) блокируются DPI. "
        "Белый список: community-curated 2026 (~910 доменов из "
        "hxehex/russia-mobile-internet-whitelist) + встроенный (~80). "
        "Синк скриптом scripts/sync_sni_whitelist.py."
    ),
    "bs_allow_grey": (
        "(с «Только БС») Включать «серые» SNI — реальные домены не из списков "
        "(realhost.com, sub.domain.ru ...). Часто проходят DPI как обычный TLS. "
        "По умолчанию ON. Если у вас жёсткая сеть (мобильный оператор с полным "
        "SNI-whitelist'ом) — выключите для строгого режима."
    ),
    "bs_allow_fake": (
        "(с «Только БС») Включать «фейк» SNI — короткие строки без точки "
        "(abc12345). НЕ рекомендуется: ТСПУ быстро учится их блокировать. "
        "По умолчанию OFF."
    ),
}

# Заголовки групп измерений (порядок = порядок на странице).
GROUP_TITLES = {
    "protocol": "Протокол",
    "security": "Шифрование",
    "transport": "Транспорт",
    "flow": "Flow (XTLS)",
}


class FiltersPage(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)

        # v17: страница живёт во вкладке «Фильтры» страницы «Мои подписки» —
        # большого заголовка здесь больше нет.
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=theme.ACCENT,
            scrollbar_button_hover_color=theme.ACCENT_HOVER,
        )
        self.scroll.grid(row=0, column=0, padx=8, pady=(8, 8), sticky="nsew")
        self.scroll.grid_columnconfigure(0, weight=1)

        self.card_params = self._make_card(self.scroll, 0, "Параметры конфигов")
        self.card_geo = self._make_card(self.scroll, 1, "Гео и нейросети")
        self.card_sni = self._make_card(self.scroll, 2, "SNI категории (БС/ЧС)")

        self._build_params_card(self.card_params.inner)
        self._build_geo_card(self.card_geo.inner)
        self._build_sni_card(self.card_sni.inner)

        # Восстановить сохранённые настройки (мастер-тумблер, галочки, ai_*).
        self._restore_settings()

    # ------------------------------------------------------------ карточки
    def _make_card(self, parent, row, title: str) -> ctk.CTkFrame:
        """Карточка в стиле страницы «Тестирование» (заголовок + содержимое)."""
        card = ctk.CTkFrame(
            parent, fg_color=theme.CARD, corner_radius=10,
            border_width=1, border_color=theme.BORDER,
        )
        card.grid(row=row, column=0, padx=8, pady=6, sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        head = ctk.CTkLabel(
            card, text=title,
            font=ctk.CTkFont(size=14, weight="bold"), text_color=theme.TEXT,
        )
        head.grid(row=0, column=0, padx=12, pady=(10, 2), sticky="w")

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.grid(row=1, column=0, padx=6, pady=(2, 10), sticky="ew")

        card.inner = inner  # type: ignore[attr-defined]
        return card

    # ------------------------------------------------------------ параметры
    def _build_params_card(self, inner: ctk.CTkFrame) -> None:
        inner.grid_columnconfigure(0, weight=1)

        # Мастер-тумблер фильтра.
        master_frame = ctk.CTkFrame(inner, fg_color="transparent")
        master_frame.grid(row=0, column=0, padx=6, pady=4, sticky="ew")
        master_frame.grid_columnconfigure(0, weight=1)
        master_label = ctk.CTkLabel(
            master_frame, text="Фильтровать конфиги по параметрам",
            anchor="w", text_color=theme.TEXT,
        )
        master_label.grid(row=0, column=0, sticky="w")
        info = info_label(master_frame, HELP["params_master"])
        info.grid(row=0, column=1, padx=(4, 0), sticky="w")
        self.toggle_params_master = ctk.CTkSwitch(master_frame, text="", width=42)
        self.toggle_params_master.grid(row=0, column=2, padx=(10, 0), sticky="e")
        CTkToolTip(self.toggle_params_master, HELP["params_master"])
        self.toggle_params_master.configure(command=self._sync_master_state)

        # Группы галочек: измерение -> {значение -> чекбокс}.
        self._checkboxes: dict[str, dict[str, ctk.CTkCheckBox]] = {}
        row = 1
        for dim, values in DIMENSIONS.items():
            group = self._make_checkbox_group(inner, row, dim, values)
            self._checkboxes[dim] = group
            row += 1

        # Кнопки «выбрать всё / снять всё» (по всем группам).
        btn_row = ctk.CTkFrame(inner, fg_color="transparent")
        btn_row.grid(row=row, column=0, padx=6, pady=(6, 2), sticky="e")
        self.btn_select_all = ctk.CTkButton(
            btn_row, text="Выбрать всё", width=110, height=26,
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            text_color="#0C1014", font=ctk.CTkFont(size=11),
            command=self._select_all,
        )
        self.btn_select_all.grid(row=0, column=0, padx=(0, 6))
        CTkToolTip(self.btn_select_all, "Отметить все значения во всех группах (фильтр пропускает всё).")
        self.btn_deselect_all = ctk.CTkButton(
            btn_row, text="Снять всё", width=90, height=26,
            fg_color="transparent", hover_color=theme.BORDER,
            text_color=theme.MUTED, font=ctk.CTkFont(size=11),
            command=self._deselect_all,
        )
        self.btn_deselect_all.grid(row=0, column=1)
        CTkToolTip(
            self.btn_deselect_all,
            "Снять все галочки — все измерения перестают фильтровать "
            "(аналог выключенного тумблера).",
        )

        # v14: приписка юзеру — какие значения сейчас самые ходовые.
        # Галочки НЕ вырезаются (разнообразие остаётся): звёздочка — метка.
        note = ctk.CTkLabel(
            inner,
            text=POPULAR_FOOTNOTE,
            font=ctk.CTkFont(size=11), text_color=theme.MUTED,
            justify="left", wraplength=560,
        )
        note.grid(row=row + 1, column=0, padx=10, pady=(8, 2), sticky="ew")

        self._sync_master_state()

    def _make_checkbox_group(
        self, parent: ctk.CTkFrame, row: int, dim: str, values: tuple[str, ...]
    ) -> dict[str, ctk.CTkCheckBox]:
        """Группа галочек одного измерения: заголовок + значения + «прочие»."""
        group_frame = ctk.CTkFrame(parent, fg_color="transparent")
        group_frame.grid(row=row, column=0, padx=6, pady=4, sticky="ew")
        group_frame.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            group_frame, text=GROUP_TITLES.get(dim, dim) + ":",
            font=ctk.CTkFont(size=12, weight="bold"), text_color=theme.MUTED,
            anchor="w",
        )
        title.grid(row=0, column=0, sticky="w")
        CTkToolTip(title, HELP["params_group"])

        # Значения — в 2 столбика, чтобы страница не растягивалась вдаль.
        checks_frame = ctk.CTkFrame(group_frame, fg_color="transparent")
        checks_frame.grid(row=1, column=0, padx=(10, 0), sticky="ew")
        for col in range(2):
            checks_frame.grid_columnconfigure(col, weight=1)

        checkboxes: dict[str, ctk.CTkCheckBox] = {}
        all_values = list(values) + [OTHER]
        popular_values = POPULAR.get(dim, frozenset())
        for i, value in enumerate(all_values):
            label = LABELS.get(value, value)
            is_popular = value in popular_values
            if is_popular:
                label = f"★ {label}"
            chk = ctk.CTkCheckBox(
                checks_frame, text=label, checkbox_width=18, checkbox_height=18,
                text_color=(theme.ACCENT if is_popular else theme.TEXT),
                font=ctk.CTkFont(size=12),
            )
            chk.grid(row=i // 2, column=i % 2, padx=4, pady=2, sticky="w")
            if is_popular:
                CTkToolTip(
                    chk,
                    POPULAR_NOTES.get(value, HELP["params_popular"]),
                )
            chk.select()  # по умолчанию всё выбрано (фильтр ничего не режет)
            checkboxes[value] = chk
        return checkboxes

    def _sync_master_state(self) -> None:
        """Галочки доступны только при включённом мастер-тумблере."""
        enabled = bool(self.toggle_params_master.get())
        state = "normal" if enabled else "disabled"
        for group in self._checkboxes.values():
            for chk in group.values():
                chk.configure(state=state)

    def _select_all(self) -> None:
        for group in self._checkboxes.values():
            for chk in group.values():
                chk.select()

    def _deselect_all(self) -> None:
        for group in self._checkboxes.values():
            for chk in group.values():
                chk.deselect()

    # ------------------------------------------------------------ гео
    def _build_geo_card(self, inner: ctk.CTkFrame) -> None:
        for col in range(2):
            inner.grid_columnconfigure(col, weight=1)

        # Перенесено со страницы «Тестирование»: исключение РФ-слепка.
        ai_frame = ctk.CTkFrame(inner, fg_color="transparent")
        ai_frame.grid(row=0, column=0, padx=6, pady=4, sticky="ew")
        ai_frame.grid_columnconfigure(0, weight=1)
        ai_label = ctk.CTkLabel(
            ai_frame, text="Исключить РФ-слепок", anchor="w", text_color=theme.TEXT,
        )
        ai_label.grid(row=0, column=0, sticky="w")
        info = info_label(ai_frame, HELP["ai_strict"])
        info.grid(row=0, column=1, padx=(4, 0), sticky="w")
        self.toggle_ai_strict = ctk.CTkSwitch(ai_frame, text="", width=42)
        self.toggle_ai_strict.grid(row=0, column=2, padx=(10, 0), sticky="e")
        CTkToolTip(self.toggle_ai_strict, HELP["ai_strict"])

        self.ai_timeout = self._make_entry(
            inner, 0, 1, "Таймаут ИИ-гео (сек)", "6", help=HELP["ai_timeout"]
        )

        # Пояснение, что слепок выполняется всегда и как читать его в отчёте.
        note = ctk.CTkLabel(
            inner,
            text=(
                "ИИ-гео слепок выполняется для каждого узла ВСЕГДА (даже без "
                "тумблера): Cloudflare trace chatgpt.com/claude.ai + футер Google "
                "+ консенсус ipinfo/ip-api. Вердикты «пускают ли нейросети» "
                "(openai_ok / gemini_ok, страна консенсуса) — в report.json, "
                "узлы с exit-РФ помечаются в логе. Тумблер выше лишь ОТБРАКОВЫВАЕТ "
                "такие узлы из итоговой подписки."
            ),
            font=ctk.CTkFont(size=11), text_color=theme.MUTED,
            justify="left", wraplength=560,
        )
        note.grid(row=1, column=0, columnspan=2, padx=10, pady=(8, 2), sticky="ew")

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
        if help:
            CTkToolTip(entry, help)
        return entry

    # ------------------------------------------------------------ SNI категории
    def _build_sni_card(self, inner: ctk.CTkFrame) -> None:
        """v22: тумблеры SNI-категоризации для ограниченных сетей РФ.

        Кейс юзера 2026-09-29: на мобильных операторах РФ (МТС/МегаФон/Билайн/
        Tele2) проходят только узлы с SNI из БЕЛОГО списка (sberbank.ru, vk.com,
        gosuslugi.ru, github.com ...). ЧС-узлы (instagram.com, chatgpt.com ...)
        блокируются DPI. Эти тумблеры:
          - «Сортировать по SNI» — БС-узлы идут первыми в финальной подписке;
          - «Только БС-узлы» — строгий фильтр для ограниченных сетей;
          - «Включать серые» — реальные домены не из списков (по умолчанию ON);
          - «Включать фейки» — короткие строки (по умолчанию OFF, нестабильно).
        """
        inner.grid_columnconfigure(0, weight=1)

        # 1) Сортировка БС-первым (мягкая опция, не фильтрует, только порядок).
        row = 0
        sort_frame = ctk.CTkFrame(inner, fg_color="transparent")
        sort_frame.grid(row=row, column=0, padx=6, pady=4, sticky="ew")
        sort_frame.grid_columnconfigure(0, weight=1)
        sort_label = ctk.CTkLabel(
            sort_frame, text="Сортировать по SNI (БС первым)",
            anchor="w", text_color=theme.TEXT,
        )
        sort_label.grid(row=0, column=0, sticky="w")
        info = info_label(sort_frame, HELP["sort_by_sni"])
        info.grid(row=0, column=1, padx=(4, 0), sticky="w")
        self.toggle_sort_by_sni = ctk.CTkSwitch(sort_frame, text="", width=42)
        self.toggle_sort_by_sni.grid(row=0, column=2, padx=(10, 0), sticky="e")
        CTkToolTip(self.toggle_sort_by_sni, HELP["sort_by_sni"])

        # 2) Только БС-узлы (жёсткий фильтр для ограниченных сетей).
        row = 1
        bs_frame = ctk.CTkFrame(inner, fg_color="transparent")
        bs_frame.grid(row=row, column=0, padx=6, pady=4, sticky="ew")
        bs_frame.grid_columnconfigure(0, weight=1)
        bs_label = ctk.CTkLabel(
            bs_frame, text="Только БС-узлы (для ограниченной сети РФ)",
            anchor="w", text_color=theme.TEXT,
        )
        bs_label.grid(row=0, column=0, sticky="w")
        info2 = info_label(bs_frame, HELP["bs_only"])
        info2.grid(row=0, column=1, padx=(4, 0), sticky="w")
        self.toggle_bs_only = ctk.CTkSwitch(bs_frame, text="", width=42)
        self.toggle_bs_only.grid(row=0, column=2, padx=(10, 0), sticky="e")
        CTkToolTip(self.toggle_bs_only, HELP["bs_only"])
        # При включении bs_only — опциональные тумблеры (grey/fake) активны;
        # при выключении — disabled.
        self.toggle_bs_only.configure(command=self._sync_sni_subtoggles)

        # 3) Включать серые SNI (подопция bs_only).
        row = 2
        grey_frame = ctk.CTkFrame(inner, fg_color="transparent")
        grey_frame.grid(row=row, column=0, padx=(20, 6), pady=2, sticky="ew")
        grey_frame.grid_columnconfigure(0, weight=1)
        grey_label = ctk.CTkLabel(
            grey_frame, text="Включать серые SNI (realhost.com и т.п.)",
            anchor="w", text_color=theme.MUTED,
            font=ctk.CTkFont(size=12),
        )
        grey_label.grid(row=0, column=0, sticky="w")
        info3 = info_label(grey_frame, HELP["bs_allow_grey"])
        info3.grid(row=0, column=1, padx=(4, 0), sticky="w")
        self.toggle_bs_allow_grey = ctk.CTkSwitch(grey_frame, text="", width=42)
        self.toggle_bs_allow_grey.grid(row=0, column=2, padx=(10, 0), sticky="e")
        CTkToolTip(self.toggle_bs_allow_grey, HELP["bs_allow_grey"])
        # По умолчанию ON — серые часто проходят.
        self.toggle_bs_allow_grey.select()

        # 4) Включать фейки SNI (подопция bs_only, нестабильно).
        row = 3
        fake_frame = ctk.CTkFrame(inner, fg_color="transparent")
        fake_frame.grid(row=row, column=0, padx=(20, 6), pady=2, sticky="ew")
        fake_frame.grid_columnconfigure(0, weight=1)
        fake_label = ctk.CTkLabel(
            fake_frame, text="Включать фейки (abc12345, нестабильно)",
            anchor="w", text_color=theme.MUTED,
            font=ctk.CTkFont(size=12),
        )
        fake_label.grid(row=0, column=0, sticky="w")
        info4 = info_label(fake_frame, HELP["bs_allow_fake"])
        info4.grid(row=0, column=1, padx=(4, 0), sticky="w")
        self.toggle_bs_allow_fake = ctk.CTkSwitch(fake_frame, text="", width=42)
        self.toggle_bs_allow_fake.grid(row=0, column=2, padx=(10, 0), sticky="e")
        CTkToolTip(self.toggle_bs_allow_fake, HELP["bs_allow_fake"])

        # v38: Pattern scoring toggle.
        row = 4
        ps_frame = ctk.CTkFrame(inner, fg_color="transparent")
        ps_frame.grid(row=row, column=0, padx=6, pady=4, sticky="ew")
        ps_frame.grid_columnconfigure(0, weight=1)
        ps_label = ctk.CTkLabel(
            ps_frame, text="Pattern scoring (по known_good.txt)",
            anchor="w", text_color=theme.TEXT,
        )
        ps_label.grid(row=0, column=0, sticky="w")
        info_ps = info_label(ps_frame, "Оценивает конфиги по сходству с data/known_good.txt "
                                  "(SNI, host, протокол). Узлы с score < порога отбраковываются. "
                                  "known_good всегда добавляются в финал. "
                                  "Файл: data/known_good.txt (положите туда проверенные на мобилке конфиги).")
        info_ps.grid(row=0, column=1, padx=(4, 0), sticky="w")
        self.toggle_pattern_score = ctk.CTkSwitch(ps_frame, text="", width=42)
        self.toggle_pattern_score.grid(row=0, column=2, padx=(10, 0), sticky="e")
        CTkToolTip(self.toggle_pattern_score, "Pattern scoring: оценивает каждый конфиг по "
                   "сходству с known_good (SNI +40, host +25, стек +45). Порог: 40 по умолчанию.")

        # Приписка про источники whitelist'а (community-curated + builtin).
        note = ctk.CTkLabel(
            inner,
            text=(
                "Белый список SNI: community-curated 2026 (~910 доменов из "
                "hxehex/russia-mobile-internet-whitelist) + встроенный (~80). "
                "Чёрный список: ~30 запрещённых в РФ доменов (instagram.com, "
                "chatgpt.com, twitter.com ...). Синк community list'а — скриптом "
                "scripts/sync_sni_whitelist.py. Суффиксное сравнение защищает "
                "от подделки: «sberbank.ru.evil.com» НЕ считается белым."
            ),
            font=ctk.CTkFont(size=11), text_color=theme.MUTED,
            justify="left", wraplength=560,
        )
        note.grid(row=4, column=0, padx=10, pady=(8, 2), sticky="ew")

        self._sync_sni_subtoggles()

    def _sync_sni_subtoggles(self) -> None:
        """Подопции bs_only (grey/fake) активны только при включённом bs_only."""
        enabled = bool(self.toggle_bs_only.get())
        state = "normal" if enabled else "disabled"
        for tgl in (self.toggle_bs_allow_grey, self.toggle_bs_allow_fake):
            tgl.configure(state=state)

    # ------------------------------------------------------------ сохранение
    def _restore_settings(self) -> None:
        opts = get_test_options()
        enabled = bool(opts.get("params_filter_enabled", False))
        if enabled:
            self.toggle_params_master.select()
        else:
            self.toggle_params_master.deselect()
        for dim, group in self._checkboxes.items():
            saved = opts.get(f"params_{dim}")
            if isinstance(saved, list) and saved:
                allowed = {str(v).strip().lower() for v in saved}
                # v14-миграция: hysteria (v1) раньше сливалась с hysteria2,
                # в сохранённых настройках её нет. Если hysteria2 выбрана —
                # включаем и hysteria, чтобы обновление не сузило фильтр
                # пользователя молча (раньше эти узлы проходили).
                if dim == "protocol" and "hysteria2" in allowed:
                    allowed.add("hysteria")
                for value, chk in group.items():
                    if value in allowed:
                        chk.select()
                    else:
                        chk.deselect()
            else:
                # Нет сохранённых значений — всё выбрано (фильтр всё пропускает).
                for chk in group.values():
                    chk.select()
        self._set_toggle(self.toggle_ai_strict, bool(opts.get("ai_strict", False)))
        self.ai_timeout.delete(0, "end")
        self.ai_timeout.insert(0, str(opts.get("ai_timeout", 6.0)))
        # v22: восстановить SNI-тумблеры (sort_by_sni, bs_only, bs_allow_*).
        self._set_toggle(self.toggle_sort_by_sni, bool(opts.get("sort_by_sni", False)))
        self._set_toggle(self.toggle_bs_only, bool(opts.get("bs_only", False)))
        self._set_toggle(self.toggle_bs_allow_grey, bool(opts.get("bs_allow_grey", True)))
        self._set_toggle(self.toggle_bs_allow_fake, bool(opts.get("bs_allow_fake", False)))
        self._set_toggle(self.toggle_pattern_score, bool(opts.get("pattern_score", False)))
        self._sync_sni_subtoggles()
        self._sync_master_state()

    @staticmethod
    def _set_toggle(toggle: ctk.CTkSwitch, value: bool) -> None:
        if value:
            toggle.select()
        else:
            toggle.deselect()

    def _group_csv(self, dim: str) -> str:
        """CSV выбранных значений группы; «» — если ничего/всё выбрано."""
        group = self._checkboxes.get(dim, {})
        selected = [v for v, chk in group.items() if chk.get()]
        if not selected or len(selected) == len(group):
            return ""
        return ",".join(sorted(selected))

    def get_filter_options(self) -> dict[str, object]:
        """Опции фильтров для PipelineOptions (вызывается при запуске)."""
        enabled = bool(self.toggle_params_master.get())
        return {
            "params_filter_enabled": enabled,
            "proto_filter": self._group_csv("protocol") if enabled else "",
            "security_filter": self._group_csv("security") if enabled else "",
            "transport_filter": self._group_csv("transport") if enabled else "",
            "flow_filter": self._group_csv("flow") if enabled else "",
            "ai_strict": bool(self.toggle_ai_strict.get()),
            "ai_timeout": self._float_value(self.ai_timeout, 6.0),
            # v22: SNI-категоризация (БС/ЧС/серый/фейк/none).
            "sort_by_sni": bool(self.toggle_sort_by_sni.get()),
            "bs_only": bool(self.toggle_bs_only.get()),
            "bs_allow_grey": bool(self.toggle_bs_allow_grey.get()),
            "bs_allow_fake": bool(self.toggle_bs_allow_fake.get()),
            # v38: Pattern scoring + known-good.
            "pattern_score": bool(self.toggle_pattern_score.get()),
            "pattern_score_min": 40,
            "known_good": "known_good.txt",
        }

    def save_current_settings(self) -> None:
        """Сохранить настройки вкладки в data/settings.json (merge, не затирая
        чужие ключи — save_test_options обновляет только переданные)."""
        opts: dict[str, object] = {
            "params_filter_enabled": bool(self.toggle_params_master.get()),
            "params_protocols": [v for v, c in self._checkboxes["protocol"].items() if c.get()],
            "params_security": [v for v, c in self._checkboxes["security"].items() if c.get()],
            "params_transport": [v for v, c in self._checkboxes["transport"].items() if c.get()],
            "params_flow": [v for v, c in self._checkboxes["flow"].items() if c.get()],
            "ai_strict": bool(self.toggle_ai_strict.get()),
            "ai_timeout": self._float_value(self.ai_timeout, 6.0),
            # v22: SNI-категоризация (БС/ЧС/серый/фейк/none).
            "sort_by_sni": bool(self.toggle_sort_by_sni.get()),
            "bs_only": bool(self.toggle_bs_only.get()),
            "bs_allow_grey": bool(self.toggle_bs_allow_grey.get()),
            "bs_allow_fake": bool(self.toggle_bs_allow_fake.get()),
            # v38: Pattern scoring + known-good.
            "pattern_score": bool(self.toggle_pattern_score.get()),
            "pattern_score_min": 40,
            "known_good": "known_good.txt",
        }
        try:
            save_test_options(opts)
        except Exception as exc:
            _logger.warning("настройки фильтров не сохранены: %s", exc)

    @staticmethod
    def _float_value(entry, default: float) -> float:
        try:
            return float(entry.get().strip())
        except (ValueError, AttributeError):
            return default
