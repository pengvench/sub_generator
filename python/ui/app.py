"""Главное окно SubGenerator (customtkinter, Material-тема как ZapretUI)."""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
import traceback
from tkinter import messagebox


import customtkinter as ctk

from . import paths, theme
from . import hotkeys
from .pages.log_page import LogPage
from .pages.recheck_page import RecheckPage
from .pages.settings_page import SettingsPage, SettingsRootPage
from .pages.sources_page import SourcesPage
from .pages.start_page import StartPage
from .pages.filters_page import FiltersPage
from .pages.diag_page import DiagPage
from .pages.import_page import ImportPage
from .pages.mysubs_page import MySubsPage

from .runner import PipelineRunner, build_pipeline_args, filter_sources_by_history
from .tooltip import CTkToolTip

_logger = logging.getLogger(__name__)

theme.apply_theme()


class SubGenApp(ctk.CTk):
    TITLE = "SubGenerator — сборка и тест конфигов из подписок"

    def __init__(self) -> None:
        super().__init__()
        self.title(self.TITLE)
        # Компактное фиксированное окно: расширяться/сужаться нельзя.
        W, H = 980, 620
        self.geometry(f"{W}x{H}")
        self.minsize(W, H)
        self.maxsize(W, H)
        self.resizable(False, False)
        self.configure(fg_color=theme.BG)
        # Иконка окна (titlebar) — из assets/ (исходники) или рядом с exe
        # (собранная сборка: build_release.bat кладёт icon.ico рядом).
        try:
            icon_path = paths.assets_dir() / "icon.ico"
            if not icon_path.exists():
                icon_path = paths.app_root() / "icon.ico"
            if icon_path.exists():
                self.iconbitmap(str(icon_path))
        except Exception as exc:
            # Иконка — косметика: на некоторых Linux/Wayland bitmap не ставится.
            _logger.debug("иконка окна не установлена: %s", exc)
        # Центрируем окно на экране
        self.update_idletasks()

        # Хоткеи копирования/вставки (Ctrl+C/V/A/X), работающие при ЛЮБОЙ
        # раскладке — в русской раскладке Tk не матчит <Control-v> по
        # кириллическому keysym (жалоба юзера 2026-09-20).
        hotkeys.install(self)

        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{W}x{H}+{(sw - W) // 2}+{(sh - H) // 2}")


        self.sources_file = paths.sources_file()
        self.data_dir = paths.data_dir()
        self.runner = PipelineRunner()
        self._busy = False
        self._paused = False


        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_pages()
        self._build_footer()
        # Кнопки «Пауза»/«Стоп» неактивны, пока ничего не запущено.
        self._set_busy(False)

        self._show_page("start")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Если есть свежий report.json от прошлого прогона (завершился
        # недавно, в течение последних 2 часов) — показываем окно с цифрами.
        self._maybe_show_results()

    def _maybe_show_results(self) -> None:
        """Показать окно результатов, если есть свежий report.json.

        Проверяем время модификации файла: если отчёт создан/обновлён
        менее 2 часов назад, считаем его «свежим» и показываем сводку.
        Это срабатывает при следующем запуске GUI после того, как
        PowerShell-окно завершилось.
        """
        import json as _json
        import time as _time

        report_path = self.data_dir / "report.json"
        if not report_path.exists():
            return
        try:
            mtime = report_path.stat().st_mtime
            age_sec = _time.time() - mtime
            # 2 часа — порог «свежести» отчёта.
            if age_sec > 7200:
                return
            data = _json.loads(report_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(data, dict):
            return
        self._show_results_dialog(data)

    def _dialog_scale(self) -> float:
        """Коэффициент DPI-масштаба для диалогов на чистом tk.

        Диалоги результатов — чистый tkinter с геометрией в ФИЗИЧЕСКИХ
        пикселях, а шрифты в них заданы в ПУНКТАХ и растут вместе с DPI
        системы (customtkinter делает процесс DPI-aware, tk scaling =
        dpi/72). При DPI 125–150% контент становился шире окна, и значения,
        прижатые к правому краю grid-колонки, улетали за видимую область —
        окно «Результаты» показывало подписи без цифр (инцидент 2026-09-19).
        Возвращаем множитель относительно эталонных 96 DPI (tk scaling
        1.333): на 96 DPI это 1.0, на 125% — 1.25, на 150% — 1.5.
        """
        try:
            s = float(self.tk.call("tk", "scaling"))
        except Exception:
            s = 96.0 / 72.0
        if s <= 0.9:
            # X11 с bitmap-шрифтами рапортует ~1.0 (72 dpi) — не сжимаем окно.
            return 1.0
        return max(1.0, s / (96.0 / 72.0))

    def _show_results_dialog(self, report: dict) -> None:
        """Показать модальное окно с результатами прогона.

        БАГФИКС (2026-09-19, «заголовки есть, а цифр нет»): при DPI > 100%
        (или подстановке широкого шрифта вместо Segoe UI) текстовый
        разделитель «─»×60 и подписи раздували grid-таблицу шире окна —
        значения со sticky="e" оказывались за правым краем окна. Теперь:
        размер окна масштабируется под DPI, разделитель — Frame высотой
        2px (ширина не зависит от шрифта), grid замкнут на размер окна
        (propagate off), у колонки подписей weight=1 — значения всегда
        прижаты к правому краю ВИДИМОЙ области.
        """
        from tkinter import Toplevel, Label, Button, Frame

        # Считаем строки заранее — высота окна зависит от числа этапов.
        stage_keys = [
            ("initial_check", "Initial check"),
            ("dpi", "DPI-проверка"),
            ("dpi_active", "DPI-актив"),
            ("telegram_pro", "Telegram-PRO"),
            ("ai_geo", "ИИ-гео (Gemini/OpenAI)"),
            ("route", "Route"),
            ("resilience", "Resilience"),
            ("recheck", "Финальный спидтест"),
        ]
        sources_report = report.get("sources_report")
        has_sources = isinstance(sources_report, dict) and sources_report.get("enabled")
        # v14: строка «Утечки exit-IP» — если leak_check в ai_geo-отчёте включён.
        ai_geo_stage = report.get("ai_geo")
        leak_check = (
            ai_geo_stage.get("leak_check")
            if isinstance(ai_geo_stage, dict) else None
        )
        has_leak = isinstance(leak_check, dict) and leak_check.get("enabled")
        n_stages = sum(
            1 for key, _ in stage_keys
            if isinstance(report.get(key), dict) and report[key].get("enabled")
        )
        n_rows = (
            6
            + (1 if report.get("pending") else 0)
            + n_stages
            + (1 if has_leak else 0)
            + (1 if has_sources else 0)
        )

        k = self._dialog_scale()
        W = int(560 * k)
        H = int((185 + 26 * n_rows) * k)

        dlg = Toplevel(self)
        dlg.title("📊 Результаты прогона")
        dlg.transient(self)
        dlg.configure(bg=str(theme.BG))

        # Центрируем и вписываем в экран.
        dlg.update_idletasks()
        sw = dlg.winfo_screenwidth()
        sh = dlg.winfo_screenheight()
        W = max(420, min(W, sw - 80))
        H = max(400, min(H, sh - 80))
        x = max(0, (sw - W) // 2)
        y = max(0, (sh - H) // 2)
        dlg.geometry(f"{W}x{H}+{x}+{y}")
        dlg.resizable(False, False)

        # Grid жёстко замкнут на размер окна: колонка подписей забирает всё
        # дополнительное место, колонка значений прижата к правому краю ОКНА
        # (а не к правому краю раздутого контента, как раньше).
        dlg.grid_propagate(False)
        dlg.columnconfigure(0, weight=1)
        dlg.columnconfigure(1, weight=0, minsize=110)

        def _add_row(row: int, label: str, value: str, color: str = str(theme.TEXT)) -> None:
            lbl = Label(
                dlg, text=label, anchor="w", bg=str(theme.BG), fg=str(theme.MUTED),
                font=("Segoe UI", 10),
            )
            lbl.grid(row=row, column=0, padx=(20, 6), pady=4, sticky="w")
            val = Label(
                dlg, text=value, anchor="e", bg=str(theme.BG), fg=color,
                font=("Segoe UI", 11, "bold"),
            )
            val.grid(row=row, column=1, padx=(6, 20), pady=4, sticky="e")

        header = Label(
            dlg, text="📊 Результаты последнего прогона",
            bg=str(theme.BG), fg=str(theme.TEXT),
            font=("Segoe UI", 13, "bold"),
        )
        header.grid(row=0, column=0, columnspan=2, padx=20, pady=(16, 12), sticky="w")

        generated_at = str(report.get("generated_at_utc", "?"))
        _add_row(1, "Время (UTC):", generated_at[:19])
        _add_row(2, "Источников (sources):", str(len(report.get("sources", []))))
        _add_row(3, "Найдено узлов (discovered):", str(report.get("discovered", 0)))
        _add_row(4, "Рабочих (working):", str(report.get("working", 0)),
                 color=str(theme.SUCCESS))
        _add_row(5, "Отбраковано (rejected):", str(report.get("rejected", 0)),
                 color=str(theme.WARNING))
        _add_row(6, "Экспортировано в подписку:", str(report.get("exported", 0)),
                 color=str(theme.ACCENT))

        # БАГФИКС (2026-09-16): крашнутый прогон раньше не оставлял отчёта
        # вовсе — окно показывало пустые цифры. Теперь pipeline пишет
        # pending-отчёт в начале прогона; помечаем его явным предупреждением.
        sep_row = 7
        if report.get("pending"):
            _add_row(7, "⚠ Статус прогона:", "НЕ ЗАВЕРШИЛСЯ (краш/остановка)",
                     color=str(theme.ERROR))
            sep_row = 8

        # Разделитель — Frame высотой 2px: ширина не зависит от шрифта/DPI
        # (текстовый «─»×60 при крупном/подставленном шрифте раздувал
        # grid-таблицу до тысяч пикселей и выталкивал цифры за край).
        sep = Frame(dlg, height=2, bg=str(theme.BORDER), bd=0, highlightthickness=0)
        sep.grid(row=sep_row, column=0, columnspan=2, padx=20, pady=(10, 6), sticky="ew")

        # Этапы с количеством прошедших/отбракованных.
        stage_row = sep_row + 1
        for stage_key, stage_label in stage_keys:
            stage = report.get(stage_key)
            if not isinstance(stage, dict) or not stage.get("enabled"):
                continue
            passed = stage.get("passed", 0)
            failed = stage.get("failed", 0)
            checked = stage.get("checked", passed + failed)
            color = str(theme.SUCCESS) if failed == 0 else (
                str(theme.WARNING) if passed > 0 else str(theme.ERROR)
            )
            _add_row(stage_row, f"{stage_label}:", f"{passed}/{checked} прошли", color)
            stage_row += 1
            # v14: сразу под ИИ-гео — счётчик прозрачных узлов (утечка
            # SOCKS-пути: exit-IP узла == ваш IP). Зелёный — утечек нет.
            if stage_key == "ai_geo":
                leak = stage.get("leak_check")
                if isinstance(leak, dict) and leak.get("enabled"):
                    n_leak = int(leak.get("rejected", 0) or 0)
                    leak_color = (
                        str(theme.SUCCESS) if n_leak == 0 else str(theme.ERROR)
                    )
                    _add_row(
                        stage_row,
                        "Утечки exit-IP (прозрачные):",
                        f"{n_leak} узлов",
                        leak_color,
                    )
                    stage_row += 1

        # v13: из каких подписок собрана итоговая подписка.
        sources_report = report.get("sources_report")
        if isinstance(sources_report, dict) and sources_report.get("enabled"):
            contributed = sources_report.get("contributed", 0)
            total_src = sources_report.get("sources_total", 0)
            dead_src = sources_report.get("dead", 0)
            src_color = str(theme.SUCCESS) if contributed > 0 else str(theme.ERROR)
            _add_row(
                stage_row,
                "Подписок дали узлы:",
                f"{contributed} из {total_src} (мёртвых: {dead_src})",
                color=src_color,
            )
            stage_row += 1

        # Кнопки: детализация по источникам + закрытие.
        btn_row = stage_row
        if isinstance(sources_report, dict) and sources_report.get("enabled"):
            btn_sources = Button(
                dlg,
                text="📚 Из каких подписок собрано",
                bg=str(theme.SIDEBAR), fg=str(theme.TEXT),
                font=("Segoe UI", 10, "bold"),
                command=lambda: self._show_sources_dialog(sources_report),
            )
            btn_sources.grid(row=btn_row, column=0, columnspan=2, padx=20, pady=(12, 0), sticky="ew")
            btn_row += 1

        btn_close = Button(
            dlg, text="Закрыть", width=14,
            bg=str(theme.ACCENT), fg="#0C1014", font=("Segoe UI", 11, "bold"),
            command=dlg.destroy,
        )
        btn_close.grid(row=btn_row, column=0, columnspan=2, padx=20, pady=(16, 12))

    def _show_sources_dialog(self, sources_report: dict) -> None:
        """Детальный отчёт: из каких подписок собрана итоговая подписка."""
        import tkinter as tk
        from tkinter import Toplevel, Label, Button
        from tkinter import BOTH, BOTTOM, END, LEFT, RIGHT, Scrollbar, Text, X, Y

        dlg = Toplevel(self)
        dlg.title("📚 Из каких подписок собрано")
        dlg.transient(self)
        dlg.configure(bg=str(theme.BG))

        # DPI-масштаб (инцидент 2026-09-19): геометрия в физических
        # пикселях должна расти вместе с DPI, иначе шрифты в пунктах
        # перестают влезать в окно.
        k = self._dialog_scale()
        W = int(760 * k)
        H = int(560 * k)
        dlg.update_idletasks()
        sw = dlg.winfo_screenwidth()
        sh = dlg.winfo_screenheight()
        W = max(520, min(W, sw - 80))
        H = max(360, min(H, sh - 80))
        x = max(0, (sw - W) // 2)
        y = max(0, (sh - H) // 2)
        dlg.geometry(f"{W}x{H}+{x}+{y}")

        header = Label(
            dlg,
            text=(
                f"Итог собран из {sources_report.get('contributed', 0)} подписок — "
                f"{sources_report.get('nodes_total', 0)} узлов "
                f"(источников всего: {sources_report.get('sources_total', 0)})"
            ),
            bg=str(theme.BG), fg=str(theme.TEXT),
            font=("Segoe UI", 12, "bold"),
            anchor="w",
        )
        header.pack(fill=X, padx=16, pady=(14, 6))

        frame = tk.Frame(dlg, bg=str(theme.BG))
        frame.pack(fill=BOTH, expand=True, padx=16, pady=(0, 8))

        text = Text(
            frame, wrap="none", bg=str(theme.SIDEBAR), fg=str(theme.TEXT),
            insertbackground=str(theme.TEXT), relief="flat",
            font=("Consolas", 10), borderwidth=0, highlightthickness=0,
        )
        # Ориентации скроллов — строками "vertical"/"horizontal": валидны
        # и в tk 8.6 (сборки юзера), и в tk 9.x (константы Y/X запрещены).
        scroll_y = Scrollbar(frame, orient="vertical", command=text.yview)
        scroll_x = Scrollbar(frame, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        scroll_y.pack(side=RIGHT, fill=Y)
        scroll_x.pack(side=BOTTOM, fill=X)
        text.pack(side=LEFT, fill=BOTH, expand=True)

        contributed_color = "#7FD18A"      # тон темы: зелёный для давших узлы
        checked_only_color = "#E0B364"     # жёлтый: узлы были, до финала не дошли
        dead_color = str(theme.MUTED)      # серый: пустые/мёртвые

        text.tag_configure("hdr", foreground=str(theme.TEXT), font=("Consolas", 10, "bold"))
        text.tag_configure("ok", foreground=contributed_color)
        text.tag_configure("mid", foreground=checked_only_color)
        text.tag_configure("dead", foreground=dead_color)

        text.insert(END, "вклад   узлы→финал  отвалились                 подписка\n", "hdr")
        text.insert(END, "─" * 92 + "\n", "dead")
        entries = sources_report.get("nodes") or []

        def _lost_summary(entry: dict) -> str:
            """v15: компактная сводка «где отвалились узлы подписки».

            lost_at: {стадия: {причина: число}} — берём топ-2 стадии по
            числу потерь (quick 82, tg 5). Пусто → «—» (всё дожило).
            """
            lost = entry.get("lost_at") or {}
            if not isinstance(lost, dict) or not lost:
                return "—"
            stage_counts = []
            for stage, reasons in lost.items():
                if isinstance(reasons, dict):
                    stage_counts.append((str(stage), sum(int(v or 0) for v in reasons.values())))
            stage_counts.sort(key=lambda kv: -kv[1])
            parts = [f"{stage} {n}" for stage, n in stage_counts[:2]]
            return ", ".join(parts) if parts else "—"

        for e in entries:
            exported = int(e.get("exported", 0) or 0)
            found = int(e.get("discovered", 0) or 0)
            share = float(e.get("share_pct", 0.0) or 0.0)
            src = str(e.get("source", "?"))
            lost = _lost_summary(e)
            if exported > 0:
                tag, prefix = "ok", f"{share:5.1f}%  {found:>4}→{exported:<4}"
            elif found > 0:
                tag, prefix = "mid", f"  ---   {found:>4}→0   "
            else:
                tag, prefix = "dead", "  ---     0→0   "
            text.insert(END, f"{prefix} {lost:<24} {src}\n", tag)

        note = str(sources_report.get("note", "") or "")
        if note:
            text.insert(END, "\n" + note + "\n", "dead")

        text.configure(state="disabled")

        btn_close = Button(
            dlg, text="Закрыть", width=14,
            bg=str(theme.ACCENT), fg="#0C1014", font=("Segoe UI", 11, "bold"),
            command=dlg.destroy,
        )
        btn_close.pack(pady=(2, 14))


    # ------------------------------------------------------------ sidebar
    def _build_sidebar(self) -> None:
        self.sidebar = ctk.CTkFrame(
            self, width=220, corner_radius=0, fg_color=theme.SIDEBAR,
        )
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsw")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)

        # Лого
        logo = ctk.CTkLabel(
            self.sidebar, text="SubGenerator",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=theme.TEXT,
        )
        logo.grid(row=0, column=0, padx=16, pady=(24, 2), sticky="w")

        logo_sub = ctk.CTkLabel(
            self.sidebar, text="находит рабочие VPN-конфиги",
            text_color=theme.MUTED,
            font=ctk.CTkFont(size=11),
        )
        logo_sub.grid(row=1, column=0, padx=16, pady=(0, 26), sticky="w")

        # Разделитель
        sep = ctk.CTkFrame(self.sidebar, height=1, fg_color=theme.BORDER)
        sep.grid(row=2, column=0, padx=14, sticky="ew")

        # v17 (запрос юзера): меню — всего 4 пункта: Запуск / Мои
        # подписки / Перепроверка / Настройки. Бывшие «Импорт» и «Фильтры» —
        # вкладки страницы «Мои подписки»; «Диагностика» и «Журнал» — вкладки
        # «Настроек». Порядок — как ими пользуются.
        self.btn_start = self._nav_button(3, "🚀 Запуск", "start")
        self.btn_sources = self._nav_button(4, "📚 Мои подписки", "sources")
        self.btn_recheck = self._nav_button(5, "🔁 Перепроверка", "recheck")
        self.btn_settings = self._nav_button(6, "⚙ Настройки", "settings")

        self._nav_buttons = {
            "start": self.btn_start,
            "sources": self.btn_sources,
            "recheck": self.btn_recheck,
            "settings": self.btn_settings,
        }

    def _nav_button(self, row, text, page) -> ctk.CTkButton:
        btn = ctk.CTkButton(
            self.sidebar,
            text=text,
            anchor="w",
            height=40,
            corner_radius=8,
            fg_color="transparent",
            hover_color=theme.CARD_ALT,
            text_color=theme.TEXT,
            font=ctk.CTkFont(size=14),
            command=lambda: self._show_page(page),
        )
        btn.grid(row=row, column=0, padx=10, pady=3, sticky="ew")
        return btn

    # ------------------------------------------------------------ pages
    # v17: бывшие отдельные страницы — вкладки: «Импорт»/«Фильтры» внутри
    # «Мои подписки», «Диагностика»/«Журнал» внутри «Настройки». Ключи
    # import/filters/diag/log остаются рабочими (алиасы) — весь старый код
    # навигации (_show_page("import") и т.д.) продолжает работать.
    _PAGE_ALIASES = {
        "import": ("sources", "import"),
        "filters": ("sources", "filters"),
        "diag": ("settings", "diag"),
        "log": ("settings", "log"),
    }

    def _build_pages(self) -> None:
        self.pages_frame = ctk.CTkFrame(self, fg_color=theme.BG)
        self.pages_frame.grid(row=0, column=1, sticky="nsew")
        self.pages_frame.grid_columnconfigure(0, weight=1)
        self.pages_frame.grid_rowconfigure(0, weight=1)

        self.page_start = StartPage(self.pages_frame, self)
        self.page_mysubs = MySubsPage(self.pages_frame, self)
        self.page_settings_root = SettingsRootPage(self.pages_frame, self)
        self.page_recheck = RecheckPage(self.pages_frame, self)

        # Ссылки на дочерние страницы-вкладки — ВЕСЬ существующий код
        # (page_sources.get_sources, page_log.append_log, …) не меняется.
        self.page_sources = self.page_mysubs.list_tab
        self.page_import = self.page_mysubs.import_tab
        self.page_filters = self.page_mysubs.filters_tab
        self.page_settings = self.page_settings_root.basic_tab
        self.page_diag = self.page_settings_root.diag_tab
        self.page_log = self.page_settings_root.log_tab

        self.pages = {
            "start": self.page_start,
            "sources": self.page_mysubs,
            "recheck": self.page_recheck,
            "settings": self.page_settings_root,
        }

        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

    def _show_page(self, name: str) -> None:
        # Алиасы вкладок: показываем страницу-контейнер + включаем вкладку.
        # Прямой клик по пункту меню открывает вкладку ПО УМОЛЧАНИЮ
        # («Список» / «Основные») — предсказуемо для новичка; навигация
        # кнопками-ссылками (напр. «⬇ Импорт…») открывает нужную вкладку.
        target, tab = self._PAGE_ALIASES.get(name, (name, None))
        page = self.pages[target]
        if target == "sources":
            show_tab = getattr(page, "show_tab", None)
            if show_tab is not None:
                show_tab(tab or "sources")
        elif target == "settings":
            show_tab = getattr(page, "show_tab", None)
            if show_tab is not None:
                show_tab(tab or "basic")
        elif tab is not None:
            show_tab = getattr(page, "show_tab", None)
            if show_tab is not None:
                show_tab(tab)
        page.tkraise()
        # v16: при показе главной — обновить счётчик подписок в режиме «Просто»
        # (мог измениться со страницы «Мои подписки»).
        if target == "start":
            try:
                self.page_start.refresh_novice()
            except Exception:
                pass
        # При показе страницы перепроверки обновляем доступность этапов
        # (после завершения прогона кеш мог появиться).
        if target == "recheck":
            self.page_recheck.refresh_availability()
        # v17: при показе «Мои подписки» — обновить список файлов импорта.
        if target == "sources":
            try:
                self.page_mysubs.on_shown()
            except Exception:
                pass

        for key, btn in self._nav_buttons.items():
            active = key == target
            btn.configure(
                fg_color=theme.ACCENT_SOFT if active else "transparent",
                text_color=theme.ACCENT_HOVER if active else theme.TEXT,
            )
            if active:
                btn.configure(
                    border_width=1,
                    border_color=theme.ACCENT,
                )
            else:
                btn.configure(border_width=0)


    # ------------------------------------------------------------ footer
    def _build_footer(self) -> None:


        self.footer = ctk.CTkFrame(self, fg_color=theme.BG_ALT, corner_radius=0)
        self.footer.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.footer.grid_columnconfigure(0, weight=1)

        self.progress = ctk.CTkProgressBar(self.footer, height=5)
        self.progress.grid(row=0, column=0, columnspan=2, padx=0, pady=0, sticky="ew")
        self.progress.set(0)

        inner = ctk.CTkFrame(self.footer, fg_color="transparent")
        inner.grid(row=1, column=0, columnspan=2, padx=16, pady=(6, 8), sticky="ew")
        inner.grid_columnconfigure(0, weight=1)

        # Процентовка (широкий явный индикатор).
        self.lbl_progress = ctk.CTkLabel(
            inner, text="Готов к работе.", anchor="w",
            text_color=theme.MUTED, font=ctk.CTkFont(size=12),
        )
        self.lbl_progress.grid(row=0, column=0, sticky="w")

        # Подсказка: запуск происходит в отдельном окне PowerShell.
        self.lbl_hint = ctk.CTkLabel(
            inner, text="Проверка идёт в отдельном окне консоли — не закрывайте его",
            text_color=theme.MUTED, anchor="e",
            font=ctk.CTkFont(size=11),
        )
        self.lbl_hint.grid(row=0, column=1, columnspan=2, padx=(8, 6), sticky="e")

        self.lbl_status = ctk.CTkLabel(
            inner, text="", text_color=theme.INFO, anchor="e",
            font=ctk.CTkFont(size=12),
        )
        self.lbl_status.grid(row=0, column=3, padx=(10, 0), sticky="e")
        CTkToolTip(self.lbl_status, "Статус последнего действия")

    # ------------------------------------------------------------ status
    def show_status(self, message: str, error: bool = False) -> None:
        self.lbl_status.configure(
            text=message,
            text_color=theme.ERROR if error else theme.INFO,
        )

    def _set_progress(self, pct: int, message: str) -> None:
        self.progress.set(max(0.0, min(100, pct)) / 100.0)
        self.lbl_progress.configure(text=f"{pct}% — {message}")

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.page_start.set_running(busy)
        self.page_mysubs.set_busy(busy)
        self.page_recheck.set_busy(busy)
        self.page_settings_root.set_busy(busy)


    # ------------------------------------------------------------ actions
    def on_start_clicked(self) -> None:
        if self._busy:
            self.show_status("Уже выполняется задача — дождитесь завершения.", error=True)
            return
        options = self.page_start.get_options()
        # Сохраняем настройки тестирования (workers, timeout, тумблеры),
        # чтобы при следующем запуске пользователь получил те же значения.
        # Вкладка «Фильтры» сохраняет свои ключи отдельно (merge — ключи
        # этой страницы не затираются).
        self.page_start.save_current_settings()
        self.page_filters.save_current_settings()
        # start_stage берём со страницы «Перепроверка».
        options.start_stage = self.page_recheck.get_start_stage()
        sources = self.page_sources.get_sources()

        # Перепроверка с этапа возможна только после хотя бы одного полного прогона
        # (пинг + стресс-тест), результаты которого сохранены в кеше.
        if options.start_stage != "ping" and not self.page_recheck.has_cached_working():
            messagebox.showwarning(
                "Перепроверка недоступна",
                "Проверка ещё не проводилась. Сначала запустите полный прогон "
                "(пинг и стресс-тест), чтобы появилась возможность перепроверки с этапа.",
            )
            self._show_page("recheck")
            return

        # Кастомный файл конфигов (страница «Тестирование») заменяет подписки:
        # можно запускать проверку вообще без sources.txt.
        if not sources and not options.custom_file:
            self.show_status("Список подписок пуст. Добавьте их на странице «Мои подписки».", error=True)
            self._show_page("sources")
            return


        # Сохраняем актуальный список подписок перед запуском.
        if sources:
            self._save_sources_silent(sources)


        args = build_pipeline_args(options, sources)
        # В собранной сборке ps1 лежит рядом с exe, в исходниках — в scripts/.
        launcher = paths.app_root() / "run_sub_generator.ps1"
        if not launcher.exists():
            launcher = paths.scripts_dir() / "run_sub_generator.ps1"

        if not launcher.exists():
            self.show_status(
                f"Не найден {launcher.name} рядом с приложением. "
                "Пересоберите сборку (build_release.bat).",
                error=True,
            )
            return


        self.show_status("Запускаем PowerShell…")
        self.update_idletasks()

        # PowerShell 5.1 НЕ поддерживает "--" как разделитель аргументов после
        # -Command (в отличие от pwsh 7): "--" склеивается с командой и парсер
        # падает, а окно закрывается мгновенно. Поэтому аргументы передаём через
        # переменную окружения SUB_GEN_ARGS (JSON-массив строк), а в -Command
        # только вызываем скрипт.
        #
        # Пауза Read-Host находится в finally, поэтому она выполнится ВСЕГДА —
        # даже если сам скрипт упадёт с ошибкой. Это гарантирует, что окно не
        # закроется, пока пользователь не нажмёт Enter.
        import json as _json

        env = dict(os.environ)
        env["SUB_GEN_ARGS"] = _json.dumps(args, ensure_ascii=False)

        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            (
                f"try {{ & '{launcher}' }} "
                "catch { Write-Host \"Ошибка: $($_.Exception.Message)\" -ForegroundColor Red; "
                "$global:SubGenExitCode = 1 } "
                "finally { Write-Host ''; "
                "Write-Host '=== Готово. Нажмите Enter, чтобы закрыть окно ===' -ForegroundColor DarkGray; "
                "Read-Host }"
            ),
        ]



        try:
            subprocess.Popen(
                cmd,
                cwd=str(paths.app_root()),
                env=env,
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
        except OSError as exc:
            self.show_status(f"Не удалось запустить PowerShell: {exc}", error=True)
            return

        # GUI закрывается — дальше работает отдельное окно PowerShell.
        self.destroy()


    def on_cleanup_clicked(self) -> None:
        working_path = self.data_dir / ".runtime_cache" / "xray_working.json"
        rejected_path = self.data_dir / ".runtime_cache" / "xray_rejected.json"
        if not working_path.exists() and not rejected_path.exists():
            self.show_status("Нет данных прошлых прогонов. Сначала запустите тестирование.", error=True)
            return

        sources = self.page_sources.get_sources()
        kept, removed = filter_sources_by_history(sources, working_path, rejected_path)
        self.page_log.append_log(f"[отсев] Всего подписок: {len(sources)}, оставлено: {len(kept)}, удалено: {len(removed)}")
        for u in removed:
            self.page_log.append_log(f"[отсев]  - удалена: {u}")
        if removed:
            self.page_sources.set_sources(kept)
            self._save_sources_silent(kept)
            self.show_status(f"Отсеяно подписок: {len(removed)}. Сохранено в sources.txt.")
        else:
            self.show_status("Мусорных подписок не найдено — все подписки живые.")

    def _save_sources_silent(self, urls: list[str]) -> None:
        try:
            self.sources_file.write_text(
                "\n".join(urls) + ("\n" if urls else ""),
                encoding="utf-8",
            )
        except OSError as exc:
            self.show_status(f"Не удалось сохранить sources.txt: {exc}", error=True)

    def on_liveness_clicked(self) -> None:
        if self._busy:
            self.show_status("Уже выполняется задача — дождитесь завершения.", error=True)
            return
        sources = self.page_sources.get_sources()
        if not sources:
            self.show_status("Список подписок пуст. Добавьте подписки.", error=True)
            return

        self._set_busy(True)
        self.page_log.clear_log()
        self._set_progress(0, "проверка живучести…")
        self._show_page("log")
        self.show_status("Проверка живучести подписок…")

        threading.Thread(
            target=self._liveness_worker,
            args=(list(sources),),
            daemon=True,
            name="liveness-check",
        ).start()

    def _liveness_worker(self, sources: list[str]) -> None:
        from subgen.refresh import run_refresh

        try:
            start = time.perf_counter()
            log_sink = lambda msg: self._post(lambda: self._handle_live_log(msg))
            working, rejected, discovered = run_refresh(
                sources,
                timeout=15.0,
                workers=16,
                max_servers=0,
                stress=False,
                log_sink=log_sink,
                progress=None,
                min_speed_kbps=0.0,
                cancel_event=self.runner.cancel_event,
                pause_event=self.runner.pause_event,
            )
            elapsed = time.perf_counter() - start
            self._post(lambda: self._liveness_done(working, rejected, discovered, elapsed))
        except RuntimeError as exc:
            if "refresh_cancelled" in str(exc):
                self._post(lambda: self.show_status("Проверка живучести остановлена."))
            else:
                traceback.print_exc()
                _err = f"Ошибка проверки живучести: {exc}"
                self._post(lambda: self.show_status(_err, error=True))
        except Exception as exc:
            traceback.print_exc()
            _err = f"Ошибка проверки живучести: {exc}"
            self._post(lambda: self.show_status(_err, error=True))

        finally:
            self._post(lambda: self._set_busy(False))

    def _handle_live_log(self, msg: str) -> None:
        self.page_log.append_log(msg)
        low = msg.lower()
        if "загрузка" in low or "ping" in low:
            self.lbl_progress.configure(text=f"… {msg[:90]}")

    def _liveness_done(self, working, rejected, discovered, elapsed: float) -> None:
        alive_urls: set[str] = {w.node.source_url for w in working if w.node.source_url}
        alive_urls |= {r.node.source_url for r in rejected if r.node.source_url and r.latency_ms is not None}

        total = self.page_sources.get_sources()
        # Подписки, реально отдавшие узлы при импорте (импорт прошёл успешно).
        imported_urls: set[str] = {n.source_url for n in discovered if n.source_url}
        # Импортировалась, но ни один узел не прошёл пинг/telegram-проверку.
        imported_dead = sorted(imported_urls - alive_urls)
        # Не отдала ни одного узла: сеть/404/пустое тело/битый URL.
        failed = sorted({u for u in total if u not in imported_urls})
        dead = sorted({u for u in total if u not in alive_urls})

        self.page_log.append_log("─" * 96)
        self.page_log.append_log(
            f"[живучесть] Завершено за {elapsed:.1f} сек: подписок {len(total)}, "
            f"живых {len(alive_urls)}, импортировалось но без живых {len(imported_dead)}, "
            f"не импортировалось/пустых {len(failed)}"
        )
        for u in sorted(alive_urls):
            self.page_log.append_log(f"✓ живая: {u}")
        for u in imported_dead:
            self.page_log.append_log(f"✗ импортировалась, но без живых конфигов: {u}")
        for u in failed:
            self.page_log.append_log(f"✗ не импортировалась/пустая: {u}")
        if dead:
            self.page_log.append_log("Совет: удалите мёртвые подписки кнопкой «🧹 Убрать мёртвые…» на странице «Мои подписки».")

        self._set_progress(100, "проверка живучести завершена")
        self.show_status(f"Живых подписок: {len(alive_urls)} из {len(total)}")


    def on_export_clicked(self) -> None:
        if self._busy:
            self.show_status("Уже выполняется задача — дождитесь завершения.", error=True)
            return
        sources = self.page_sources.get_sources()
        if not sources:
            self.show_status("Список подписок пуст. Добавьте подписки.", error=True)
            return

        self._set_busy(True)
        self.page_log.clear_log()
        self._set_progress(0, "Экспорт конфигов…")
        self._show_page("log")
        self.show_status("Экспорт конфигов из подписок…")
        self.page_log.append_log("[экспорт] Инициализация экспорта...")

        def _export_worker():
            import traceback
            try:
                from types import SimpleNamespace

                from xray_runtime import collect_subscription_nodes

                def _log(msg: str) -> None:
                    self._post(lambda: self.page_log.append_log(msg))

                def _progress(index: int, total: int, url: str) -> None:
                    pct = int(index / total * 40) if total else 0
                    short = (url or "").split("/")[-1][:48] if url else ""
                    self._post(lambda: self._set_progress(pct, f"Загрузка подписок {index}/{total} {short}"))

                self._post(lambda: self.page_log.append_log("[экспорт] Начало загрузки подписок..."))

                # Тот же синхронный fetch-код, что используется в начале теста:
                # collect_subscription_nodes сам многопоточно собирает узлы.
                discovered = collect_subscription_nodes(
                    sources,
                    timeout=30.0,
                    max_servers=0,
                    log_sink=_log,
                    on_progress=_progress,
                    cancel_event=self.runner.cancel_event,
                    pause_event=self.runner.pause_event,
                )
                self._post(lambda: self.page_log.append_log(f"[экспорт] Загружено {len(discovered)} узлов"))
                self._post(lambda: self._set_progress(50, f"Загружено {len(discovered)} узлов"))

                # Дедупликация по node.key (protocol/host/port/sha256(normalized-url)),
                # а не по raw_url — два узла с разным порядком query-параметров
                # или разными именами считаются одним конфигом.
                # node.key уже отдалён collect_subscription_nodes (дедупликация на
                # уровне сбора), но all_configs = set() был по raw_url — некорректно.
                all_configs: dict[tuple, str] = {}  # node.key → uri
                per_source: dict[str, int] = {}
                for node in discovered:
                    uri = getattr(node, "raw_url", "") or (
                        node.to_uri() if hasattr(node, "to_uri") else ""
                    )
                    if uri:
                        all_configs[node.key] = uri
                    source = getattr(node, "source_url", "") or "unknown"
                    per_source[source] = per_source.get(source, 0) + 1

                # Блок «Конфиги по подпискам» на странице лога.
                stats = [
                    SimpleNamespace(
                        url=source,
                        discovered=count,
                        ping_passed=0,
                        working=count,
                        rejected=0,
                    )
                    for source, count in sorted(per_source.items())
                ]
                self._post(lambda s=stats: self.page_log.set_stats(s))

                unique_configs = sorted(all_configs.values())
                self._post(lambda: self.page_log.append_log(f"[экспорт] Собрано {len(unique_configs)} уникальных конфигов"))
                for source, count in sorted(per_source.items()):
                    self._post(lambda src=source, cnt=count: self.page_log.append_log(f"[экспорт]  - {src}: {cnt} конфигов"))
                self._post(lambda: self._set_progress(80, f"Собрано {len(unique_configs)} конфигов"))

                export_path = paths.app_root() / "preload.txt"
                try:
                    export_path.write_text("\n".join(unique_configs) + ("\n" if unique_configs else ""), encoding="utf-8")
                    self._post(lambda: self.show_status(f"Экспортировано {len(unique_configs)} конфигов в {export_path}"))
                    self._post(lambda: self.page_log.append_log(f"[экспорт] Сохранено {len(unique_configs)} конфигов в {export_path}"))
                    self._post(lambda: self._set_progress(100, "Экспорт завершён"))
                except Exception as e:
                    _err = f"Ошибка сохранения: {e}"
                    self._post(lambda: self.show_status(_err, error=True))
                    self._post(lambda: self.page_log.append_log(f"[экспорт] {_err}"))
            except Exception as e:
                _err = f"Ошибка экспорта: {e}"
                self._post(lambda: self.show_status(_err, error=True))
                self._post(lambda: self.page_log.append_log(f"[экспорт] {_err}"))
                tb = traceback.format_exc()
                self._post(lambda: self.page_log.append_log(f"[экспорт] Трассировка:\n{tb}"))
            finally:
                self._post(lambda: self._set_busy(False))

        threading.Thread(target=_export_worker, daemon=True).start()

    def on_combined_clicked(self) -> None:
        # Сначала отсеять мусорные подписки, затем проверить живучесть оставшихся.
        self.on_cleanup_clicked()
        self.on_liveness_clicked()

    # ------------------------------------------------------------ helpers
    def _post(self, fn) -> None:
        """Отложить вызов в поток Tk из фонового потока."""
        try:
            self.after_idle(fn)
        except Exception as exc:
            # Окно уже разрушено — отложенный вызов не нужен; это штатный
            # путь при закрытии приложения во время фонового конвейера.
            _logger.debug("_post пропущен (окно закрыто): %s", exc)

    # ------------------------------------------------------------ close
    def _on_close(self) -> None:
        try:
            self.runner.stop()
        except Exception as exc:
            # Сбой остановки конвейера = возможные живые потоки/ядра после
            # закрытия окна — предупреждаем, а не молчим.
            _logger.warning("остановка конвейера при закрытии не удалась: %s", exc)
        self.destroy()
