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
from .pages.log_page import LogPage
from .pages.recheck_page import RecheckPage
from .pages.settings_page import SettingsPage
from .pages.sources_page import SourcesPage
from .pages.start_page import StartPage
from .pages.diag_page import DiagPage
from .pages.import_page import ImportPage

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

    def _show_results_dialog(self, report: dict) -> None:
        """Показать модальное окно с результатами прогона."""
        from tkinter import Toplevel, Label, Button

        dlg = Toplevel(self)
        dlg.title("📊 Результаты прогона")
        dlg.geometry("520x560")
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.configure(bg=str(theme.BG))

        # Центрируем окно.
        dlg.update_idletasks()
        sw = dlg.winfo_screenwidth()
        sh = dlg.winfo_screenheight()
        x = (sw - 520) // 2
        y = (sh - 560) // 2
        dlg.geometry(f"520x560+{x}+{y}")

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

        sep = Label(dlg, text="─" * 60, bg=str(theme.BG), fg=str(theme.BORDER))
        sep.grid(row=7, column=0, columnspan=2, padx=20, pady=(10, 4), sticky="ew")

        # Этапы с количеством прошедших/отбракованных.
        stage_row = 8
        for stage_key, stage_label in [
            ("initial_check", "Initial check"),
            ("dpi", "DPI-проверка"),
            ("dpi_active", "DPI-актив"),
            ("telegram_pro", "Telegram-PRO"),
            ("ai_geo", "ИИ-гео (Gemini/OpenAI)"),
            ("route", "Route"),
            ("resilience", "Resilience"),
            ("recheck", "Финальный спидтест"),
        ]:
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


        # Кнопки.
        btn_close = Button(
            dlg, text="Закрыть", width=14,
            bg=str(theme.ACCENT), fg="#0C1014", font=("Segoe UI", 11, "bold"),
            command=dlg.destroy,
        )
        btn_close.grid(row=stage_row, column=0, columnspan=2, padx=20, pady=(16, 12))


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
            self.sidebar, text="конфиги из подписок",
            text_color=theme.MUTED,
            font=ctk.CTkFont(size=11),
        )
        logo_sub.grid(row=1, column=0, padx=16, pady=(0, 26), sticky="w")

        # Разделитель
        sep = ctk.CTkFrame(self.sidebar, height=1, fg_color=theme.BORDER)
        sep.grid(row=2, column=0, padx=14, sticky="ew")

        self.btn_start = self._nav_button(3, "▶ Тестирование", "start")
        self.btn_sources = self._nav_button(4, "📚 Подписки", "sources")
        self.btn_import = self._nav_button(5, "📥 Импорт", "import")
        self.btn_recheck = self._nav_button(6, "🔁 Перепроверка", "recheck")
        self.btn_diag = self._nav_button(7, "🔬 Диагностика", "diag")
        self.btn_log = self._nav_button(8, "📊 Лог", "log")
        self.btn_settings = self._nav_button(9, "⚙ Настройки", "settings")

        self._nav_buttons = {
            "start": self.btn_start,
            "sources": self.btn_sources,
            "import": self.btn_import,
            "recheck": self.btn_recheck,
            "diag": self.btn_diag,
            "log": self.btn_log,
            "settings": self.btn_settings,
        }


        # Низ сайдбара: версия/источник
        foot = ctk.CTkLabel(
            self.sidebar,
            text=f"sources.txt · data/\nsubs.txt — рядом с exe",
            text_color=theme.MUTED,
            font=ctk.CTkFont(size=10),
            justify="left",
        )
        foot.grid(row=10, column=0, padx=16, pady=16, sticky="sw")

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
    def _build_pages(self) -> None:
        self.pages_frame = ctk.CTkFrame(self, fg_color=theme.BG)
        self.pages_frame.grid(row=0, column=1, sticky="nsew")
        self.pages_frame.grid_columnconfigure(0, weight=1)
        self.pages_frame.grid_rowconfigure(0, weight=1)

        self.page_start = StartPage(self.pages_frame, self)
        self.page_sources = SourcesPage(self.pages_frame, self)
        self.page_import = ImportPage(self.pages_frame, self)
        self.page_recheck = RecheckPage(self.pages_frame, self)
        self.page_diag = DiagPage(self.pages_frame, self)
        self.page_log = LogPage(self.pages_frame, self)
        self.page_settings = SettingsPage(self.pages_frame, self)

        self.pages = {
            "start": self.page_start,
            "sources": self.page_sources,
            "import": self.page_import,
            "recheck": self.page_recheck,
            "diag": self.page_diag,
            "log": self.page_log,
            "settings": self.page_settings,
        }

        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

    def _show_page(self, name: str) -> None:
        page = self.pages[name]
        page.tkraise()
        # При показе страницы перепроверки обновляем доступность этапов
        # (после завершения прогона кеш мог появиться).
        if name == "recheck":
            self.page_recheck.refresh_availability()

        for key, btn in self._nav_buttons.items():
            active = key == name
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
            inner, text="Запуск откроет PowerShell и закроет окно",
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
        self.page_sources.set_busy(busy)
        self.page_recheck.set_busy(busy)
        self.page_diag.set_busy(busy)
        self.page_log.set_busy(busy)
        self.page_settings.set_busy(busy)


    # ------------------------------------------------------------ actions
    def on_start_clicked(self) -> None:
        if self._busy:
            self.show_status("Уже выполняется задача — дождитесь завершения.", error=True)
            return
        options = self.page_start.get_options()
        # Сохраняем настройки тестирования (workers, timeout, тумблеры),
        # чтобы при следующем запуске пользователь получил те же значения.
        self.page_start.save_current_settings()
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
            self.show_status("Список подписок пуст. Добавьте подписки на странице «Подписки».", error=True)
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
            self.page_log.append_log("Совет: удалите мёртвые подписки кнопкой «🧹 Отсеять мусорные» на странице «Подписки».")

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
