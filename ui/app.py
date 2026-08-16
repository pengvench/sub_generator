"""Главное окно SubGenerator (customtkinter, Material-тема как ZapretUI)."""
from __future__ import annotations

import os
import subprocess
import threading
import time
import traceback
from tkinter import messagebox


import customtkinter as ctk


from . import paths, theme
from .pages.log_page import LogPage
from .pages.settings_page import SettingsPage
from .pages.sources_page import SourcesPage
from .pages.start_page import StartPage

from .runner import PipelineRunner, build_pipeline_args, filter_sources_by_history
from .tooltip import CTkToolTip

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
        # Иконка окна (titlebar) — из каталога рядом с exe / корня проекта.
        try:
            icon_path = paths.app_root() / "icon.ico"
            if icon_path.exists():
                self.iconbitmap(str(icon_path))
        except Exception:
            pass
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
        self.btn_log = self._nav_button(5, "📊 Лог", "log")
        self.btn_settings = self._nav_button(6, "⚙ Настройки", "settings")

        self._nav_buttons = {
            "start": self.btn_start,
            "sources": self.btn_sources,
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
        self.page_log = LogPage(self.pages_frame, self)
        self.page_settings = SettingsPage(self.pages_frame, self)

        self.pages = {
            "start": self.page_start,
            "sources": self.page_sources,
            "log": self.page_log,
            "settings": self.page_settings,
        }

        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

    def _show_page(self, name: str) -> None:
        page = self.pages[name]
        page.tkraise()
        # При показе страницы настроек обновляем доступность этапов перепроверки
        # (после завершения прогона кеш мог появиться).
        if name == "settings":
            self.page_settings.refresh_stage_availability()
        # При показе страницы тестирования обновляем доступность тумблера
        # запуска с сохранённого кеша (появляется после первого полного прогона).
        if name == "start":
            self.page_start.refresh_cache_toggle()

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
        self.page_log.set_busy(busy)
        self.page_settings.set_busy(busy)


    # ------------------------------------------------------------ actions
    def on_start_clicked(self) -> None:
        if self._busy:
            self.show_status("Уже выполняется задача — дождитесь завершения.", error=True)
            return
        options = self.page_start.get_options()
        options.start_stage = self.page_settings.get_start_stage()
        # Тумблер «С сохранённого кеша»: не повторяем пинг и стресс-тест,
        # проверки идут с сохранённых конфигов (data/.runtime_cache).
        if options.use_cache and options.start_stage == "ping":
            # В настройках выбран полный прогон — при включённом тумблере
            # начинаем с DPI-проверки, чтобы прогнать все остальные этапы.
            options.start_stage = "dpi"
        sources = self.page_sources.get_sources()

        # Перепроверка с этапа возможна только после хотя бы одного полного прогона
        # (пинг + стресс-тест), результаты которого сохранены в кеше.
        if options.start_stage != "ping" and not self.page_settings.has_cached_working():

            messagebox.showwarning(
                "Перепроверка недоступна",
                "Проверка ещё не проводилась. Сначала запустите полный прогон "
                "(пинг и стресс-тест), чтобы появилась возможность перепроверки с этапа.",
            )
            self._show_page("settings")
            return

        if not sources:
            self.show_status("Список подписок пуст. Добавьте подписки на странице «Подписки».", error=True)
            self._show_page("sources")
            return


        # Сохраняем актуальный список подписок перед запуском.
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
                self._post(lambda: self.show_status(f"Ошибка проверки живучести: {exc}", error=True))
        except Exception as exc:
            traceback.print_exc()
            self._post(lambda: self.show_status(f"Ошибка проверки живучести: {exc}", error=True))

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
        dead = {u for u in total if u not in alive_urls}

        self.page_log.append_log("─" * 96)
        self.page_log.append_log(
            f"[живучесть] Завершено за {elapsed:.1f} сек: "
            f"подписок {len(total)}, живых {len(alive_urls)}, мёртвых/пустых {len(dead)}"
        )
        for u in sorted(dead):
            self.page_log.append_log(f"✗ не отдала живых конфигов: {u}")
        for u in sorted(alive_urls):
            self.page_log.append_log(f"✓ живая: {u}")
        if dead:
            self.page_log.append_log("Совет: удалите мёртвые подписки кнопкой «🧹 Отсеять мусорные» на странице «Подписки».")

        self._set_progress(100, "проверка живучести завершена")
        self.show_status(f"Живых подписок: {len(alive_urls)} из {len(total)}")

    # ------------------------------------------------------------ helpers
    def _post(self, fn) -> None:
        """Отложить вызов в поток Tk из фонового потока."""
        try:
            self.after_idle(fn)
        except Exception:
            pass

    # ------------------------------------------------------------ close
    def _on_close(self) -> None:
        try:
            self.runner.stop()
        except Exception:
            pass
        self.destroy()
