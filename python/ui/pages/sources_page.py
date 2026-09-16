"""Страница «Подписки» — управление списком подписок (Material)."""
from __future__ import annotations

import logging

import tkinter as tk

import customtkinter as ctk

from .. import theme
from ..tooltip import CTkToolTip

_logger = logging.getLogger(__name__)


class SourcesPage(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self._sources: list[str] = []
        self._use_saved_subs = True  # toggle: auto-merge saved_subs into sources
        self.configure(fg_color=theme.BG)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)  # textbox (list) is expandable

        header = ctk.CTkLabel(
            self, text="Подписки",
            font=ctk.CTkFont(size=22, weight="bold"), text_color=theme.TEXT,
        )
        header.grid(row=0, column=0, padx=24, pady=(22, 0), sticky="w")
        sub = ctk.CTkLabel(
            self,
            text="Управляйте списком подписок. Файл: sources.txt (рядом с приложением).",
            text_color=theme.MUTED, font=ctk.CTkFont(size=12),
        )
        sub.grid(row=1, column=0, padx=24, pady=(2, 16), sticky="w")

        # ---------------- Добавление / удаление ----------------
        add_frame = ctk.CTkFrame(self, fg_color=theme.CARD, corner_radius=10,
                                 border_width=1, border_color=theme.BORDER)
        add_frame.grid(row=2, column=0, padx=24, pady=(0, 12), sticky="ew")
        add_frame.grid_columnconfigure(0, weight=1)

        self.entry_url = ctk.CTkEntry(
            add_frame,
            placeholder_text="Вставьте ссылку на подписку (URL)…",
        )
        self.entry_url.grid(row=0, column=0, padx=14, pady=12, sticky="ew")
        self.entry_url.bind("<Return>", lambda _e: self._add_urls())
        # Ctrl+V в поле ввода: привязка на внутренний tk.Entry
        # (widget-level binding срабатывает раньше стандартных обработчиков).
        self.entry_url._entry.bind("<Control-KeyPress>", self._on_entry_ctrl_key)

        CTkToolTip(self.entry_url, "Ссылка на подписку. Enter — добавить.")






        self.btn_add = ctk.CTkButton(
            add_frame, text="+ Добавить", width=110,
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            text_color="#0C1014", command=self._add_urls,
        )
        self.btn_add.grid(row=0, column=1, padx=(0, 8), pady=12)
        CTkToolTip(self.btn_add, "Добавить.")

        self.btn_remove = ctk.CTkButton(
            add_frame, text="− Удалить", width=110,
            fg_color=theme.DANGER, hover_color=theme.DANGER_HOVER,
            command=self._remove_selected,
        )
        self.btn_remove.grid(row=0, column=2, padx=(0, 14), pady=12)
        CTkToolTip(self.btn_remove, "Удалить выделенные.")

        # ---------------- Список ----------------
        self.list_frame = ctk.CTkFrame(self, fg_color=theme.CARD, corner_radius=10,
                                       border_width=1, border_color=theme.BORDER)
        self.list_frame.grid(row=3, column=0, padx=24, pady=(0, 12), sticky="nsew")
        self.list_frame.grid_columnconfigure(0, weight=1)
        self.list_frame.grid_rowconfigure(1, weight=1)

        header_row = ctk.CTkFrame(self.list_frame, fg_color="transparent")
        header_row.grid(row=0, column=0, padx=14, pady=(10, 6), sticky="ew")
        header_row.grid_columnconfigure(0, weight=1)

        self.lbl_list_title = ctk.CTkLabel(header_row, text="Список подписок:", anchor="w", text_color=theme.TEXT)
        self.lbl_list_title.grid(row=0, column=0, sticky="w")

        self.lbl_count = ctk.CTkLabel(header_row, text="0", text_color=theme.INFO)
        self.lbl_count.grid(row=0, column=1, sticky="e")

        self.textbox = ctk.CTkTextbox(
            self.list_frame, font=ctk.CTkFont(family=theme.FONT_MONO, size=12),
            wrap="none", state="disabled",
        )
        self.textbox.grid(row=1, column=0, padx=14, pady=(0, 14), sticky="nsew")
        # Ctrl+C/A в списке: привязка на внутренний tk.Text
        # (widget-level binding срабатывает раньше стандартных обработчиков).
        self.textbox._textbox.bind("<Control-KeyPress>", self._on_text_ctrl_key)






        # ---------------- Тумблер: импортированные подписки ----------------
        toggle_frame = ctk.CTkFrame(self, fg_color=theme.CARD, corner_radius=10,
                                    border_width=1, border_color=theme.BORDER)
        toggle_frame.grid(row=4, column=0, padx=24, pady=(0, 12), sticky="ew")
        toggle_frame.grid_columnconfigure(1, weight=1)

        self.chk_saved_subs = ctk.CTkSwitch(
            toggle_frame,
            text="Использовать импортированные подписки (data/saved_subs/)",
            command=self._on_saved_subs_toggle,
        )
        self.chk_saved_subs.grid(row=0, column=0, padx=14, pady=10, sticky="w")
        self.chk_saved_subs.select()  # ON by default
        CTkToolTip(self.chk_saved_subs,
                   "Включить/выключить авто-загрузку файлов из data/saved_subs/ "
                   "(вкладка «Импорт»). При включении — они добавляются к sources.txt "
                   "и тестируются вместе с основными подписками.")

        self.lbl_saved_count = ctk.CTkLabel(
            toggle_frame, text="Найдено: 0",
            text_color=theme.MUTED, font=ctk.CTkFont(size=11),
        )
        self.lbl_saved_count.grid(row=0, column=1, padx=14, pady=10, sticky="e")
        self._update_saved_count()

        # ---------------- Действия ----------------

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=5, column=0, padx=24, pady=(0, 20), sticky="ew")

        self.btn_save = ctk.CTkButton(
            actions, text=" Сохранить", width=140,
            command=self._save_all,
        )
        self.btn_save.grid(row=0, column=0, padx=(0, 8))
        CTkToolTip(self.btn_save, "Сохранить в sources.txt.")

        self.btn_reload = ctk.CTkButton(
            actions, text="↻ Перечитать", width=140,
            command=self.reload,
        )
        self.btn_reload.grid(row=0, column=1, padx=(0, 8))
        CTkToolTip(self.btn_reload, "Перечитать sources.txt.")

        self.btn_combined = ctk.CTkButton(
            actions, text=" Проверить и отсеять", width=220,
            fg_color=theme.WARNING_BTN, hover_color=theme.WARNING_BTN_HOVER,
            command=self.app.on_combined_clicked,
        )
        self.btn_combined.grid(row=0, column=2, padx=(0, 8))
        CTkToolTip(self.btn_combined, "Отсеять мусорные + проверить живучесть.")

        self.btn_export = ctk.CTkButton(
            actions, text=" Экспорт", width=140,
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            command=self.app.on_export_clicked,
        )
        self.btn_export.grid(row=0, column=3, padx=(0, 0))
        CTkToolTip(self.btn_export, "Собрать конфиги в preload.txt.")

        self.reload()

    # ------------------------------------------------------------ actions
    def reload(self) -> None:
        try:
            lines = self.app.sources_file.read_text(encoding="utf-8")
        except OSError:
            lines = ""
        # Filter out comment lines (#) and empty lines.
        # Also filter out direct configs (vless://, vmess://, etc) - they are
        # handled by _load_sources via direct_configs.txt, not as HTTP sources.
        _DIRECT_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "hysteria://")
        self._sources = [
            ln.strip()
            for ln in lines.splitlines()
            if ln.strip()
            and not ln.lstrip().startswith("#")
            and not ln.lower().lstrip().startswith(_DIRECT_SCHEMES)
        ]
        self._refresh_list()

    def _refresh_list(self) -> None:
        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", "end")
        for url in self._sources:
            self.textbox.insert("end", url + "\n")
        self.textbox.configure(state="disabled")
        self.lbl_count.configure(text=str(len(self._sources)))

    def _add_urls(self) -> None:
        raw = self.entry_url.get().strip()
        self.entry_url.delete(0, "end")
        if not raw:
            return
        candidates = raw.replace("\n", " ").split(" ")
        added = 0
        for u in candidates:
            u = u.strip()
            if u and u not in self._sources:
                self._sources.append(u)
                added += 1
        self._refresh_list()
        if added:
            self.app.show_status(f"Добавлено подписок: {added}")

    # Физические коды клавиш (VK) — не зависят от раскладки.
    _KEY_V = 86
    _KEY_C = 67
    _KEY_A = 65

    @staticmethod
    def _is_ctrl_key(event, keycode: int, keysyms: tuple[str, ...]) -> bool:
        """Совпадение по физическому коду клавиши (основной) или keysym (запасной).

        На русской раскладке keysym меняется ('м'/'с'/'ф'), а keycode остаётся
        тем же (V=86, C=67, A=65) — поэтому проверяем именно его.
        """
        if getattr(event, "keycode", 0) == keycode:
            return True
        return getattr(event, "keysym", "").lower() in keysyms

    def _on_entry_ctrl_key(self, event=None) -> str | None:
        """Ctrl+V в поле ввода (рус. раскладка тоже)."""
        if event is None:
            return None
        if self._is_ctrl_key(event, self._KEY_V, ("v", "м")):
            return self._paste_url()
        return None

    def _on_text_ctrl_key(self, event=None) -> str | None:
        """Ctrl+C / Ctrl+A в списке (рус. раскладка тоже)."""
        if event is None:
            return None
        if self._is_ctrl_key(event, self._KEY_C, ("c", "с")):
            return self._copy_selection()
        if self._is_ctrl_key(event, self._KEY_A, ("a", "ф")):
            return self._select_all()
        return None


    # ------------------------------------------------------------ буфер обмена
    def _paste_url(self, event=None) -> str:

        """Вставка из буфера обмена в поле ввода (Ctrl+V, в т.ч. русская раскладка)."""
        try:
            text = self.clipboard_get()
        except tk.TclError:
            return "break"
        self.entry_url.insert("insert", text)
        return "break"

    def _copy_selection(self, event=None) -> str:
        """Копирование выделенного текста из списка (Ctrl+C, в т.ч. русская раскладка).

        Если выделения нет — копируется весь список подписок.
        """
        try:
            selection = self.textbox.get("sel.first", "sel.last")
        except tk.TclError:
            selection = ""
        if not selection:
            selection = "\n".join(self._sources)
        if selection:
            self.clipboard_clear()
            self.clipboard_append(selection)
        return "break"

    def _select_all(self, event=None) -> str:
        """Выделить весь список подписок (Ctrl+A, в т.ч. русская раскладка)."""
        self.textbox.configure(state="normal")
        self.textbox.tag_add("sel", "1.0", "end")
        self.textbox.configure(state="disabled")
        return "break"

    def _remove_selected(self) -> None:
        before = len(self._sources)
        try:
            selection = self.textbox.get("sel.first", "sel.last")
        except tk.TclError:
            selection = ""
        selected = {ln.strip() for ln in selection.splitlines() if ln.strip()}
        if not selected:
            self.app.show_status("Выделите подписки для удаления (зажав Ctrl).", error=True)
            return
        self._sources = [u for u in self._sources if u not in selected]
        self._refresh_list()
        self.app.show_status(f"Удалено подписок: {before - len(self._sources)}")

    def _save_all(self) -> None:
        self._sources = [ln for ln in self._sources if ln.strip()]
        try:
            self.app.sources_file.write_text(
                "\n".join(self._sources) + ("\n" if self._sources else ""),
                encoding="utf-8",
            )
        except OSError as exc:
            self.app.show_status(f"Не удалось сохранить: {exc}", error=True)
            return
        self._refresh_list()
        self.app.show_status(f"Сохранено: {len(self._sources)} подписок → {self.app.sources_file}")

    # ------------------------------------------------------------ api
    def get_sources(self) -> list[str]:
        """Return sources list + saved_subs files (from "Импорт" tab) if toggle is ON.

        saved_subs/*.txt are added to the sources list so pipeline tests them
        TOGETHER with the main sources.txt subscriptions.
        """
        sources = list(self._sources)
        if not self._use_saved_subs:
            return sources
        try:
            from ..paths import data_dir
            saved_dir = data_dir() / "saved_subs"
            if saved_dir.exists():
                for f in sorted(saved_dir.glob("*.txt")) + sorted(saved_dir.glob("*.json")):
                    if f.name == "README.txt":
                        continue
                    fp = str(f.resolve())
                    if fp not in sources:
                        sources.append(fp)
        except Exception as exc:
            # Пользователь включил «saved_subs»: если каталог не прочитался —
            # часть источников молча пропадёт из проверки, предупреждаем.
            _logger.warning("saved_subs не прочитаны: %s", exc)
        return sources

    def _on_saved_subs_toggle(self) -> None:
        self._use_saved_subs = bool(self.chk_saved_subs.get())
        self._update_saved_count()
        if self._use_saved_subs:
            self.app.show_status("Импортированные подписки ВКЛЮЧЕНЫ (добавлены к sources.txt)")
        else:
            self.app.show_status("Импортированные подписки ВЫКЛЮЧЕНЫ")

    def _update_saved_count(self) -> None:
        try:
            from ..paths import data_dir
            saved_dir = data_dir() / "saved_subs"
            if saved_dir.exists():
                files = [f for f in (list(saved_dir.glob("*.txt")) + list(saved_dir.glob("*.json")))
                         if f.name != "README.txt"]
                self.lbl_saved_count.configure(text=f"Найдено: {len(files)}")
            else:
                self.lbl_saved_count.configure(text="Найдено: 0")
        except Exception:
            self.lbl_saved_count.configure(text="Найдено: ?")

    def set_sources(self, urls: list[str]) -> None:
        self._sources = list(urls)
        self._refresh_list()

    def set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        for btn in (self.btn_add, self.btn_remove, self.btn_save, self.btn_reload, self.btn_combined, self.btn_export):
            btn.configure(state=state)

