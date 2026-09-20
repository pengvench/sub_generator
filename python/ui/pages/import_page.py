"""Вкладка «Импорт» — сохранение конфигов в data/saved_subs/."""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime
from pathlib import Path

_logger = logging.getLogger(__name__)

import customtkinter as ctk

from .. import paths, theme

NODE_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "hysteria://")

# Ссылки на подписки, которые можно вставить в поле «Вставка конфигов»:
# зашифрованные happ:// и обычные http(s):// — они качаются через общий
# конвейер загрузки (_fetch_text), а не ищутся как готовые конфиги.
_SUB_LINK_RE = re.compile(r"\b(?:happ://|https?://)\S+", re.IGNORECASE)


def _extract_sub_links(text: str) -> list[str]:
    """Ссылки на подписки (happ://, https://) из вставленного текста."""
    links: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        for m in _SUB_LINK_RE.finditer(line):
            link = m.group(0).rstrip(".,;)")
            if link and link.lower() not in seen:
                seen.add(link.lower())
                links.append(link)
    return links


def _extract_configs(text: str) -> list[str]:
    configs: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        for scheme in NODE_SCHEMES:
            idx = line.lower().find(scheme)
            if idx >= 0:
                config = line[idx:].split()[0]
                if config and config not in seen:
                    seen.add(config)
                    configs.append(config)
                break
    if not configs:
        import base64 as _b64
        compact = "".join(text.split())
        if compact:
            try:
                padded = compact + "=" * (-len(compact) % 4)
                decoded = _b64.b64decode(padded).decode("utf-8", errors="replace")
                if decoded and any(s in decoded.lower() for s in NODE_SCHEMES):
                    for line in decoded.splitlines():
                        line = line.strip()
                        for scheme in NODE_SCHEMES:
                            idx = line.lower().find(scheme)
                            if idx >= 0:
                                config = line[idx:].split()[0]
                                if config and config not in seen:
                                    seen.add(config)
                                    configs.append(config)
                                break
            except Exception as exc:
                # Горячий цикл разбора вставленного текста: битые строки
                # пропускаем, причину — в debug (SUBGEN_DEBUG=1).
                _logger.debug("строка импорта пропущена: %s", exc)
    if not configs:
        try:
            data = json.loads(text)
            items = data if isinstance(data, list) else data.get("configs", data.get("nodes", []))
            for item in items:
                if isinstance(item, str) and any(item.lower().startswith(s) for s in NODE_SCHEMES):
                    if item not in seen:
                        seen.add(item)
                        configs.append(item)
        except Exception as exc:
            # Файл сохранённых конфигов побит/нестандартен — берём что дали.
            _logger.debug("файл сохранённых конфигов разобран частично: %s", exc)
    return configs


class ImportPage(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.scroll = ctk.CTkScrollableFrame(self, fg_color=theme.BG)
        self.scroll.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.scroll.grid_columnconfigure(0, weight=1)

        # --- Paste ---
        card_paste = ctk.CTkFrame(self.scroll, fg_color=theme.CARD, corner_radius=10,
                                   border_width=1, border_color=theme.BORDER)
        card_paste.grid(row=0, column=0, padx=8, pady=6, sticky="ew")
        card_paste.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card_paste, text="Вставка конфигов",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=theme.TEXT).grid(row=0, column=0, padx=10, pady=(8, 4), sticky="w")

        self.txt_input = ctk.CTkTextbox(card_paste, height=160,
                                         font=ctk.CTkFont(family=theme.FONT_MONO, size=11))
        self.txt_input.grid(row=1, column=0, padx=10, pady=4, sticky="ew")
        self.txt_input.insert("1.0", "vless://...\nvmess://...\nss://...")

        btn_frame = ctk.CTkFrame(card_paste, fg_color="transparent")
        btn_frame.grid(row=2, column=0, padx=10, pady=(4, 8), sticky="ew")
        btn_frame.grid_columnconfigure(0, weight=1)

        self.btn_save_paste = ctk.CTkButton(
            btn_frame, text="Сохранить", height=32,
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, text_color="#0C1014",
            command=self._save_paste)
        self.btn_save_paste.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        self.btn_paste_clipboard = ctk.CTkButton(
            btn_frame, text="Из буфера", width=120, height=32,
            fg_color=theme.CARD, hover_color=theme.CARD_ALT, text_color=theme.TEXT,
            command=self._paste_from_clipboard)
        self.btn_paste_clipboard.grid(row=0, column=1, padx=6)

        self.btn_clear = ctk.CTkButton(
            btn_frame, text="Очистить", width=90, height=32,
            fg_color="transparent", hover_color=theme.CARD_ALT, text_color=theme.MUTED,
            command=lambda: self.txt_input.delete("1.0", "end"))
        self.btn_clear.grid(row=0, column=2, padx=(6, 0))

        # Статус вставки (в этой же карточке — не в карточке URL).
        self.lbl_paste_status = ctk.CTkLabel(card_paste, text="", text_color=theme.MUTED,
                                             font=ctk.CTkFont(size=11))
        self.lbl_paste_status.grid(row=3, column=0, padx=10, pady=(0, 8), sticky="w")

        # Ctrl+V в поле вставки — вставка С ЗАМЕНОЙ всего содержимого.
        # Биндинг вешается на ВНУТРЕННИЙ tk.Text (CTkTextbox — это фрейм,
        # фокус клавиатуры получает внутренний текстовый виджет, биндинг
        # на самом CTkTextbox никогда не срабатывал). Виртуальное событие
        # <<Paste>> генерируется и в английской раскладке (штатно), и в
        # русской (наш глобальный перехватчик по keycode, см. ui/hotkeys.py)
        # — поведение одинаковое в любой раскладке. 'break' не даёт
        # классовому биндингу вставить текст второй раз.
        self.txt_input._textbox.bind(
            "<<Paste>>", lambda e: (self._paste_from_clipboard(), "break")[1])

        # --- URL ---
        card_url = ctk.CTkFrame(self.scroll, fg_color=theme.CARD, corner_radius=10,
                                 border_width=1, border_color=theme.BORDER)
        card_url.grid(row=1, column=0, padx=8, pady=6, sticky="ew")
        card_url.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card_url, text="Импорт из URL",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=theme.TEXT).grid(row=0, column=0, padx=10, pady=(8, 4), sticky="w")

        url_frame = ctk.CTkFrame(card_url, fg_color="transparent")
        url_frame.grid(row=1, column=0, padx=10, pady=4, sticky="ew")
        url_frame.grid_columnconfigure(0, weight=1)

        self.entry_url = ctk.CTkEntry(url_frame, placeholder_text="https://...")
        self.entry_url.grid(row=0, column=0, padx=(0, 6), sticky="ew")
        self.entry_url.bind("<Return>", lambda e: self._import_from_url())

        self.btn_import_url = ctk.CTkButton(
            url_frame, text="Скачать", width=100, height=32,
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, text_color="#0C1014",
            command=self._import_from_url)
        self.btn_import_url.grid(row=0, column=1)

        self.lbl_url_status = ctk.CTkLabel(card_url, text="", text_color=theme.MUTED,
                                            font=ctk.CTkFont(size=11))
        self.lbl_url_status.grid(row=2, column=0, padx=10, pady=(0, 8), sticky="w")

        # --- File ---
        card_file = ctk.CTkFrame(self.scroll, fg_color=theme.CARD, corner_radius=10,
                                  border_width=1, border_color=theme.BORDER)
        card_file.grid(row=2, column=0, padx=8, pady=6, sticky="ew")
        card_file.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card_file, text="Импорт из файла",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=theme.TEXT).grid(row=0, column=0, padx=10, pady=(8, 4), sticky="w")

        self.btn_import_file = ctk.CTkButton(
            card_file, text="Выбрать файл (.txt / .json)", height=32,
            fg_color=theme.CARD, hover_color=theme.CARD_ALT, text_color=theme.TEXT,
            command=self._import_from_file)
        self.btn_import_file.grid(row=1, column=0, padx=10, pady=(4, 8), sticky="ew")

        # --- Saved files ---
        card_saved = ctk.CTkFrame(self.scroll, fg_color=theme.CARD, corner_radius=10,
                                   border_width=1, border_color=theme.BORDER)
        card_saved.grid(row=3, column=0, padx=8, pady=6, sticky="ew")
        card_saved.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card_saved, text="Сохранённые файлы (data/saved_subs/)",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=theme.TEXT).grid(row=0, column=0, padx=10, pady=(8, 4), sticky="w")

        self.saved_frame = ctk.CTkFrame(card_saved, fg_color="transparent")
        self.saved_frame.grid(row=1, column=0, padx=10, pady=(4, 8), sticky="ew")
        self.saved_frame.grid_columnconfigure(0, weight=1)

        self.btn_refresh = ctk.CTkButton(
            card_saved, text="Обновить", width=120, height=28,
            fg_color=theme.CARD, hover_color=theme.CARD_ALT, text_color=theme.TEXT,
            font=ctk.CTkFont(size=12),
            command=self._refresh_saved_list)
        self.btn_refresh.grid(row=2, column=0, padx=10, pady=(0, 8), sticky="w")

        self._refresh_saved_list()

    def _paste_from_clipboard(self):
        try:
            text = self.app.clipboard_get()
            self.txt_input.delete("1.0", "end")
            self.txt_input.insert("1.0", text)
        except Exception as exc:
            # Пустой/недоступный буфер обмена — пользователь поймёт по пустому
            # полю, но причину оставляем в предупреждении.
            _logger.warning("вставка из буфера обмена не удалась: %s", exc)

    def _saved_subs_dir(self) -> Path:
        d = paths.data_dir() / "saved_subs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _save_configs(self, configs: list[str], source_name: str = "manual") -> int:
        if not configs:
            return 0
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self._saved_subs_dir() / f"{source_name}_{timestamp}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {source_name} | {len(configs)} configs\n")
            for c in configs:
                f.write(c + "\n")
        return len(configs)

    def _save_paste(self):
        text = self.txt_input.get("1.0", "end").strip()
        configs = _extract_configs(text)
        if configs:
            count = self._save_configs(configs, "paste")
            self.lbl_paste_status.configure(text=f"Сохранено {count} конфигов", text_color=theme.SUCCESS)
            self._refresh_saved_list()
            return
        # Готовых конфигов нет — но текст может быть ссылкой на подписку
        # (happ:// или https://): качаем её через общий конвейер.
        links = _extract_sub_links(text)
        if links:
            self._import_links(links, self.lbl_paste_status)
            return
        self.lbl_paste_status.configure(text="Конфиги не найдены", text_color=theme.DANGER)

    def _import_links(self, links: list[str], status) -> None:
        """Скачать подписки по ссылкам (happ:// расшифровка + зеркала + транспорт).

        Единый конвейер из runtime.fetch — тот же, что и в основном тесте:
        happ://cryptN/ расшифровывается здесь же, и причина неудачи
        (например, нестандартный формат ссылки) попадает в статус.
        """
        links = list(links)
        status.configure(text=f"Скачивание ({len(links)} ссылок)...", text_color=theme.WARNING)
        self.btn_save_paste.configure(state="disabled")
        self.btn_import_url.configure(state="disabled")

        def worker():
            all_configs: list[str] = []
            seen: set[str] = set()
            errors: list[str] = []
            try:
                from xray_runtime import _fetch_text

                for index, url in enumerate(links, 1):
                    self.after(0, lambda i=index, t=len(links): status.configure(
                        text=f"Скачивание {i}/{t}...", text_color=theme.WARNING))
                    try:
                        data = _fetch_text(url, timeout=20.0, log_sink=_logger.warning)
                        found = _extract_configs(data)
                        for cfg in found:
                            if cfg not in seen:
                                seen.add(cfg)
                                all_configs.append(cfg)
                    except Exception as e:
                        msg = str(e)
                        if len(msg) > 220:
                            msg = msg[:220] + "…"
                        errors.append(msg)
            finally:
                def finish(configs=all_configs, errs=errors):
                    self.btn_save_paste.configure(state="normal")
                    self.btn_import_url.configure(state="normal")
                    if configs:
                        count = self._save_configs(configs, "url")
                        status.configure(text=f"Сохранено {count} конфигов", text_color=theme.SUCCESS)
                        self._refresh_saved_list()
                    elif errs:
                        status.configure(text=f"Ошибка: {errs[0]}", text_color=theme.DANGER)
                    else:
                        status.configure(text="Конфиги не найдены", text_color=theme.DANGER)
                self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _import_from_url(self):
        url = self.entry_url.get().strip()
        if not url:
            return
        self._import_links([url], self.lbl_url_status)

    def _import_from_file(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            title="Выбрать файл", filetypes=[("Text/JSON", "*.txt *.json"), ("All", "*.*")])
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            self.lbl_url_status.configure(text=f"Ошибка: {e}", text_color=theme.DANGER)
            return
        configs = _extract_configs(text)
        if configs:
            count = self._save_configs(configs, f"file_{Path(path).stem[:20]}")
            self.lbl_url_status.configure(text=f"Сохранено {count} из {Path(path).name}", text_color=theme.SUCCESS)
            self._refresh_saved_list()
            return
        # В файле не готовые конфиги — а ссылки на подписки (happ://, https://)?:
        # качаем их тем же конвейером, как из вставки/URL-поля.
        links = _extract_sub_links(text)
        if links:
            self._import_links(links, self.lbl_url_status)
            return
        self.lbl_url_status.configure(text="Конфиги не найдены", text_color=theme.DANGER)

    def _refresh_saved_list(self):
        for w in self.saved_frame.winfo_children():
            w.destroy()
        saved_dir = self._saved_subs_dir()
        files = sorted(saved_dir.glob("*.txt")) + sorted(saved_dir.glob("*.json"))
        if not files:
            ctk.CTkLabel(self.saved_frame, text="Пусто",
                         text_color=theme.MUTED, font=ctk.CTkFont(size=12)).grid(
                row=0, column=0, padx=4, pady=8, sticky="w")
            return
        for i, f in enumerate(files):
            if f.name == "README.txt":
                continue
            row = ctk.CTkFrame(self.saved_frame, fg_color="transparent")
            row.grid(row=i, column=0, padx=4, pady=2, sticky="ew")
            row.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(row, text=f.name, text_color=theme.TEXT,
                         font=ctk.CTkFont(size=12), anchor="w").grid(row=0, column=0, padx=4, sticky="w")
            ctk.CTkButton(row, text="X", width=28, height=24,
                          fg_color="transparent", hover_color=theme.DANGER,
                          text_color=theme.MUTED, font=ctk.CTkFont(size=12),
                          command=lambda p=f: self._delete_saved(p)).grid(row=0, column=1, padx=4)

    def _delete_saved(self, path: Path):
        try:
            path.unlink()
            self._refresh_saved_list()
        except Exception as exc:
            # Пользователь просил удалить файл — молчаливый сбой выглядит
            # как «кнопка не работает».
            _logger.warning("не удалось удалить %s: %s", path, exc)
