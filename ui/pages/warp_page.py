"""Страница «🌀 WARP» — генерация и добавление WARP-конфигов в подписку.

Отдельная страница в сайдбаре (как «Подписки»). Содержит:
  - Радиокнопки выбора пресета (single-select, т.к. пресет «🚀 Полный
    обход» и так добавляет до 16 конфигов).
  - Выбор DNS: Cloudflare (1.1.1.1) / xbox-dns.ru (разблокировка ChatGPT) /
    свой DNS.
  - Тумблер «Добавлять WARP при каждом тестировании» — сохраняется в
    settings.json, используется в pipeline.py.
  - Кнопку «Сгенерировать и скопировать» — для preview без запуска теста.
"""
from __future__ import annotations

import threading
import time

import customtkinter as ctk

from .. import theme
from ..tooltip import CTkToolTip, info_label
from subgen.settings import load_settings, save_settings


HELP = {
    "preset": "Выбери ОДИН пресет. Каждый пресет генерирует от 1 до 16 "
              "конфигов с разными endpoint:port:MTU. «🚀 Полный обход» "
              "даёт максимум шансов пробить DPI — 16 конфигов с разными IP, "
              "портами и MTU.",
    "dns": "DNS-сервер для WARP-конфигов:\n"
           "• Cloudflare (1.1.1.1) — быстрый, стандартный.\n"
           "• xbox-dns.ru (111.88.96.50) — резолвит chatgpt.com, openai.com,\n"
           "  discord.com через неразблокированные IP. Открывает нейросети.\n"
           "• Свой — впиши свой DNS (через запятую, если несколько).",
    "auto_add": "Если включено — WARP-конфиги добавляются в подписку "
                "автоматически при каждом запуске тестирования. "
                "Отключи, если хочешь добавлять WARP только вручную "
                "(кнопкой «Сгенерировать и скопировать»).",
    "generate": "Сгенерировать WARP-конфиги по выбранному пресету и "
                "скопировать warp:// URL в буфер обмена. Можно вставить "
                "вручную в подписку или клиент.",
}


# Опции DNS для dropdown.
DNS_OPTIONS = [
    ("Cloudflare (1.1.1.1, 1.0.0.1)", ["1.1.1.1", "1.0.0.1"]),
    ("xbox-dns.ru (ChatGPT/Discord)", ["111.88.96.50", "111.88.96.51",
                                       "2a00:ab00:1233:26::50",
                                       "2a00:ab00:1233:26::51"]),
    ("Свой DNS", None),  # None = использовать entry ниже
]


class WarpPage(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkLabel(
            self, text="🌀 WARP",
            font=ctk.CTkFont(size=22, weight="bold"), text_color=theme.TEXT,
        )
        header.grid(row=0, column=0, padx=20, pady=(16, 10), sticky="w")

        self.scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=theme.ACCENT,
            scrollbar_button_hover_color=theme.ACCENT_HOVER,
        )
        self.scroll.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")
        self.scroll.grid_columnconfigure(0, weight=1)

        # --- Карточка: пресет ---
        card_preset = self._make_card(self.scroll, 0, "Пресет генерации")
        inner_preset = card_preset.inner
        inner_preset.grid_columnconfigure(0, weight=1)

        lbl_preset = ctk.CTkLabel(
            inner_preset, text="Выберите пресет (один):",
            anchor="w", text_color=theme.TEXT,
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        lbl_preset.grid(row=0, column=0, padx=6, pady=(6, 0), sticky="w")
        info_label(inner_preset, HELP["preset"]).grid(row=0, column=1, padx=(4, 0), pady=(6, 0), sticky="w")

        # Radio buttons для пресетов (single-select).
        try:
            from subgen.warp import WARP_PRESETS
            preset_items = [(p.user_facing, p.description, p.total) for p in WARP_PRESETS]
        except Exception:
            preset_items = [
                ("Авто", "1 конфиг", 1),
                ("🌐 Мобильный интернет", "3 конфига", 3),
                ("🤖 Нейросети ChatGPT", "2 конфига", 2),
                ("🛡️ Максимальный обход", "6 конфигов", 6),
                ("🚀 Полный обход", "16 конфигов", 16),
            ]

        self.preset_var = ctk.IntVar(value=0)
        self._preset_radios: list[ctk.CTkRadioButton] = []
        for i, (label, desc, total) in enumerate(preset_items):
            rb = ctk.CTkRadioButton(
                inner_preset,
                text=f"{label}  ({total} конф.)",
                value=i, variable=self.preset_var,
                text_color=theme.TEXT, font=ctk.CTkFont(size=13),
            )
            rb.grid(row=1 + i, column=0, columnspan=2, padx=10, pady=3, sticky="w")
            CTkToolTip(rb, desc)
            self._preset_radios.append(rb)

        # --- Карточка: DNS ---
        card_dns = self._make_card(self.scroll, 1, "DNS для WARP")
        inner_dns = card_dns.inner
        inner_dns.grid_columnconfigure(0, weight=1)

        lbl_dns = ctk.CTkLabel(
            inner_dns, text="Выберите DNS:",
            anchor="w", text_color=theme.TEXT,
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        lbl_dns.grid(row=0, column=0, padx=6, pady=(6, 0), sticky="w")
        info_label(inner_dns, HELP["dns"]).grid(row=0, column=1, padx=(4, 0), pady=(6, 0), sticky="w")

        self.dns_var = ctk.StringVar(value=DNS_OPTIONS[0][0])
        self.dns_menu = ctk.CTkOptionMenu(
            inner_dns, variable=self.dns_var,
            values=[opt[0] for opt in DNS_OPTIONS],
            height=30, font=ctk.CTkFont(size=12),
            fg_color=theme.CARD_ALT,
            button_color=theme.ACCENT, button_hover_color=theme.ACCENT_HOVER,
            text_color=theme.TEXT,
        )
        self.dns_menu.grid(row=1, column=0, columnspan=2, padx=6, pady=(4, 6), sticky="ew")
        CTkToolTip(self.dns_menu, HELP["dns"])

        # Entry для своего DNS (показывается только при выборе "Свой DNS").
        self.custom_dns_entry = ctk.CTkEntry(
            inner_dns, height=30, justify="left",
            placeholder_text="Например: 8.8.8.8, 8.8.4.4",
        )
        self.custom_dns_entry.grid(row=2, column=0, columnspan=2, padx=6, pady=(0, 6), sticky="ew")
        self.custom_dns_entry.grid_remove()  # скрыт по умолчанию
        self.dns_var.trace_add("write", lambda *_: self._sync_dns_entry())

        # --- Карточка: автоматическое добавление ---
        card_auto = self._make_card(self.scroll, 2, "Автоматическое добавление")
        inner_auto = card_auto.inner
        inner_auto.grid_columnconfigure(0, weight=1)

        self.toggle_auto_add = ctk.CTkSwitch(
            inner_auto, text="Добавлять WARP при каждом тестировании",
            height=24, font=ctk.CTkFont(size=13),
        )
        self.toggle_auto_add.grid(row=0, column=0, padx=6, pady=6, sticky="w")
        CTkToolTip(self.toggle_auto_add, HELP["auto_add"])

        # --- Кнопка генерации ---
        self.btn_generate = ctk.CTkButton(
            self.scroll,
            text="🌀 Сгенерировать и скопировать WARP",
            height=44, corner_radius=8,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            text_color="#0C1014",
            command=self._on_generate_clicked,
        )
        self.btn_generate.grid(row=3, column=0, padx=12, pady=(8, 14), sticky="ew")
        CTkToolTip(self.btn_generate, HELP["generate"])

        # --- Статус ---
        self.lbl_status = ctk.CTkLabel(
            self.scroll, text="", text_color=theme.INFO,
            font=ctk.CTkFont(size=12), justify="left", anchor="w",
        )
        self.lbl_status.grid(row=4, column=0, padx=12, pady=(0, 6), sticky="w")

        self._restore_settings()

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

    def _sync_dns_entry(self) -> None:
        """Показать/скрыть поле ввода своего DNS."""
        selected = self.dns_var.get()
        if selected == "Свой DNS":
            self.custom_dns_entry.grid()
        else:
            self.custom_dns_entry.grid_remove()

    def _get_selected_dns(self) -> list[str] | None:
        """Вернуть выбранный DNS как список, или None для дефолта пресета."""
        selected = self.dns_var.get()
        for label, dns in DNS_OPTIONS:
            if label == selected:
                if dns is None:
                    # "Свой DNS" — берём из entry.
                    custom = self.custom_dns_entry.get().strip()
                    if custom:
                        return [d.strip() for d in custom.split(",") if d.strip()]
                    return None
                return dns
        return None

    def _get_selected_preset_idx(self) -> int:
        """Индекс выбранного пресета (0-4)."""
        return int(self.preset_var.get())

    # ------------------------------------------------------------ сохранение
    def _restore_settings(self) -> None:
        """Восстановить настройки WARP из settings.json."""
        settings = load_settings()
        warp_settings = settings.get("warp", {})
        if not isinstance(warp_settings, dict):
            warp_settings = {}

        # Пресет.
        preset_idx = int(warp_settings.get("preset", 0))
        if 0 <= preset_idx < len(self._preset_radios):
            self.preset_var.set(preset_idx)

        # DNS.
        dns_label = str(warp_settings.get("dns_label", DNS_OPTIONS[0][0]))
        if dns_label in [opt[0] for opt in DNS_OPTIONS]:
            self.dns_var.set(dns_label)
        custom_dns = str(warp_settings.get("custom_dns", ""))
        if custom_dns:
            self.custom_dns_entry.delete(0, "end")
            self.custom_dns_entry.insert(0, custom_dns)
        self._sync_dns_entry()

        # Авто-добавление.
        auto_add = bool(warp_settings.get("auto_add", False))
        if auto_add:
            self.toggle_auto_add.select()
        else:
            self.toggle_auto_add.deselect()

    def save_current_settings(self) -> None:
        """Сохранить настройки WARP в settings.json."""
        settings = load_settings()
        settings["warp"] = {
            "preset": self._get_selected_preset_idx(),
            "dns_label": self.dns_var.get(),
            "custom_dns": self.custom_dns_entry.get().strip(),
            "auto_add": bool(self.toggle_auto_add.get()),
            "dns": self._get_selected_dns(),
        }
        try:
            save_settings(settings)
        except Exception:
            pass

    # ------------------------------------------------------------ API
    def get_warp_options(self) -> dict:
        """Вернуть словарь с настройками WARP для pipeline."""
        return {
            "enabled": bool(self.toggle_auto_add.get()),
            "preset": self._get_selected_preset_idx(),
            "dns": self._get_selected_dns(),
        }

    def set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.btn_generate.configure(state=state)
        for rb in self._preset_radios:
            rb.configure(state=state)
        self.dns_menu.configure(state=state)
        self.custom_dns_entry.configure(state=state)
        self.toggle_auto_add.configure(state=state)

    # ------------------------------------------------------------ генерация
    def _on_generate_clicked(self) -> None:
        """Сгенерировать WARP-конфиги и скопировать в буфер обмена."""
        self.btn_generate.configure(state="disabled")
        self.lbl_status.configure(
            text="Генерация WARP-конфигов (запрос к Cloudflare API)...",
            text_color=theme.INFO,
        )
        self.update_idletasks()

        def _worker():
            try:
                from subgen.warp import (
                    WARP_PRESETS,
                    generate_warp_uri,
                    generate_warp_uris_for_presets,
                    _build_uris_for_preset,
                    fetch_warp_config_parsed,
                    WireGuardConfig,
                    warp_config_to_uri_with_endpoint,
                )
                from copy import deepcopy

                preset_idx = self._get_selected_preset_idx()
                custom_dns = self._get_selected_dns()

                # Генерация.
                if preset_idx == 0 and not custom_dns:
                    # Авто — 1 конфиг от Cloudflare API, как есть.
                    uris = [generate_warp_uri(timeout=45.0)]
                else:
                    preset = WARP_PRESETS[preset_idx]
                    cfg = fetch_warp_config_parsed(timeout=45.0)
                    # Подменяем DNS, если выбран кастомный.
                    if custom_dns:
                        cfg = deepcopy(cfg)
                        cfg.dns = list(custom_dns)
                    # Если пресет 0 (Авто) и выбран кастомный DNS —
                    # генерим 1 конфиг с этим DNS.
                    if preset_idx == 0:
                        uris = [warp_config_to_uri(cfg)]
                    else:
                        uris = _build_uris_for_preset(cfg, preset)

                urls_text = "\n".join(uris)

                # Копируем в буфер обмена.
                self.app.clipboard_clear()
                self.app.clipboard_append(urls_text)

                self._post(lambda: self.lbl_status.configure(
                    text=f"✓ Сгенерировано {len(uris)} конфиг(ов). URL скопированы в буфер обмена.\n"
                         f"Вставь их в подписку или клиент (Ctrl+V).",
                    text_color=theme.SUCCESS,
                ))
            except Exception as exc:
                self._post(lambda: self.lbl_status.configure(
                    text=f"✗ Ошибка: {exc}",
                    text_color=theme.ERROR,
                ))
            finally:
                self._post(lambda: self.btn_generate.configure(state="normal"))

        threading.Thread(target=_worker, daemon=True, name="warp-gen").start()

    def _post(self, fn) -> None:
        try:
            self.after_idle(fn)
        except Exception:
            pass
