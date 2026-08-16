"""Страница «Настройки» — описание/префикс конфигов и перепроверка с этапа."""
from __future__ import annotations

import json

import customtkinter as ctk

from .. import paths, theme
from ..tooltip import CTkToolTip, info_label
from subgen.settings import load_settings, save_settings


STAGES = {
    "ping": "Сначала (полный прогон)",
    "dpi": "С этапа DPI (после пинга и стресс-теста)",
    "zapret": "С этапа Zapret",
    "recheck": "С этапа перепроверки",
}


class SettingsPage(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkLabel(
            self, text="Настройки",
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

        # ---------------- Карточка: описание и префикс ----------------
        card_desc = self._make_card(self.scroll, 0, "Описание и префикс конфигов")
        inner = card_desc.inner
        inner.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(
            inner, text="Префикс (первая строка подписки)",
            anchor="w", text_color=theme.TEXT,
        )
        lbl.grid(row=0, column=0, padx=6, pady=(6, 0), sticky="w")
        info = info_label(inner, "Строка, добавляемая в начало подписки перед описанием.")
        info.grid(row=0, column=1, padx=(4, 0), pady=(6, 0), sticky="w")

        self.entry_prefix = ctk.CTkEntry(inner, height=34)
        self.entry_prefix.grid(row=1, column=0, columnspan=2, padx=6, pady=(4, 8), sticky="ew")

        lbl2 = ctk.CTkLabel(
            inner, text="Описание (вторая строка подписки)",
            anchor="w", text_color=theme.TEXT,
        )
        lbl2.grid(row=2, column=0, padx=6, pady=(6, 0), sticky="w")
        info2 = info_label(inner, "Описание, добавляемое в подписку после префикса.")
        info2.grid(row=2, column=1, padx=(4, 0), pady=(6, 0), sticky="w")

        self.text_desc = ctk.CTkTextbox(inner, height=70, wrap="word")
        self.text_desc.grid(row=3, column=0, columnspan=2, padx=6, pady=(4, 8), sticky="ew")

        # ---------------- Карточка: перепроверка с этапа ----------------
        card_stage = self._make_card(self.scroll, 1, "Перепроверка с этапа")
        inner2 = card_stage.inner
        inner2.grid_columnconfigure(0, weight=1)

        lbl3 = ctk.CTkLabel(
            inner2, text="Начать проверку с этапа",
            anchor="w", text_color=theme.TEXT,
        )
        lbl3.grid(row=0, column=0, padx=6, pady=(6, 0), sticky="w")
        info3 = info_label(
            inner2,
            "После пинга и стресс-теста рабочие конфиги сохраняются. "
            "Можно перезапустить проверку с любого более позднего этапа, "
            "не повторяя пинг и стресс-тест.",
        )
        info3.grid(row=0, column=1, padx=(4, 0), pady=(6, 0), sticky="w")

        self.stage_var = ctk.StringVar(value="ping")
        self._stage_radios: dict[str, ctk.CTkRadioButton] = {}
        for i, (key, label) in enumerate(STAGES.items()):
            rb = ctk.CTkRadioButton(
                inner2, text=label, value=key, variable=self.stage_var,
                text_color=theme.TEXT, font=ctk.CTkFont(size=13),
            )
            rb.grid(row=1 + i, column=0, columnspan=2, padx=10, pady=3, sticky="w")
            self._stage_radios[key] = rb

        self.lbl_stage_warn = ctk.CTkLabel(
            inner2, text="", text_color=theme.WARNING,
            font=ctk.CTkFont(size=12), justify="left", anchor="w",
        )
        self.lbl_stage_warn.grid(row=1 + len(STAGES), column=0, columnspan=2,
                                 padx=10, pady=(4, 0), sticky="w")


        # ---------------- Кнопка сохранения ----------------
        self.btn_save = ctk.CTkButton(
            self.scroll,
            text="💾 Сохранить настройки",
            height=44,
            corner_radius=8,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color="#0C1014",
            command=self._save,
        )
        self.btn_save.grid(row=2, column=0, padx=12, pady=(8, 14), sticky="ew")
        CTkToolTip(self.btn_save, "Сохранить описание, префикс и этап перепроверки.")

        self.lbl_saved = ctk.CTkLabel(
            self.scroll, text="", text_color=theme.SUCCESS,
            font=ctk.CTkFont(size=12),
        )
        self.lbl_saved.grid(row=3, column=0, padx=12, pady=(0, 6), sticky="w")

        self._load()
        self.refresh_stage_availability()

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

    def _load(self) -> None:
        settings = load_settings()
        self.entry_prefix.delete(0, "end")
        self.entry_prefix.insert(0, settings.get("prefix", ""))
        self.text_desc.delete("1.0", "end")
        self.text_desc.insert("1.0", settings.get("description", ""))

    def _save(self) -> None:
        settings = load_settings()
        settings["prefix"] = self.entry_prefix.get().strip()
        settings["description"] = self.text_desc.get("1.0", "end").strip()
        save_settings(settings)
        self.lbl_saved.configure(text="✓ Настройки сохранены.")
        self.app.show_status("Настройки сохранены.")

    # ------------------------------------------------------------ API
    def get_start_stage(self) -> str:
        return self.stage_var.get()

    def set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.btn_save.configure(state=state)

    # ------------------------------------------------------------ кеш этапов
    def has_cached_working(self) -> bool:
        """Есть ли сохранённые рабочие конфиги (после пинга и стресс-теста)."""
        path = paths.data_dir() / ".runtime_cache" / "xray_working.json"
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return False
        if not isinstance(data, list):
            return False
        return any(row.get("fully_checked") for row in data)

    def refresh_stage_availability(self) -> None:
        """Включает/отключает выбор этапов перепроверки в зависимости от кеша.

        Если проверка ещё ни разу не проводилась (нет сохранённых рабочих
        конфигов), этапы dpi/zapret/recheck недоступны, а выбор сбрасывается
        на «Сначала (полный прогон)».
        """
        available = self.has_cached_working()
        for key, rb in self._stage_radios.items():
            if key == "ping":
                continue
            rb.configure(state="normal" if available else "disabled")
        if not available and self.stage_var.get() != "ping":
            self.stage_var.set("ping")
        if available:
            self.lbl_stage_warn.configure(text="")
        else:
            self.lbl_stage_warn.configure(
                text="⚠ Проверка ещё не проводилась. Сначала запустите полный "
                     "прогон (пинг и стресс-тест), чтобы появилась возможность "
                     "перепроверки с этапа."
            )

