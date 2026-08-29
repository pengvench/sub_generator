"""Страница «🔁 Перепроверка» — запуск проверки с сохранённого кеша.

Объединяет бывший тумблер «С сохранённого кеша» (из «Дополнительно») и
бывшую карточку «Перепроверка с этапа» (из «Настроек»). Теперь всё в
одном месте — здесь пользователь выбирает:
  1. Полный прогон с нуля (как обычно).
  2. Перепроверку с конкретного этапа, используя сохранённые рабочие
     конфиги из data/.runtime_cache/xray_working.json.

Список этапов расширен: теперь доступны ВСЕ этапы pipeline, а не только
4 из 8. Если TUN-check включён на странице «Тестирование» — часть
этапов автоматически помечается как «дублируется в TUN-check» и не
доступна для отдельной перепроверки.
"""
from __future__ import annotations

import json
import os

import customtkinter as ctk

from .. import paths, theme
from ..tooltip import CTkToolTip, info_label


# Полный список этапов pipeline в порядке выполнения.
# key — значение для --start-stage в pipeline.run().
# label — что видит пользователь.
# requires_tun_check_disabled — если True, этап доступен только когда
#   TUN-check выключен на странице «Тестирование» (т.к. при TUN-check
#   он дублируется внутри probe_node_full и пропускается).
STAGES: list[tuple[str, str, bool]] = [
    ("ping", "Сначала (полный прогон: пинг + стресс-тест)", False),
    ("initial", "Initial check (TCP+HTTP HEAD)", True),
    ("dpi", "DPI-проверка (обход блокировок)", False),
    ("dpi_active", "DPI-актив (SNI/ECH/TLS 1.2/1.3)", False),
    ("telegram_pro", "Telegram-PRO (MTProto connect/auth)", True),
    ("route", "Route (трассировка маршрута)", True),
    ("zapret", "Zapret (DPI suite + HTTP test)", False),
    ("resilience", "Resilience (живучесть в блокировках)", True),
    ("tun_full", "TUN-check (полная проверка через TUN)", False),
    ("recheck", "Финальный спидтест", True),
]


class RecheckPage(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkLabel(
            self, text="🔁 Перепроверка",
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

        # ---------------- Карточка: режим запуска ----------------
        card_mode = self._make_card(self.scroll, 0, "Режим запуска")
        inner = card_mode.inner
        inner.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(
            inner, text="Выберите режим проверки",
            anchor="w", text_color=theme.TEXT,
        )
        lbl.grid(row=0, column=0, padx=6, pady=(6, 0), sticky="w")
        info = info_label(
            inner,
            "Полный прогон скачивает все подписки, пингует и проверяет узлы "
            "с нуля. Перепроверка с этапа использует сохранённые рабочие "
            "конфиги (data/.runtime_cache) и начинает с выбранного этапа — "
            "пинг и стресс-тест не повторяются."
        )
        info.grid(row=0, column=1, padx=(4, 0), pady=(6, 0), sticky="w")

        self.stage_var = ctk.StringVar(value="ping")
        self._stage_radios: dict[str, ctk.CTkRadioButton] = {}
        self._stage_disabled_labels: dict[str, ctk.CTkLabel] = {}

        for i, (key, label, requires_tun_disabled) in enumerate(STAGES):
            rb = ctk.CTkRadioButton(
                inner, text=label, value=key, variable=self.stage_var,
                text_color=theme.TEXT, font=ctk.CTkFont(size=13),
            )
            rb.grid(row=1 + i, column=0, columnspan=2, padx=10, pady=3, sticky="w")
            self._stage_radios[key] = rb
            # Метка-подсказка справа от radio — для этапов, которые
            # пропускаются при TUN-check.
            if requires_tun_disabled:
                note = ctk.CTkLabel(
                    inner, text="(пропускается при TUN-check)",
                    text_color=theme.MUTED, font=ctk.CTkFont(size=10),
                )
                note.grid(row=1 + i, column=1, padx=(10, 6), pady=3, sticky="e")
                self._stage_disabled_labels[key] = note

        self.lbl_stage_warn = ctk.CTkLabel(
            inner, text="", text_color=theme.WARNING,
            font=ctk.CTkFont(size=12), justify="left", anchor="w",
        )
        last_row = 1 + len(STAGES)
        self.lbl_stage_warn.grid(
            row=last_row, column=0, columnspan=2,
            padx=10, pady=(4, 0), sticky="w",
        )

        # ---------------- Карточка: информация о кеше ----------------
        card_cache = self._make_card(self.scroll, 1, "Сохранённый кеш")
        inner2 = card_cache.inner
        inner2.grid_columnconfigure(0, weight=1)

        self.lbl_cache_status = ctk.CTkLabel(
            inner2, text="", text_color=theme.TEXT,
            font=ctk.CTkFont(size=12), justify="left", anchor="w",
        )
        self.lbl_cache_status.grid(row=0, column=0, padx=6, pady=6, sticky="ew")

        self.btn_open_cache = ctk.CTkButton(
            inner2, text="📂 Открыть папку кеша",
            height=32, corner_radius=6,
            fg_color=theme.CARD_ALT, hover_color=theme.BORDER,
            text_color=theme.TEXT, font=ctk.CTkFont(size=12),
            command=self._open_cache_dir,
        )
        self.btn_open_cache.grid(row=1, column=0, padx=6, pady=(0, 6), sticky="w")
        CTkToolTip(self.btn_open_cache, "Открыть data/.runtime_cache в проводнике.")

        # ---------------- Кнопка запуска ----------------
        self.btn_run = ctk.CTkButton(
            self.scroll,
            text="▶ Запустить перепроверку",
            height=44,
            corner_radius=8,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color="#0C1014",
            command=self.app.on_start_clicked,
        )
        self.btn_run.grid(row=2, column=0, padx=12, pady=(8, 14), sticky="ew")
        CTkToolTip(self.btn_run, "Запустить проверку с выбранным режимом. "
                                  "При перепроверке с этапа пинг и стресс-тест "
                                  "не повторяются — используются сохранённые конфиги.")

        self.refresh_availability()

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

    def _open_cache_dir(self) -> None:
        """Открыть папку с кешем в проводнике Windows."""
        cache_dir = paths.data_dir() / ".runtime_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = str(cache_dir)
        try:
            if os.name == "nt":
                os.startfile(path)  # type: ignore[attr-defined]
            else:
                import subprocess
                subprocess.run(["xdg-open", path], check=False)
        except Exception:
            pass

    # ------------------------------------------------------------ API
    def get_start_stage(self) -> str:
        """Текущий выбранный этап для --start-stage."""
        return self.stage_var.get()

    def set_running(self, running: bool) -> None:
        self.btn_run.configure(state="disabled" if running else "normal")

    def set_busy(self, busy: bool) -> None:
        self.btn_run.configure(state="disabled" if busy else "normal")

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
        return any(row.get("fully_checked") for row in data if isinstance(row, dict))

    def refresh_availability(self) -> None:
        """Обновить доступность этапов и статус кеша.

        - Если кеша нет (первый запуск) — все radio, кроме «Сначала», disabled.
        - Если TUN-check включён на странице «Тестирование» — этапы, которые
          дублируются в probe_node_full, помечаются как «пропускается при
          TUN-check» и автоматически disabled.
        """
        available = self.has_cached_working()

        # Узнать, включён ли TUN-check на странице «Тестирование».
        tun_check_on = False
        try:
            tun_check_on = bool(self.app.page_start.get_options().tun_check)
        except Exception:
            pass

        # Обновить radio-кнопки.
        for key, rb in self._stage_radios.items():
            if key == "ping":
                # «Сначала» — всегда доступно.
                rb.configure(state="normal")
                continue

            # Базовая доступность: зависит от наличия кеша.
            base_enabled = available

            # Дополнительная блокировка при TUN-check:
            # если этап помечен как «пропускается при TUN-check» и TUN включён,
            # его выбор не имеет смысла (всё равно пропустится).
            stage_meta = next((s for s in STAGES if s[0] == key), None)
            skips_with_tun = bool(stage_meta[2]) if stage_meta else False
            if tun_check_on and skips_with_tun:
                base_enabled = False

            rb.configure(state="normal" if base_enabled else "disabled")

            # Подсветить метку «пропускается при TUN-check».
            note = self._stage_disabled_labels.get(key)
            if note is not None:
                if tun_check_on:
                    note.configure(text_color=theme.WARNING)
                else:
                    note.configure(text_color=theme.MUTED)

        # Если выбранный этап стал недоступен — сбросить на «Сначала».
        if not available and self.stage_var.get() != "ping":
            self.stage_var.set("ping")
        if tun_check_on:
            stage_meta = next((s for s in STAGES if s[0] == self.stage_var.get()), None)
            if stage_meta and stage_meta[2]:
                self.stage_var.set("ping")

        # Обновить предупреждение.
        if not available:
            self.lbl_stage_warn.configure(
                text="⚠ Проверка ещё не проводилась. Сначала запустите полный "
                     "прогон (пинг и стресс-тест), чтобы появилась возможность "
                     "перепроверки с этапа."
            )
        elif tun_check_on:
            self.lbl_stage_warn.configure(
                text="ℹ TUN-check включён. Этапы initial_check, telegram_pro, "
                     "route, resilience и recheck пропускаются — они дублируются "
                     "внутри probe_node_full. Можно перепроверять только "
                     "DPI / DPI-active / Zapret / TUN-check."
            )
        else:
            self.lbl_stage_warn.configure(text="")

        # Обновить статус кеша.
        if available:
            count = self._count_cached_working()
            self.lbl_cache_status.configure(
                text=f"✓ Кеш найден: {count} рабочих конфигов сохранено "
                     f"в data/.runtime_cache/xray_working.json",
                text_color=theme.SUCCESS,
            )
        else:
            self.lbl_cache_status.configure(
                text="✗ Кеш не найден. Запустите полный прогон, чтобы "
                     "сохранить рабочие конфиги для перепроверки.",
                text_color=theme.MUTED,
            )

    def _count_cached_working(self) -> int:
        """Посчитать количество сохранённых рабочих конфигов в кеше."""
        path = paths.data_dir() / ".runtime_cache" / "xray_working.json"
        if not path.exists():
            return 0
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return 0
        if not isinstance(data, list):
            return 0
        return sum(1 for row in data if isinstance(row, dict) and row.get("fully_checked"))
