"""Страница «Лог» — статистика по подпискам и журнал выполнения (Material)."""
from __future__ import annotations

import customtkinter as ctk

from .. import theme
from ..tooltip import CTkToolTip


class LogPage(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=3)
        self.grid_rowconfigure(2, weight=4)

        header = ctk.CTkLabel(
            self, text="Лог выполнения",
            font=ctk.CTkFont(size=22, weight="bold"), text_color=theme.TEXT,
        )
        header.grid(row=0, column=0, padx=24, pady=(22, 14), sticky="w")

        # ---------------- Статистика по подпискам ----------------
        self.stats_card = ctk.CTkFrame(self, fg_color=theme.CARD, corner_radius=10,
                                       border_width=1, border_color=theme.BORDER)
        self.stats_card.grid(row=1, column=0, padx=24, pady=(0, 12), sticky="nsew")
        self.stats_card.grid_columnconfigure(0, weight=1)
        self.stats_card.grid_rowconfigure(1, weight=1)

        stats_header_row = ctk.CTkFrame(self.stats_card, fg_color="transparent")
        stats_header_row.grid(row=0, column=0, padx=14, pady=(10, 6), sticky="ew")
        stats_header_row.grid_columnconfigure(0, weight=1)

        stats_header = ctk.CTkLabel(
            stats_header_row, text="📊 Конфиги по подпискам",
            font=ctk.CTkFont(size=14, weight="bold"), anchor="w", text_color=theme.TEXT,
        )
        stats_header.grid(row=0, column=0, sticky="w")
        CTkToolTip(stats_header, "Статистика из последнего прогона: сколько узлов найдено, прошло пинг и признано рабочими.")

        self.stats_box = ctk.CTkTextbox(
            self.stats_card, font=ctk.CTkFont(family=theme.FONT_MONO, size=12),
            wrap="none", state="disabled", height=140,
            text_color=theme.TEXT,
        )
        self.stats_box.grid(row=1, column=0, padx=14, pady=(0, 6), sticky="nsew")

        self.lbl_stats_summary = ctk.CTkLabel(
            self.stats_card, text="", text_color=theme.INFO, anchor="w",
            font=ctk.CTkFont(size=12),
        )
        self.lbl_stats_summary.grid(row=2, column=0, padx=14, pady=(0, 10), sticky="w")

        # ---------------- Журнал выполнения ----------------
        self.log_card = ctk.CTkFrame(self, fg_color=theme.CARD, corner_radius=10,
                                     border_width=1, border_color=theme.BORDER)
        self.log_card.grid(row=2, column=0, padx=24, pady=(0, 16), sticky="nsew")
        self.log_card.grid_columnconfigure(0, weight=1)
        self.log_card.grid_rowconfigure(1, weight=1)

        log_header_row = ctk.CTkFrame(self.log_card, fg_color="transparent")
        log_header_row.grid(row=0, column=0, padx=14, pady=(10, 6), sticky="ew")
        log_header_row.grid_columnconfigure(0, weight=1)

        log_header = ctk.CTkLabel(
            log_header_row, text="Журнал выполнения",
            font=ctk.CTkFont(size=14, weight="bold"), anchor="w", text_color=theme.TEXT,
        )
        log_header.grid(row=0, column=0, sticky="w")

        self.btn_clear = ctk.CTkButton(
            log_header_row, text="🧹 Очистить", width=110,
            command=self.clear_log,
        )
        self.btn_clear.grid(row=0, column=1)
        CTkToolTip(self.btn_clear, "Очистить журнал выполнения (статистика останется).")

        self.log_box = ctk.CTkTextbox(
            self.log_card, font=ctk.CTkFont(family=theme.FONT_MONO, size=12),
            wrap="word", state="disabled",
            text_color=theme.TEXT,
        )
        self.log_box.grid(row=1, column=0, padx=14, pady=(0, 14), sticky="nsew")

    # ------------------------------------------------------------ лог
    def append_log(self, message: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", message + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def clear_log(self) -> None:
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    # ------------------------------------------------------------ статистика
    def set_stats(self, stats) -> None:
        self._render_stats(stats)

    def _render_stats(self, stats) -> None:
        self.stats_box.configure(state="normal")
        self.stats_box.delete("1.0", "end")
        if stats:
            header = (
                f"{'Подписка':<46} {'Найдено':>8} {'Пинг':>8} {'Рабочие':>8} {'Отклонено':>9}\n"
            )
            self.stats_box.insert("end", header)
            self.stats_box.insert("end", "-" * 90 + "\n")
            total_discovered = total_ping = total_working = total_rejected = 0
            for s in stats:
                url = s.url or "?"
                if len(url) > 44:
                    url = url[:41] + "…"
                self.stats_box.insert(
                    "end",
                    f"{url:<46} {s.discovered:>8} {s.ping_passed:>8} {s.working:>8} {s.rejected:>9}\n",
                )
                total_discovered += s.discovered
                total_ping += s.ping_passed
                total_working += s.working
                total_rejected += s.rejected
            self.stats_box.insert("end", "-" * 90 + "\n")
            self.stats_box.insert(
                "end",
                f"{'ИТОГО':<46} {total_discovered:>8} {total_ping:>8} {total_working:>8} {total_rejected:>9}\n",
            )
            self.lbl_stats_summary.configure(
                text=f"Всего подписок: {len(stats)} · рабочих конфигов: {total_working} · subs.txt уже рядом с exe"
            )
        else:
            self.stats_box.insert("end", "Статистики пока нет — запустите тестирование.")
            self.lbl_stats_summary.configure(text="")
        self.stats_box.configure(state="disabled")

    # ------------------------------------------------------------ api
    def set_busy(self, busy: bool) -> None:
        self.btn_clear.configure(state="disabled" if busy else "normal")
