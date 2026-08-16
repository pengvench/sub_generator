"""Всплывающая подсказка в стиле ZapretUI (тёмный фон, рамка, (?) иконка)."""
from __future__ import annotations

import tkinter as tk


class CTkToolTip:
    """Тултип поверх виджета. delay — задержка показа в мс."""

    def __init__(self, widget, text: str, delay: int = 500) -> None:
        self.widget = widget
        self.text = str(text)
        self.delay = delay
        self._tip: tk.Toplevel | None = None
        self._after_id: str | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None) -> None:
        self._cancel()
        self._after_id = self.widget.after(self.delay, self._show)

    def _cancel(self) -> None:
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show(self) -> None:
        self._hide()
        try:
            x = self.widget.winfo_rootx() + 18
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        except Exception:
            return
        tip = tk.Toplevel(self.widget)
        tip.wm_overrideredirect(True)
        tip.wm_geometry(f"+{x}+{y}")
        tip.configure(bg="#111922")
        frame = tk.Frame(tip, bg="#111922", highlightbackground="#22C7E8", highlightthickness=1)
        frame.pack(fill="both", expand=True)
        label = tk.Label(
            frame,
            text=self.text,
            justify="left",
            bg="#111922",
            fg="#E7EDF3",
            font=("Segoe UI", 9),
            padx=10,
            pady=7,
            wraplength=340,
        )
        label.pack()
        self._tip = tip

    def _hide(self, _event=None) -> None:
        self._cancel()
        if self._tip is not None:
            try:
                self._tip.destroy()
            except Exception:
                pass
            self._tip = None


def info_label(master, help_text: str, **kwargs):
    """Иконка (?) с тултипом-справкой, как в ZapretUI (🛈 #7DD8ED)."""
    import customtkinter as ctk

    lbl = ctk.CTkLabel(
        master,
        text="(?)",
        width=18,
        text_color="#22C7E8",
        cursor="hand2",
        font=ctk.CTkFont(size=12, weight="bold"),
        **kwargs,
    )
    CTkToolTip(lbl, help_text)
    return lbl
