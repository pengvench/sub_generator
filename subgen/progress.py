"""Единый сквозной прогресс через PowerShell Write-Progress.

Скрипт печатает в stdout маркеры вида:
  [POWERPROGRESS]|pct|stage|current|total|message
Обёртка run_sub_generator.ps1 перехватывает их и рисует Write-Progress
(полосу в заголовке окна). При прямом запуске python маркеры не выводятся,
и вывод остаётся обычным текстовым логом.
"""
from __future__ import annotations

import os

from subgen.logging import _safe_print

_ps_available = os.environ.get("SUB_GEN_PS_WRAPPER") == "1"



class _PowerShellProgress:
    """Единый сквозной прогресс всего процесса через Write-Progress.

    Фазы (загрузка подписок, ping, stress, dpi, geo) имеют веса;
    индикатор показывает глобальный процент и текущую фазу в строке
    заголовка окна PowerShell, поэтому текстовый вывод логов не портится.
    """

    MARKER = "[POWERPROGRESS]"

    def __init__(self) -> None:
        self._stages: list[str] = []
        self._weights: list[float] = []
        self._counts: list[int] = []
        self._totals: list[int] = []
        self._completed: list[float] = []
        self._active_stage = 0
        self._last_pct = -1
        self._last_msg: str = ""
        self._cleared = False

    # -- построение шкалы (весов и границ фаз) --------------------------------
    def add_stage(self, label: str, weight: float, total: int = 1) -> None:
        """Зарегистрировать фазу с весом (0..1). total можно уточнить позже."""
        self._stages.append(str(label))
        self._weights.append(max(0.0, float(weight)))
        self._counts.append(0)
        self._totals.append(max(1, int(total)))
        self._completed.append(0.0)

    def set_total(self, index: int, total: int) -> None:
        """Установить реальное количество элементов фазы (когда оно известно)."""
        if 0 <= index < len(self._stages):
            self._totals[index] = max(1, int(total))

    def stage_index(self, label: str) -> int:
        """Индекс фазы по метке или -1, если фаза не зарегистрирована."""
        try:
            return self._stages.index(str(label))
        except ValueError:
            return -1

    @property
    def active_stage(self) -> int:
        return self._active_stage

    # -- расчёт глобального процента ------------------------------------------
    def _fraction(self, stage: int) -> float:
        total = self._totals[stage] if 0 <= stage < len(self._totals) else 0
        if total <= 0:
            return 0.0
        return max(0.0, min(1.0, self._counts[stage] / total))

    def _global_fraction(self) -> float:
        total_weight = sum(self._weights)
        if total_weight <= 1e-9:
            return 0.0
        done = 0.0
        for i, weight in enumerate(self._weights):
            if i < self._active_stage:
                done += weight
            elif i == self._active_stage:
                done += self._fraction(i) * weight
        return max(0.0, min(1.0, done / total_weight))

    def _percent(self, stage: int) -> int:
        if 0 <= stage < len(self._totals) and self._totals[stage] > 0:
            return int(round(100.0 * self._counts[stage] / self._totals[stage]))
        return 100

    # -- рендер маркера ----------------------------------------------------------
    def _render(self, current_message: str = "") -> None:
        if not _ps_available:
            return
        pct = int(round(self._global_fraction() * 100))
        stage = self._stages[self._active_stage] if self._stages else ""
        current = self._counts[self._active_stage] if self._stages else 0
        total = self._totals[self._active_stage] if self._stages else 0
        msg = str(current_message or stage or "")
        if pct == self._last_pct and msg == self._last_msg:
            return
        self._last_pct = pct
        self._last_msg = msg
        clean = " ".join(msg.split())[:120].replace("|", "/").replace("\n", " ")
        _safe_print(f"{self.MARKER}|{pct}|{stage}|{current}|{total}|{clean}")


    def _clear(self) -> None:
        if not _ps_available or self._cleared:
            return
        self._cleared = True
        _safe_print(f"{self.MARKER}_END")


    # -- публичный API ----------------------------------------------------------
    def start_stage(self, index: int, message: str = "") -> None:
        if not (0 <= index < len(self._stages)):
            return
        self._active_stage = index
        self._counts[index] = 0
        self._completed[index] = 0.0
        if message:
            self._render(message)

    def update(self, done: int, message: str = "") -> None:
        if not self._stages:
            return
        self._counts[self._active_stage] = int(done)
        self._render(message or "")

    def message(self, text: str) -> None:
        """Печать служебного сообщения в обычный поток логов."""
        _safe_print(str(text))


    def finish_stage(self, index: int, summary: str = "") -> None:
        """Завершить фазу и перейти к следующей зарегистрированной."""
        if 0 <= index < len(self._stages):
            self._completed[index] = self._weights[index]
            self._counts[index] = self._totals[index]
            if index == self._active_stage:
                nxt = self._next_stage(index)
                if nxt is None:
                    self._clear()
                else:
                    self._active_stage = nxt
                    self._render("")
        if summary:
            self.message(summary)

    def is_completed(self, index: int) -> bool:
        """Завершена ли фаза (вклад в глобальный прогресс зафиксирован)."""
        return 0 <= index < len(self._completed) and self._completed[index] >= self._weights[index]

    def _next_stage(self, index: int) -> int | None:
        for i in range(index + 1, len(self._stages)):
            if self._weights[i] > 0 and self._completed[i] <= 0:
                return i
        return None

    def close(self) -> None:
        """Скрыть индикатор (вызывается в конце)."""
        self._clear()
