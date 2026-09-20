"""Хоткеи копирования/вставки, работающие при ЛЮБОЙ раскладке (RU/EN/…).

Жалоба юзера 2026-09-20: «много где не работает копипаст на русском —
Ctrl+C/V/A на английской раскладке работают, на русской нет; импорт тому
пример».

Причина: Tk матчит биндинги <Control-v> по KEYSYM (символу), а на русской
раскладке физическая клавиша V даёт keysym 'Cyrillic_em' — паттерн
<Control-v> не совпадает, виртуальное событие <<Paste>> не генерируется,
и вставка молча не происходит.

Решение: один перехватчик <Control-KeyPress> через bind_all (тег 'all'
срабатывает последним, ПОСЛЕ классовых биндингов Tk). Виджет в фокусе
достаётся из event.widget; раскладку определяем по KEYSYM: латиница =
английская раскладка, штатные биндинги уже всё сделали — пропускаем
(иначе вставка задвоится). Иначе диспетчерим по KEYCODE — коду ФИЗИЧЕСКОЙ
клавиши, который не зависит от раскладки (на Windows это VK-код: C=67,
V=86, A=65, X=88) — и генерируем виртуальное событие <<Copy>>/<<Cut>>/
<<Paste>>/<<SelectAll>>, которое классовые биндинги Entry/Text умеют
обрабатывать.

Приоритет пользовательских биндингов не нарушается: виджетные биндинги
срабатывают раньше 'all', и их 'break' останавливает наш обработчик.
Поэтому кастомное поведение (вставка-с-заменой в «Импорт», копирование
всего списка в «Списке») работает как раньше — но теперь и на русской
раскладке, потому что такие обработчики вешаются на ВИРТУАЛЬНЫЕ события
(<<Paste>>), которые мы тоже синтезируем.

Проверено на Windows (VK-коды) и X11 (keycode физической клавиши),
плюс страховочный матчинг по keysym и самому символу (в т.ч. кириллица:
C=с, V=м, A=ф, X=ч).
"""
from __future__ import annotations

import tkinter as tk

# Коды ФИЗИЧЕСКИХ клавиш (не зависят от раскладки).
_VK = {'c': 67, 'v': 86, 'a': 65, 'x': 88}   # Windows (VK_*)
_XK = {'c': 54, 'v': 55, 'a': 38, 'x': 53}   # Linux/X11 (core keycodes)
# Кириллические двойники на русской раскладке (та же физическая клавиша).
_CYR = {'c': 'с', 'v': 'м', 'a': 'ф', 'x': 'ч'}

# Оконная система ('win32' / 'x11' / 'aqua') — определяется при install().
# На win32 keycode = VK-код, на x11 — X-keycode; таблицы не смешиваем
# (на X11 код 65 — это ПРОБЕЛ, а не VK_A: смешение давало бы ложные срабатывания).
_WINDOWINGSYSTEM = None


# Клавиши, чьи Ctrl-комбинации УЖЕ покрыты классовыми биндингами Tk на
# текущей платформе (наш обработчик на теге 'all' срабатывает ПОСЛЕ
# классовых — для них пропускаем, чтобы не задвоить действие).
#   win32: Ctrl+C/X/V/A — всё покрыто (<<Copy>>=<Control-c> и т.д.).
#   x11:   Ctrl+C/X/V покрыты, а <<SelectAll>> висит на <Control-/>
#          (Ctrl+A классом НЕ покрыт — обрабатываем сами, как на Windows).
_CLASS_COVERED = {"win32": {"c", "x", "v", "a"}, "x11": {"c", "x", "v"}}

# Физическая клавиша -> виртуальное событие Tk (классовые биндинги
# Entry/Text уже умеют их выполнять).
_ACTIONS = (
    ('c', '<<Copy>>'),
    ('x', '<<Cut>>'),
    ('v', '<<Paste>>'),
    ('a', '<<SelectAll>>'),
)


def _latin_keycodes(latin: str) -> tuple[int, ...]:
    """Допустимые keycode физической клавиши для текущей платформы."""
    if _WINDOWINGSYSTEM == "win32":
        return (_VK[latin],)
    if _WINDOWINGSYSTEM == "x11":
        return (_XK[latin],)
    return (_VK[latin], _XK[latin])  # неизвестно — обе таблицы


def _is_ctrl(event) -> bool:
    """Зажат ли Control (бит 0x4 в state)."""
    try:
        return bool(event.state & 0x0004)
    except Exception:
        return False


def _match_key(event, latin: str) -> bool:
    """Нажата ли физическая клавиша `latin` (в любой раскладке)."""
    keysym = (getattr(event, "keysym", "") or "").lower()
    if keysym == latin:
        return True
    keycode = getattr(event, "keycode", 0) or 0
    if keycode in _latin_keycodes(latin):
        return True
    char = (getattr(event, "char", "") or "").lower()
    return char in (latin, _CYR[latin])


def _is_latin_letter_keysym(keysym: str) -> bool:
    """ KEYSYM — латинская БУКВЕННАЯ клавиша (английская раскладка)?

    Важно: сравниваем ОДНОСИМВОЛЬНЫЙ keysym. Имена НЕбуквенных клавиш —
    тоже слова из латинских букв ('space', 'Return', 'Escape', 'Home',
    'Prior', 'Insert'...) — их пропускать нельзя (иначе Ctrl+пробел в RU
    раскладке будет ложно считаться «уже обработанным»). Реальная
    латинская буква всегда даёт keysym из одного символа ('c', 'V').
    """
    return len(keysym) == 1 and keysym.isascii() and keysym.isalpha()


def _on_ctrl_key(event):
    """Перехватчик на теге 'all' (срабатывает ПОСЛЕ классовых биндингов)."""
    widget = event.widget
    if not isinstance(widget, (tk.Entry, tk.Text)):
        return None
    if not _is_ctrl(event):
        return None
    keysym = getattr(event, "keysym", "") or ""
    if _is_latin_letter_keysym(keysym):
        covered = _CLASS_COVERED.get(_WINDOWINGSYSTEM, {"c", "x", "v", "a"})
        if keysym.lower() in covered:
            # Английская раскладка: штатные биндинги Tk уже сработали на
            # классовом уровне (до нас). Не дублируем — иначе двойная вставка.
            return None
        # x11 и Ctrl+A (и прочие платформенные пробелы) — идём дальше:
        # _match_key сработает по самому keysym.
    for latin, virtual in _ACTIONS:
        if _match_key(event, latin):
            try:
                widget.event_generate(virtual)
            except Exception:
                pass
            return "break"
    return None


def install(app) -> None:
    """Повесить перехватчик на всё приложение (все окна, включая диалоги)."""
    global _WINDOWINGSYSTEM
    try:
        _WINDOWINGSYSTEM = app.tk.call("tk", "windowingsystem")
    except Exception:
        _WINDOWINGSYSTEM = None
    app.bind_all("<Control-KeyPress>", _on_ctrl_key, add="+")
