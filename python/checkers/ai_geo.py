"""ИИ-гео слепок узла: под какой страной exit-IP видят Gemini/OpenAI.

Gemini (Google) и OpenAI/Anthropic блокируют доступ по гео IP-адреса выхода
прокси. Узел с отличной скоростью, но exit-IP в РФ, бесполезен для ИИ-сервисов
— и наоборот: слепок «не Россия» почти гарантирует доступность.

Как тестируем (официального API «в какой я стране» у Google нет):

1. **Cloudflare trace** — GET ``https://chatgpt.com/cdn-cgi/trace`` (fallback
   ``https://claude.ai/cdn-cgi/trace``). Это машиночитаемый plain-text
   ответedge-сервера Cloudflare, перед которым стоит сам OpenAI/Anthropic:

       fl=xxx
       ip=185.123.45.6
       loc=DE          <- ISO-код страны, под которой CF видит exit-IP узла
       http=http/2

   chatgpt.com / claude.ai обслуживаются Cloudflare, поэтому ``loc`` — это
   ровно тот гео-вердикт, по которому OpenAI блокирует РФ. Это самый надёжный
   и «официальный» из доступных машинных сигналов (Cloudflare сам отдаёт его).

2. **Google footer** — GET ``https://www.google.com/`` с Accept-Language: ru.
   Google сам определяет страну IP и пишет её в футер страницы:

       <div class="O3yKUb">Россия</div>

   Это тот же гео-движок, которым руководствуется доступность Gemini: если
   в футере не Россия — Gemini с этого exit-IP открывается. Парсим div по
   классу O3yKUb (класс стабилен годами; CSS-правило ``.O3yKUb{...}``
   отфильтровано требованием закрывающей кавычки перед ``>``).

3. **gemini.google.com** — досягаемость (информативно): SPA всегда отвечает
   200, но вместе со слепком из п.2 даёт уверенный ответ.

Все запросы идут ЧЕРЕЗ ПРОКСИ-УЗЕЛ (SOCKS5 → core → exit): домен цели
передаётся в SOCKS-запросе (ATYP=0x03), резолв выполняет выход узла /
DNS-модуль ядра (IP-literal DoH 1.1.1.1/8.8.8.8). Системный hosts-файл
пользователя (в т.ч. записи, «разблокирующие» сервисы) не участвует вообще:
сервис видит именно exit-IP узла, а не подменённый локальный адрес.

Вердикт ``ai_unblocked``:
- True  — хотя бы один сигнал (CF loc или Google footer) показывает не-РФ;
- False — доступный сигнал показывает РФ;
- None  — сигналы не получены (сервис недоступен/не спарсились) — не фильтрует.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import base

logger = logging.getLogger(__name__)

# Cloudflare-trace эндпоинты ИИ-сервисов (перед Cloudflare).
AI_CF_TRACE_TARGETS: tuple[tuple[str, str], ...] = (
    ("chatgpt.com", "chatgpt.com"),
    ("claude.ai", "claude.ai"),
)
CF_TRACE_PATH = "/cdn-cgi/trace"

# Google-страницы с гео-футером (в порядке приоритета).
GOOGLE_COUNTRY_TARGETS: tuple[tuple[str, str], ...] = (
    ("www.google.com", "/"),
    ("www.google.com", "/search?q=test&num=1"),
)

# Gemini (информативная досягаемость).
GEMINI_HOST = "gemini.google.com"
GEMINI_PATH = "/"

# Таймаут одного запроса (сек).
AI_GEO_TIMEOUT = 6.0

# Имена «России» в футере Google (footer локализуется по Accept-Language;
# мы шлём ru, но добавляем английские варианты на всякий случай).
_RU_NAMES = {"россия", "russia", "russian federation", "российская федерация"}

# <div class="O3yKUb">Россия</div> — захват текста до закрывающего тега.
# CSS-правило `.O3yKUb{padding:...}` не матчится: после имени класса
# требуется закрывающая кавычка + '>' (в CSS идёт '{').
_GOOGLE_COUNTRY_RE = re.compile(rb'O3yKUb"\s*>\s*([^<]{1,48}?)\s*<')

# ISO-код в CF trace: строка "loc=XX".
_CF_LOC_RE = re.compile(rb"^loc=([A-Za-z]{2})\s*$", re.MULTILINE)

# RU-коды (сам ISO и числовой ISO 643 тоже совместим).
_RU_ISO = {"RU", "RUS"}


@dataclass
class AiGeoResult:
    """Результат ИИ-гео слепка узла."""

    checked: bool = False
    accepted: bool = True  # по умолчанию проверка информативная — не отсеивает
    # Сигналы.
    cf_loc: str = ""  # ISO-код страны от Cloudflare (пусто = не получен)
    cf_source: str = ""  # какой из эндпоинтов ответил (chatgpt.com / claude.ai)
    google_country: str = ""  # страна из футера Google (пусто = не спарсился)
    gemini_reachable: bool = False
    # Вердикты.
    openai_ok: bool = False  # CF слепок != RU
    gemini_ok: bool = False  # Google footer != Россия
    ai_unblocked: Optional[bool] = None  # True/False/None (неизвестно)
    reason: str = ""
    details: dict = field(default_factory=dict)

    def row(self) -> dict:
        return {
            "checked": self.checked,
            "accepted": self.accepted,
            "cf_loc": self.cf_loc,
            "cf_source": self.cf_source,
            "google_country": self.google_country,
            "gemini_reachable": self.gemini_reachable,
            "openai_ok": self.openai_ok,
            "gemini_ok": self.gemini_ok,
            "ai_unblocked": self.ai_unblocked,
            "reason": self.reason,
            "details": self.details,
        }


def parse_cf_trace(body: bytes) -> str:
    """Вытащить ISO-код страны (loc=XX) из тела /cdn-cgi/trace."""
    if not body:
        return ""
    match = _CF_LOC_RE.search(body)
    if match is None:
        return ""
    return match.group(1).decode("ascii", errors="replace").upper()


def parse_google_country(html: bytes) -> str:
    """Вытащить страну из футера Google (<div class="O3yKUb">Россия</div>).

    В HTML страницы есть и CSS-правило ``.O3yKUb{padding:...}`` — regex
    требует ``O3yKUb">`` (закрывающая кавычка атрибута класса), поэтому CSS
    не матчится. Возвращает пустую строку, если футера нет.
    """
    if not html:
        return ""
    for match in _GOOGLE_COUNTRY_RE.finditer(html):
        text = match.group(1).decode("utf-8", errors="replace").strip()
        if text:
            return text
    return ""


def is_russia_name(name: str) -> bool:
    """Является ли страна из футера Google Россией (ru/en написания)."""
    return (name or "").strip().lower() in _RU_NAMES


def is_russia_iso(code: str) -> bool:
    """Является ли ISO-код из CF trace кодом России."""
    return (code or "").strip().upper() in _RU_ISO


def compute_verdict(
    cf_loc: str,
    google_country: str,
) -> tuple[bool, bool, Optional[bool], str]:
    """Собрать вердикты из сигналов.

    Возвращает (openai_ok, gemini_ok, ai_unblocked, reason).
    ai_unblocked=None — оба сигнала недоступны (не фильтруем).
    """
    cf_known = bool(cf_loc)
    google_known = bool(google_country)

    openai_ok = cf_known and not is_russia_iso(cf_loc)
    gemini_ok = google_known and not is_russia_name(google_country)

    if not cf_known and not google_known:
        return openai_ok, gemini_ok, None, "ai_signals_unavailable"
    if openai_ok or gemini_ok:
        parts = []
        if cf_known:
            parts.append(f"cf={cf_loc}")
        if google_known:
            parts.append(f"google={google_country}")
        return openai_ok, gemini_ok, True, "ai_geo_ok (" + ", ".join(parts) + ")"
    # Оба доступных сигнала говорят «РФ» (или один сигнал есть и он РФ).
    parts = []
    if cf_known:
        parts.append(f"cf={cf_loc}")
    if google_known:
        parts.append(f"google={google_country}")
    return openai_ok, gemini_ok, False, "ai_geo_russia (" + ", ".join(parts) + ")"


def _probe_cf_trace(
    socks_host: str,
    socks_port: int,
    timeout: float,
) -> tuple[str, str]:
    """Cloudflare trace через прокси. Возвращает (loc, endpoint_host)."""
    for host, sni in AI_CF_TRACE_TARGETS:
        ok, body, status = base.http_get_body(
            socks_host,
            socks_port,
            host,
            443,
            sni,
            CF_TRACE_PATH,
            timeout=timeout,
            max_bytes=8 * 1024,
        )
        if not ok or status != 200 or not body:
            continue
        loc = parse_cf_trace(body)
        if loc:
            return loc, host
    return "", ""


def _probe_google_country(
    socks_host: str,
    socks_port: int,
    timeout: float,
) -> str:
    """Страна из футера Google через прокси (Accept-Language: ru)."""
    for host, path in GOOGLE_COUNTRY_TARGETS:
        ok, body, status = base.http_get_body(
            socks_host,
            socks_port,
            host,
            443,
            host,
            path,
            timeout=timeout,
            max_bytes=320 * 1024,
            extra_headers={"Accept-Language": "ru-RU,ru;q=0.9,en;q=0.6"},
        )
        if not ok or status != 200 or not body:
            continue
        country = parse_google_country(body)
        if country:
            return country
    return ""


def _probe_gemini(
    socks_host: str,
    socks_port: int,
    timeout: float,
) -> bool:
    """Досягаемость gemini.google.com через прокси (информативно)."""
    ok, body, status = base.http_get_body(
        socks_host,
        socks_port,
        GEMINI_HOST,
        443,
        GEMINI_HOST,
        GEMINI_PATH,
        timeout=timeout,
        max_bytes=16 * 1024,
    )
    return bool(ok and status in (200, 302))


def _run_ai_geo_checks(host: str, port: int, timeout: float) -> AiGeoResult:
    """Выполнить ИИ-гео слепок через локальный SOCKS5-прокси узла."""
    result = AiGeoResult(checked=True)

    result.cf_loc, result.cf_source = _probe_cf_trace(host, port, timeout)
    result.google_country = _probe_google_country(host, port, timeout)
    result.gemini_reachable = _probe_gemini(host, port, timeout)

    result.openai_ok, result.gemini_ok, result.ai_unblocked, result.reason = compute_verdict(
        result.cf_loc, result.google_country
    )
    result.details = {
        "cf_loc": result.cf_loc,
        "cf_source": result.cf_source,
        "google_country": result.google_country,
        "gemini_reachable": result.gemini_reachable,
    }
    return result


def check_node_ai_geo_detailed(
    node_url: str,
    timeout: float = AI_GEO_TIMEOUT,
    root_dir: Optional[Path] = None,
) -> AiGeoResult:
    """ИИ-гео слепок узла: под какой страной exit-IP видят Gemini/OpenAI.

    Поднимает временный core-процесс узла и через локальный SOCKS5 запрашивает
    Cloudflare trace (chatgpt.com / claude.ai), футер Google и gemini.google.com.
    Домены целей резолвит выход узла — системный hosts-файл не участвует.

    ``accepted`` = True, если слепок получен (в т.ч. «РФ» — это тоже результат);
    фильтрацию по вердикту выполняет конвейер (``--ai-strict``): узел с
    ``ai_unblocked=False`` (слепок РФ) отбрасывается с reason=ai_geo_russia.
    """
    if not node_url:
        return AiGeoResult(checked=False, accepted=False, reason="empty_node")

    budget = max(20.0, timeout * 5.0)
    result = base.run_with_node(
        node_url,
        lambda host, port: _run_ai_geo_checks(host, port, timeout),
        timeout=timeout,
        root_dir=root_dir,
        budget=budget,
    )
    if result is None:
        return AiGeoResult(checked=False, accepted=False, reason="node_start_failed")
    return result


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if len(sys.argv) < 2:
        print("Usage: python -m checkers.ai_geo <node_url>")
        sys.exit(1)
    res = check_node_ai_geo_detailed(sys.argv[1])
    print(f"AI-geo for {sys.argv[1]}:")
    print(
        f"  cf_loc={res.cf_loc or '-'} (via {res.cf_source or '-'}) "
        f"google={res.google_country or '-'} gemini={res.gemini_reachable}"
    )
    print(f"  openai_ok={res.openai_ok} gemini_ok={res.gemini_ok} verdict={res.ai_unblocked}")
    print(f"  reason={res.reason}")
