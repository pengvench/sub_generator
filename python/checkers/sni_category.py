"""Классификация SNI-домена узла: БС / ЧС / серый / фейк.

Введено под запрос юзера 2026-09-29: на ограниченных сетях РФ (мобильные
операторы) работают только узлы с SNI из БЕЛОГО списка (www.sberbank.ru,
vk.com, www.gosuslugi.ru ...). Узлы с SNI из чёрного списка
(instagram.com, chatgpt.com ...) НЕ проходят DPI-блок. Узлы со случайным
или фейковым SNI (типа abc12345.example) сейчас могут работать, но это
хрупкая конструкция: ТСПУ обучают распознавать паттерны.

Этот модуль НЕ запускает xray — это чистая статическая классификация
по полям XrayNode.query (sni/host) или XrayNode.host. Работает на Linux
и Windows, в GHA и в основном приложении.

Категории:
  БС (white)   — SNI домен в WHITE_SNI_DOMAINS. На ограниченных сетях РФ
                  проходит без проблем.
  ЧС (black)   — SNI домен в BLACK_SNI_DOMAINS. На ограниченных сетях РФ
                  блокируется DPI. На открытом интернете — работает.
  серый (grey) — SNI похож на реальный домен (есть ., известная TLD),
                  но не входит в белый/чёрный список. Поведение на
                  ограниченных сетях неизвестно.
  фейк (fake)  — SNI выглядит сгенерированным (короткий, без точки,
                  случайные символы). Сейчас может работать, но
                  нестабилен — ТСПУ обучают распознавать.
  none         — SNI не задан в URL узла (используется host:port напрямую,
                  что на паблик-узлах == его реальному домену). На
                  ограниченных сетях почти наверняка блокируется.

Источники списков:
  WHITE — расширенный список из checkers/resilience.py:WHITE_SNI_TARGETS
          (банки/маркетплейсы/госуслуги РФ) + ручные дополнения
          (CDN-домены, известные whitelist'ы) + dynamic-load из
          data/sni_whitelist.txt (community-curated 2026: см.
          scripts/sync_sni_whitelist.py — синк из hxehex/russia-mobile-
          internet-whitelist, ~910 доменов, обновляется сообществом).
  BLACK — checkers.blocked_services + runtime.types.BLOCKED_MEDIA_TARGETS
          (Instagram, ChatGPT, Twitter, Facebook, ...).

Конфиг считается прошедшим «БС-фильтр» для ограниченной сети если его
SNI-категория == "white" (строгий режим) или {"white","grey","fake"}
(мягкий режим: фейки пока работают).
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Iterable

from runtime.types import XrayNode


# -------------------------------------------------------------------- списки

# Путь к dynamic-whitelist файлу — кладётся scripts/sync_sni_whitelist.py
# (зеркало hxehex/russia-mobile-internet-whitelist/main/whitelist.txt,
# ~910 доменов). Файл ищется относительно:
#   1. переменной окружения SNI_WHITELIST_FILE (для GHA/CI);
#   2. data/sni_whitelist.txt относительно корня репо;
#   3. data/sni_whitelist.txt относительно cwd.
# ВНИМАНИЕ: не кешируем список путей на уровне модуля — env var должна
# перечитываться при каждом вызове (иначе тесты, меняющие os.environ,
# не увидят изменений).
def _extra_whitelist_paths() -> list[Path]:
    return [
        Path(os.environ.get("SNI_WHITELIST_FILE", "")),
        Path(__file__).resolve().parent.parent.parent / "data" / "sni_whitelist.txt",
        Path.cwd() / "data" / "sni_whitelist.txt",
    ]


def _load_extra_whitelist() -> set[str]:
    """Динамический whitelist из data/sni_whitelist.txt (если есть).

    Файл — простые строки (по одной на домен), пустые/# игнорируются.
    Зеркалит hxehex/russia-mobile-internet-whitelist/main/whitelist.txt
    (community-curated RU mobile whitelist, ~910 доменов). Если файла нет
    (например, запустили без sync_sni_whitelist.py) — берём только
    встроенный WHITE_SNI_DOMAINS.
    """
    for path in _extra_whitelist_paths():
        try:
            if not path or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            return {
                line.strip().lower().rstrip(".")
                for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            }
        except Exception:
            continue
    return set()


# РАЗРЕШЁННЫЕ (БЕЛЫЕ) SNI — проходят на ограниченных сетях РФ.
# Это МИНИМАЛЬНЫЙ встроенный список (~80 доменов) для работы без
# sync_sni_whitelist.py. Для полного покрытия (~910 доменов) запустите
# scripts/sync_sni_whitelist.py — он зеркалит hxehex/russia-mobile-internet-
# whitelist (community-curated 2026 RU mobile whitelist). Список ниже —
# подмножество «must-have» (если ничего не выкачано).
WHITE_SNI_DOMAINS: frozenset[str] = frozenset({
    # РФ: банки и финансы (Tinkoff = T-Банк с 2024)
    "www.sberbank.ru", "sberbank.ru",
    "www.tinkoff.ru", "tinkoff.ru", "www.tbank.ru", "tbank.ru",
    "www.vtb.ru", "vtb.ru",
    "www.gazprombank.ru", "gazprombank.ru",
    "www.raiffeisen.ru", "raiffeisen.ru",
    "www.alfabank.ru", "alfabank.ru", "alfa-mobile.alfabank.ru",

    # РФ: маркетплейсы и интернет-сервисы
    "www.wildberries.ru", "wildberries.ru", "wb.ru", "www.wb.ru",
    "www.ozon.ru", "ozon.ru",
    "www.avito.ru", "avito.ru", "www.avito.st", "avito.st",
    "www.lamoda.ru", "lamoda.ru", "www.lemanapro.ru", "lemanapro.ru",

    # РФ: Яндекс-экосистема (mail/kinopoisk/maps/dzen/yabs)
    "www.yandex.ru", "yandex.ru", "yabs.yandex.ru", "an.yandex.ru",
    "api-maps.yandex.ru", "market.yandex.ru",
    "ya.ru", "www.ya.ru", "300.ya.ru",
    "www.yandex.com", "yandex.com", "yandex.net", "www.yandex.net",
    "yastatic.net", "www.yastatic.net",
    "www.kinopoisk.ru", "kinopoisk.ru",
    "zen.yandex.ru", "zen.yandex.com", "zen.yandex.net",
    "dzen.ru", "www.dzen.ru",

    # РФ: Mail.ru Group (входит в whitelist РФ-мобильных)
    "mail.ru", "www.mail.ru", "1l.mail.ru", "1l-api.mail.ru",
    "www.biz.mail.ru", "www.mcs.mail.ru",

    # РФ: соцсети и медиа
    "vk.com", "www.vk.com", "vk.ru", "www.vk.ru",
    "ok.ru", "www.ok.ru",
    "rutube.ru", "www.rutube.ru",
    "userapi.com", "www.userapi.com",  # VK CDN

    # РФ: госуслуги и госорганизации
    "www.gosuslugi.ru", "gosuslugi.ru", "bot.gosuslugi.ru",
    "www.gazprom.ru", "gazprom.ru",
    "www.rzd.ru", "rzd.ru", "cargo.rzd.ru", "adm.mp.rzd.ru",
    "www.aeroflot.ru", "aeroflot.ru",
    "www.cikrf.ru", "cikrf.ru", "www.gov.ru", "gov.ru",
    "www.t2.ru", "t2.ru",  # Tele2 (раньше тоже был в whitelist)

    # РФ: карты и локация
    "2gis.com", "www.2gis.com", "2gis.ru", "www.2gis.ru",

    # Глобальные CDN — РФ не блокирует по экономическим причинам.
    "www.microsoft.com", "microsoft.com", "windowsupdate.microsoft.com",
    "dl.google.com", "play.google.com", "www.google.com", "google.com",
    "www.apple.com", "apple.com", "swcdn.apple.com",
    "www.cloudflare.com", "cloudflare.com",
    "www.akamai.com", "akamai.com",
    "aws.amazon.com", "www.amazon.com", "amazon.com",
    "www.gstatic.com", "gstatic.com",
    "www.googletagmanager.com", "googletagmanager.com",
    "www.googlesyndication.com", "googlesyndication.com",

    # РФ-дополнения 2026-Q3 (по результатам авто-выборки + сообщества).
    "store.steampowered.com", "steamcommunity.com",
    "api.telegram.org",  # не блокируется в РФ для API-эндпоинтов
    "ubuntu.com", "www.ubuntu.com",
    "nodejs.org", "www.nodejs.org",
    "github.com", "www.github.com", "raw.githubusercontent.com",
    "codeload.github.com", "objects.githubusercontent.com",
    "www.max.ru", "max.ru",  # VK Music
})

# ЗАПРЕЩЁННЫЕ (ЧЁРНЫЕ) SNI — блокируются DPI в РФ. Источник:
# checkers.blocked_services.BLOCKED_SERVICES_HOSTS +
# runtime.types.BLOCKED_MEDIA_TARGETS + экстраполяция по санкционным спискам.
BLACK_SNI_DOMAINS: frozenset[str] = frozenset({
    # Соцсети и медиа (запрещены в РФ с 2022-2024)
    "instagram.com", "www.instagram.com", "i.instagram.com",
    "facebook.com", "www.facebook.com", "m.facebook.com",
    "twitter.com", "www.twitter.com", "x.com", "www.x.com",
    "tiktok.com", "www.tiktok.com",
    "whatsapp.com", "www.whatsapp.com", "web.whatsapp.com",
    "linkedin.com", "www.linkedin.com",

    # AI-сервисы (запрещены/частично блокируются)
    "chatgpt.com", "chat.openai.com", "openai.com", "www.openai.com",
    "claude.ai", "www.claude.ai", "anthropic.com",
    "gemini.google.com", "bard.google.com",

    # Новости (запрещены как «фейк-ньюс»)
    "www.bbc.com", "bbc.com",
    "www.reuters.com", "reuters.com",
    "www.dw.com", "dw.com",
    "meduza.io", "www.meduza.io",
    "svoboda.org", "www.svoboda.org",

    # Западные медиа-агрегаторы
    "www.theguardian.com", "theguardian.com",
    "www.washingtonpost.com", "washingtonpost.com",
    "www.nytimes.com", "nytimes.com",
})

# Суффиксы TLD, которые считаем «похожими на реальный домен».
# Используется для серой зоны: если SNI заканчивается на одну из этих TLD
# и не в белом/чёрном списке — это «серый» (может работать или нет).
_REAL_TLDS: frozenset[str] = frozenset({
    "com", "net", "org", "io", "ru", "su", "co", "uk", "de", "fr", "eu",
    "info", "biz", "me", "tv", "cc", "cn", "jp", "kr", "in", "br",
    "ca", "au", "ch", "nl", "es", "it", "pl", "se", "no", "fi",
    "dev", "app", "xyz", "top", "site", "online", "store", "tech",
})

# Паттерн «реального» SNI: как минимум две точки в имени (x.y.tld),
# либо one-label + TLD (y.tld), где длина x.y >= 4 символов.
_REAL_SNI_RE = re.compile(
    r"^(?=.{2,253}$)"                        # RFC 1035: 1..253
    r"(?!-)[a-z0-9-]{1,63}(?<!-)"            # первая метка
    r"(\.(?!-)[a-z0-9-]{1,63}(?<!-))+",      # ... повторяющиеся .метки
    re.IGNORECASE,
)

# Паттерн «фейкового» SNI: чисто случайная строка из латиницы/цифр,
# без точки (например «abc12345»). ТСПУ быстро учится их блокировать.
_FAKE_SNI_RE = re.compile(r"^[a-z0-9]{4,30}$", re.IGNORECASE)


# -------------------------------------------------------------------- логика

# Порядок категорий для сортировки (приоритет в выдаче).
# white (БС) — самый высокий приоритет для ограниченной сети.
# black (ЧС) — последний (на ограниченной сети точно не работает).
SNI_CATEGORY_PRIORITY: dict[str, int] = {
    "white": 0,   # БС — гарантированно проходит
    "grey":  1,   # серый — реальный домен, поведение неизвестно
    "fake":  2,   # фейк — сейчас работает, но нестабильно
    "none":  3,   # SNI не задан — почти всегда блокируется
    "black": 4,   # ЧС — точно блокируется
}


# Комбинированный whitelist: встроенный (WHITE_SNI_DOMAINS) + dynamic
# (data/sni_whitelist.txt, если sync_sni_whitelist.py его скачал).
# Ленивое кеширование при первом обращении.
_COMBINED_WHITELIST: frozenset[str] | None = None


def get_whitelist() -> frozenset[str]:
    """Полный whitelist: встроенный + dynamic-load (если data/sni_whitelist.txt есть).

    Возвращает кешированный frozenset. После sync_sni_whitelist.py кеш нужно
    инвалидировать через reset_cache() — например, в тестах.
    """
    global _COMBINED_WHITELIST
    if _COMBINED_WHITELIST is None:
        extra = _load_extra_whitelist()
        _COMBINED_WHITELIST = frozenset(WHITE_SNI_DOMAINS | extra)
    return _COMBINED_WHITELIST


def reset_cache() -> None:
    """Сбросить кеш whitelist (для тестов / после sync_sni_whitelist.py)."""
    global _COMBINED_WHITELIST
    _COMBINED_WHITELIST = None


def node_sni(node: XrayNode) -> str:
    """Эффективный SNI узла: из query.sni, query.host или из host (как fallback).

    Xray/sing-box: если sni не задан в URL, ядро использует host как SNI.
    Для паблик-узлов с реальным доменом это работает; для IP-адресов
    TLS-хендшейк падает (нет SNI) — это категория «none».
    """
    sni = (node.query.get("sni") or node.query.get("host") or "").strip().lower()
    if sni:
        return sni
    # Fallback: host может быть реальным доменом или IP.
    host = (node.host or "").strip().lower()
    if host and not _is_ip(host):
        return host
    return ""


def _is_ip(value: str) -> bool:
    """Простая IPv4/IPv6-проверка — IP не может быть SNI."""
    if not value:
        return False
    if value.count(".") == 3 and all(
        part.isdigit() and 0 <= int(part) <= 255 for part in value.split(".")
    ):
        return True
    return value.startswith("[") or ":" in value  # IPv6


def _normalize_domain(sni: str) -> str:
    """Срезать порт (если был задан sni:443), www-префикс игнорируем.

    Сравнение доменов — по суффиксу (sberbank.ru == www.sberbank.ru).
    """
    sni = sni.strip().lower().rstrip(".")
    if not sni:
        return ""
    # Срезаем :port.
    if sni.count(":") == 1 and not sni.startswith("["):
        sni = sni.split(":", 1)[0]
    return sni


def _matches_whitelist(sni: str, whitelist: Iterable[str]) -> bool:
    """SNI в whitelist по точному или суффиксному совпадению.

    «sberbank.ru» в whitelist → «www.sberbank.ru» совпадает,
                                  «sub.sberbank.ru» совпадает,
                                  «sberbank.ru.evil.com» НЕ совпадает.
    """
    sni = _normalize_domain(sni)
    if not sni:
        return False
    for w in whitelist:
        w = _normalize_domain(w)
        if not w:
            continue
        if sni == w or sni.endswith("." + w):
            return True
    return False


def sni_category(node: XrayNode) -> str:
    """Классифицировать SNI узла. Возвращает одну из категорий.

    Returns:
        "white" — SNI в БЕЛОМ списке (проходит на ограниченной сети).
        "black" — SNI в ЧЁРНОМ списке (блокируется на ограниченной сети).
        "grey"  — SNI похож на реальный домен, но не в списках.
        "fake"  — SNI выглядит сгенерированным (нет точки, короткая строка).
        "none"  — SNI не задан и host — это IP-адрес.
    """
    sni = _normalize_domain(node_sni(node))
    if not sni:
        return "none"
    # Используем комбинированный whitelist: встроенный (~80 доменов) +
    # data/sni_whitelist.txt (~910 доменов, если sync_sni_whitelist.py
    # его выкачал). Кешируется в get_whitelist().
    if _matches_whitelist(sni, get_whitelist()):
        return "white"
    if _matches_whitelist(sni, BLACK_SNI_DOMAINS):
        return "black"
    if not _REAL_SNI_RE.match(sni):
        if _FAKE_SNI_RE.match(sni):
            return "fake"
        return "none"
    # Реальный домен, проверяем TLD-суффикс.
    last_label = sni.rsplit(".", 1)[-1] if "." in sni else sni
    if last_label in _REAL_TLDS:
        return "grey"
    if _FAKE_SNI_RE.match(sni):
        return "fake"
    return "none"


def passes_filter(node: XrayNode, *, allow_grey: bool = True,
                  allow_fake: bool = False) -> bool:
    """Прошёл ли узел БС-фильтр для ограниченной сети.

    Строгий режим (allow_grey=False, allow_fake=False):
        только white SNI — гарантированно работает на ограниченной сети.
    Мягкий режим (allow_grey=True, allow_fake=False):
        white + grey — реальный домен с неизвестным DPI-статусом.
    Мягко-фейк (allow_grey=True, allow_fake=True):
        white + grey + fake — но фейки нестабильны.
    """
    cat = sni_category(node)
    if cat == "white":
        return True
    if cat == "grey" and allow_grey:
        return True
    if cat == "fake" and allow_fake:
        return True
    return False


def sort_by_sni(nodes: list[XrayNode], *, white_first: bool = True) -> list[XrayNode]:
    """Сортировать узлы по приоритету SNI-категории.

    white (БС) → grey → fake → none → black (ЧС). Сохраняет исходный порядок
    внутри одной категории. Возвращает НОВЫЙ список (не мутирует вход).
    """
    if not white_first:
        return list(nodes)
    return sorted(
        nodes,
        key=lambda n: SNI_CATEGORY_PRIORITY.get(sni_category(n), 99),
    )


def category_summary(nodes: list[XrayNode]) -> dict[str, int]:
    """Сводка: сколько узлов в каждой SNI-категории."""
    summary: dict[str, int] = {"white": 0, "grey": 0, "fake": 0,
                               "none": 0, "black": 0}
    for n in nodes:
        cat = sni_category(n)
        summary[cat] = summary.get(cat, 0) + 1
    return summary


__all__ = [
    "BLACK_SNI_DOMAINS",
    "SNI_CATEGORY_PRIORITY",
    "WHITE_SNI_DOMAINS",
    "category_summary",
    "get_whitelist",
    "node_sni",
    "passes_filter",
    "reset_cache",
    "sni_category",
    "sort_by_sni",
]
