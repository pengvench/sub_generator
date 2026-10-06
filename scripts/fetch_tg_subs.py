#!/usr/bin/env python3
"""Сбор динамических подписок из Telegram-каналов и зеркал.

Запускается в GitHub Actions перед refresh_subs.py (см.
.github/workflows/refresh-subs.yml). Собирает URL'ы подписок, которые
меняются со временем, и пишет их в data/tg_subs.txt (один URL на строку,
без комментариев). refresh_subs.py подхватывает их через
`--extra-sources-file data/tg_subs.txt` и мёрджит с основным
data/sources.txt.

Источники:
  1. t.me/s/<channel>  — Telegram web-preview последних постов публичного
     канала (HTML, не требует авторизации). Скрапим `tgme_widget_message_text`,
     ищем в постах `happ://crypt5/...` (Hiddify-зашифрованную ссылку) ИЛИ
     `https://...exec?url=...` (URL подписки).
     По умолчанию канал = happvpn (см. --channel).
     Берётся ПОСЛЕДНИЙ пост с совпадением (самый свежий).

  2. mifa.world/<category>  — публичный endpoint: возвращает base64-encoded
     подписку с vless:// / vmess:// / trojan:// конфигами. Список категорий
     (ursa, vless, bober, ronin, hysteria, ...) парсится с главной страницы
     https://mifa.world/ из таблицы статистики (HTML <td>NAME</td><td>COUNT</td>).
     Каждый день список немного меняется, поэтому ПАРИМ ВСЕ 15 категорий.

     Примечание: оригинальная инструкция юзера была «парси t.me/mifa_world/1310
     и забери https://mifa.world/ursa оттуда». Пост 1310 — это "service message"
     (фото/видео), web-preview Telegram НЕ отдаёт его текст анонимам. Поэтому
     вместо парсинга конкретного поста мы парсим главную mifa.world и забираем
     ВСЕ категории. Это надёжнее (не зависит от доступности поста) и даёт
     больше конфигов.

Запуск:
  python scripts/fg_subs.py \\
      --channel happvpn \\
      --output data/tg_subs.txt \\
      --mifa-categories-auto \\
      --timeout 20.0

  # Только happvpn (без MIFA):
  python scripts/fetch_tg_subs.py --no-mifa

  # Только MIFA (без happvpn):
  python scripts/fetch_tg_subs.py --no-tg

Артефакт:
  data/tg_subs.txt — по одной ссылке на строку. Файл перезаписывается
  при каждом запуске. Формат идентичен data/sources.txt (refresh_subs.py
  понимает оба).

Возвращает:
  0 — успех (хотя бы один URL найден, файл записан).
  1 — фатальная ошибка (нет интернета, нет постов, нет категорий —
      файл НЕ создан, чтобы сохранить старый кеш).

Зависимости:
  Только стандартная библиотека (urllib, re). Без pip-пакетов.
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Telegram web-preview возвращает HTML с user-agent check.
# Используем десктопный Chrome UA — без него t.me отдаёт упрощённую
# mobile-страницу (без div.tgme_widget_message_text).
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
_HEADERS = {
    "User-Agent": _UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
}


def _fetch_html(url: str, *, timeout: float = 20.0) -> str:
    """Скачать HTML с retries (1 попытка, без external deps).

    Telegram web-preview иногда отдаёт 429 (rate limit) или 503 —
    в таких случаях возвращаем пустую строку, вызывающий код решает
    что делать (skip / fallback).
    """
    req = Request(url, headers=_HEADERS)
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            # t.me всегда отдаёт UTF-8. В крайней ситуации (broken bytes)
            # errors='replace' не падает.
            return data.decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        print(f"[tg] fetch FAILED for {url}: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
        return ""


# --------------------------------------------------------------------- HTML parse
# <div class="tgme_widget_message_text ...">...post content...</div>
# Структура проверена на t.me/s/happvpn (2026-10-04): 20 постов на страницу,
# каждый пост обёрнут в этот div. Внутри — HTML с <tg-emoji>, <a>, текстом.
_TG_POST_RE = re.compile(
    r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
    re.DOTALL,
)

# happ://crypt5/<base64-like-payload>
# Символы: A-Z, a-z, 0-9, +, /, =, _, - (URL-safe base64 + стандартный).
_HAPP_URL_RE = re.compile(r'happ://crypt\d+/[A-Za-z0-9+/=_-]+')

# Любой https:// URL, заканчивающийся на /auto или содержащий /sub/ или /exec?url=
# (паттерн подписок tetta-prod, tetragidro, ...).
_SUB_URL_RE = re.compile(
    r'https?://[^\s<>"]+?(?:/sub/|/exec\?url=|/auto\b)[^\s<>"]*'
)

# HTML entities которые встречаются в постах (список неполный, но достаточный
# для our use-case — нам важны URL'ы, в них только &amp; обычен).
_HTML_ENTITY_MAP = {
    "&amp;": "&",
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&#x27;": "'",
    "&#39;": "'",
    "&nbsp;": " ",
}


def _strip_html(html_fragment: str) -> str:
    """Убрать HTML-теги и расшифровать базовые entities.

    Посты Telegram содержат <tg-emoji>, <a>, <br> — для поиска URL'а
    внутри нужен plain text. Делаем минимальный strip без BS4 (не тащим
    зависимость в GHA runner).
    """
    # Убираем все теги (включая атрибуты).
    text = re.sub(r"<[^>]+>", " ", html_fragment)
    # Entities → символы.
    for entity, char in _HTML_ENTITY_MAP.items():
        text = text.replace(entity, char)
    # Сжимаем множественные пробелы (от стёртых тегов).
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _find_subscription_in_post(post_html: str) -> str | None:
    """Извлечь URL подписки из HTML одного поста.

    Возвращает happ://crypt5/... ИЛИ https://... URL. Если пост не содержит
    подписки — None. Сначала ищем happ:// (более специфичный паттерн),
    потом — обычный URL с /sub/ /exec?url= /auto.
    """
    plain = _strip_html(post_html)
    # 1) happ://crypt5/... (приоритет — это явно подписка).
    m = _HAPP_URL_RE.search(plain)
    if m:
        return m.group(0)
    # 2) Обычный URL подписки.
    m = _SUB_URL_RE.search(plain)
    if m:
        return m.group(0)
    return None


def _parse_tg_channel_posts(html: str) -> list[str]:
    """Извлечь тексты постов из HTML t.me/s/<channel>.

    Возвращает список HTML-фрагментов (по одному на пост), в порядке
    их появления на странице (от старых к новым — t.me/s/ отдаёт так).
    """
    if not html:
        return []
    return _TG_POST_RE.findall(html)


# --------------------------------------------------------------------- MIFA
# mifa.world главная содержит <table> с <tr><td>NAME</td><td>COUNT</td>...
# NAME — категория (ursa/vless/bober/...), COUNT — сколько конфигов.
_MIFA_CATEGORY_ROW_RE = re.compile(
    r'<td>([a-z][a-z0-9_]{1,30})</td>\s*<td>(\d+)</td>'
)


def _parse_mifa_categories(html: str) -> list[str]:
    """Извлечь имена категорий из главной mifa.world.

    Возвращает уникальный список имён (ursa, vless, bober, ronin, ...).
    Порядок сохраняется как на странице (по убыванию популярности).
    """
    if not html:
        return []
    seen: set[str] = set()
    categories: list[str] = []
    for match in _MIFA_CATEGORY_ROW_RE.finditer(html):
        name = match.group(1)
        if name in seen:
            continue
        # Отсекаем мусор (строки-числа, общие слова).
        if name in {"other", "all"}:
            continue
        seen.add(name)
        categories.append(name)
    return categories


# --------------------------------------------------------------------- main
def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Сбор динамических подписок из Telegram + mifa.world.",
    )
    p.add_argument("--channel", default="happvpn",
                   help="Имя Telegram-канала для парсинга (default: happvpn). "
                        "Канал должен быть публичным (t.me/<channel> открывается "
                        "без входа). Если приватный — web-preview пустой.")
    p.add_argument("--output", type=Path,
                   default=Path("data/tg_subs.txt"),
                   help="Куда писать URL'ы (default: data/tg_subs.txt). "
                        "Файл перезаписывается. Если 0 URL'ов найдено — "
                        "существующий файл НЕ трогается (чтобы сохранить кеш).")
    p.add_argument("--timeout", type=float, default=20.0,
                   help="Таймаут HTTP-запроса, сек (default: 20.0).")
    p.add_argument("--no-tg", action="store_true",
                   help="Не парсить Telegram (только mifa.world).")
    p.add_argument("--no-mifa", action="store_true",
                   help="Не парсить mifa.world (только Telegram).")
    p.add_argument("--mifa-base", default="https://mifa.world",
                   help="Базовый URL MIFA (default: https://mifa.world). "
                        "Можно переопределить, если домен заблокирован.")
    p.add_argument("--mifa-categories", nargs="*", default=[],
                   help="Явный список категорий MIFA (ursa, bober, ...). "
                        "Если не задан — парсим с mifa-base главной страницы "
                        "(если --no-mifa-categories-auto не установлен).")
    p.add_argument("--mifa-categories-auto", action="store_true", default=True,
                   help="Парсить категории с главной mifa-base (default: ON). "
                        "Если задан --mifa-categories, оба списка мёрджатся.")
    p.add_argument("--no-mifa-categories-auto", dest="mifa_categories_auto",
                   action="store_false",
                   help="Не парсить главную mifa-base (только --mifa-categories).")
    args = p.parse_args(argv)

    def log(msg: str) -> None:
        print(msg, flush=True)

    urls: list[str] = []

    # 1) Telegram channel: последний пост с happ:// или sub URL.
    if not args.no_tg:
        channel_url = f"https://t.me/s/{args.channel}"
        log(f"[tg] fetching {channel_url} ...")
        html = _fetch_html(channel_url, timeout=args.timeout)
        if html:
            posts = _parse_tg_channel_posts(html)
            log(f"[tg] {args.channel}: parsed {len(posts)} posts")
            # Идём от свежих к старым (t.me/s/ отдаёт старые → свежие,
            # так что переворачиваем).
            for post_html in reversed(posts):
                sub = _find_subscription_in_post(post_html)
                if sub:
                    log(f"[tg] {args.channel}: found {sub[:80]}{'...' if len(sub) > 80 else ''}")
                    urls.append(sub)
                    break  # только последний пост
            else:
                log(f"[tg] {args.channel}: NO subscription URL in recent posts "
                    "(channel may be private or post is service-message)")
        else:
            log(f"[tg] {args.channel}: HTML fetch returned empty")

    # 2) mifa.world: парсим категории и формируем URL'ы.
    if not args.no_mifa:
        categories: list[str] = list(args.mifa_categories)
        if args.mifa_categories_auto:
            log(f"[tg] fetching {args.mifa_base}/ for categories list ...")
            home_html = _fetch_html(args.mifa_base, timeout=args.timeout)
            auto_cats = _parse_mifa_categories(home_html)
            if auto_cats:
                log(f"[tg] mifa.world: parsed {len(auto_cats)} categories: "
                    f"{', '.join(auto_cats[:10])}{' ...' if len(auto_cats) > 10 else ''}")
                # Мёрджим (preserve order, dedup).
                seen = set(categories)
                for c in auto_cats:
                    if c not in seen:
                        categories.append(c)
                        seen.add(c)
            else:
                log("[tg] mifa.world: failed to parse categories from home "
                    "(site may be down or layout changed)")
        if not categories:
            # Fallback: hardcoded минимальный набор (категории, которые
            # регулярно встречаются на mifa.world — сентябрь 2026).
            categories = ["ursa", "vless", "bober", "ronin", "hysteria"]
            log(f"[tg] mifa.world: using fallback categories: {categories}")
        # Формируем URL'ы (один на категорию).
        for cat in categories:
            url = f"{args.mifa_base}/{cat}"
            urls.append(url)
        log(f"[tg] mifa.world: {len(categories)} URLs added "
            f"(each returns base64-encoded subscription)")

    # Dedupe preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)

    if not unique:
        log("[tg] FATAL: 0 URLs collected. Existing tg_subs.txt (if any) is KEPT.")
        return 1

    # v50: СКАЧИВАЕМ подписки и парсим в КОНФИГИ (vless://, vmess://, ...).
    # Раньше писали URL'ы подписок в tg_subs.txt, потом refresh_subs.py их
    # скачивал. Теперь — пишем сразу готовые конфиги, юзер видит в файле
    # именно vless://..., а не URL подписки.
    #
    # v50b: ОТФИЛЬТРОВЫВАЕМ фейковые конфиги. Mifa.world отдаёт ОДНУ рабочую
    # категорию в день, остальные — заглушки с фейковым конфигом
    # (uuid=00000000-0000-0000-0000-000000000000, host=127.0.0.1). Фильтруем
    # их, оставляя только реальные.
    log(f"[tg] downloading {len(unique)} subscription(s) and parsing to configs...")
    REPO = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(REPO / "python"))
    try:
        from runtime.fetch import _fetch_text
        from runtime.parse import _node_links_from_text
    except ImportError as exc:
        log(f"[tg] FATAL: cannot import runtime.fetch/parse: {exc}")
        log("[tg] Make sure you're running from sub_generator/ root.")
        return 1

    # Признаки фейкового конфига (заглушка mifa.world):
    _FAKE_HOSTS = {"127.0.0.1", "0.0.0.0", "localhost", "example.com"}
    _FAKE_UUID_PART = "00000000-0000-0000-0000-000000000000"

    def _is_fake_config(cfg_url: str) -> bool:
        """Проверить, фейковый ли конфиг (заглушка mifa.world)."""
        if _FAKE_UUID_PART in cfg_url:
            return True
        # Извлечь host:port из URL (после @, до : или ?).
        # vless://uuid@host:port?... — host между @ и : port.
        if "@" in cfg_url:
            after_at = cfg_url.split("@", 1)[1]
            # host:port? или host:port/
            host_part = after_at.split(":")[0] if ":" in after_at else after_at.split("?")[0]
            if host_part in _FAKE_HOSTS:
                return True
        return False

    all_configs: list[str] = []
    failed_subs: list[str] = []
    fake_filtered = 0
    for sub_url in unique:
        try:
            body = _fetch_text(sub_url, timeout=args.timeout, log_sink=log)
            if not body:
                log(f"[tg] fetch returned empty: {sub_url[:80]}")
                failed_subs.append(sub_url)
                continue
            configs = _node_links_from_text(body)
            # v50b: отфильтровать фейковые (заглушки mifa.world).
            real_configs = [c for c in configs if not _is_fake_config(c)]
            fake_count = len(configs) - len(real_configs)
            fake_filtered += fake_count
            if real_configs:
                log(f"[tg] {sub_url[:60]}: {len(real_configs)} real configs "
                    f"({fake_count} fake filtered)")
                all_configs.extend(real_configs)
            elif configs:
                log(f"[tg] {sub_url[:60]}: 0 real ({len(configs)} all fake — placeholder)")
            else:
                log(f"[tg] {sub_url[:60]}: parsed 0 configs")
        except Exception as exc:
            log(f"[tg] {sub_url[:60]}: FAILED: {type(exc).__name__}: {exc}")
            failed_subs.append(sub_url)

    # Дедуплицируем конфиги (по полному URL).
    seen_cfg: set[str] = set()
    unique_cfgs: list[str] = []
    for cfg in all_configs:
        if cfg not in seen_cfg:
            seen_cfg.add(cfg)
            unique_cfgs.append(cfg)

    if not unique_cfgs:
        log("[tg] FATAL: 0 real configs parsed. Existing tg_subs.txt (if any) is KEPT.")
        return 1

    # Записываем конфиги (НЕ URL'ы подписок!).
    args.output.parent.mkdir(parents=True, exist_ok=True)
    header = (f"# Auto-generated by scripts/fetch_tg_subs.py at "
              f"{time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
              f"# Sources: t.me/s/{args.channel} + {args.mifa_base}/\n"
              f"# {len(unique)} subscription(s) → {len(unique_cfgs)} unique real configs "
              f"({fake_filtered} fake filtered, {len(failed_subs)} failed subs)\n"
              f"# Format: один vless:// / vmess:// / ... на строку\n")
    body = "\n".join(unique_cfgs) + "\n"
    args.output.write_text(header + body, encoding="utf-8")
    log(f"[tg] wrote {len(unique_cfgs)} real configs to {args.output} "
        f"(from {len(unique)} subs, {fake_filtered} fake filtered, {len(failed_subs)} failed)")
    # Лог топ-протоколов для прозрачности.
    protos: dict[str, int] = {}
    for cfg in unique_cfgs:
        if "://" in cfg:
            proto = cfg.split("://", 1)[0]
            protos[proto] = protos.get(proto, 0) + 1
    if protos:
        log(f"[tg] protocols breakdown: {protos}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
