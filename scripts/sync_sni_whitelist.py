#!/usr/bin/env python3
"""Синка community-curated SNI-whitelist из hxehex/russia-mobile-internet-whitelist.

Запускается перед scripts/refresh_subs.py (в GHA workflow) и локально.
Без этого скрипта checkers/sni_category.py использует только встроенный
WHITE_SNI_DOMAINS (~80 доменов) — основной, но не полный список.

Источник: https://github.com/hxehex/russia-mobile-internet-whitelist
  whitelist.txt   — 910 доменов (SNI) — community-curated 2026, обновляется
                    постоянно людьми, которые сканируют IP-диапазоны во время
                    блокировок мобильного интернета РФ и смотрят что живёт.
  ipwhitelist.txt — 141k IP-адресов (отдельные адреса, не SNI).
  cidrwhitelist.txt — 30k CIDR-подсетей.

Этот скрипт качает ТОЛЬКО whitelist.txt (домены), кладёт в
data/sni_whitelist.txt. При следующем запуске refresh_subs.py модуль
checkers.sni_category автоматически подхватит расширенный список
через _load_extra_whitelist().

Запуск:
  python scripts/sync_sni_whitelist.py                  # дефолт
  python scripts/sync_sni_whitelist.py --output /tmp/wl.txt
  python scripts/sync_sni_whitelist.py --source URL     # альтернативный upstream

Альтернативный upstream (например, форк сообщества):
  --source https://raw.githubusercontent.com/ваш/форк/main/whitelist.txt

Exit codes:
  0 — файл обновлён (или уже актуальный).
  1 — фатальная ошибка (сеть, upstream недоступен, файл не записан).
"""
from __future__ import annotations

import argparse
import sys
import time
import urllib.request
from pathlib import Path

# Дефолтный upstream — community-curated 2026 RU mobile whitelist.
# Хранилище: github.com/hxehex/russia-mobile-internet-whitelist.
# Обновляется сообществом: люди сканируют IP-диапазоны во время блокировок
# и смотрят, что живёт. ~910 доменов, постоянно обновляется.
DEFAULT_SOURCE = (
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist"
    "/main/whitelist.txt"
)

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO / "data" / "sni_whitelist.txt"

# Заголовок, который мы пишем в начало data/sni_whitelist.txt для понятности.
HEADER_TEMPLATE = """# community-curated SNI whitelist for RU mobile operators.
# Source: {source}
# Synced: {timestamp} UTC
# Domain count: {count}
# Total size: {size} bytes
#
# Format: one domain per line, lowercase, no port.
# Lines starting with '#' are ignored by checkers/sni_category.py.
# Auto-managed by scripts/sync_sni_whitelist.py — manual edits will be overwritten.
# Edit WHITE_SNI_DOMAINS in python/checkers/sni_category.py for permanent additions.
"""


def _download(url: str, timeout: float = 30.0) -> str:
    """Скачать текст по URL. Возвращает строку или поднимает исключение."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "sub_generator/sync_sni_whitelist (Linux GHA)",
        "Accept": "text/plain,*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _normalize_domains(text: str) -> list[str]:
    """Получить отсортированный список валидных доменов из upstream-текста.

    Строки с '#' в начале или пустые — пропускаются. Домены приводятся к
    lowercase, обрезается trailing '.'. Дубли убираются.
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Срезать порт, если вдруг «host:443».
        if line.count(":") == 1 and not line.startswith("["):
            line = line.split(":", 1)[0]
        line = line.lower().rstrip(".")
        # Базовая валидация: домен содержит хотя бы одну точку и буквы.
        if not line or "." not in line:
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return sorted(out)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Sync SNI whitelist from community-curated upstream.",
    )
    p.add_argument("--source", default=DEFAULT_SOURCE,
                   help=f"Upstream URL (default: hxehex/russia-mobile-internet-whitelist).")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                   help=f"Output file (default: {DEFAULT_OUTPUT}).")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="Download timeout, seconds (default: 30.0).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print stats, but don't write the file.")
    args = p.parse_args(argv)

    print(f"[sync] downloading from: {args.source}")
    try:
        text = _download(args.source, timeout=args.timeout)
    except Exception as exc:
        print(f"[sync] FATAL: download failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"[sync] downloaded {len(text)} bytes")
    domains = _normalize_domains(text)
    print(f"[sync] normalized: {len(domains)} unique domains")

    if not domains:
        print("[sync] FATAL: 0 domains after normalization — upstream returned empty/garbage")
        return 1

    body = "\n".join(domains) + "\n"
    header = HEADER_TEMPLATE.format(
        source=args.source,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        count=len(domains),
        size=len(body),
    )
    full = header + body

    if args.dry_run:
        print("[sync] --dry-run: not writing file")
        print(f"[sync] would write {len(full)} bytes to {args.output}")
        print(f"[sync] top 5 domains: {domains[:5]}")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(full, encoding="utf-8")
    print(f"[sync] wrote {len(full)} bytes ({len(domains)} domains) to {args.output}")
    print(f"[sync] top 10 domains: {domains[:10]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
