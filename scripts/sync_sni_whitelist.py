#!/usr/bin/env python3
"""Синка community-curated whitelist'ов из hxehex/russia-mobile-internet-whitelist.

Запускается перед scripts/refresh_subs.py (в GHA workflow) и локально.
Без этого скрипта checkers/sni_category.py и checkers/cidr_whitelist.py
используют только встроенные ~80 доменов (без CIDR) — основной, но не полный.

Источник: https://github.com/hxehex/russia-mobile-internet-whitelist
  whitelist.txt     — ~910 доменов (SNI) — community-curated 2026,
                      обновляется постоянно людьми, которые сканируют
                      IP-диапазоны во время блокировок мобильного интернета РФ.
  cidrwhitelist.txt — ~30 000 CIDR-подсетей (IPv4) — то, что TSPU пропускает.
                      Без этого TSPU-строгий фильтр не работает: даже при
                      идеальном SNI (sberbank.ru) узел блокируется, если IP
                      сервера не в BS-CIDR. См. checkers/cidr_whitelist.py.
  ipwhitelist.txt   — ~141 000 отдельных IP (избыточно для нас, CIDR покрывает).

Этот скрипт качает whitelist.txt (всегда) + cidrwhitelist.txt (если --with-cidr).
Кладёт в data/sni_whitelist.txt и data/cidr_whitelist.txt.

Запуск:
  python scripts/sync_sni_whitelist.py                  # только SNI
  python scripts/sync_sni_whitelist.py --with-cidr      # SNI + CIDR (рекомендуется для GHA)
  python scripts/sync_sni_whitelist.py --dry-run         # без записи

Альтернативный upstream (например, форк сообщества):
  --source-sni   https://raw.githubusercontent.com/ваш/форк/main/whitelist.txt
  --source-cidr  https://raw.githubusercontent.com/ваш/форк/main/cidrwhitelist.txt

Exit codes:
  0 — все запрошенные файлы обновлены (или уже актуальные).
  1 — фатальная ошибка (сеть, upstream недоступен, файл не записан).
"""
from __future__ import annotations

import argparse
import sys
import time
import urllib.request
from pathlib import Path

# Дефолтные upstream'ы — community-curated 2026 RU mobile whitelist.
# Хранилище: github.com/hxehex/russia-mobile-internet-whitelist.
DEFAULT_SOURCE_SNI = (
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist"
    "/main/whitelist.txt"
)
DEFAULT_SOURCE_CIDR = (
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist"
    "/main/cidrwhitelist.txt"
)

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_SNI = REPO / "data" / "sni_whitelist.txt"
DEFAULT_OUTPUT_CIDR = REPO / "data" / "cidr_whitelist.txt"

HEADER_TEMPLATE = """# {kind} whitelist for RU mobile operators (TSPU).
# Source: {source}
# Synced: {timestamp} UTC
# Entry count: {count}
# Total size: {size} bytes
#
# Format: one {kind_unit} per line, lowercase.
# Lines starting with '#' are ignored by checkers/*_whitelist modules.
# Auto-managed by scripts/sync_sni_whitelist.py — manual edits will be overwritten.
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
    """Получить отсортированный список валидных доменов из upstream-текста."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.count(":") == 1 and not line.startswith("["):
            line = line.split(":", 1)[0]
        line = line.lower().rstrip(".")
        if not line or "." not in line:
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return sorted(out)


def _normalize_cidrs(text: str) -> list[str]:
    """Получить отсортированный список валидных CIDR'ов из upstream-текста."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Срезать порт, если вдруг «2.63.0.0/17:443».
        if line.count(":") == 1:
            line = line.split(":", 1)[0]
        line = line.lower()
        if line in seen:
            continue
        # Базовая валидация: формат «A.B.C.D/MASK».
        if "/" not in line:
            continue
        seen.add(line)
        out.append(line)
    return sorted(out)


def _sync_one(name: str, source: str, output: Path, kind: str,
              kind_unit: str, normalize_fn, *, timeout: float,
              dry_run: bool) -> tuple[bool, int]:
    """Скачать + нормализовать + записать один файл. Возвращает (ok, count)."""
    print(f"[sync] {name}: downloading from: {source}")
    try:
        text = _download(source, timeout=timeout)
    except Exception as exc:
        print(f"[sync] {name}: FATAL: download failed: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return False, 0

    print(f"[sync] {name}: downloaded {len(text)} bytes")
    items = normalize_fn(text)
    print(f"[sync] {name}: normalized: {len(items)} unique {kind_unit}")

    if not items:
        print(f"[sync] {name}: FATAL: 0 {kind_unit} after normalization — upstream returned empty/garbage",
              file=sys.stderr)
        return False, 0

    body = "\n".join(items) + "\n"
    header = HEADER_TEMPLATE.format(
        kind=kind,
        source=source,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        count=len(items),
        size=len(body),
        kind_unit=kind_unit,
    )
    full = header + body

    if dry_run:
        print(f"[sync] {name}: --dry-run, not writing file")
        print(f"[sync] {name}: would write {len(full)} bytes to {output}")
        print(f"[sync] {name}: top 5 {kind_unit}: {items[:5]}")
        return True, len(items)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(full, encoding="utf-8")
    print(f"[sync] {name}: wrote {len(full)} bytes ({len(items)} {kind_unit}) to {output}")
    print(f"[sync] {name}: top 5 {kind_unit}: {items[:5]}")
    return True, len(items)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Sync SNI + CIDR whitelist from community-curated upstream.",
    )
    p.add_argument("--source-sni", default=DEFAULT_SOURCE_SNI,
                   help="Upstream URL для SNI whitelist (домены).")
    p.add_argument("--source-cidr", default=DEFAULT_SOURCE_CIDR,
                   help="Upstream URL для CIDR whitelist (IPv4 подсети).")
    p.add_argument("--output-sni", type=Path, default=DEFAULT_OUTPUT_SNI,
                   help=f"Output SNI file (default: {DEFAULT_OUTPUT_SNI}).")
    p.add_argument("--output-cidr", type=Path, default=DEFAULT_OUTPUT_CIDR,
                   help=f"Output CIDR file (default: {DEFAULT_OUTPUT_CIDR}).")
    p.add_argument("--with-cidr", action="store_true",
                   help="Также скачать cidrwhitelist.txt (30k CIDR'ов). "
                        "Рекомендуется для GHA: TSPU-строгий фильтр "
                        "(--tspu-sim в refresh_subs.py) без этого не работает.")
    p.add_argument("--sni-only", action="store_true",
                   help="Скачать ТОЛЬКО SNI whitelist (старый режим, без CIDR). "
                        "Аналог запуска БЕЗ --with-cidr; оставлен для явности.")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="Download timeout, seconds (default: 30.0).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print stats, but don't write files.")
    args = p.parse_args(argv)

    ok_total = True

    # SNI whitelist — качаем ВСЕГДА (это основной список доменов).
    ok_sni, count_sni = _sync_one(
        name="SNI",
        source=args.source_sni,
        output=args.output_sni,
        kind="community-curated SNI",
        kind_unit="domains",
        normalize_fn=_normalize_domains,
        timeout=args.timeout,
        dry_run=args.dry_run,
    )
    ok_total = ok_total and ok_sni

    # CIDR whitelist — только если --with-cidr (или не --sni-only).
    if args.with_cidr and not args.sni_only:
        ok_cidr, count_cidr = _sync_one(
            name="CIDR",
            source=args.source_cidr,
            output=args.output_cidr,
            kind="community-curated CIDR (TSPU IPv4 subnets)",
            kind_unit="CIDRs",
            normalize_fn=_normalize_cidrs,
            timeout=args.timeout,
            dry_run=args.dry_run,
        )
        ok_total = ok_total and ok_cidr

    if not ok_total:
        print("[sync] FATAL: at least one sync failed", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
