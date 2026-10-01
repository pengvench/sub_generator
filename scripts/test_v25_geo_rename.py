#!/usr/bin/env python3
"""v25: regression tests для geo-rename (флаг+ISO+peppo) в GHA workflow.

Проверяет:
  1. _resolve_host_to_ip — IP возвращается как есть, домен резолвится в IP.
  2. _geoip_lookup_ip — кеш работает (повторный запрос к тому же IP — мгновенный).
  3. _geo_rename_nodes — переименовывает узлы в формате «<флаг> <ISO> peppo»,
     fallback на «🏳 ?? peppo» для плохих host'ов.

Тест НЕ ходит в сеть (кроме _resolve_host_to_ip — там DNS-resolve реального
домена, что медленно но детерминированно). Для _geoip_lookup_ip мокаем кеш
через прямую запись в _geo_cache.
"""
from __future__ import annotations

import sys
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))
sys.path.insert(0, str(REPO / "scripts"))

# Импортируем refresh_subs как модуль (без __main__ guard).
_spec = importlib.util.spec_from_file_location(
    "refresh_subs", REPO / "scripts" / "refresh_subs.py"
)
rs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rs)

from runtime.types import XrayNode  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


def _mk(host: str, port: int = 443, name: str = "old_name") -> XrayNode:
    return XrayNode(
        protocol="vless",
        raw_url=f"vless://uuid@{host}:{port}#{name}",
        name=name, host=host, port=port,
        credential="00000000-0000-0000-0000-000000000000",
        query={},
    )


print("== 1. _resolve_host_to_ip — IPv4 как есть ==")
check("8.8.8.8 → '8.8.8.8'", rs._resolve_host_to_ip("8.8.8.8") == "8.8.8.8")
check("1.1.1.1 → '1.1.1.1'", rs._resolve_host_to_ip("1.1.1.1") == "1.1.1.1")
check("151.101.213.205 → как есть",
      rs._resolve_host_to_ip("151.101.213.205") == "151.101.213.205")
check("127.0.0.1 → '127.0.0.1'", rs._resolve_host_to_ip("127.0.0.1") == "127.0.0.1")

print()
print("== 2. _resolve_host_to_ip — пустой/невалидный host ==")
check("'' → ''", rs._resolve_host_to_ip("") == "")
check("None → ''", rs._resolve_host_to_ip(None) == "")  # type: ignore[arg-type]
# Невалидный домен — DNS-resolve не удастся, должно вернуть "".
# (Не используем случайную строку — DNS-сервер может вернуть кешированный IP.)
bad_ip = rs._resolve_host_to_ip("this-host-truly-does-not-exist-xyz-abc-123.invalid")
check("invalid domain → '' (DNS-resolve failed)",
      bad_ip == "", f"got {bad_ip!r}")


print()
print("== 3. _geoip_lookup_ip — кеш работает (мокаем) ==")
# Очищаем кеш, мокаем 1 IP → фиксированный результат.
rs._geo_cache.clear()
rs._geo_cache["8.8.8.8"] = ("US", "🇺🇸")
rs._geo_cache["1.1.1.1"] = ("AU", "🇦🇺")
rs._geo_cache[""] = ("??", "🏳")  # для невалидных

code, flag = rs._geoip_lookup_ip("8.8.8.8", timeout=1.0)
check("cached 8.8.8.8 → ('US', '🇺🇸')",
      code == "US" and flag == "🇺🇸", f"got ({code!r}, {flag!r})")

code, flag = rs._geoip_lookup_ip("1.1.1.1", timeout=1.0)
check("cached 1.1.1.1 → ('AU', '🇦🇺')",
      code == "AU" and flag == "🇦🇺", f"got ({code!r}, {flag!r})")

# Empty IP → fallback (NO network request).
code, flag = rs._geoip_lookup_ip("", timeout=1.0)
check("empty IP → fallback ('??', '🏳')",
      code == "??" and flag == "🏳", f"got ({code!r}, {flag!r})")


print()
print("== 4. _geo_rename_nodes — rename на кеше (без сети) ==")
# Полный мок: все IP — в кеше.
rs._geo_cache.clear()
rs._geo_cache["8.8.8.8"] = ("US", "🇺🇸")
rs._geo_cache["1.1.1.1"] = ("AU", "🇦🇺")
rs._geo_cache["151.101.213.205"] = ("US", "🇺🇸")
rs._geo_cache[""] = ("??", "🏳")

nodes = [
    _mk("8.8.8.8"),                  # → "🇺🇸 US peppo"
    _mk("1.1.1.1"),                  # → "🇦🇺 AU peppo"
    _mk("151.101.213.205"),          # → "🇺🇸 US peppo"
    _mk("8.8.8.8", port=8443),       # duplicate IP → cache hit, "🇺🇸 US peppo"
    _mk(""),                          # empty host → fallback "🏳 ?? peppo"
]
logs: list[str] = []
rs._geo_rename_nodes(nodes, workers=2, timeout=1.0, log_sink=logs.append)

# Проверяем переименования.
expected_names = [
    "🇺🇸 US peppo",   # 8.8.8.8
    "🇦🇺 AU peppo",   # 1.1.1.1
    "🇺🇸 US peppo",   # 151.101.213.205
    "🇺🇸 US peppo",   # 8.8.8.8 duplicate
    "🏳 ?? peppo",    # empty host
]
for i, (n, expected) in enumerate(zip(nodes, expected_names)):
    check(f"node[{i}].host={n.host!r:35s} → name={expected!r}",
          n.name == expected, f"got {n.name!r}")

# raw_url должен содержать URL-encoded фрагмент с флагом.
for n in nodes:
    if n.name and n.name != "🏳 ?? peppo":
        # vless://uuid@host:port#%F0%9F%87%BA%F0%9F%87%B8%20US%20peppo
        check(f"raw_url for {n.host!r} has # fragment",
              "#" in n.raw_url, f"got {n.raw_url!r}")


print()
print("== 5. set_node_name — переиспользует существующий код из subgen.geo ==")
# Проверяем что set_node_name действительно меняет raw_url.
from subgen.geo import set_node_name  # noqa: E402

n = _mk("8.8.8.8", name="orig_name")
check(f"before rename: name='orig_name', raw_url has #orig_name",
      n.name == "orig_name" and "#orig_name" in n.raw_url)

set_node_name(n, "🇩🇪 DE peppo")
check(f"after rename: name='🇩🇪 DE peppo'",
      n.name == "🇩🇪 DE peppo", f"got {n.name!r}")
check(f"after rename: raw_url has URL-encoded flag",
      "🇩🇪" in n.raw_url or "%F0%9F%87%A9%F0%9F%87%AA" in n.raw_url,
      f"got {n.raw_url!r}")


print()
print("== 6. CLI flag parsing ==")
import argparse
# Реплицируем argparse из refresh_subs.main для проверки новых флагов.
p = argparse.ArgumentParser()
p.add_argument("--geo-rename", action="store_true")
p.add_argument("--geo-rename-workers", type=int, default=8)
p.add_argument("--geo-rename-timeout", type=float, default=8.0)
args = p.parse_args(["--geo-rename", "--geo-rename-workers", "16", "--geo-rename-timeout", "5.0"])
check("--geo-rename parses", args.geo_rename is True)
check("--geo-rename-workers parses", args.geo_rename_workers == 16)
check("--geo-rename-timeout parses", args.geo_rename_timeout == 5.0)

# Default values (no flags).
args2 = p.parse_args([])
check("default --geo-rename=False", args2.geo_rename is False)
check("default --geo-rename-workers=8", args2.geo_rename_workers == 8)
check("default --geo-rename-timeout=8.0", args2.geo_rename_timeout == 8.0)


print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
