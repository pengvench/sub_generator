#!/usr/bin/env python3
"""v33: regression tests для known-good фильтра.

Юзер: "10 конфигов от GHA не работают, test.txt работают на мобиле" —
фикс: workflow фильтрует подписки по паттернам из known_good.txt
(SNI + IP /24) и append'ит сами verified configs в финальный список.

Этот сьют проверяет:
  1. _load_known_good — парсит known_good.txt → SNI set + IP set + узлы.
  2. _node_matches_known_good — 4 режима (sni / ip / sni_or_ip / sni_and_ip / none).
  3. _apply_known_good_filter — фильтрует список + возвращает known_good для append.
  4. CLI flag parsing — --known-good / --known-good-mode / --known-good-ip-prefix.
"""
from __future__ import annotations

import sys
import importlib.util
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))
sys.path.insert(0, str(REPO / "scripts"))

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


def _mk(host: str, sni: str = "", port: int = 443, name: str = "") -> XrayNode:
    return XrayNode(
        protocol="vless",
        raw_url=f"vless://uuid@{host}:{port}",
        name=name or f"{sni or 'no-sni'}@{host}",
        host=host, port=port,
        credential="00000000-0000-0000-0000-000000000000",
        query={"sni": sni} if sni else {},
    )


# Создаём временный known_good.txt с тестовыми конфигами.
_tmpdir = tempfile.mkdtemp(prefix="kg_test_")
_KG_PATH = Path(_tmpdir) / "known_good.txt"
_KG_PATH.write_text(
    "# Verified configs (work on mobile RF)\n"
    "vless://11111111-1111-1111-1111-111111111111@1.2.3.10:443?security=tls&type=tcp&sni=www.sberbank.ru#verified1\n"
    "vless://22222222-2222-2222-2222-222222222222@1.2.3.20:443?security=tls&type=tcp&sni=www.sberbank.ru#verified2\n"
    "vless://33333333-3333-3333-3333-333333333333@8.8.8.8:443?security=tls&type=tcp&sni=dl.google.com#verified3\n"
)

# Сброс кеша перед каждым тестом.
def _reset():
    rs._KNOWN_GOOD_SNI = None
    rs._KNOWN_GOOD_IPS = None
    rs._KNOWN_GOOD_NODES = None


print("== 1. _load_known_good — парсинг файла ==")
_reset()
sni_set, ip_set, kg_nodes = rs._load_known_good(_KG_PATH)
check(f"loaded 3 verified configs", len(kg_nodes) == 3, f"got {len(kg_nodes)}")
check(f"extracted 2 unique SNIs", len(sni_set) == 2, f"got {sni_set}")
check("SNI set has www.sberbank.ru", "www.sberbank.ru" in sni_set, str(sni_set))
check("SNI set has dl.google.com", "dl.google.com" in sni_set, str(sni_set))
check(f"extracted 3 unique IPs", len(ip_set) == 3, f"got {ip_set}")
check("IP set has 1.2.3.10", "1.2.3.10" in ip_set, str(ip_set))
check("IP set has 8.8.8.8", "8.8.8.8" in ip_set, str(ip_set))


print()
print("== 2. _load_known_good — файла нет → пустые сеты ==")
_reset()
sni_set, ip_set, kg_nodes = rs._load_known_good(Path("/nonexistent/path/xyz.txt"))
check(f"no file → empty sets", sni_set == set() and ip_set == set() and kg_nodes == [], f"got {sni_set} {ip_set} {kg_nodes}")


print()
print("== 3. _node_matches_known_good — режим sni_or_ip (default) ==")
_reset()
sni_set, ip_set, _ = rs._load_known_good(_KG_PATH)

# SNI match (sberbank.ru) + IP в /24 known (1.2.3.50 vs 1.2.3.10/24)
n1 = _mk("1.2.3.50", "www.sberbank.ru")
check(f"SNI match (sberbank.ru) + IP in /24 → match",
      rs._node_matches_known_good(n1, sni_set, ip_set, mode="sni_or_ip") is True)

# SNI match (dl.google.com) + IP НЕ в known /24 (8.8.8.8 is, but 9.9.9.9 isn't)
n2 = _mk("9.9.9.9", "dl.google.com")
check(f"SNI match (dl.google.com) + IP NOT in known → match (SNI saved it)",
      rs._node_matches_known_good(n2, sni_set, ip_set, mode="sni_or_ip") is True)

# SNI NOT match + IP в known /24
n3 = _mk("1.2.3.99", "evil.com")
check(f"SNI not match + IP in /24 known → match (IP saved it)",
      rs._node_matches_known_good(n3, sni_set, ip_set, mode="sni_or_ip") is True)

# SNI NOT match + IP NOT in known
n4 = _mk("9.9.9.9", "evil.com")
check(f"SNI not match + IP NOT in known → no match",
      rs._node_matches_known_good(n4, sni_set, ip_set, mode="sni_or_ip") is False)


print()
print("== 4. _node_matches_known_good — strict mode sni_and_ip ==")
check(f"strict AND: SNI match + IP match (n1) → True",
      rs._node_matches_known_good(n1, sni_set, ip_set, mode="sni_and_ip") is True)
check(f"strict AND: SNI match + IP NOT match (n2) → False",
      rs._node_matches_known_good(n2, sni_set, ip_set, mode="sni_and_ip") is False)
check(f"strict AND: SNI NOT match + IP match (n3) → False",
      rs._node_matches_known_good(n3, sni_set, ip_set, mode="sni_and_ip") is False)
check(f"strict AND: SNI NOT match + IP NOT match (n4) → False",
      rs._node_matches_known_good(n4, sni_set, ip_set, mode="sni_and_ip") is False)


print()
print("== 5. _node_matches_known_good — mode sni only / ip only / none ==")
check(f"mode=sni: n2 (SNI match) → True",
      rs._node_matches_known_good(n2, sni_set, ip_set, mode="sni") is True)
check(f"mode=sni: n3 (SNI NOT match) → False",
      rs._node_matches_known_good(n3, sni_set, ip_set, mode="sni") is False)
check(f"mode=ip: n3 (IP match in /24) → True",
      rs._node_matches_known_good(n3, sni_set, ip_set, mode="ip") is True)
check(f"mode=ip: n2 (IP NOT in known /24) → False",
      rs._node_matches_known_good(n2, sni_set, ip_set, mode="ip") is False)
check(f"mode=none: n4 (no match) → True (filter disabled)",
      rs._node_matches_known_good(n4, sni_set, ip_set, mode="none") is True)


print()
print("== 6. _node_matches_known_good — IP prefix /16 / /32 ==")
# /16: 9.9.0.0/16 vs 8.8.0.0/16 → not match. But 1.2.0.0/16 covers 1.2.x.x.
n5 = _mk("1.2.99.99", "evil.com")  # IP NOT in known /24 (1.2.99 vs 1.2.3)
check(f"mode=ip /24: 1.2.99.99 NOT in 1.2.3.0/24 → False",
      rs._node_matches_known_good(n5, sni_set, ip_set, ip_prefix=24, mode="ip") is False)
check(f"mode=ip /16: 1.2.99.99 IS in 1.2.0.0/16 (broader) → True",
      rs._node_matches_known_good(n5, sni_set, ip_set, ip_prefix=16, mode="ip") is True)
# /32: 1.2.3.10 exact only.
check(f"mode=ip /32: 1.2.3.10 exact match → True",
      rs._node_matches_known_good(_mk("1.2.3.10", "evil.com"), sni_set, ip_set, ip_prefix=32, mode="ip") is True)
check(f"mode=ip /32: 1.2.3.11 (same /24, but not exact) → False",
      rs._node_matches_known_good(_mk("1.2.3.11", "evil.com"), sni_set, ip_set, ip_prefix=32, mode="ip") is False)


print()
print("== 7. _apply_known_good_filter — фильтр + append verified ==")
_reset()
nodes = [n1, n2, n3, n4]  # 4 входящих узла
logs: list[str] = []
filtered, kg_to_append = rs._apply_known_good_filter(
    nodes, _KG_PATH, mode="sni_or_ip", ip_prefix=24, log_sink=logs.append,
)
check(f"filter: 4 → 3 (n1 n2 n3 passed, n4 filtered out)",
      len(filtered) == 3, f"got {len(filtered)}")
check(f"known_good configs for append: 3",
      len(kg_to_append) == 3, f"got {len(kg_to_append)}")
# Verify log content.
check(f"log has loaded line", any("loaded 3 verified configs" in l for l in logs), str(logs))
check(f"log has filter line", any("filter: 4 → 3" in l for l in logs), str(logs))


print()
print("== 8. _apply_known_good_filter — файла нет → skip filter ==")
_reset()
nodes = [n1, n2, n3, n4]
logs = []
filtered, kg_to_append = rs._apply_known_good_filter(
    nodes, Path("/nonexistent/path/xyz.txt"),
    mode="sni_or_ip", ip_prefix=24, log_sink=logs.append,
)
check(f"no file → no filter (all 4 pass)", len(filtered) == 4, f"got {len(filtered)}")
check(f"no file → 0 kg_to_append", len(kg_to_append) == 0, f"got {len(kg_to_append)}")
check(f"log has 'not found' message", any("not found" in l for l in logs), str(logs))


print()
print("== 9. CLI flag parsing ==")
import argparse
p = argparse.ArgumentParser()
p.add_argument("--known-good", type=Path)
p.add_argument("--known-good-mode", choices=["sni", "ip", "sni_or_ip", "sni_and_ip", "none"])
p.add_argument("--known-good-ip-prefix", type=int, default=24)
args = p.parse_args([
    "--known-good", "data/known_good.txt",
    "--known-good-mode", "sni_and_ip",
    "--known-good-ip-prefix", "16",
])
check("--known-good parses", args.known_good == Path("data/known_good.txt"), str(args.known_good))
check("--known-good-mode parses", args.known_good_mode == "sni_and_ip", str(args.known_good_mode))
check("--known-good-ip-prefix parses", args.known_good_ip_prefix == 16, str(args.known_good_ip_prefix))

# Default values.
args2 = p.parse_args([])
check(f"default --known-good=None", args2.known_good is None)
check(f"default --known-good-mode=None", args2.known_good_mode is None)
check(f"default --known-good-ip-prefix=24", args2.known_good_ip_prefix == 24)


print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
