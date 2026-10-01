#!/usr/bin/env python3
"""v24: TSPU-эмулятор (SNI в BS AND IP в BS-CIDR) — статическая эмуляция TSPU.

Реальная TSPU на мобильной сети РФ проверяет ДВА условия одновременно:
  1. SNI в TLS ClientHello должен быть в БЕЛОМ списке (sberbank.ru, vk.com ...).
  2. Destination IP (это IP прокси-сервера) должен быть в CIDR-whitelist'е
     (30k подсетей от hxehex/russia-mobile-internet-whitelist).

Без ОДНОГО условия — ТСПУ блокирует (RST или silent drop). Модуль
checkers/cidr_whitelist.py эмулирует эту логику статически, без поднятия
сети: валидирует SNI через sni_category + проверяет IP через cidr_whitelist.

Этот сьют проверяет все категории verdict'ов и комбинации флагов.
"""
from __future__ import annotations

import sys
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

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


# Stub CIDR whitelist file for deterministic tests — указываем через env var
# ДО импорта модуля, чтоб _extra_whitelist_paths() подхватил.
import os as _os  # noqa: E402
import tempfile  # noqa: E402
_tmpdir = tempfile.mkdtemp(prefix="tspu_test_")
_cidr_file = Path(_tmpdir) / "cidr_whitelist.txt"
_cidr_file.write_text(
    "# test cidr whitelist\n"
    "2.63.0.0/17\n"          # 2.63.0.0 — 2.63.127.255 (passes)
    "192.168.1.0/24\n"       # 192.168.1.0 — 192.168.1.255 (passes)
    "10.0.0.0/8\n"           # 10.0.0.0 — 10.255.255.255 (passes)
)
_os.environ["CIDR_WHITELIST_FILE"] = str(_cidr_file)

from checkers.cidr_whitelist import (  # noqa: E402
    is_ip_in_whitelist,
    load_cidr_whitelist,
    node_ip_status,
    reset_cache,
    tspu_strict_passes,
    tspu_summary,
)
from checkers.sni_category import reset_cache as _reset_sni_cache  # noqa: E402
from runtime.types import XrayNode  # noqa: E402

# Сброс кешей, чтобы подхватить test cidr file.
reset_cache()
_reset_sni_cache()


def _mk(host: str, sni: str = "", port: int = 443) -> XrayNode:
    """Создать XrayNode с заданным host (IP/domain) и SNI в query."""
    return XrayNode(
        protocol="vless",
        raw_url=f"vless://uuid@{host}:{port}",
        name=f"{sni or 'no-sni'}@{host}",
        host=host, port=port,
        credential="00000000-0000-0000-0000-000000000000",
        query={"sni": sni} if sni else {},
    )


print("== 1. is_ip_in_whitelist: валидные IP в тестовом whitelist ==")
check("2.63.5.10 в 2.63.0.0/17", is_ip_in_whitelist("2.63.5.10"))
check("2.63.127.255 — последняя в /17", is_ip_in_whitelist("2.63.127.255"))
check("192.168.1.100 в 192.168.1.0/24", is_ip_in_whitelist("192.168.1.100"))
check("10.5.5.5 в 10.0.0.0/8", is_ip_in_whitelist("10.5.5.5"))

print()
print("== 2. is_ip_in_whitelist: IP НЕ в whitelist ==")
check("2.63.128.1 — первая после /17", not is_ip_in_whitelist("2.63.128.1"))
check("1.1.1.1 (Cloudflare DNS)", not is_ip_in_whitelist("1.1.1.1"))
check("8.8.8.8 (Google DNS)", not is_ip_in_whitelist("8.8.8.8"))
check("192.168.2.1 — другая /24", not is_ip_in_whitelist("192.168.2.1"))

print()
print("== 3. is_ip_in_whitelist: не-IP host'ы ==")
check("www.example.com (domain) → False", not is_ip_in_whitelist("www.example.com"))
check("empty string → False", not is_ip_in_whitelist(""))
check("None → False", not is_ip_in_whitelist(None))  # type: ignore[arg-type]
check("IPv6 [::1] → False (не IPv4)", not is_ip_in_whitelist("[::1]"))
check("IPv6 plain 2001:db8::1 → False", not is_ip_in_whitelist("2001:db8::1"))

print()
print("== 4. node_ip_status — категории IP узла ==")
check("IP в whitelist → 'whitelisted'",
      node_ip_status(_mk("2.63.5.10")) == "whitelisted")
check("IPv4 не в whitelist → 'ip_not_whitelisted'",
      node_ip_status(_mk("1.1.1.1")) == "ip_not_whitelisted")
check("domain host → 'domain'",
      node_ip_status(_mk("realhost.com")) == "domain")
check("empty host → 'empty'",
      node_ip_status(XrayNode("vless", "url", "n", "", 443, "x", {})) == "empty")


print()
print("== 5. tspu_strict_passes — строгий режим (default) ==")
# Идеальный узел: BS SNI + IP в CIDR.
ok, reason = tspu_strict_passes(_mk("2.63.5.10", "www.sberbank.ru"))
check(f"BS SNI + IP в CIDR → PASS ({reason})", ok and reason == "whitelisted",
      f"got {(ok, reason)}")

# SNI в BS, но IP НЕ в CIDR — типичный «обломится на мобильной сети РФ».
ok, reason = tspu_strict_passes(_mk("1.1.1.1", "www.sberbank.ru"))
check(f"BS SNI + IP НЕ в CIDR (v36 cidr_check=False default) → PASS",
      ok and reason == "whitelisted", f"got {(ok, reason)}")

# SNI ЧС, IP в CIDR — блок по SNI.
ok, reason = tspu_strict_passes(_mk("2.63.5.10", "instagram.com"))
check(f"ЧС SNI + IP в CIDR → FAIL ({reason})",
      not ok and reason == "sni_blacklisted", f"got {(ok, reason)}")

# SNI в BS, но host — домен (не можем проверить CIDR без DNS).
# v34: было FAIL "ip_domain_unresolved" → теперь SKIP (TSPU делает DNS-resolve сам).
ok, reason = tspu_strict_passes(_mk("realhost.com", "www.sberbank.ru"))
check(f"BS SNI + domain host → PASS (whitelisted, domain host skip CIDR check)",
      ok and reason == "whitelisted", f"got {(ok, reason)}")

# Серый SNI + IP в CIDR — strict FAIL (allow_grey=False explicitly).
ok, reason = tspu_strict_passes(_mk("2.63.5.10", "realhost.com"), allow_grey=False)
check(f"серый SNI + IP в CIDR (strict, allow_grey=False) → FAIL ({reason})",
      not ok and reason == "sni_grey", f"got {(ok, reason)}")

# v35: DEFAULT allow_grey=True → серый SNI проходит!
ok, reason = tspu_strict_passes(_mk("2.63.5.10", "realhost.com"))  # default
check(f"серый SNI + IP в CIDR (DEFAULT allow_grey=True) → PASS ({reason})",
      ok and reason == "whitelisted", f"got {(ok, reason)}")

# Фейк SNI + IP в CIDR — strict FAIL по SNI.
ok, reason = tspu_strict_passes(_mk("2.63.5.10", "abc12345"))
check(f"фейк SNI + IP в CIDR → FAIL ({reason})",
      not ok and reason == "sni_fake", f"got {(ok, reason)}")

# Пустой SNI + IP в CIDR — FAIL (нет SNI = блок).
ok, reason = tspu_strict_passes(_mk("2.63.5.10", ""))
check(f"пустой SNI + IP в CIDR → FAIL ({reason})",
      not ok and reason == "sni_empty", f"got {(ok, reason)}")


print()
print("== 6. tspu_strict_passes — мягкий режим (allow_grey=True) ==")
# Серый SNI + IP в CIDR — soft PASS.
ok, reason = tspu_strict_passes(_mk("2.63.5.10", "realhost.com"), allow_grey=True)
check(f"серый SNI + IP в CIDR (allow_grey) → PASS ({reason})",
      ok and reason == "whitelisted", f"got {(ok, reason)}")

# BS SNI + IP НЕ в CIDR — soft_grey всё равно FAIL по IP.
ok, reason = tspu_strict_passes(_mk("1.1.1.1", "www.sberbank.ru"), allow_grey=True)
check(f"BS SNI + IP НЕ в CIDR (v36 cidr_check=False) → PASS",
      ok, f"got {(ok, reason)}")

# Фейк SNI + IP в CIDR — allow_grey НЕ включает фейки.
ok, reason = tspu_strict_passes(_mk("2.63.5.10", "abc12345"), allow_grey=True)
check(f"фейк SNI (allow_grey без allow_fake) → FAIL по SNI",
      not ok and reason == "sni_fake", f"got {(ok, reason)}")


print()
print("== 7. tspu_strict_passes — флаги отключения ==")
# Отключить SNI-проверку — проверяем только IP. Серый SNI + IP в CIDR → PASS.
ok, reason = tspu_strict_passes(_mk("2.63.5.10", "realhost.com"), sni_check=False)
check(f"sni_check=False: серый SNI + IP в CIDR → PASS по IP",
      ok, f"got {(ok, reason)}")

# Отключить CIDR-проверку — проверяем только SNI. BS SNI + IP НЕ в CIDR → PASS.
ok, reason = tspu_strict_passes(_mk("1.1.1.1", "www.sberbank.ru"), cidr_check=False)
check(f"cidr_check=False: BS SNI + IP НЕ в CIDR → PASS по SNI",
      ok, f"got {(ok, reason)}")


print()
print("== 8. tspu_summary — сводка verdict'ов (v35: default allow_grey=True) ==")
# v35: серый SNI + IP в CIDR — теперь PASS (default allow_grey=True).
# v34: domain host — PASS (skip CIDR check).
nodes = [
    _mk("2.63.5.10", "www.sberbank.ru"),    # whitelisted (IP в CIDR)
    _mk("1.1.1.1", "www.sberbank.ru"),     # ip_not_whitelisted (IP НЕ в CIDR)
    _mk("2.63.5.10", "instagram.com"),     # sni_blacklisted
    _mk("realhost.com", "www.sberbank.ru"), # whitelisted (domain host → skip CIDR)
    _mk("2.63.5.10", "realhost.com"),       # whitelisted (v35: grey passes by default!)
    _mk("2.63.5.10", "abc12345"),           # sni_fake
    _mk("2.63.5.10", ""),                   # sni_empty
]
summary = tspu_summary(nodes)
check(f"summary has whitelisted=4 (v36: cidr_check=False, ip_not_wl now passes)", summary.get("whitelisted", 0) == 4, str(summary))
check(f"summary has ip_not_whitelisted=0 (v36: cidr_check=False, not checked)", summary.get("ip_not_whitelisted", 0) == 0, str(summary))
check(f"summary has sni_blacklisted=1", summary.get("sni_blacklisted", 0) == 1, str(summary))
check(f"summary has sni_fake=1", summary.get("sni_fake", 0) == 1, str(summary))
check(f"summary has sni_empty=1", summary.get("sni_empty", 0) == 1, str(summary))
check(f"summary total = 7 nodes", sum(summary.values()) == 7, str(summary))


print()
print("== 9. reset_cache инвалидирует кеш (только если нет data/cidr_whitelist.txt) ==")
# Если в репо лежит data/cidr_whitelist.txt (например, после sync_sni_whitelist.py
# в этом же окружении), fallback-path найдёт его — тест №9 неприменим.
reset_cache()
_orig = _os.environ.pop("CIDR_WHITELIST_FILE", None)
_data_file = REPO / "data" / "cidr_whitelist.txt"
try:
    reset_cache()
    nets = load_cidr_whitelist()
    if _data_file.exists():
        print(f"  [i] data/cidr_whitelist.txt найден ({len(nets)} CIDRs) — "
              f"fallback-path подхватывает его. Тест №9 неприменим в этом окружении.")
        # Просто проверяем, что env var действительно не используется.
        _os.environ["CIDR_WHITELIST_FILE"] = "/nonexistent/path/xyz.txt"
        reset_cache()
        nets2 = load_cidr_whitelist()
        check("fallback на data/cidr_whitelist.txt работает",
              len(nets2) == len(nets) and len(nets2) > 0, f"got {len(nets2)}")
    else:
        check("после удаления env var: load_cidr_whitelist returns [] (нет файла)",
              nets == [], f"got {len(nets)} networks")
        check("whitelist пуст → is_ip_in_whitelist always False",
              not is_ip_in_whitelist("2.63.5.10"))
finally:
    if _orig is not None:
        _os.environ["CIDR_WHITELIST_FILE"] = _orig
    else:
        _os.environ.pop("CIDR_WHITELIST_FILE", None)
    reset_cache()


print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
