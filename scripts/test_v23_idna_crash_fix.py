#!/usr/bin/env python3
"""v23: регрессионный тест на падение GHA при TCP-ping невалидных hostname.

Инцидент 2026-09-29: workflow упал на 12825/25853 узле с UnicodeError из
encodings.idna — _tcp_ping() ловил (OSError, gaierror, TimeoutError), но
UnicodeError не входит в это множество. Это ValueError, поднимается внутри
socket.create_connection → getaddrinfo → encodings.idna.ToASCII.

Причины:
  - метка DNS-имени длиннее 63 символов (label too long)
  - пустые метки (a..b.com — последовательные точки)
  - недопустимые символы (но underscore мы принимаем — встречается на паблик-узлах)

Чиним так:
  1. _is_valid_hostname(host) — регулярка для DNS-метки (≤63, [a-zA-Z0-9_-]) +
     IPv4 (4 октета 0..255) + IPv6 (содержит ':'). Возвращает False для мусора.
  2. _tcp_ping вызывает _is_valid_hostname ДО socket.create_connection —
     невалидные host'ы сразу отбраковываются, без DNS-запроса.
  3. except Exception (широкий) — на случай, если что-то всё же прорвалось.

Этот сьют проверяет все 3 слоя: валидатор, _tcp_ping (не падает на мусоре),
_ping_filter (не падает, считает bad-host skipped).
"""
from __future__ import annotations

import sys
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

# Импортируем scripts/refresh_subs.py как модуль (без __main__ guard).
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


def _mk(host: str, port: int = 443) -> XrayNode:
    """Создать XrayNode с заданным host (для теста валидации)."""
    return XrayNode(
        protocol="vless",
        raw_url=f"vless://uuid@{host}:{port}",
        name=f"node_{host}",
        host=host, port=port,
        credential="00000000-0000-0000-0000-000000000000",
        query={},
    )


print("== 1. _is_valid_hostname — валидные ==")
check("IPv4 1.2.3.4", rs._is_valid_hostname("1.2.3.4"))
check("IPv4 8.8.8.8", rs._is_valid_hostname("8.8.8.8"))
check("IPv4 0.0.0.0", rs._is_valid_hostname("0.0.0.0"))
check("IPv4 255.255.255.255", rs._is_valid_hostname("255.255.255.255"))
check("DNS www.example.com", rs._is_valid_hostname("www.example.com"))
check("DNS a.b", rs._is_valid_hostname("a.b"))
check("DNS с дефисом sub.domain.example.com", rs._is_valid_hostname("sub.domain.example.com"))
check("DNS с underscore sub_domain.example.com (common in real subs)",
      rs._is_valid_hostname("sub_domain.example.com"))
check("DNS с trailing dot www.example.com.",
      rs._is_valid_hostname("www.example.com."))
check("IPv6 [::1]", rs._is_valid_hostname("[::1]"))
check("IPv6 2001:db8::1", rs._is_valid_hostname("2001:db8::1"))
check("DNS с заглавными Example.COM",
      rs._is_valid_hostname("Example.COM"))

print()
print("== 2. _is_valid_hostname — НЕвалидные (те, что падали GHA) ==")
# Тот самый кейс из GHA-инцидента: метка длиннее 63 символов.
long_label = "a" * 100 + ".com"
check(f"метка > 63 символов ({len(long_label)} chars)",
      not rs._is_valid_hostname(long_label))
check("метка ровно 64 (boundary)",
      not rs._is_valid_hostname("a" * 64 + ".com"))
check("метка ровно 63 (boundary, валидна)",
      rs._is_valid_hostname("a" * 63 + ".com"))
check("пустые метки a..b.com",
      not rs._is_valid_hostname("a..b.com"))
check("пустые метки ...com",
      not rs._is_valid_hostname("...com"))
check("leading dot .example.com",
      not rs._is_valid_hostname(".example.com"))
check("только точки ...", not rs._is_valid_hostname("..."))
check("пустая строка", not rs._is_valid_hostname(""))
check("None (not str)", not rs._is_valid_hostname(None))  # type: ignore[arg-type]
check("DNS > 253 символа (всё имя)",
      not rs._is_valid_hostname("a" * 250 + ".com"))
# ВАЖНО: «1.2.3.256», «1.2.3», «1.2.3.4.5» — синтаксически ВАЛИДНЫ как DNS-имена
# (метки 1/2/3/256 — все в [0-9]). Они НЕ вызовут UnicodeError в IDNA, потому
# что метки короткие и не пустые. Они упадут уже на DNS-резолве (gaierror),
# что ловится широким `except Exception` в _tcp_ping. Эти кейсы не относятся
# к нашему крашу (там был label too long / empty labels) — фикс их не отбраковывает
# валидатором, а ловит на ping-этапе. Проверяем что _tcp_ping НЕ падает:
for tricky_host in ("1.2.3.256", "1.2.3", "1.2.3.4.5", "999.999.999.999"):
    try:
        result = rs._tcp_ping(_mk(tricky_host), timeout=0.5)
        check(f"_tcp_ping('{tricky_host}') НЕ падает (DNS-fail ловится)",
              result == (False, 0.0), f"got {result}")
    except Exception as exc:
        check(f"_tcp_ping('{tricky_host}') НЕ падает",
              False, f"CRASHED: {type(exc).__name__}: {exc}")


print()
print("== 3. _tcp_ping не падает на мусоре (главный кейс) ==")
# ДО фикса это вызывало UnicodeError. ПОСЛЕ фикса — return (False, 0.0).
crash_cases = [
    ("label too long", _mk("a" * 100 + ".com")),
    ("empty labels a..b.com", _mk("a..b.com")),
    ("all dots ...", _mk("...")),
    ("leading dot .example.com", _mk(".example.com")),
]
for label, node in crash_cases:
    try:
        result = rs._tcp_ping(node, timeout=0.5)
        check(f"_tcp_ping('{node.host}'[:40]) НЕ падает, return (False, 0.0)",
              result == (False, 0.0), f"got {result}")
    except Exception as exc:
        check(f"_tcp_ping('{node.host}'[:40]) НЕ падает",
              False, f"CRASHED: {type(exc).__name__}: {exc}")

# Валидный узел — должен пинговаться (или падать с OSError, но НЕ UnicodeError).
# Не проверяем alive/timeout (зависит от сети тест-машины), только что нет крэша.
node_valid = _mk("www.example.com")
try:
    result = rs._tcp_ping(node_valid, timeout=2.0)
    check("_tcp_ping на валидном www.example.com НЕ падает",
          isinstance(result, tuple) and len(result) == 2,
          f"got {result!r}")
except Exception as exc:
    check("_tcp_ping на валидном НЕ падает",
          False, f"CRASHED: {type(exc).__name__}: {exc}")


print()
print("== 4. _ping_filter на смешанном списке (без крэша) ==")
nodes = [
    _mk("a" * 100 + ".com"),  # bad host
    _mk("a..b.com"),         # empty labels
    _mk("..."),              # all dots
    _mk("www.example.com"),  # valid
    _mk("1.2.3.4"),          # valid IPv4
]
logs: list[str] = []
try:
    alive = rs._ping_filter(nodes, timeout=1.0, workers=4, log_sink=logs.append)
    check(f"_ping_filter НЕ падает на смешанном списке, alive={len(alive)}",
          isinstance(alive, list))
except Exception as exc:
    check("_ping_filter НЕ падает", False,
          f"CRASHED: {type(exc).__name__}: {exc}")

# Должен увидеть "bad-host skipped" в логе.
check("в логе есть упоминание bad-host",
      any("bad-host skipped" in line for line in logs), str(logs))

# Должен увидеть progress-строку.
check("в логе есть progress",
      any("ping progress" in line for line in logs), str(logs))


print()
print("== 5. --max-ping-nodes обрезает список (экономия GHA минут) ==")
nodes_big = [_mk(f"host{i}.example.com") for i in range(50)]
logs2: list[str] = []
alive = rs._ping_filter(nodes_big, timeout=0.3, workers=8,
                        log_sink=logs2.append, max_nodes=10)
check("max_nodes=10 отрезал список до 10 (progress log total=10)",
      any("ping progress 10/10" in line or "ping progress 5/10" in line
          or "ping progress 1/10" in line for line in logs2),
      str(logs2))
check("в логе есть truncation message",
      any("truncating" in line for line in logs2), str(logs2))


print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
