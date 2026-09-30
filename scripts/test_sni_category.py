#!/usr/bin/env python3
"""Тесты SNI-классификации: БС / ЧС / серый / фейк / none.

Кейсы из чата:
  юзер жалуется, что на ограниченной сети РФ проходят только «БС»
  (белый список SNI) конфиги, а «ЧС» (чёрный список) — нет. Нужна
  статическая классификация по полям XrayNode.query (sni/host) или
  XrayNode.host, чтобы отделять рабочие конфиги на ограниченной сети
  без реального запуска xray.exe.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from checkers.sni_category import (  # noqa: E402
    BLACK_SNI_DOMAINS,
    SNI_CATEGORY_PRIORITY,
    WHITE_SNI_DOMAINS,
    category_summary,
    node_sni,
    passes_filter,
    sni_category,
    sort_by_sni,
)
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


def _mk(protocol: str = "vless", host: str = "151.101.213.205",
        port: int = 443, query: dict[str, str] | None = None,
        name: str = "") -> XrayNode:
    return XrayNode(
        protocol=protocol,
        raw_url=f"{protocol}://uuid@{host}:{port}",
        name=name or f"{protocol}://{host}:{port}",
        host=host, port=port, credential="00000000-0000-0000-0000-000000000000",
        query=query or {},
    )


print("== 1. БС (белый список) — проходит на ограниченной сети РФ ==")
check("sberbank.ru в whitelist", "www.sberbank.ru" in WHITE_SNI_DOMAINS)
check("vk.com в whitelist", "vk.com" in WHITE_SNI_DOMAINS)
check("gosuslugi.ru в whitelist", "www.gosuslugi.ru" in WHITE_SNI_DOMAINS)
check("github.com в whitelist", "github.com" in WHITE_SNI_DOMAINS)
n = _mk(query={"sni": "www.sberbank.ru"})
check("sni=sberbank.ru -> white", sni_category(n) == "white", sni_category(n))
n = _mk(query={"sni": "sberbank.ru"})
check("sni без www -> white", sni_category(n) == "white", sni_category(n))
n = _mk(query={"sni": "api.sberbank.ru"})
check("api.sberbank.ru (subdomain) -> white", sni_category(n) == "white", sni_category(n))

print()
print("== 2. ЧС (чёрный список) — блокируется на ограниченной сети РФ ==")
check("instagram.com в blacklist", "instagram.com" in BLACK_SNI_DOMAINS)
check("chatgpt.com в blacklist", "chatgpt.com" in BLACK_SNI_DOMAINS)
check("twitter.com в blacklist", "twitter.com" in BLACK_SNI_DOMAINS)
n = _mk(query={"sni": "instagram.com"})
check("sni=instagram.com -> black", sni_category(n) == "black", sni_category(n))
n = _mk(query={"sni": "www.instagram.com"})
check("sni=www.instagram.com -> black", sni_category(n) == "black", sni_category(n))
n = _mk(query={"sni": "i.instagram.com"})
check("sni=i.instagram.com (subdomain) -> black", sni_category(n) == "black", sni_category(n))

print()
print("== 3. Серый — реальный домен, не в списках ==")
n = _mk(query={"sni": "www.example.com"})
check("sni=www.example.com -> grey", sni_category(n) == "grey", sni_category(n))
n = _mk(query={"sni": "real-host.io"})
check("sni=real-host.io -> grey", sni_category(n) == "grey", sni_category(n))
n = _mk(query={"sni": "sub.domain.ru"})
check("sni=sub.domain.ru -> grey", sni_category(n) == "grey", sni_category(n))

print()
print("== 4. Фейк — нет точки, похоже на случайную строку ==")
n = _mk(query={"sni": "abc12345"})
check("sni=abc12345 -> fake", sni_category(n) == "fake", sni_category(n))
n = _mk(query={"sni": "xyzzysomething"})
check("sni=xyzzysomething -> fake", sni_category(n) == "fake", sni_category(n))

print()
print("== 5. None — SNI не задан, host — IP ==")
n = _mk(query={})
check("no sni, IP host -> none", sni_category(n) == "none", sni_category(n))
n = _mk(query={"sni": "127.0.0.1"})
check("sni=127.0.0.1 (IP) -> none", sni_category(n) == "none", sni_category(n))

print()
print("== 6. host как fallback SNI ==")
n = _mk(host="www.microsoft.com", query={})
check("host=www.microsoft.com as SNI -> white",
      sni_category(n) == "white", sni_category(n))
n = _mk(host="evil.attacker.com", query={})
check("host=evil.attacker.com as SNI -> grey",
      sni_category(n) == "grey", sni_category(n))

print()
print("== 7. passes_filter — фильтр для ограниченной сети ==")
bs_node = _mk(query={"sni": "www.sberbank.ru"})  # white
cs_node = _mk(query={"sni": "instagram.com"})    # black
grey_node = _mk(query={"sni": "real-host.com"})  # grey
fake_node = _mk(query={"sni": "abc12345"})        # fake

check("white проходит strict", passes_filter(bs_node, allow_grey=False, allow_fake=False))
check("white проходит soft-grey", passes_filter(bs_node, allow_grey=True, allow_fake=False))
check("black НЕ проходит strict", not passes_filter(cs_node, allow_grey=False, allow_fake=False))
check("black НЕ проходит soft-grey", not passes_filter(cs_node, allow_grey=True, allow_fake=False))
check("grey НЕ проходит strict", not passes_filter(grey_node, allow_grey=False, allow_fake=False))
check("grey проходит soft-grey", passes_filter(grey_node, allow_grey=True, allow_fake=False))
check("fake НЕ проходит strict", not passes_filter(fake_node, allow_grey=False, allow_fake=False))
check("fake НЕ проходит soft-grey (по умолчанию)", not passes_filter(fake_node, allow_grey=True, allow_fake=False))
check("fake проходит allow_fake=True", passes_filter(fake_node, allow_grey=True, allow_fake=True))

print()
print("== 8. sort_by_sni — приоритет белый-первый ==")
nodes = [cs_node, fake_node, grey_node, bs_node]
sorted_nodes = sort_by_sni(nodes)
categories = [sni_category(n) for n in sorted_nodes]
check("white first", categories[0] == "white", str(categories))
check("black last", categories[-1] == "black", str(categories))
check("order: white, grey, fake, black",
      categories == ["white", "grey", "fake", "black"], str(categories))

print()
print("== 9. category_summary — сводка по списку ==")
nodes = [
    _mk(query={"sni": "www.sberbank.ru"}),
    _mk(query={"sni": "www.tinkoff.ru"}),
    _mk(query={"sni": "instagram.com"}),
    _mk(query={"sni": "real.com"}),
    _mk(query={"sni": "abc12345"}),
    _mk(host="1.2.3.4", query={}),
]
summary = category_summary(nodes)
check("2 white", summary["white"] == 2, str(summary))
check("1 grey", summary["grey"] == 1, str(summary))
check("1 fake", summary["fake"] == 1, str(summary))
check("1 black", summary["black"] == 1, str(summary))
check("1 none (IP host)", summary["none"] == 1, str(summary))

print()
print("== 10. Суффиксная защита от обхода ==")
# ВАЖНО: «sberbank.ru.evil.com» НЕ должен попасть в whitelist — это
# классическая атака: злоумышленник подделывает SNI под whitelist-домен,
# но реально это совсем другой хост.
n = _mk(query={"sni": "sberbank.ru.evil.com"})
check("sberbank.ru.evil.com (subdomain attack) -> grey",
      sni_category(n) == "grey", sni_category(n))
# «evil.com» должен быть grey, а не white.
n = _mk(query={"sni": "evil.com"})
check("evil.com (suffix coincidence) -> grey",
      sni_category(n) == "grey", sni_category(n))

print()
print("== 11. Dynamic whitelist (data/sni_whitelist.txt) integration ==")
# Скрипт scripts/sync_sni_whitelist.py качает ~910 доменов из
# hxehex/russia-mobile-internet-whitelist. Модуль должен их подхватить
# через get_whitelist() — без sync'а работает только встроенный ~80 доменов.
import os as _os
import tempfile
from checkers.sni_category import get_whitelist, reset_cache

# Сохраним окружение и кеш, восстановим в finally.
_orig_env = _os.environ.get("SNI_WHITELIST_FILE")
reset_cache()
try:
    # Тест: указываем кастомный whitelist-файл через env var.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("# test whitelist\n")
        f.write("custom-test-domain.com\n")
        f.write("www.sberbank.ru\n")  # дубликат встроенного — должен дедуплицироваться
        f.write("another.example.org\n")
        custom_path = f.name
    _os.environ["SNI_WHITELIST_FILE"] = custom_path
    reset_cache()
    wl = get_whitelist()
    check("dynamic whitelist добавил custom-test-domain.com",
          "custom-test-domain.com" in wl, repr(list(wl)[:5]))
    check("dynamic whitelist добавил another.example.org",
          "another.example.org" in wl)
    check("встроенный www.sberbank.ru всё ещё в whitelist (merged)",
          "www.sberbank.ru" in wl)
    check("размер whitelist = встроенный + dynamic (без дубликатов)",
          len(wl) >= 82, f"len={len(wl)}")
    # Тест: узел с custom-test-domain.com теперь классифицируется как white.
    n = _mk(query={"sni": "custom-test-domain.com"})
    check("sni=custom-test-domain.com -> white (dynamic load)",
          sni_category(n) == "white", sni_category(n))
    n = _mk(query={"sni": "sub.custom-test-domain.com"})
    check("subdomain of dynamic whitelist domain -> white",
          sni_category(n) == "white", sni_category(n))
    _os.unlink(custom_path)
finally:
    if _orig_env is None:
        _os.environ.pop("SNI_WHITELIST_FILE", None)
    else:
        _os.environ["SNI_WHITELIST_FILE"] = _orig_env
    reset_cache()

print()
print("== 12. Re-run with real downloaded data/sni_whitelist.txt (if present) ==")
reset_cache()
wl = get_whitelist()
real_count = len(wl)
check("real whitelist has >= 80 (builtin only OR builtin + dynamic)",
      real_count >= 80, f"len={real_count}")
# Если scripts/sync_sni_whitelist.py уже отрабатывал, должен быть ~910+ доменов.
if real_count > 100:
    check(f"dynamic whitelist loaded (count={real_count} > 100)",
          True, f"len={real_count}")
    # Проверим, что какой-нибудь домен из community-списка распознаётся.
    n = _mk(query={"sni": "1l.mail.ru"})
    check("community domain 1l.mail.ru -> white",
          sni_category(n) == "white", sni_category(n))
    n = _mk(query={"sni": "00.img.avito.st"})
    check("community domain 00.img.avito.st -> white",
          sni_category(n) == "white", sni_category(n))
else:
    print(f"  [i] data/sni_whitelist.txt не выкачан (len={real_count}) — только встроенный")

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
