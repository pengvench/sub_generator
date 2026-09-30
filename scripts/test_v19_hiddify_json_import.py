#!/usr/bin/env python3
"""v19: импорт JSON-массива объектов-конфигов Xray/Hiddify.

Регрессионный тест на кейс из чата:
  happ://crypt5/...
    → decrypt_happ_link → https://tetragidropiranilciklopentiltetragidropiridopiridinovye.ru/exec?url=...
    → body = JSON-массив объектов Xray/Hiddify:
      [{"remarks":..., "outbounds":[{"protocol":"vless",
        "settings":{"vnext":[{"address":..., "port":...,
        "users":[{"id":...}]}]}}]}]

До v19 _extract_configs в import_page.py умел только:
  - plain-text построчно;
  - base64 (одноуровневый);
  - JSON-массив строк-ссылок.

JSON-массив объектов-конфигов не парсился (возвращалось 0 конфигов,
статус «Конфиги не найдены» при живой подписке). v19 делегирует разбор
в runtime.parse._subscription_lines — той же функции, что используется
при основном тестировании, и умеет ходить вглубь по JSON-дереву
(_node_links_from_json → _node_link_from_json_object →
_standard_link_from_json → читает settings.vnext[].users[].id).

Юнит-часть проверяет парсер без GUI: заглушает customtkinter и ui.tooltip,
чтобы import_page можно было импортировать в любом окружении.
"""
from __future__ import annotations

import base64
import json
import sys
import types
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


# ----------------------------------------------------------------- stubs
# Заглушаем customtkinter (UI lib) и ui.tooltip, чтобы import_page
# импортировался в среде без установленных GUI-зависимостей.
class _Ctor:
    def __init__(self, *a, **k):
        pass


_ctk = types.ModuleType("customtkinter")
for _n in (
    "CTkFrame",
    "CTkButton",
    "CTkLabel",
    "CTkTextbox",
    "CTkEntry",
    "CTkScrollableFrame",
    "CTkFont",
    "CTkToplevel",
    "CTkSwitch",
):
    setattr(_ctk, _n, _Ctor)
_ctk.set_appearance_mode = lambda *a, **k: None
sys.modules.setdefault("customtkinter", _ctk)

_tooltip = types.ModuleType("ui.tooltip")


class _Tip:
    def __init__(self, *a, **k):
        pass


_tooltip.CTkToolTip = _Tip
sys.modules.setdefault("ui.tooltip", _tooltip)

# ----------------------------------------------------------------- импорт
from ui.pages.import_page import _extract_configs, _extract_configs_fallback  # noqa: E402

# ----------------------------------------------------------------- синтетика
print("== 1. JSON-массив объектов-конфигов Xray (Hiddify-формат) ==")
HIDDIIFY_BODY = json.dumps([
    {
        "remarks": "🇪🇺 Автовыбор",
        "inbounds": [],
        "outbounds": [
            {
                "tag": "proxy-0",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "151.101.213.205",
                            "port": 443,
                            "users": [
                                {
                                    "id": "ba47e800-ecb1-4db5-902e-c708881ebedc",
                                    "encryption": "none",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "accounts.fastly.com",
                        "fingerprint": "chrome",
                        "alpn": ["h3"],
                    },
                    "xhttpSettings": {"path": "/", "host": "oh1.global.ssl.fastly.net"},
                },
            },
            {
                "tag": "proxy-1",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "151.101.213.206",
                            "port": 8443,
                            "users": [
                                {
                                    "id": "11111111-2222-3333-4444-555555555555",
                                    "encryption": "none",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "wsSettings": {"path": "/sub", "headers": {"Host": "alt.example.com"}},
                },
            },
        ],
    }
])
configs = _extract_configs(HIDDIIFY_BODY)
check(
    "Hiddify JSON -> 2 конфига (vless xhttp + vless ws)",
    len(configs) == 2,
    f"got {len(configs)}: {configs}",
)
check(
    "Hiddify JSON -> vless с правильным UUID",
    any("ba47e800-ecb1-4db5-902e-c708881ebedc" in c for c in configs),
    str(configs),
)
check(
    "Hiddify JSON -> vless на правильном хосте 151.101.213.205",
    any("151.101.213.205" in c for c in configs),
    str(configs),
)
check(
    "Hiddify JSON -> второй vless с другим UUID",
    any("11111111-2222-3333-4444-555555555555" in c for c in configs),
    str(configs),
)

print()
print("== 2. JSON-массив строк-ссылок (старый формат, regression) ==")
LINK_LIST = json.dumps([
    "vless://uuid-1@host1.example.com:443?security=tls#n1",
    "ss://YWVzLTI1Ni1nY206cGFzcw@host2.example.com:8388#n2",
])
configs = _extract_configs(LINK_LIST)
check("JSON-массив строк -> 2 конфига", len(configs) == 2, f"got {len(configs)}")
check(
    "JSON-массив строк -> vless сохранён",
    any(c.startswith("vless://") for c in configs),
    str(configs),
)

print()
print("== 3. JSON-объект с полем configs (старый клиентский формат) ==")
LEGACY = json.dumps({
    "configs": [
        "vless://uuid-x@host-x:443#x",
        "trojan://password@host-y:443#y",
    ]
})
configs = _extract_configs(LEGACY)
check("JSON {configs:[...]} -> 2", len(configs) == 2, f"got {len(configs)}")

print()
print("== 4. Plain text (regression) ==")
PLAIN = "vless://uuid@9.9.9.9:443?security=tls#saved1\nss://abc@1.2.3.4:8388#saved2"
configs = _extract_configs(PLAIN)
check("plain text -> 2", len(configs) == 2, f"got {len(configs)}")

print()
print("== 5. Base64-тело (regression) ==")
B64 = base64.b64encode(
    b"vless://a@h1.ru:443?encryption=none#n1\nvless://b@h2.ru:8443?encryption=none#n2\n"
).decode()
configs = _extract_configs(B64)
check("base64 body -> 2", len(configs) == 2, f"got {len(configs)}")

print()
print("== 6. Garbage (v18 test #4 regression) ==")
configs = _extract_configs("просто текст без всего")
check("garbage -> 0 (не падает в saved_subs как фантом)", configs == [], str(configs))

configs = _extract_configs("just some text no configs")
check("english garbage -> 0", configs == [], str(configs))

print()
print("== 7. Embedded vless in plain text (old find-anywhere behavior) ==")
configs = _extract_configs("prefix vless://uuid@host.com:443?x=1#n1 suffix")
check("embedded vless -> 1", len(configs) == 1, str(configs))

print()
print("== 8. Empty ==")
check("empty -> 0", _extract_configs("") == [])
check("None -> 0", _extract_configs(None) == [])  # type: ignore[arg-type]

print()
print("== 9. Fallback path (xray_runtime недоступен) ==")
import builtins  # noqa: E402

_orig_import = builtins.__import__


def _block_runtime(name, *a, **k):
    if name == "xray_runtime" or name.startswith("xray_runtime."):
        raise ImportError("blocked by test")
    return _orig_import(name, *a, **k)


builtins.__import__ = _block_runtime
try:
    r = _extract_configs("vless://uuid@1.1.1.1:443?#manual")
    check("fallback: single vless -> 1", len(r) == 1, str(r))
    r = _extract_configs("просто текст без всего")
    check("fallback: garbage -> 0", r == [], str(r))
finally:
    builtins.__import__ = _orig_import

print()
print("== 10. Реальный сниппет из happ-decrypted подписки ==")
# Минимизированный фрагмент реального body из чата (2 vless с разными тэгами,
# одинаковыми UUID@host:port, но разными streamSettings — итоговые URL-ссылки
# РАЗЛИЧАЮТСЯ фрагментом #proxy-N, поэтому НЕ дедуплицируются.
REAL_SNIPPET = json.dumps([
    {
        "remarks": "🇪🇺 Автовыбор 🔍",
        "inbounds": [{"listen": "0.0.0.0", "port": 10808, "protocol": "socks"}],
        "outbounds": [
            {
                "tag": "proxy-0",
                "protocol": "vless",
                "settings": {"vnext": [
                    {"address": "151.101.213.205", "port": 443,
                     "users": [{"id": "ba47e800-ecb1-4db5-902e-c708881ebedc"}]}
                ]},
                "streamSettings": {"network": "xhttp", "security": "tls"},
            },
            {
                "tag": "proxy-1",
                "protocol": "vless",
                "settings": {"vnext": [
                    {"address": "151.101.213.205", "port": 443,
                     "users": [{"id": "ba47e800-ecb1-4db5-902e-c708881ebedc"}]}
                ]},
                "streamSettings": {"network": "ws", "security": "tls"},
            },
        ],
    }
])
configs = _extract_configs(REAL_SNIPPET)
# 2 разных URL (разные #proxy-0/#proxy-1 фрагменты + разные type=xhttp/ws)
check(
    "real snippet -> 2 (различаются тэгом и транспортом)",
    len(configs) == 2,
    f"got {len(configs)}: {configs[:1]}",
)

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
