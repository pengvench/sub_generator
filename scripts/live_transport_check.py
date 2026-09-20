#!/usr/bin/env python3
"""Живая симуляция сети пользователя: Python-стек «заблокирован» (urlopen всегда
RemoteDisconnected — как в логе юзера), загрузку подхватывает системный curl.

Проверяет на РЕАЛЬНЫХ URL: полный путь _fetch_text -> curl -> parse_node_link.
Не входит в регрессионный набор: зависит от сети и наличия curl в песочнице."""
from __future__ import annotations

import http.client
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from runtime import fetch as F  # noqa: E402
from runtime.parse import _subscription_lines, parse_node_link  # noqa: E402

URLS = [
    "https://p.kfwl.lol/https://freevpnhappcluchi.duckdns.org/sub/o20pq89rdo9e7afo",
    "https://panel.elix.lol/api/sub/MvrYyN9U5XS8AuAp",
]

# Python-стек «мёртв», как у пользователя (RemoteDisconnected на каждый запрос).
F.urlopen = lambda req, timeout=None, context=None: (_ for _ in ()).throw(
    http.client.RemoteDisconnected("DPI blocks python TLS fingerprint")
)
F._powershell_exe = lambda: ""


def _broken_urlopen(req, timeout=None, context=None):
    raise http.client.RemoteDisconnected("DPI blocks python TLS fingerprint")


F.urlopen = _broken_urlopen
print("urlopen подменён на постоянный RemoteDisconnected — имитация блокировки Python-стека\n")

real_curl = F._system_curl_info()
print(f"system curl: {real_curl[0] or 'НЕ НАЙДЕН'} (HTTP/2: {real_curl[1]})\n")

for url in URLS:
    print(f"=== {url[:70]}...")
    logs: list[str] = []
    try:
        text = F._fetch_text(url, timeout=15.0, log_sink=logs.append)
        for line in logs:
            print(f"  log: {line[:110]}")
        lines = _subscription_lines(text)
        nodes = []
        for raw in lines:
            try:
                node = parse_node_link(raw, source_url=url)
            except Exception:
                node = None
            if node is not None:
                nodes.append(node)
        print(f"  RESULT: {len(text)} chars body, {len(lines)} ссылок, {len(nodes)} конфигов")
    except Exception as exc:
        for line in logs:
            print(f"  log: {line[:110]}")
        print(f"  FAILED: {type(exc).__name__}: {exc}")
    print()
