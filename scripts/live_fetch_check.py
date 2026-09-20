#!/usr/bin/env python3
"""Живая (сетевая) проверка фикса загрузки подписок на реальных URL пользователя.
Не входит в регрессионный набор: зависит от доступности сети и хостов."""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from runtime import fetch as F  # noqa: E402
from runtime.parse import _subscription_lines, parse_node_link  # noqa: E402

URLS = [
    "https://p.kfwl.lol/https://freevpnhappcluchi.duckdns.org/sub/o20pq89rdo9e7afo",
    "https://p.kfwl.lol/https://freevpnhappcluchi.duckdns.org/sub/lew1ik2xiuohs9v3",
    "https://panel.elix.lol/api/sub/MvrYyN9U5XS8AuAp",
]

for url in URLS:
    print(f"\n=== {url[:70]}...")
    print(f"candidates: {[u[:60] for u in F._subscription_candidate_urls(url)]}")
    logs: list[str] = []
    try:
        text = F._fetch_text(url, timeout=15.0, log_sink=logs.append)
        for line in logs:
            print(f"  log: {line[:100]}")
        print(f"  body: {len(text)} chars, head={text[:60]!r}")
        lines = _subscription_lines(text)
        nodes = []
        for raw in lines:
            try:
                node = parse_node_link(raw, source_url=url)
            except Exception:
                node = None
            if node is not None:
                nodes.append(node)
        print(f"  RESULT: {len(lines)} ссылок, {len(nodes)} конфигов (parse_node_link)")
        if nodes:
            n = nodes[0]
            proto = getattr(n, "protocol", "?")
            host = getattr(n, "server", "?")
            print(f"  первый: {proto}://{host}")
    except Exception as exc:
        for line in logs:
            print(f"  log: {line[:100]}")
        print(f"  FAILED: {type(exc).__name__}: {exc}")
