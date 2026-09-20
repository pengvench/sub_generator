#!/usr/bin/env python3
"""v17 e2e: XrayBatchPool с НАСТОЯЩИМ ядром xray (bin/xray, Linux).

Проверяет полный жизненный цикл пула:
  1. start(): процесс жив, ВСЕ N SOCKS-портов слушают;
  2. SOCKS5-greeting на каждом порту (сервер отвечает \x05\x00);
  3. конфиг с reality/utls/grpc/ws/xhttp проходит `xray run -test`
     (ядро реально парсит нашу мульти-outbound сборку);
  4. select()/endpoint: каждый узел → свой порт;
  5. stop(): процесс убит, порты закрылись;
  6. батч с битым узлом не рушит остальных (unsupported → fallback путь).
"""
from __future__ import annotations

import base64
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(f"{name} {detail}")
    print(("  ok   " if cond else "  FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))


XRAY = REPO / "bin" / "xray"
if not XRAY.exists():
    print(f"xray не найден ({XRAY}) — e2e пропущен")
    sys.exit(0)

import xray_runtime as xr  # noqa: E402
from runtime.xray_pool import XrayBatchPool  # noqa: E402


def make_node(url: str):
    node = xr.parse_node_link(url)
    assert node is not None, f"не распарсился: {url[:60]}"
    return node


# Валидный Reality pbk: 32 байта в URL-safe base64 без padding (как дают
# подписки; xray парсит именно так — см. _normalize_reality_pbk).
VALID_PBK = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()

NODES = [
    make_node(
        f"vless://01234567-89ab-cdef-0123-456789abcdef@reality.example.com:443"
        f"?encryption=none&security=reality&sni=reality.example.com&fp=chrome"
        f"&pbk={VALID_PBK}&sid=12&type=tcp&flow=xtls-rprx-vision#reality"
    ),
    make_node("vmess://eyJhZGQiOiJ2bS5leGFtcGxlLmNldCIsInBvcnQiOjQ0MywiaWQiOiIwMTIzNDU2Ny04OWFiLWNkZWYtMDEyMy00NTY3ODlhYmNkZWYiLCJhaWQiOjAsIm5ldCI6ImdycGMiLCJwYXRoIjoiL2dycGMiLCJ0bHMiOiJ0bHMifQ=="),
    make_node("trojan://secretpass@trojan.example.net:443?security=tls&sni=trojan.example.net&type=ws&path=%2Fws#trojan-ws"),
    make_node("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@ss.example.org:8388#ss"),
    make_node(
        "vless://01234567-89ab-cdef-0123-456789abcdef@xhttp.example.io:443"
        "?encryption=none&security=tls&sni=xhttp.example.io&type=xhttp&path=%2Fxh&fp=chrome#xhttp"
    ),
    make_node("hysteria2://pass@hy2.example.io:443?sni=hy2.example.io#hy2"),
]

logs: list[str] = []
pool = XrayBatchPool(NODES, root_dir=REPO, batch_id=42, log_sink=logs.append)

print("=== 1. конфиг и валидация настоящим xray ===")
check("5 поддерживаемых (hy2 — unsupported)", pool.supported_count == 5, str(pool.supported_count))

# Сохраняем конфиг и валидируем `xray run -test` — ядро парсит сборку целиком.
import json  # noqa: E402
import tempfile  # noqa: E402

with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as fh:
    json.dump(pool._config, fh, ensure_ascii=False)
    cfg_path = fh.name
proc = subprocess.run([str(XRAY), "run", "-test", "-c", cfg_path], capture_output=True, text=True, timeout=30)
check("xray run -test: конфиг валиден", proc.returncode == 0, (proc.stderr or "")[-200:])
Path(cfg_path).unlink(missing_ok=True)

print("=== 2. запуск пула ===")
started = pool.start()
check("start() = True", started, "; ".join(logs[-3:]))
check("процесс жив", pool.is_started())

print("=== 3. все порты слушают + SOCKS-greeting ===")


def socks_greeting(port: int, timeout: float = 2.0) -> bool:
    """SOCKS5-приветствие: \x05\x01\x00 → \x05\x00 (no-auth)."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.sendall(b"\x05\x01\x00")
            return s.recv(2) == b"\x05\x00"
    except OSError:
        return False


all_greet = True
port_detail = []
for node in NODES[:5]:
    if not pool.select(node):
        all_greet = False
        port_detail.append(f"{node.title()}: not selected")
        continue
    host, port = pool.endpoint
    if not socks_greeting(port):
        all_greet = False
        port_detail.append(f"{node.title()}:{port} no greeting")
check("SOCKS-приветствие на всех 5 портах", all_greet, "; ".join(port_detail))

print("=== 4. select/endpoint mapping ===")
map_ok = True
for i, node in enumerate(NODES[:5]):
    pool.select(node)
    if pool.endpoint[1] != pool.base_port + i:
        map_ok = False
check("порт узла i = base+i (строго свой)", map_ok)

print("=== 5. stop() ===")
pool.stop()
time.sleep(0.2)
check("процесс убит", not pool.is_started())
closed = True
for node in NODES[:5]:
    port = pool._node_key_to_port.get(node.key)
    if port and socks_greeting(port, timeout=0.4):
        closed = False
check("порты закрылись", closed)

print("=== 6. битый узел не рушит батч ===")
# 6a. неизвестный протокол — отсеивается ещё при сборке конфига.
bad = make_node("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@bad.example.com:8388#bad")
bad.protocol = "unknown-proto"
pool2 = XrayBatchPool([NODES[0], bad, NODES[3]], root_dir=REPO, batch_id=43, log_sink=logs.append)
check("2 поддерживаемых, битый — unsupported", pool2.supported_count == 2 and bad.key in pool2.unsupported_keys)
ok2 = pool2.start()
check("батч с битым узлом стартует", ok2, "; ".join(logs[-3:]))
if ok2:
    pool2.select(NODES[0])
    check("SOCKS работает и в смешанном батче", socks_greeting(pool2.endpoint[1]))
pool2.stop()

# 6b. битый Reality pbk — xray валит конфиг, но пул выбрасывает ТОЛЬКО этот
# узел (по тегу из stderr) и стартует с остальными (регрессия v17).
bad_reality = make_node(
    "vless://01234567-89ab-cdef-0123-456789abcdef@broken.example.com:443"
    "?encryption=none&security=reality&sni=broken.example.com&fp=chrome"
    "&pbk=not-base64-at-all!&sid=12&type=tcp#broken-reality"
)
pool2b = XrayBatchPool([bad_reality, NODES[3], NODES[4]], root_dir=REPO, batch_id=45, log_sink=logs.append)
logs.clear()
ok2b = pool2b.start()
check("битый pbk: батч стартует без него", ok2b, "; ".join(logs[-4:]))
check("битый pbk: узел ушёл в unsupported (per-node fallback)",
      bad_reality.key in pool2b.unsupported_keys and pool2b.supported_count == 2,
      f"supported={pool2b.supported_count}")
if ok2b:
    pool2b.select(NODES[3])
    check("битый pbk: остальные узлы работают", socks_greeting(pool2b.endpoint[1]))
pool2b.stop()

print("=== 7. пул из 50 узлов (масштаб) ===")
big_nodes = []
for i in range(50):
    big_nodes.append(make_node(f"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@host{i}.example.com:{8388 + i}#n{i}"))
t0 = time.monotonic()
pool3 = XrayBatchPool(big_nodes, root_dir=REPO, batch_id=44, log_sink=logs.append)
build_ms = (time.monotonic() - t0) * 1000
ok3 = pool3.start()
total_ms = (time.monotonic() - t0) * 1000
check("50 узлов: стартует", ok3, "; ".join(logs[-3:]))
check(f"сборка+старт 50 узлов < 6с ({build_ms:.0f}+{total_ms - build_ms:.0f}мс)", total_ms < 6000, f"{total_ms:.0f}мс")
if ok3:
    pool3.select(big_nodes[49])
    check("последний узел 50-го порта отвечает", socks_greeting(pool3.endpoint[1]))
pool3.stop()

print()
print(f"=== v17 e2e xray-pool: {len(PASS)} PASS, {len(FAIL)} FAIL ===")
if FAIL:
    print("ПРОВАЛЫ:")
    for f in FAIL:
        print("  -", f)
    sys.exit(1)
