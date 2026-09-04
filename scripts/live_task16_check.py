#!/usr/bin/env python3
"""Живая сквозная проверка новых механик Task 16 (без прокси-узла).

Поднимает локальный SOCKS5-релей (CONNECT-туннель в прямую сеть) и через
него прогоняет НОВЫЕ проверки так, как их выполняет конвейер (через SOCKS):

1. TG-медиа фильтр (обязательный): страница t.me/s/peppe_poppo -> видео -> Range-окно.
2. ИИ-гео слепок: CF trace chatgpt.com + футер Google + gemini.

Запуск:  python3 scripts/live_task16_check.py
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO_ROOT, "python")
sys.path.insert(0, ROOT)


def _relay_socks5(port: int) -> threading.Thread:
    """Простейший SOCKS5-сервер: CONNECT -> прямое TCP-соединение."""

    def handle(client: socket.socket):
        try:
            client.settimeout(30)
            client.recv(4096)  # greeting
            client.sendall(b"\x05\x00")
            req = client.recv(4096)
            if len(req) < 7 or req[1] != 1:
                client.close()
                return
            atyp = req[3]
            if atyp == 1:
                host = socket.inet_ntoa(req[4:8])
                head = 8
            elif atyp == 3:
                n = req[4]
                host = req[5 : 5 + n].decode()
                head = 5 + n
            else:
                client.close()
                return
            port_ = int.from_bytes(req[head : head + 2], "big")
            upstream = socket.create_connection((host, port_), timeout=15)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            client.settimeout(None)
            upstream.settimeout(None)
            stop = threading.Event()

            def pump(a, b):
                try:
                    while not stop.is_set():
                        data = a.recv(65536)
                        if not data:
                            break
                        b.sendall(data)
                except Exception:
                    pass
                finally:
                    stop.set()

            t1 = threading.Thread(target=pump, args=(client, upstream), daemon=True)
            t2 = threading.Thread(target=pump, args=(upstream, client), daemon=True)
            t1.start()
            t2.start()
            t1.join(60)
            stop.set()
            upstream.close()
        except Exception:
            pass
        finally:
            try:
                client.close()
            except Exception:
                pass

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def main() -> int:
    port = 19080
    _relay_socks5(port)
    time.sleep(0.3)

    import xray_runtime as xr
    from checkers import ai_geo

    print("=== 1. TG-медиа фильтр (t.me/s/peppe_poppo через SOCKS) ===")
    started = time.perf_counter()
    kbps = xr._tg_media_probe("127.0.0.1", port, 15.0)
    elapsed = time.perf_counter() - started
    if kbps is None:
        print(f"  FAIL: медиа-проба не сработала ({elapsed:.1f}s)")
    else:
        verdict = "OK" if kbps >= xr.TG_MEDIA_MIN_KBPS else "ниже порога"
        print(f"  PASS: {kbps:.0f} КБ/с (порог {xr.TG_MEDIA_MIN_KBPS:.0f}) за {elapsed:.1f}s -> {verdict}")

    print("=== 2. ИИ-гео слепок (CF trace + Google footer + gemini) ===")
    res = ai_geo._run_ai_geo_checks("127.0.0.1", port, 10.0)
    print(f"  cf_loc={res.cf_loc or '-'} (via {res.cf_source or '-'})")
    print(f"  google_country={res.google_country or '-'}")
    print(f"  gemini_reachable={res.gemini_reachable}")
    print(f"  openai_ok={res.openai_ok} gemini_ok={res.gemini_ok}")
    print(f"  ai_unblocked={res.ai_unblocked} reason={res.reason}")
    ok = res.ai_unblocked is not None
    print(f"  {'PASS' if ok else 'FAIL'}: вердикт получен")
    return 0 if (kbps is not None and ok) else 1


if __name__ == "__main__":
    sys.exit(main())
