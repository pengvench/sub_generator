"""Дешёвые предфильтры живости узлов: TCP-connect ping и UDP/QUIC-подобный
ping для hysteria/hy2 (без поднятия ядра)."""
from __future__ import annotations


import contextlib
import os
import socket
import time

from .types import XrayNode  # noqa: F401  (аннотации)


def _tcp_ping_node(node: "XrayNode", timeout: float = 2.0) -> float | None:
    """Быстрый TCP-ping: connect к (host, port) без поднятия ядра.

    Возвращает latency в мс или None, если connect не удался за timeout.
    Намного дешевле, чем поднимать xray.exe/sing-box.exe на каждый узел:
    на 10000 узлов TCP-ping занимает ~30 сек (32 потока × 2 сек timeout),
    тогда как xray-ping — 10000 старт-стопов ~ 5-8 часов.

    Не проверяет протокол — только доступность порта. Этого достаточно для
    отсеивания 60-70% мёртвых узлов до дорогих проверок.
    """
    host = node.host
    port = int(node.port)
    started = time.perf_counter()
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        latency_ms = (time.perf_counter() - started) * 1000.0
        return latency_ms
    except Exception:
        return None
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()


# Протоколы, которые работают по UDP (hysteria/hy2). Для них TCP-ping
# бесполезен — сервер слушает UDP, и TCP-порт может быть закрыт, хотя узел
# жив. Для них используем UDP-ping: отправляем QUIC-like Initial-пакет
# и ждём любого ответа. Это не полноценный QUIC-handshake (это сложно),
# но достаточный для проверки «жив ли UDP-порт и отвечает ли сервер».
UDP_PROTOCOLS = frozenset({"hysteria", "hysteria2", "hy2"})


def _udp_ping_node(node: "XrayNode", timeout: float = 2.0) -> float | None:
    """UDP-ping для hysteria/hy2 узлов.

    Отправляет упрощённый QUIC Initial-пакет и ждёт ответа. Если сервер
    ответил хоть чем-то за timeout — узел жив. Если нет — мёртв.

    Полноценный QUIC-handshake требует реализации crypto frames, TLS 1.3
    ClientHello и обработки retry-пакетов — это слишком сложно для
    предфильтра. Мы используем эвристику:

    1. Отправляем несколько «проб» — пустой UDP-пакет, QUIC Initial-заголовок
       с фейковым DCID и random payload. Hysteria-сервер (на базе quic-go)
       обычно отвечает одним из:
         - Retry-пакетом (если требует token)
         - Initial-пакетом (если принимает соединение)
         - ICMP Port Unreachable (если порт закрыт — но это не приходит
           обратно как UDP-ответ, мы этого не увидим)
    2. Если за timeout получен ЛЮБОЙ UDP-пакет от сервера — узел жив.
    3. Если ничего не пришло — узел мёртв (или за NAT, или порт закрыт).

    Ложноположительные срабатывания: сервер мог ответить на наш мусорный
    пакет, но реальный handshake потом упадёт (например, неверный auth_str).
    Это нормально — отсеет следующая SOCKS/UDP-проверка через ядро.

    Ложноотрицательные: сервер мог быть жив, но не ответить за timeout
    (большой RTT, потеря пакетов). Поэтому timeout = 3 сек (больше, чем
    у TCP, т.к. UDP может потеряться и сервер делает retransmit).
    """
    host = node.host
    port = int(node.port)
    started = time.perf_counter()
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Несколько пробных пакетов разной формы — повышает шанс, что
        # хотя бы на один сервер ответит. Hysteria слушает QUIC, поэтому
        # делаем QUIC-like пакеты:
        probes = [
            # 1. Минимальный QUIC Initial (Long Header, type=0xC0, DCID=8 байт).
            #    Это не валидный QUIC, но quic-go часто отвечает на «похожее»
            #    retry-пакетом или сразу сбрасывает соединение.
            bytes([0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x40, 0x00])
            + b"\x01\x02\x03\x04\x05\x06\x07\x08"  # DCID (8 байт)
            + b"\x00" * 20,  #(payload)
            # 2. Пустой UDP-пакет — некоторые серверы отвечают ICMP/RESET.
            #    Мы не увидим ICMP, но если сервер использует raw-socket, может
            #    прислать ошибку в UDP-домене.
            b"",
            # 3. Случайные байты — для серверов с нестандартной обработкой.
            os.urandom(32),
        ]

        for probe in probes:
            try:
                sock.sendto(probe, (host, port))
            except Exception:
                # sendto может упасть на недоступном хосте — пробуем следующий.
                continue
            try:
                # Ждём ответ. Если получен любой пакет — узел жив.
                data, _ = sock.recvfrom(2048)
                if data:
                    return (time.perf_counter() - started) * 1000.0
            except socket.timeout:
                # Эта проба не дала ответа — пробуем следующую.
                continue
            except Exception:
                continue
        return None
    except Exception:
        return None
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()


def _tcp_udp_ping_node(node: "XrayNode", timeout: float = 2.0) -> float | None:
    """Универсальный предфильтр: TCP для TCP-протоколов, UDP для UDP-протоколов.

    Для vless/vmess/trojan/ss — TCP-ping (узел работает по TCP).
    Для hysteria/hy2 — UDP-ping (узел работает по UDP/QUIC).

    Возвращает latency_ms или None (узел мёртв).
    """
    if node.protocol in UDP_PROTOCOLS:
        # Для UDP-протоколов даём чуть больше времени (потеря пакетов).
        return _udp_ping_node(node, timeout=max(timeout, 3.0))
    return _tcp_ping_node(node, timeout=timeout)
