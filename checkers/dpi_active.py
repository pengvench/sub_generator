"""Активное DPI-тестирование ПРОТОКОЛА узла (анти-DPI устойчивость).

Отвечает на вопрос: «Сможет ли узел обходить конкретные DPI-механизмы?»,
а не «Работает ли интернет через узел?».

Классическая ошибка — тестировать узел из своей среды и считать успешный TLS
handshake до заблокированного сайта признаком устойчивости к DPI. Но DPI сидит
между пользователем и VPN-сервером: после поднятия туннеля трафик уже идёт
внутри VPN, и DPI пользователя его не видит.

Поэтому здесь проверяются три вещи:

1. **Fingerprint-матрица** — пытаемся «сломать» VPN-хэндшейк, поднимая узел с
   разными TLS-фингерпринтами uTLS: Chrome, Firefox, без uTLS (системный TLS),
   Random. Для каждого варианта перезапускается core с принудительным
   fingerprint (``run_with_node(..., fp=...)``) и выполняется TLS handshake к
   контрольному хосту. Смотрим: подключился ли узел, сколько времени заняло,
   что ответил сервер. Узел, который поднимается только с одним «идеальным»
   fingerprint и молчит на остальных, — хрупкий против DPI.

2. **Tunnel-блок** — через поднятый узел выполняем реальные клиентские
   TLS-варианты: TLS 1.2 / TLS 1.3 по отдельности, неверный/случайный/
   отсутствующий SNI, мусорный ClientHello (garbage). Узел, который одинаково
   стабильно прокидывает все варианты, — устойчив.

3. **Direct-блок** (для TLS-based транспортов) — отправляем серверу узла
   ClientHello с DPI-сигнатурами напрямую (клиент -> DPI -> сервер узла).
   Если DPI блокирует нестандартный ClientHello, сервер не ответит.

**ECH** — только исследовательская метрика ``ech_supported`` и НЕ входит в
score (большинство VPN-узлов ECH не используют).

Итоговая оценка — **robustness_score** (X из 10), а не pass/fail:
4 fingerprint-теста + TLS 1.2 + TLS 1.3 + wrong/missing/random SNI + garbage.
``score`` (процент) вычисляется из robustness для обратной совместимости.
"""

from __future__ import annotations

import logging
import os
import random
import socket
import ssl
import string
import time
import contextlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import base
from xray_runtime import parse_node_link

logger = logging.getLogger(__name__)

# Контрольный хост для tunnel/fingerprint-блоков (не заблокирован в РФ,
# дружелюбен к нестандартным SNI — отвечает alert вместо сброса,
# поддерживает TLS 1.2/1.3).
DPI_ACTIVE_CONTROL_HOST = "cloudflare.com"
DPI_ACTIVE_CONTROL_PORT = 443

# Порог принятия: доля успешных robustness-тестов (0..1), напр. 0.6 = 6/10.
DPI_ACTIVE_MIN_SCORE = 0.6
# Таймаут одного сетевого варианта (сек).
DPI_ACTIVE_TIMEOUT = 4.0
# Пауза при фрагментации ClientHello (сек) — классический интервал обхода SNI-DPI.
DPI_ACTIVE_FRAGMENT_DELAY = 0.4
# Количество байт padding для «большого» ClientHello (маскировка SNI).
DPI_ACTIVE_PADDING_BYTES = 900
# Размер мусорного ClientHello (garbage) — сырые байты, не TLS record.
DPI_ACTIVE_GARBAGE_BYTES = 256

# Fingerprint-матрица: (fp_override, метка). Каждый вариант = отдельный
# перезапуск core с принудительным fingerprint. "none" = системный TLS без uTLS.
DPI_ACTIVE_FINGERPRINT_TESTS: tuple[tuple[str, str], ...] = (
    ("chrome", "Chrome"),
    ("firefox", "Firefox"),
    ("none", "Без uTLS"),
    ("random", "Random"),
)

# Порядок robustness-тестов (10 шт): fingerprint-матрица + tunnel-блок.
_ROBUSTNESS_FINGERPRINT_KEYS = [fp for fp, _ in DPI_ACTIVE_FINGERPRINT_TESTS]
_ROBUSTNESS_TUNNEL_KEYS = ("tls12", "tls13", "wrong_sni", "missing_sni", "random_sni", "garbage")

# Протоколы, чей транспорт построен на TLS (сервер узла отвечает на ClientHello).
_TLS_BASED_PROTOCOLS = ("trojan", "vless", "vmess", "vless-reality", "reality")


@dataclass
class DpiActiveResult:
    """Результат активной DPI-проверки протокола узла."""

    accepted: bool
    reason: str = ""
    # Число успешных robustness-тестов из robustness_total (например 8/10).
    robustness_score: int = 0
    robustness_total: int = 0
    # Процент успешных тестов (0..100), для обратной совместимости.
    score: float = 0.0
    # ECH — исследовательская метрика, НЕ входит в score.
    ech_supported: bool = False
    # Fingerprint-матрица: fp -> {ok, ms, type}.
    fingerprints: dict = field(default_factory=dict)
    # Direct-блок (ClientHello напрямую на сервер узла, TLS-based).
    direct: dict = field(default_factory=dict)
    # Tunnel-блок (клиентские TLS-варианты через поднятый узел).
    tunnel: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)

    def row(self) -> dict:
        return {
            "accepted": self.accepted,
            "score": round(self.score, 1),
            "robustness_score": self.robustness_score,
            "robustness_total": self.robustness_total,
            "ech_supported": self.ech_supported,
            "reason": self.reason,
            "fingerprints": self.fingerprints,
            "direct": self.direct,
            "tunnel": self.tunnel,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Ручная сборка TLS ClientHello (raw record).
# ---------------------------------------------------------------------------

def _extension(ext_type: int, data: bytes) -> bytes:
    return ext_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _sni_extension(server_name: str) -> bytes:
    if not server_name:
        return b""
    name = server_name.encode("idna")
    return _extension(0x0000, b"\x00" + len(name).to_bytes(2, "big") + name)


def build_client_hello(
    server_name: str | None,
    *,
    tls13: bool = True,
    padding_bytes: int = 0,
    ech: bool = False,
) -> bytes:
    """Собрать TLS ClientHello record (0x16 0x0301 ...).

    Параметры:
    - ``server_name`` — SNI (None = без SNI);
    - ``tls13`` — True: TLS 1.3 (cipher + supported_versions 1.3);
                False: только TLS 1.2 (legacy cipher + supported_versions 1.2);
    - ``padding_bytes`` — размер padding extension (большой ClientHello);
    - ``ech`` — добавить ECH extension (0xfe0d) с dummy-данными.
    """
    legacy_version = b"\x03\x03"  # TLS 1.2 (legacy_version всегда 0x0303 в 1.3)
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)

    if tls13:
        cipher_suites = (
            b"\x13\x01"  # TLS_AES_128_GCM_SHA256
            b"\x13\x02"  # TLS_AES_256_GCM_SHA384
            b"\x13\x03"  # TLS_CHACHA20_POLY1305_SHA256
            b"\xcc\xa9"  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            b"\xcc\xa8"  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            b"\xc0\x2f"  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            b"\xc0\x2b"  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        )
    else:
        cipher_suites = (
            b"\xc0\x2f"
            b"\xc0\x2b"
            b"\xc0\x30"
            b"\xc0\x2c"
            b"\x00\x9c"
            b"\x00\x9d"
        )

    extensions = bytearray()
    extensions += _sni_extension(server_name or "")
    extensions += _extension(
        0x000A,  # supported_groups
        b"\x00\x04" + b"\x00\x1d" + b"\x00\x17",  # x25519, P-256
    )
    extensions += _extension(
        0x000D,  # signature_algorithms
        b"\x00\x0c"
        + b"\x08\x04"  # rsa_pss_rsae_sha256
        + b"\x04\x03"  # ecdsa_secp256r1_sha256
        + b"\x05\x03"  # rsa_pkcs1_sha256
        + b"\x08\x06"  # rsa_pss_pss_sha256
        + b"\x04\x01"  # rsa_pkcs1_sha1
        + b"\x02\x01",  # ecdsa_sha1
    )
    # key_share: x25519 со случайным публичным ключом (сервер ответит HRR/ServerHello).
    if tls13:
        extensions += _extension(
            0x0033,
            b"\x00\x22" + b"\x00\x1d" + b"\x00\x20" + os.urandom(32),
        )
    extensions += _extension(0x002D, b"\x01\x01")  # psk_key_exchange_modes
    if tls13:
        extensions += _extension(0x002B, b"\x00\x02" + b"\x03\x04")  # TLS 1.3
    else:
        extensions += _extension(0x002B, b"\x00\x02" + b"\x03\x03")  # TLS 1.2
    if ech:
        # ECH: outer extension c(0xfe0d), dummy содержимое (не настоящий ключ).
        dummy = b"\x01\x00\x00\x0a" + os.urandom(10)
        extensions += _extension(0xFE0D, dummy)
    if padding_bytes > 0:
        # Padding extension: маскирует SNI (клиентские обходы SNI-DPI).
        extensions += _extension(0x0015, b"\x00" * padding_bytes)

    ext_block = bytes(extensions)
    body = (
        legacy_version
        + random_bytes
        + bytes([len(session_id)])
        + session_id
        + len(cipher_suites).to_bytes(2, "big")
        + cipher_suites
        + b"\x01\x00"
        + len(ext_block).to_bytes(2, "big")
        + ext_block
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _random_sni() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=12)) + ".com"


# ---------------------------------------------------------------------------
# Direct-блок: ClientHello к серверу узла (путь клиент -> DPI -> сервер узла).
# ---------------------------------------------------------------------------

def _probe_direct(
    node_host: str,
    node_port: int,
    variant: str,
    timeout: float,
) -> dict:
    """Отправить ClientHello напрямую на сервер узла и прочитать реакцию.

    Моделирует DPI-путь пользователя: ClientHello идёт в открытом виде к
    серверу узла. Если DPI (или сам сервер узла) блокирует нестандартный
    вариант — реакции не будет.

    Возвращает {"ok": bool, "bytes": int, "type": "serverhello"|"alert"|"close"},
    где ok = получены любые данные от сервера.
    """
    started = time.perf_counter()
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((node_host, int(node_port)), timeout=timeout)
        sock.settimeout(timeout)

        if variant == "correct_sni":
            hello = build_client_hello("www.cloudflare.com", tls13=True)
        elif variant == "wrong_sni":
            hello = build_client_hello("example.org", tls13=True)
        elif variant == "random_sni":
            hello = build_client_hello(_random_sni(), tls13=True)
        elif variant == "missing_sni":
            hello = build_client_hello(None, tls13=True)
        elif variant == "large":
            hello = build_client_hello("www.cloudflare.com", tls13=True, padding_bytes=DPI_ACTIVE_PADDING_BYTES)
        elif variant == "garbage":
            # Мусорный ClientHello: сырые случайные байты, не TLS record.
            hello = os.urandom(DPI_ACTIVE_GARBAGE_BYTES)
        else:  # fragmented
            hello = build_client_hello("www.cloudflare.com", tls13=True)

        if variant == "fragmented":
            # Отправляем record-заголовок + часть handshake, пауза, остальное.
            split_at = min(64, len(hello))
            sock.sendall(hello[:split_at])
            time.sleep(DPI_ACTIVE_FRAGMENT_DELAY)
            sock.sendall(hello[split_at:])
        else:
            sock.sendall(hello)

        data = b""
        deadline = time.perf_counter() + timeout
        while len(data) < 5 and time.perf_counter() < deadline:
            chunk = sock.recv(5 - len(data))
            if not chunk:
                break
            data += chunk
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if not data:
            return {"ok": False, "bytes": 0, "type": "close", "ms": round(elapsed_ms, 1)}
        if data[0] == 0x16:
            return {"ok": True, "bytes": len(data), "type": "serverhello", "ms": round(elapsed_ms, 1)}
        if data[0] == 0x15:
            return {"ok": True, "bytes": len(data), "type": "alert", "ms": round(elapsed_ms, 1)}
        return {"ok": True, "bytes": len(data), "type": "raw", "ms": round(elapsed_ms, 1)}
    except (socket.timeout, TimeoutError, ConnectionError, OSError):
        return {"ok": False, "bytes": 0, "type": "timeout", "ms": None}
    except Exception:
        return {"ok": False, "bytes": 0, "type": "error", "ms": None}
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()


def _run_direct_block(node_url: str, timeout: float) -> tuple[dict, dict]:
    """Direct-блок для TLS-based протоколов. Возвращает (результаты, детали)."""
    node = parse_node_link(node_url)
    if node is None:
        return {}, {"skipped": "parse_failed"}
    host, port = getattr(node, "host", ""), getattr(node, "port", 0)
    if not host or not port:
        return {}, {"skipped": "no_host_port"}

    tls_like = node.protocol.lower() in _TLS_BASED_PROTOCOLS
    if not tls_like and "tls" not in (node_url or "").lower():
        return {}, {"skipped": "not_tls_transport"}

    variants = ("correct_sni", "wrong_sni", "random_sni", "missing_sni", "fragmented", "large", "garbage")
    results: dict = {}
    ok = 0
    for v in variants:
        res = _probe_direct(host, port, v, timeout)
        results[v] = res
        if res.get("ok"):
            ok += 1
    return results, {"ok": ok, "total": len(variants), "host": str(host), "port": int(port)}


# ---------------------------------------------------------------------------
# Fingerprint-матрица: перезапуск core с принудительным uTLS fingerprint.
# ---------------------------------------------------------------------------

def _make_tunnel_handshake(timeout: float) -> Callable[[str, int], dict]:
    """Вернуть fn(host, port): полный TLS handshake к контрольному хосту.

    Используется внутри ``run_with_node(..., fp=...)``: core уже поднят с
    принудительным fingerprint. Возвращает {"ok", "type", "ms"}.
    """

    def _fn(host: str, port: int) -> dict:
        started = time.perf_counter()
        try:
            ok = base.tls_handshake_ok(
                host,
                port,
                DPI_ACTIVE_CONTROL_HOST,
                DPI_ACTIVE_CONTROL_PORT,
                DPI_ACTIVE_CONTROL_HOST,
                timeout,
            )
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if ok:
                return {"ok": True, "type": "handshake", "ms": round(elapsed_ms, 1)}
            return {"ok": False, "type": "handshake_failed", "ms": round(elapsed_ms, 1)}
        except Exception:
            return {"ok": False, "type": "error", "ms": None}

    return _fn


def _run_fingerprint_block(
    node_url: str,
    timeout: float,
    root_dir: Optional[Path],
) -> tuple[dict, dict]:
    """Fingerprint-матрица: для каждого fp перезапускаем core с override.

    Возвращает (результаты, детали). Результаты: fp -> {"ok", "ms", "type"}.
    """
    results: dict = {}
    ok = 0
    for fp, _label in DPI_ACTIVE_FINGERPRINT_TESTS:
        budget = max(10.0, timeout * 6.0)
        res = base.run_with_node(
            node_url,
            _make_tunnel_handshake(timeout),
            timeout=timeout,
            root_dir=root_dir,
            budget=budget,
            fp=fp,
        )
        if res is None:
            results[fp] = {"ok": False, "type": "core_failed", "ms": None}
        elif isinstance(res, dict):
            results[fp] = res
        else:
            results[fp] = {"ok": False, "type": "bad_result", "ms": None}
        if results[fp].get("ok"):
            ok += 1
    return results, {"ok": ok, "total": len(DPI_ACTIVE_FINGERPRINT_TESTS)}


# ---------------------------------------------------------------------------
# Tunnel-блок: стабильность туннеля через run_with_node.
# ---------------------------------------------------------------------------

def _socks_probe_raw(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    payload: bytes,
    *,
    fragmented: bool,
    timeout: float,
) -> dict:
    """Отправить raw payload через SOCKS-туннель и прочитать реакцию."""
    raw: socket.socket | None = None
    started = time.perf_counter()
    try:
        raw = base._socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw is None:
            return {"ok": False, "type": "socks_fail"}
        raw.settimeout(timeout)
        if fragmented:
            split_at = min(64, len(payload))
            raw.sendall(payload[:split_at])
            time.sleep(DPI_ACTIVE_FRAGMENT_DELAY)
            raw.sendall(payload[split_at:])
        else:
            raw.sendall(payload)
        data = b""
        deadline = time.perf_counter() + timeout
        while len(data) < 5 and time.perf_counter() < deadline:
            chunk = raw.recv(5 - len(data))
            if not chunk:
                break
            data += chunk
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if not data:
            return {"ok": False, "type": "close", "ms": round(elapsed_ms, 1)}
        if data[0] == 0x16:
            return {"ok": True, "type": "serverhello", "ms": round(elapsed_ms, 1)}
        if data[0] == 0x15:
            return {"ok": False, "type": "alert", "ms": round(elapsed_ms, 1)}
        return {"ok": False, "type": "raw", "ms": round(elapsed_ms, 1)}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "type": "timeout"}
    except Exception:
        return {"ok": False, "type": "error"}
    finally:
        if raw is not None:
            with contextlib.suppress(Exception):
                raw.close()


def _tls_version_ok(socks_host: str, socks_port: int, timeout: float, tls12: bool) -> bool:
    """Полный TLS handshake с ограничением версии (TLS 1.2 или 1.3)."""
    try:
        version = ssl.TLSVersion.TLSv1_2 if tls12 else ssl.TLSVersion.TLSv1_3
        raw = base._socks_open_connection(
            socks_host, socks_port, DPI_ACTIVE_CONTROL_HOST, DPI_ACTIVE_CONTROL_PORT, timeout
        )
        if raw is None:
            return False
        with base._wrap_tls_version(
            raw, DPI_ACTIVE_CONTROL_HOST, timeout, minimum_version=version, maximum_version=version
        ):
            return True
    except Exception:
        return False
    finally:
        pass


def _run_tunnel_block(
    socks_host: str,
    socks_port: int,
    timeout: float,
) -> tuple[dict, dict]:
    """Tunnel-блок: реальные TLS-варианты через поднятый узел."""
    results: dict = {}

    # 1. Контрольный полный handshake (обычный ClientHello через ssl).
    control_ok = base.tls_handshake_ok(
        socks_host, socks_port, DPI_ACTIVE_CONTROL_HOST, DPI_ACTIVE_CONTROL_PORT,
        DPI_ACTIVE_CONTROL_HOST, timeout,
    )
    results["control"] = {"ok": control_ok, "type": "handshake"}

    # 2. TLS 1.2 / TLS 1.3 по отдельности.
    results["tls12"] = {"ok": _tls_version_ok(socks_host, socks_port, timeout, True), "type": "handshake"}
    results["tls13"] = {"ok": _tls_version_ok(socks_host, socks_port, timeout, False), "type": "handshake"}

    # 3. Большой и фрагментированный ClientHello.
    large = build_client_hello(DPI_ACTIVE_CONTROL_HOST, tls13=True, padding_bytes=DPI_ACTIVE_PADDING_BYTES)
    results["large"] = _socks_probe_raw(
        socks_host, socks_port, DPI_ACTIVE_CONTROL_HOST, DPI_ACTIVE_CONTROL_PORT,
        large, fragmented=False, timeout=timeout,
    )
    frag = build_client_hello(DPI_ACTIVE_CONTROL_HOST, tls13=True)
    results["fragmented"] = _socks_probe_raw(
        socks_host, socks_port, DPI_ACTIVE_CONTROL_HOST, DPI_ACTIVE_CONTROL_PORT,
        frag, fragmented=True, timeout=timeout,
    )

    # 4. ECH — исследовательская метрика (не входит в score).
    ech = build_client_hello(DPI_ACTIVE_CONTROL_HOST, tls13=True, ech=True)
    results["ech"] = _socks_probe_raw(
        socks_host, socks_port, DPI_ACTIVE_CONTROL_HOST, DPI_ACTIVE_CONTROL_PORT,
        ech, fragmented=False, timeout=timeout,
    )

    # 5. SNI-варианты через туннель (информативные: сервер цели решает сам).
    wrong = build_client_hello("example.org", tls13=True)
    results["wrong_sni"] = _socks_probe_raw(
        socks_host, socks_port, DPI_ACTIVE_CONTROL_HOST, DPI_ACTIVE_CONTROL_PORT,
        wrong, fragmented=False, timeout=timeout,
    )
    missing = build_client_hello(None, tls13=True)
    results["missing_sni"] = _socks_probe_raw(
        socks_host, socks_port, DPI_ACTIVE_CONTROL_HOST, DPI_ACTIVE_CONTROL_PORT,
        missing, fragmented=False, timeout=timeout,
    )
    rand_sni = _random_sni()
    rand = build_client_hello(rand_sni, tls13=True)
    results["random_sni"] = _socks_probe_raw(
        socks_host, socks_port, DPI_ACTIVE_CONTROL_HOST, DPI_ACTIVE_CONTROL_PORT,
        rand, fragmented=False, timeout=timeout,
    )

    # 6. Мусорный ClientHello: сырые байты. Успех = туннель доставил данные
    #    (сервер отреагировал alert/raw/close, а не завис таймаут).
    garbage = os.urandom(DPI_ACTIVE_GARBAGE_BYTES)
    results["garbage"] = _socks_probe_raw(
        socks_host, socks_port, DPI_ACTIVE_CONTROL_HOST, DPI_ACTIVE_CONTROL_PORT,
        garbage, fragmented=False, timeout=timeout,
    )

    # Классификация успеха:
    # - полные handshake (control/tls12/tls13): ok=True;
    # - SNI-варианты (wrong/missing/random): любая реакция сервера — туннель жив;
    # - raw-варианты (large/fragmented): serverhello от цели;
    # - garbage: любая реакция (alert/raw/close/serverhello) — данные доставлены;
    # - ech: метрика, в counts не входит.
    ok_names = {"control", "tls12", "tls13"}
    sni_names = {"wrong_sni", "missing_sni", "random_sni"}
    any_reaction_names = {"garbage"}
    counts = {"ok": 0, "total": 0}
    details: dict = {}
    for name, res in results.items():
        if name == "ech":
            # Метрика: serverhello = сервер поддержал ECH (или туннель прокинул).
            continue
        counts["total"] += 1
        if name in ok_names:
            good = bool(res.get("ok"))
            counts["ok"] += 1 if good else 0
            details[name] = "handshake" if good else "failed"
        elif name in sni_names:
            good = res.get("type") in ("serverhello", "alert", "raw")
            counts["ok"] += 1 if good else 0
            details[name] = res.get("type", "close")
        elif name in any_reaction_names:
            good = res.get("type") in ("serverhello", "alert", "raw", "close")
            counts["ok"] += 1 if good else 0
            details[name] = res.get("type", "timeout")
        else:
            good = res.get("type") == "serverhello"
            counts["ok"] += 1 if good else 0
            details[name] = res.get("type", "close")
    counts["details"] = details
    return results, counts


# ---------------------------------------------------------------------------
# Публичное API.
# ---------------------------------------------------------------------------

def check_node_dpi_active_detailed(
    node_url: str,
    timeout: float = DPI_ACTIVE_TIMEOUT,
    root_dir: Optional[Path] = None,
) -> DpiActiveResult:
    """Детальная активная DPI-проверка протокола узла (анти-DPI устойчивость).

    - Fingerprint-матрица: 4 перезапуска core с принудительным uTLS
      fingerprint (chrome/firefox/none/random) + TLS handshake к control хосту;
    - Tunnel-блок: TLS 1.2/1.3, большой/фрагментированный ClientHello,
      wrong/missing/random SNI, мусорный ClientHello;
    - Direct-блок (для TLS-based транспортов): ClientHello с DPI-сигнатурами
      напрямую на сервер узла.

    **robustness_score** = число успешных тестов из 10 (4 fingerprint + 6 tunnel).
    Узел принят, если контрольный handshake успешен и доля успешных тестов >=
    ``DPI_ACTIVE_MIN_SCORE``. ECH — только метрика ``ech_supported``.
    """
    if not node_url:
        return DpiActiveResult(accepted=False, reason="empty_node")

    direct, direct_meta = _run_direct_block(node_url, timeout)

    # Tunnel-блок: один core, fingerprint из ссылки узла.
    def _tunnel(host: str, port: int) -> tuple[dict, dict] | None:
        return _run_tunnel_block(host, port, timeout)

    budget = max(15.0, timeout * 12.0)
    tunnel_res = base.run_with_node(node_url, _tunnel, timeout=timeout, root_dir=root_dir, budget=budget)

    if tunnel_res is None:
        return DpiActiveResult(
            accepted=False,
            reason="node_start_failed",
            direct=direct,
            tunnel={},
            details={"direct_meta": direct_meta},
        )

    tunnel, tunnel_counts = tunnel_res

    # Fingerprint-матрица: отдельный core под каждый fingerprint.
    fingerprints, fp_meta = _run_fingerprint_block(node_url, timeout, root_dir)

    # ECH — исследовательская метрика, не входит в score.
    ech_supported = tunnel.get("ech", {}).get("type") == "serverhello"

    # robustness_score: X из 10.
    robustness: list[bool] = []
    for key in _ROBUSTNESS_FINGERPRINT_KEYS:
        robustness.append(bool(fingerprints.get(key, {}).get("ok")))
    for key in _ROBUSTNESS_TUNNEL_KEYS:
        robustness.append(bool(tunnel.get(key, {}).get("ok")))
    robustness_total = len(robustness)
    robustness_score = sum(1 for item in robustness if item)
    score = (robustness_score / max(1, robustness_total)) * 100.0

    control_ok = bool(tunnel.get("control", {}).get("ok"))
    accepted = control_ok and score >= DPI_ACTIVE_MIN_SCORE * 100.0
    if not control_ok:
        reason = "control_failed"
    elif not accepted:
        reason = "dpi_signature_unstable"
    else:
        reason = "ready"

    return DpiActiveResult(
        accepted=accepted,
        reason=reason,
        robustness_score=robustness_score,
        robustness_total=robustness_total,
        score=round(score, 1),
        ech_supported=ech_supported,
        fingerprints=fingerprints,
        direct=direct,
        tunnel=tunnel,
        details={
            "direct_meta": direct_meta,
            "fp_meta": fp_meta,
            "tunnel_counts": tunnel_counts,
            "control_host": DPI_ACTIVE_CONTROL_HOST,
        },
    )


def check_node_dpi_active(
    node_url: str,
    timeout: float = DPI_ACTIVE_TIMEOUT,
    root_dir: Optional[Path] = None,
) -> bool:
    """Упрощённая активная DPI-проверка (bool)."""
    return check_node_dpi_active_detailed(node_url, timeout=timeout, root_dir=root_dir).accepted


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m checkers.dpi_active <node_url>")
        sys.exit(1)
    r = check_node_dpi_active_detailed(sys.argv[1])
    print(
        f"DPI-ACTIVE for {sys.argv[1]}: {'PASS' if r.accepted else 'FAIL'} "
        f"score={r.score} robustness={r.robustness_score}/{r.robustness_total} "
        f"ech={r.ech_supported} reason={r.reason}"
    )
    print(f"  fingerprints: {r.fingerprints}")
    print(f"  tunnel: {r.details.get('tunnel_counts')}")
    print(f"  direct: {r.details.get('direct_meta')}")
