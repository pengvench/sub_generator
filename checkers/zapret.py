"""Zapret-стиль проверка узлов (методика из ``C:\\Zapret\\utils\\test zapret.ps1``).

Повторяет логику тестов Zapret через прокси-узел:

1. **DPI suite (tcp 16-20)**: POST с 64KB случайным payload на suite-хосты
   (``https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json``)
   через три протокола: HTTP/1.1, TLS1.2, TLS1.3 (как ``--http1.1``,
   ``--tlsv1.2 --tls-max 1.2``, ``--tlsv1.3 --tls-max 1.3`` в curl).
   Детекция паттерна "freeze" (цензура режет стратегию на 16-20KB):
   загружено >0 байт, скачано 0, время >= таймаута -> ``LIKELY_BLOCKED``.

2. **Standard HTTP test**: HEAD-запросы к основным ресурсам (discord.com,
   youtube.com, google.com, cloudflare.com) через те же три протокола.
   Статусы: OK / SSL / UNSUP / ERROR.

Score-логика как в Zapret: узел оценивается долей успешных тестов из общего
числа (targets x 3 протокола). 60/60 бывает редко — из-за погрешностей
отдельных хостов/протоколов нормально 55/60 и даже ниже. Узел принимается,
если доля OK >= ``ZAPRET_MIN_SCORE`` (по умолчанию 0.75, т.е. ~45/60).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import base

logger = logging.getLogger(__name__)

# URL suite-целей (как Get-DpiSuite в Zapret).
DPI_SUITE_URL = "https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json"
# Резервный источник того же suite: GitHub Pages у hyperion-cs периодически
# не отвечает (TLS handshake таймаутит). Файл в репозитории идентичен.
DPI_SUITE_URL_RAW = "https://raw.githubusercontent.com/hyperion-cs/dpi-checkers/main/ru/tcp-16-20/suite.v2.json"
# Локальная копия suite (скачана на случай недоступности GitHub — например,
# когда сам GitHub временно лежит). Используется после сетевых источников
# и перед встроенным fallback.
_LOCAL_SUITE_PATH = Path(__file__).resolve().parent / "suite.v2.json"

# Таймаут на один протокол-тест одной цели (сек).
ZAPRET_TIMEOUT = 5.0
# Размер payload (как `--range 0-65535` в Zapret, 64KB).
ZAPRET_PAYLOAD_BYTES = 64 * 1024
# Максимум целей suite, проверяемых на один узел (для скорости).
ZAPRET_MAX_TARGETS = 8
# Количество параллельных проверок на узел (как `-Parallel 8` в Zapret).
ZAPRET_PARALLEL = 8
# Общий бюджет времени на проверку одного узла (защита от зависаний).
ZAPRET_BUDGET = 90.0
# Минимальная доля успешных probe-тестов (score) для принятия узла.
# Как в Zapret: 60/60 бывает редко (часто 55/60 из-за погрешностей), поэтому
# по умолчанию достаточно ~75% успеха (например, 45/60).
ZAPRET_MIN_SCORE = 0.75

# Статусы результата отдельного теста (как в Zapret).
STATUS_OK = "OK"
STATUS_FAIL = "FAIL"
STATUS_UNSUP = "UNSUP"
STATUS_SSL = "SSL"
STATUS_BLOCKED = "LIKELY_BLOCKED"

# Протоколы тестирования (как флаги curl в Zapret).
PROTO_HTTP11 = "http1.1"
PROTO_TLS12 = "tls1.2"
PROTO_TLS13 = "tls1.3"
PROTOCOLS = (PROTO_HTTP11, PROTO_TLS12, PROTO_TLS13)

# Встроенный fallback, если suite недоступен (генератор может работать
# на машине без прямого интернета).
_FALLBACK_TARGETS = (
    ("fallback-akamai", "Akamai", "US", "akamai.com"),
    ("fallback-cloudflare", "Cloudflare", "US", "cloudflare.com"),
    ("fallback-google", "Google", "US", "google.com"),
    ("fallback-amazon", "Amazon", "US", "amazon.com"),
    ("fallback-fastly", "Fastly", "US", "fastly.com"),
    ("fallback-hetzner", "Hetzner", "DE", "hetzner.com"),
    ("fallback-vultr", "Vultr", "US", "vultr.com"),
    ("fallback-discord", "Discord", "US", "discord.com"),
)

# Стандартные ресурсы для HTTP-теста (как targets.txt в Zapret).
HTTP_TEST_TARGETS = (
    "discord.com",
    "www.youtube.com",
    "www.google.com",
    "cloudflare.com",
)


@dataclass
class ZapretTarget:
    """Цель из DPI suite (одна запись suite.v2.json)."""

    id: str
    provider: str
    country: str
    host: str


@dataclass
class ZapretProbeResult:
    """Результат одного протокол-теста на одной цели.

    Аналог строки ``-w "%{http_code} %{size_upload} %{size_download}
    %{time_total}"`` в Zapret.
    """

    protocol: str
    status: str = STATUS_FAIL
    http_code: int = 0
    up_bytes: int = 0
    down_bytes: int = 0
    time_sec: float = 0.0
    detail: str = ""

    def row(self) -> dict:
        return {
            "protocol": self.protocol,
            "status": self.status,
            "http_code": self.http_code,
            "up_bytes": self.up_bytes,
            "down_bytes": self.down_bytes,
            "time_sec": round(self.time_sec, 2),
            "detail": self.detail,
        }


@dataclass
class ZapretHttpResult:
    """Результат HTTP-теста (standard) для одного хоста."""

    host: str
    probes: list[ZapretProbeResult] = field(default_factory=list)

    def row(self) -> dict:
        return {
            "host": self.host,
            "probes": [p.row() for p in self.probes],
        }


@dataclass
class ZapretCheckResult:
    """Результат Zapret-проверки узла.

    Score-логика как в Zapret: узел оценивается долей успешных тестов
    из общего числа (targets x 3 протокола). 60/60 бывает редко — из-за
    погрешностей отдельных хостов/протоколов нормально 55/60 и даже ниже.
    Узел принимается, если ``ok_probes / total_probes >= min_score``.
    """

    accepted: bool
    reason: str = ""
    blocked_targets: int = 0
    ok_targets: int = 0
    total_targets: int = 0
    total_probes: int = 0
    ok_probes: int = 0
    blocked_probes: int = 0
    unsup_probes: int = 0
    fail_probes: int = 0
    score: float = 0.0
    min_score: float = 0.75
    targets: list[dict] = field(default_factory=list)
    http_tests: list[ZapretHttpResult] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def score_text(self) -> str:
        """Строка вида '55/60' (как в логах Zapret)."""
        return f"{self.ok_probes}/{self.total_probes}"

    def row(self) -> dict:
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "blocked_targets": self.blocked_targets,
            "ok_targets": self.ok_targets,
            "total_targets": self.total_targets,
            "total_probes": self.total_probes,
            "ok_probes": self.ok_probes,
            "blocked_probes": self.blocked_probes,
            "unsup_probes": self.unsup_probes,
            "fail_probes": self.fail_probes,
            "score": round(self.score, 3),
            "score_text": self.score_text,
            "min_score": self.min_score,
            "targets": self.targets,
            "http_tests": [t.row() for t in self.http_tests],
        }


def _parse_suite(data: list) -> list[ZapretTarget]:
    """Распарсить suite.v2.json в список ZapretTarget (без пустых хостов)."""
    targets: list[ZapretTarget] = []
    for item in data:
        host = str(item.get("host", "")).strip()
        if not host:
            continue
        targets.append(
            ZapretTarget(
                id=str(item.get("id", "")),
                provider=str(item.get("provider", "")),
                country=str(item.get("country", "")),
                host=host,
            )
        )
    return targets


def _fetch_suite_json(url: str, fetch_timeout: float) -> list | None:
    """Скачать suite.v2.json по url, вернуть список целей или None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SubGenerator/1.0"})
        with urllib.request.urlopen(req, timeout=fetch_timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if not isinstance(data, list):
            return None
        return _parse_suite(data)
    except Exception as exc:
        logger.warning("DPI suite: источник %s недоступен (%s)", url, exc)
        return None


def _select_targets(targets: list[ZapretTarget], max_targets: int) -> list[ZapretTarget]:
    """Равномерно выбрать до max_targets целей разных провайдеров."""
    selected: list[ZapretTarget] = []
    seen: set[str] = set()
    for t in targets:
        if t.provider not in seen:
            selected.append(t)
            seen.add(t.provider)
        if len(selected) >= max_targets:
            break
    if len(selected) < max_targets:
        for t in targets:
            if all(t.host != s.host for s in selected):
                selected.append(t)
            if len(selected) >= max_targets:
                break
    return selected[:max_targets]


def _load_local_suite() -> list[ZapretTarget] | None:
    """Прочитать локальную копию suite.v2.json (запас на случай падения GitHub)."""
    try:
        with _LOCAL_SUITE_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            return None
        return _parse_suite(data)
    except Exception as exc:
        logger.warning("DPI suite: локальный файл %s недоступен (%s)", _LOCAL_SUITE_PATH, exc)
        return None


def load_dpi_suite(
    url: str = DPI_SUITE_URL,
    max_targets: int = ZAPRET_MAX_TARGETS,
    fetch_timeout: float = 10.0,
) -> list[ZapretTarget]:
    """Загрузить suite-цели (как Get-DpiSuite в Zapret).

    Порядок источников:
    1. GitHub Pages (DPI_SUITE_URL) — актуальный suite.
    2. raw.githubusercontent.com (DPI_SUITE_URL_RAW) — тот же файл.
    3. Локальная копия (_LOCAL_SUITE_PATH) — запас на случай падения GitHub.
    4. Встроенные хосты (_FALLBACK_TARGETS) — совсем без сети.
    """
    for source_url in (url, DPI_SUITE_URL_RAW):
        targets = _fetch_suite_json(source_url, fetch_timeout)
        if targets:
            selected = _select_targets(targets, max_targets)
            logger.info("DPI suite: %d целей (из %d) из %s", len(selected), len(targets), source_url)
            return selected
    targets = _load_local_suite()
    if targets:
        selected = _select_targets(targets, max_targets)
        logger.info(
            "DPI suite: %d целей (из %d) из локального файла %s",
            len(selected),
            len(targets),
            _LOCAL_SUITE_PATH,
        )
        return selected
    logger.warning("DPI suite недоступен, использую встроенные цели")
    return [
        ZapretTarget(id=t[0], provider=t[1], country=t[2], host=t[3])
        for t in _FALLBACK_TARGETS[:max_targets]
    ]



def _classify_tls_error(exc: ssl.SSLError, result: ZapretProbeResult) -> ZapretProbeResult:
    """Классифицировать TLS-ошибку (как exit 35/статусы в Zapret)."""
    msg = str(exc).lower()
    result.detail = str(exc)
    if (
        "unsupported protocol" in msg
        or "wrong version" in msg
        or "no appropriate" in msg
        or "tlsv1" in msg
    ):
        result.status = STATUS_UNSUP  # TLS-версия не поддерживается сервером.
    elif "certificate" in msg or "cert verify" in msg:
        result.status = STATUS_SSL  # DNS-hijack / ошибка сертификата.
    else:
        result.status = STATUS_FAIL
    return result


def _post_payload_probe(
    socks_host: str,
    socks_port: int,
    host: str,
    protocol: str,
    timeout: float,
    payload_bytes: int = ZAPRET_PAYLOAD_BYTES,
) -> ZapretProbeResult:
    """POST 64KB payload через прокси по протоколу (как curl в Zapret).

    Измеряет up_bytes (отправлено), down_bytes (получено), time_sec и
    http_code. Детектирует freeze-паттерн 16-20KB: загружено >0 байт,
    скачано 0, время >= таймаута -> ``LIKELY_BLOCKED``.
    """
    start = time.perf_counter()
    result = ZapretProbeResult(protocol=protocol)
    raw_sock: socket.socket | None = None
    tls_sock: ssl.SSLSocket | None = None
    try:
        raw_sock = base._socks_open_connection(socks_host, socks_port, host, 443, timeout)
        if raw_sock is None:
            result.time_sec = time.perf_counter() - start
            result.detail = "socks_failed"
            return result

        if protocol == PROTO_TLS12:
            tls_sock = base._wrap_tls_version(
                raw_sock,
                host,
                timeout,
                minimum_version=ssl.TLSVersion.TLSv1_2,
                maximum_version=ssl.TLSVersion.TLSv1_2,
            )
        elif protocol == PROTO_TLS13:
            tls_sock = base._wrap_tls_version(
                raw_sock,
                host,
                timeout,
                minimum_version=ssl.TLSVersion.TLSv1_3,
                maximum_version=ssl.TLSVersion.TLSv1_3,
            )
        else:
            tls_sock = base._wrap_tls_version(raw_sock, host, timeout)
        raw_sock = None

        body = os.urandom(payload_bytes)
        header = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: SubGenerator/1.0\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {payload_bytes}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")

        # Отправляем заголовки + payload, считая отправленные байты.
        sent = 0
        try:
            tls_sock.sendall(header)
            sent += len(header)
        except (socket.timeout, TimeoutError):
            result.up_bytes = sent
            result.time_sec = time.perf_counter() - start
            result.detail = "write_timeout"
            if sent > 0 and result.time_sec >= timeout:
                result.status = STATUS_BLOCKED
            return result
        except Exception as exc:
            result.up_bytes = sent
            result.time_sec = time.perf_counter() - start
            result.detail = str(exc)
            return result

        chunk = 8192
        for i in range(0, len(body), chunk):
            try:
                tls_sock.sendall(body[i : i + chunk])
                sent += min(chunk, len(body) - i)
            except (socket.timeout, TimeoutError):
                result.up_bytes = sent
                result.time_sec = time.perf_counter() - start
                result.detail = "write_timeout"
                if sent > 0 and result.time_sec >= timeout:
                    result.status = STATUS_BLOCKED
                return result
            except Exception as exc:
                result.up_bytes = sent
                result.time_sec = time.perf_counter() - start
                result.detail = str(exc)
                return result
        result.up_bytes = sent

        # Читаем ответ до закрытия/таймаута.
        down = 0
        buffer = b""
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            try:
                piece = tls_sock.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not piece:
                break
            down += len(piece)
            buffer += piece

        result.down_bytes = down
        result.time_sec = time.perf_counter() - start

        # Разбираем http_code из ответа.
        if buffer:
            head, _, _ = buffer.partition(b"\r\n\r\n")
            try:
                parts = head.split(b" ", 2)
                if len(parts) >= 2:
                    result.http_code = int(parts[1])
            except Exception:
                pass

        # Классификация статуса (как в Zapret).
        if result.http_code >= 100:
            result.status = STATUS_OK
        elif result.up_bytes > 0 and result.down_bytes == 0 and result.time_sec >= timeout:
            result.status = STATUS_BLOCKED
            result.detail = "freeze (up>0, down==0, time>=timeout)"
        else:
            result.status = STATUS_FAIL
            result.detail = result.detail or "no_response"
        return result

    except ssl.SSLCertVerificationError:
        result.time_sec = time.perf_counter() - start
        result.status = STATUS_SSL
        result.detail = "cert_verification_failed"
        return result
    except ssl.SSLError as exc:
        result.time_sec = time.perf_counter() - start
        return _classify_tls_error(exc, result)
    except Exception as exc:
        result.time_sec = time.perf_counter() - start
        result.detail = str(exc) or type(exc).__name__
        result.status = STATUS_FAIL
        return result
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()
        if tls_sock is not None:
            with contextlib.suppress(Exception):
                tls_sock.close()


def _head_http_probe(
    socks_host: str,
    socks_port: int,
    host: str,
    protocol: str,
    timeout: float,
) -> ZapretProbeResult:
    """HEAD-запрос через прокси по протоколу (как ``curl -I`` в Zapret).

    Статусы: OK (получен HTTP-код), SSL (ошибка сертификата / DNS-hijack),
    UNSUP (TLS-версия не поддерживается), ERROR (остальное).
    """
    start = time.perf_counter()
    result = ZapretProbeResult(protocol=protocol)
    raw_sock: socket.socket | None = None
    tls_sock: ssl.SSLSocket | None = None
    try:
        raw_sock = base._socks_open_connection(socks_host, socks_port, host, 443, timeout)
        if raw_sock is None:
            result.time_sec = time.perf_counter() - start
            result.detail = "socks_failed"
            return result

        if protocol == PROTO_TLS12:
            tls_sock = base._wrap_tls_version(
                raw_sock,
                host,
                timeout,
                minimum_version=ssl.TLSVersion.TLSv1_2,
                maximum_version=ssl.TLSVersion.TLSv1_2,
            )
        elif protocol == PROTO_TLS13:
            tls_sock = base._wrap_tls_version(
                raw_sock,
                host,
                timeout,
                minimum_version=ssl.TLSVersion.TLSv1_3,
                maximum_version=ssl.TLSVersion.TLSv1_3,
            )
        else:
            tls_sock = base._wrap_tls_version(raw_sock, host, timeout)
        raw_sock = None

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        tls_sock.sendall(request)
        result.up_bytes = len(request)

        buffer = b""
        deadline = time.perf_counter() + timeout
        while b"\r\n\r\n" not in buffer and time.perf_counter() < deadline:
            try:
                piece = tls_sock.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            if not piece:
                break
            buffer += piece

        result.down_bytes = len(buffer)
        result.time_sec = time.perf_counter() - start

        if buffer:
            head, _, _ = buffer.partition(b"\r\n\r\n")
            try:
                parts = head.split(b" ", 2)
                if len(parts) >= 2:
                    result.http_code = int(parts[1])
            except Exception:
                pass

        if result.http_code >= 100:
            result.status = STATUS_OK
        else:
            result.status = STATUS_FAIL
            result.detail = result.detail or "no_response"
        return result

    except ssl.SSLCertVerificationError:
        result.time_sec = time.perf_counter() - start
        result.status = STATUS_SSL
        result.detail = "cert_verification_failed"
        return result
    except ssl.SSLError as exc:
        result.time_sec = time.perf_counter() - start
        return _classify_tls_error(exc, result)
    except Exception as exc:
        result.time_sec = time.perf_counter() - start
        result.detail = str(exc) or type(exc).__name__
        result.status = STATUS_FAIL
        return result
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()
        if tls_sock is not None:
            with contextlib.suppress(Exception):
                tls_sock.close()


def _probe_target(
    socks_host: str,
    socks_port: int,
    target: ZapretTarget,
    timeout: float,
) -> dict:
    """Прогнать 3 протокола POST-payload на одну цель."""
    probes = [
        _post_payload_probe(socks_host, socks_port, target.host, protocol, timeout)
        for protocol in PROTOCOLS
    ]
    blocked = any(p.status == STATUS_BLOCKED for p in probes)
    ok = any(p.status == STATUS_OK for p in probes)
    return {
        "id": target.id,
        "provider": target.provider,
        "country": target.country,
        "host": target.host,
        "blocked": blocked,
        "ok": ok,
        "probes": [p.row() for p in probes],
    }


def _http_test_host(
    socks_host: str,
    socks_port: int,
    host: str,
    timeout: float,
) -> ZapretHttpResult:
    """HTTP-тест (standard) для одного хоста: HEAD по 3 протоколам."""
    probes = [
        _head_http_probe(socks_host, socks_port, host, protocol, timeout)
        for protocol in PROTOCOLS
    ]
    return ZapretHttpResult(host=host, probes=probes)


def _run_zapret_checks(
    socks_host: str,
    socks_port: int,
    targets: list[ZapretTarget],
    timeout: float,
    run_http_test: bool,
    min_score: float = ZAPRET_MIN_SCORE,
) -> ZapretCheckResult:
    """Выполнить Zapret-проверки через локальный SOCKS5-прокси.

    Цели и HTTP-тесты прогоняются параллельно (как ``-Parallel 8`` в Zapret).

    Score-логика как в Zapret: успешных probe-тестов из общего числа
    (targets x 3 протокола). LIKELY_BLOCKED не учитывается в знаменателе,
    остальные (OK/SSL/FAIL) — учитываются. Узел принимается, если доля OK
    >= ``min_score``.
    """
    workers = min(ZAPRET_PARALLEL, max(len(targets), 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        target_rows = list(
            pool.map(lambda t: _probe_target(socks_host, socks_port, t, timeout), targets)
        )
        http_tests: list[ZapretHttpResult] = []
        if run_http_test:
            http_tests = list(
                pool.map(
                    lambda h: _http_test_host(socks_host, socks_port, h, timeout),
                    HTTP_TEST_TARGETS,
                )
            )

    blocked = sum(1 for r in target_rows if r["blocked"])
    ok = sum(1 for r in target_rows if r["ok"])
    total_targets = len(target_rows)

    # Подсчёт probe-статистики (как счётчики OK/FAIL/UNSUPPORTED/LIKELY_BLOCKED
    # в Zapret).
    all_probes: list[ZapretProbeResult] = []
    for row in target_rows:
        for pr in row["probes"]:
            all_probes.append(
                ZapretProbeResult(
                    protocol=pr["protocol"],
                    status=pr["status"],
                    http_code=pr["http_code"],
                    up_bytes=pr["up_bytes"],
                    down_bytes=pr["down_bytes"],
                    time_sec=pr["time_sec"],
                    detail=pr["detail"],
                )
            )
    ok_probes = sum(1 for p in all_probes if p.status == STATUS_OK)
    blocked_probes = sum(1 for p in all_probes if p.status == STATUS_BLOCKED)
    unsup_probes = sum(1 for p in all_probes if p.status in (STATUS_UNSUP, STATUS_SSL))
    total_probes = len(all_probes)
    fail_probes = total_probes - ok_probes - blocked_probes - unsup_probes

    # Знаменатель: все тесты, которые реально прошли (не LIKELY_BLOCKED).
    # LIKELY_BLOCKED — это проявление цензуры, а не неработоспособность узла.
    denom = total_probes - blocked_probes
    score = (ok_probes / denom) if denom > 0 else 0.0

    accepted = score >= min_score
    reason = (
        "ready"
        if accepted
        else f"score_{score:.3f}_below_{min_score:.2f} (blocked={blocked}/{total_targets})"
    )
    return ZapretCheckResult(
        accepted=accepted,
        reason=reason,
        blocked_targets=blocked,
        ok_targets=ok,
        total_targets=total_targets,
        total_probes=total_probes,
        ok_probes=ok_probes,
        blocked_probes=blocked_probes,
        unsup_probes=unsup_probes,
        fail_probes=fail_probes,
        score=score,
        min_score=min_score,
        targets=target_rows,
        http_tests=http_tests,
        details={"timeout": timeout},
    )


def check_node_zapret_detailed(
    node_url: str,
    targets: Optional[list[ZapretTarget]] = None,
    timeout: float = ZAPRET_TIMEOUT,
    max_targets: int = ZAPRET_MAX_TARGETS,
    root_dir: Optional[Path] = None,
    run_http_test: bool = True,
    min_score: float = ZAPRET_MIN_SCORE,
) -> ZapretCheckResult:
    """Детальная Zapret-проверка узла (возвращает ZapretCheckResult).

    Поднимает временный core-процесс узла и прогоняет DPI suite (tcp 16-20)
    + стандартный HTTP-тест через локальный SOCKS5-прокси.

    ``min_score`` — минимальная доля успешных тестов (0..1). Как в Zapret:
    чем больше хостов доступно, тем лучше конфиг, но 60/60 бывает редко
    (зачастую 55/60 из-за погрешностей), поэтому по умолчанию достаточно
    ~75% успеха.
    """
    if not node_url:
        return ZapretCheckResult(accepted=False, reason="empty_node")
    if targets is None:
        targets = load_dpi_suite(max_targets=max_targets)

    def _check(host: str, port: int) -> ZapretCheckResult:
        return _run_zapret_checks(host, port, targets, timeout, run_http_test, min_score)

    result = base.run_with_node(
        node_url,
        _check,
        timeout=timeout,
        root_dir=root_dir,
        budget=ZAPRET_BUDGET,
    )
    if result is None:
        return ZapretCheckResult(accepted=False, reason="node_start_failed")
    return result


def check_node_zapret(
    node_url: str,
    targets: Optional[list[ZapretTarget]] = None,
    timeout: float = ZAPRET_TIMEOUT,
    max_targets: int = ZAPRET_MAX_TARGETS,
    root_dir: Optional[Path] = None,
    run_http_test: bool = True,
    min_score: float = ZAPRET_MIN_SCORE,
) -> bool:
    """Проверить узел Zapret-методом (возвращает bool)."""
    result = check_node_zapret_detailed(
        node_url,
        targets=targets,
        timeout=timeout,
        max_targets=max_targets,
        root_dir=root_dir,
        run_http_test=run_http_test,
        min_score=min_score,
    )
    return result.accepted


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if len(sys.argv) < 2:
        print("Usage: python -m checkers.zapret <node_url> [max_targets]")
        sys.exit(1)
    url = sys.argv[1]
    max_t = int(sys.argv[2]) if len(sys.argv) > 2 else ZAPRET_MAX_TARGETS
    res = check_node_zapret_detailed(url, max_targets=max_t)
    print(f"Zapret check for {url}: {'PASS' if res.accepted else 'FAIL'}")
    print(
        f"  score={res.score_text} ({res.score:.1%} >= {res.min_score:.1%}) "
        f"targets={res.total_targets} ok={res.ok_targets} "
        f"blocked={res.blocked_targets} reason={res.reason}"
    )
    for t in res.targets:
        statuses = ", ".join(
            f"{p['protocol']}={p['status']}({p['http_code']})" for p in t["probes"]
        )
        print(f"  dpi {t['host']}: {statuses}")
    for ht in res.http_tests:
        statuses = ", ".join(
            f"{p['protocol']}={p['status']}({p['http_code']})" for p in ht.probes
        )
        print(f"  http {ht.host}: {statuses}")
