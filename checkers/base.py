"""Общие низкоуровневые операции для проверок узлов через SOCKS5-прокси.

Содержит функции, которые поднимают временный core-процесс узла и выполняют
реальные сетевые операции через локальный SOCKS5: TLS-хендшейки, передачу
больших payload (метод tcp 16-20 / l4-25), загрузку данных и т.п.

Методы проверки повторяют логику инструментария dpi-ch (dpich), но работают
через прокси-узел, а не через локальное соединение.
"""

from __future__ import annotations

import contextlib
import os
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, Callable


from xray_runtime import XrayCoreRuntime, XrayNode, parse_node_link

# Размер случайного payload для проверки tcp 16-20 / l4-25 (как в dpich).
TCP1620_PAYLOAD_BYTES = 64 * 1024
# Количество TLS-хендшейков для проверки "siberian"-ограничений.
SIBERIAN_CONN_COUNT = 4
# Таймаут по умолчанию для сетевых операций (сек).
DEFAULT_TIMEOUT = 10.0


def _socks_open_connection(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float,
) -> socket.socket | None:
    """Открыть TCP-соединение через SOCKS5-прокси к целевому хосту."""
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            sock.close()
            return None
        host_bytes = target_host.encode("idna")
        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + int(target_port).to_bytes(2, "big")
        )
        sock.sendall(request)
        header = _recv_exact(sock, 4)
        if len(header) < 4 or header[1] != 0:
            sock.close()
            return None
        atyp = header[3]
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 3:
            length = _recv_exact(sock, 1)
            if not length:
                sock.close()
                return None
            _recv_exact(sock, length[0])
        elif atyp == 4:
            _recv_exact(sock, 16)
        _recv_exact(sock, 2)
        return sock
    except Exception:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()
        return None


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _wrap_tls(
    raw_sock: socket.socket,
    server_name: str,
    timeout: float,
) -> ssl.SSLSocket:
    """Обернуть сокет в TLS с проверкой сертификата."""
    raw_sock.settimeout(timeout)
    context = ssl.create_default_context()
    return context.wrap_socket(raw_sock, server_hostname=server_name)


def _wrap_tls_version(
    raw_sock: socket.socket,
    server_name: str,
    timeout: float,
    minimum_version: ssl.TLSVersion | None = None,
    maximum_version: ssl.TLSVersion | None = None,
) -> ssl.SSLSocket:
    """Обернуть сокет в TLS с ограничением версии протокола.

    Используется для Zapret-стиля тестов: HTTP/1.1 (без ограничений),
    TLS1.2 (min=max=1.2), TLS1.3 (min=max=1.3) — как ``--tlsv1.2 --tls-max 1.2``
    в curl.
    """
    raw_sock.settimeout(timeout)
    context = ssl.create_default_context()
    if minimum_version is not None:
        context.minimum_version = minimum_version
    if maximum_version is not None:
        context.maximum_version = maximum_version
    return context.wrap_socket(raw_sock, server_hostname=server_name)


def tls_handshake_ok(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> bool:
    """Успешен ли TLS-хендшейк к целевому хосту через прокси.

    Используется для проверки "alive" и как часть "siberian"-проверки.
    """
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return False
        with _wrap_tls(raw_sock, server_name, timeout):
            raw_sock = None
            return True
    except Exception:
        return False
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


# Уровни результата проверки tcp 16-20 (как в dpich).
TCP1620_NOT_DETECTED = "not_detected"  # DPI не обнаружен — данные проходят ✅
TCP1620_POSSIBLE = "possible"  # возможно обнаружен ⚠️
TCP1620_PROBABLY = "probably"  # вероятно обнаружен ⚠️
TCP1620_DETECTED = "detected"  # DPI обнаружен — передача блокируется ❗️
TCP1620_UNLIKELY = "unlikely"  # маловероятно ⚠️


def tcp1620_payload_ok(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    timeout: float = DEFAULT_TIMEOUT,
    payload_bytes: int = TCP1620_PAYLOAD_BYTES,
) -> str:
    """Проверка tcp 16-20 / l4-25 через прокси.

    Отправляет большой случайный payload через TLS-соединение и проверяет,
    что данные реально проходят (сервер не блокирует передачу). Возвращает
    уровень DPI-обнаружения (как в dpich):

    - ``not_detected`` — данные реально переданы, DPI не блокирует;
    - ``possible``/``probably`` — неопределённо (частичная передача);
    - ``detected`` — write заблокирован (timeout), DPI ограничивает передачу.

    Успехом (не_detected) считается факт передачи данных (write не
    заблокирован), даже если сервер закрыл соединение без HTTP-ответа.
    Многие сайты (например, за Cloudflare) закрывают соединение после
    получения мусорного POST-payload — это значит, что данные реально
    дошли до сервера, т.е. узел корректно обходит DPI.
    """
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return TCP1620_DETECTED
        with _wrap_tls(raw_sock, server_name, timeout) as tls_sock:
            raw_sock = None
            body = os.urandom(payload_bytes)
            request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: SubGenerator/1.0\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {payload_bytes}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            # Отправляем payload порциями, как в dpich (l4-25).
            chunk = 4096
            sent = 0
            for i in range(0, len(body), chunk):
                tls_sock.sendall(body[i : i + chunk])
                sent += min(chunk, len(body) - i)
            # Данные успешно переданы через прокси — write не заблокирован.
            # HTTP-ответ не обязателен: сервер может закрыть соединение после
            # получения мусорного payload (это нормальная реакция, данные
            # реально дошли). Возвращаем not_detected.
            return TCP1620_NOT_DETECTED

    except (socket.timeout, TimeoutError):
        # Write timeout — DPI ограничивает передачу данных.
        return TCP1620_DETECTED
    except Exception:
        return TCP1620_DETECTED
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()




def siberian_check_ok(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    timeout: float = DEFAULT_TIMEOUT,
    conn_count: int = SIBERIAN_CONN_COUNT,
) -> bool:
    """Проверка «siberian»-ограничений через прокси (эмуляция ТСПУ).

    Воспроизводит сигнатуру ТСПУ из статьи dpi-tls-june-2026 (Сигнал 3):
    «залп» из conn_count (>3) ПАРАЛЛЕЛЬНЫХ TLS-хендшейков к ОДНОМУ И ТОМУ ЖЕ
    SNI с интервалом <~350-400 мс. Если залп замораживается/сбрасывается, а
    одиночный контрольный хендшейк к другому случайному SNI проходит — это
    классический признак «siberian»-ограничения, а не общей недоступности.

    Раньше хендшейки шли ПОСЛЕДОВАТЕЛЬНО, что не давало ТСПУ увидеть
    характерный залп и превращало проверку в «проверку сети».

    Возвращает True, если ограничений не обнаружено.
    """
    import random
    import string

    def _random_sni() -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=12)) + ".com"

    def _handshake(sni: str) -> bool:
        return tls_handshake_ok(socks_host, socks_port, target_host, target_port, sni, timeout)

    # Залп: conn_count ПАРАЛЛЕЛЬНЫХ хендшейков к одному и тому же SNI.
    # Используем реальный server_name цели (не случайный) — это точнее всего
    # моделирует реальный браузер, открывающий несколько соединений к сайту.
    burst_sni = str(server_name or "").strip() or _random_sni()
    burst_results: list[bool] = []
    burst_started = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, conn_count)) as executor:
        futures = [executor.submit(_handshake, burst_sni) for _ in range(conn_count)]
        for future in futures:
            try:
                burst_results.append(bool(future.result(timeout=timeout + 2.0)))
            except FutureTimeout:
                burst_results.append(False)
    burst_elapsed = time.monotonic() - burst_started
    burst_ok = all(burst_results)

    # Контрольный одиночный хендшейк к другому случайному SNI.
    control_sni = _random_sni()
    if control_sni == burst_sni:
        control_sni += "x"
    control_ok = _handshake(control_sni)

    # Ограничение обнаружено, если залп заблокирован, а одиночное соединение
    # к другому SNI проходит (т.е. сеть в целом работает).
    if not burst_ok and control_ok:
        return False
    return True


def download_bytes(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = 256 * 1024,
    extra_headers: dict[str, str] | None = None,
) -> tuple[bool, int, float]:
    """Реально скачать данные через прокси.

    Возвращает (успех, получено_байт, скорость_кб_с). Используется для
    проверки реальной загрузки (например, контента YouTube).

    ``extra_headers`` — дополнительные HTTP-заголовки (например, Cookie для
    обхода consent-страницы Google).
    """
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return False, 0, 0.0
        with _wrap_tls(raw_sock, server_name, timeout) as tls_sock:
            raw_sock = None
            header_lines = [
                f"GET {path} HTTP/1.1\r\n",
                f"Host: {server_name}\r\n",
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n",
                f"Connection: close\r\n",
            ]
            for key, value in (extra_headers or {}).items():
                header_lines.append(f"{key}: {value}\r\n")
            header_lines.append("\r\n")
            request = "".join(header_lines).encode("ascii")
            tls_sock.sendall(request)

            buffer = b""
            body_bytes = 0
            started: float | None = None
            deadline = time.perf_counter() + timeout
            while body_bytes < max_bytes and time.perf_counter() < deadline:
                chunk = tls_sock.recv(min(65536, max_bytes - body_bytes + 4096))
                if not chunk:
                    break
                if started is None:
                    buffer += chunk
                    header_end = buffer.find(b"\r\n\r\n")
                    if header_end < 0:
                        continue
                    headers = buffer[:header_end]
                    if not headers.startswith(b"HTTP/"):
                        return False, 0, 0.0
                    status = headers.split(b" ", 2)[1:2]
                    if not status or not status[0].startswith(b"2"):
                        return False, 0, 0.0
                    body = buffer[header_end + 4 :]
                    body_bytes += len(body)
                    started = time.perf_counter()
                    buffer = b""
                else:
                    body_bytes += len(chunk)
            if started is None or body_bytes <= 0:
                return False, 0, 0.0
            elapsed = max(0.001, time.perf_counter() - started)
            return True, body_bytes, (body_bytes / 1024.0) / elapsed
    except Exception:
        return False, 0, 0.0
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def _http_read_headers(
    sock: socket.socket,
    timeout: float,
    max_header_bytes: int = 128 * 1024,
) -> tuple[bytes, bytes, int, bool, int]:
    """Прочитать HTTP-заголовки.

    Возвращает (raw_headers, body_buffer, status_code, is_chunked, content_length).
    content_length = -1 если не указан.
    """
    buf = b""
    deadline = time.perf_counter() + timeout
    while b"\r\n\r\n" not in buf and time.perf_counter() < deadline:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_header_bytes:
            break
    header_end = buf.find(b"\r\n\r\n")
    if header_end < 0:
        return buf, b"", 0, False, -1
    headers = buf[:header_end]
    try:
        status_code = int(headers.split(b" ", 2)[1])
    except Exception:
        return headers, b"", 0, False, -1
    if not headers.startswith(b"HTTP/"):
        return headers, b"", 0, False, -1
    text = headers.decode("latin1", errors="replace").lower()
    is_chunked = "transfer-encoding: chunked" in text
    content_length = -1
    for line in headers.decode("latin1", errors="replace").split("\r\n"):
        if line.lower().startswith("content-length:"):
            try:
                content_length = int(line.split(":", 1)[1].strip())
            except Exception:
                content_length = -1
            break
    return headers, buf[header_end + 4 :], status_code, is_chunked, content_length


def _http_read_chunked(
    sock: socket.socket,
    initial_body: bytes,
    max_bytes: int,
    timeout: float,
) -> bytes:
    """Декодировать chunked-ответ.

    ``initial_body`` — данные, уже прочитанные после заголовков (это начало
    первого чанка: строка размера + данные). Функция корректно декодирует
    чанки из этого буфера и дочитывает из сокета.
    """
    body = b""
    buf = initial_body
    deadline = time.perf_counter() + timeout

    while len(body) < max_bytes and time.perf_counter() < deadline:
        # Ищем строку размера чанка в буфере.
        while b"\r\n" not in buf:
            if time.perf_counter() > deadline:
                return body
            chunk = sock.recv(4096)
            if not chunk:
                return body
            buf += chunk
        size_line, buf = buf.split(b"\r\n", 1)
        size_str = size_line.split(b";")[0].strip()
        try:
            size = int(size_str, 16)
        except ValueError:
            return body
        if size <= 0:
            # Терминальный чанк (0).
            return body
        # Читаем size байт + завершающий \r\n.
        while len(buf) < size + 2:
            if time.perf_counter() > deadline:
                return body
            chunk = sock.recv(65536)
            if not chunk:
                return body
            buf += chunk
        body += buf[:size]
        buf = buf[size + 2 :]
        if len(body) >= max_bytes:
            break
    return body


def _http_read_fixed(
    sock: socket.socket,
    initial_body: bytes,
    content_length: int,

    max_bytes: int,
    timeout: float,
) -> bytes:
    """Прочитать ответ с известной Content-Length."""
    body = initial_body
    deadline = time.perf_counter() + timeout
    remaining = content_length - len(body)
    if remaining < 0:
        remaining = 0
    limit = max_bytes - len(body)
    if remaining > limit:
        remaining = limit
    while remaining > 0 and time.perf_counter() < deadline:
        chunk = sock.recv(min(65536, remaining))
        if not chunk:
            break
        body += chunk
        remaining -= len(chunk)
    return body


def http_get_body(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = 2 * 1024 * 1024,
    extra_headers: dict[str, str] | None = None,
) -> tuple[bool, bytes, int]:
    """GET через прокси, возвращает (успех, тело, http_status).

    Нужна для случаев, когда требуется получить тело ответа целиком
    (например, HTML-страница для парсинга ytInitialPlayerResponse), а не
    только факт загрузки и скорость. Поддерживает Content-Length и
    Transfer-Encoding: chunked.
    """
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return False, b"", 0
        with _wrap_tls(raw_sock, server_name, timeout) as tls_sock:
            raw_sock = None
            header_lines = [
                f"GET {path} HTTP/1.1\r\n",
                f"Host: {server_name}\r\n",
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n",
                f"Accept: */*\r\n",
                f"Connection: close\r\n",
            ]
            for key, value in (extra_headers or {}).items():
                header_lines.append(f"{key}: {value}\r\n")
            header_lines.append("\r\n")
            tls_sock.sendall("".join(header_lines).encode("ascii"))

            _headers, initial, status_code, is_chunked, content_length = _http_read_headers(
                tls_sock, timeout
            )
            if status_code == 0:
                return False, b"", 0
            if is_chunked:
                body = _http_read_chunked(tls_sock, initial, max_bytes, timeout)
            elif content_length >= 0:
                body = _http_read_fixed(tls_sock, initial, content_length, max_bytes, timeout)
            else:
                # Нет Content-Length и не chunked — читаем до конца соединения.
                body = initial
                deadline = time.perf_counter() + timeout
                while len(body) < max_bytes and time.perf_counter() < deadline:
                    chunk = tls_sock.recv(65536)
                    if not chunk:
                        break
                    body += chunk
            return True, body, status_code
    except Exception:
        return False, b"", 0
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def run_with_node(
    node_url: str,
    fn: Callable[[str, int], Any],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    root_dir: Path | None = None,
    budget: float | None = None,
    fp: str | None = None,
) -> Any:
    """Поднять временный core-процесс узла и выполнить fn(host, port).

    Возвращает результат fn или None при ошибке поднятия узла.

    ``budget`` — общий бюджет времени на всю проверку узла (поднятие
    процесса + fn). По умолчанию ``max(5.0, timeout * 3.0)``. Для
    длительных проверок (например, Zapret suite) передаётся большее
    значение.

    ``fp`` — принудительный TLS-фингерпринт uTLS для fingerprint-матрицы:
    "chrome"/"firefox"/"random" (настоящие пресеты), "none" = системный TLS
    без uTLS. None = использовать fp из ссылки узла.
    """
    node = parse_node_link(node_url)
    if node is None:
        return None
    root = root_dir or Path(__file__).resolve().parent.parent
    from xray_runtime import XrayRuntimeConfig

    config = XrayRuntimeConfig(
        subscription_urls=[],
        probe_workers=1,
        probe_timeout_sec=timeout,
        max_servers=0,
    )
    out_dir = root / "data" / ".runtime_cache"
    runtime = XrayCoreRuntime(
        config,
        root_dir=root,
        out_dir=out_dir,
        log_sink=lambda msg: None,
    )
    # Защищает от зависаний, если узел поднялся, но сетевые операции не
    # завершаются в рамках отдельных таймаутов.
    budget = budget or max(5.0, timeout * 3.0)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(runtime.with_node_process, node, fn, fp=fp)
            try:
                return future.result(timeout=budget)
            except FutureTimeout:
                return None
    except Exception:
        return None
    finally:
        with contextlib.suppress(Exception):
            runtime.stop()

