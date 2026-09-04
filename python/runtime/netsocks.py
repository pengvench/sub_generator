"""SOCKS5-клиент и HTTP(S) поверх SOCKS: CONNECT, TLS, HEAD/GET/POST,
замеры скорости загрузки/выгрузки через произвольный SOCKS-порт."""
from __future__ import annotations


import contextlib
import socket
import ssl
import time


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


def _socks_open_connection(socks_host: str, socks_port: int, target_host: str, target_port: int, timeout: float) -> socket.socket | None:
    """Открыть соединение через SOCKS5 к target_host:target_port.

    ATYP выбирается автоматически:
      * IPv4-строка (1.1.1.1) → ATYP=1 (4 байта). Ядро подключается к IP напрямую,
        БЕЗ DNS-резолвинга. На заблокированных сетях DNS через DoH таймаутится,
        но с IP это не проблема.
      * Домен (www.google.com) → ATYP=3 (домен-строка, ядро само резолвит).
    """
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
        sock.settimeout(timeout)
        # Greeting: VER=5, NMETHODS=1, METHOD=0x00 (no auth).
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            sock.close()
            return None
        # CONNECT request. ATYP=1 для IP-адреса (4 сырых байта),
        # ATYP=3 для домена (длина+строка).
        try:
            # socket.inet_aton бросает OSError для невалидных IPv4 —
            # значит это домен, используем ATYP=3.
            ip_bytes = socket.inet_aton(target_host)
            request = b"\x05\x01\x00\x01" + ip_bytes + int(target_port).to_bytes(2, "big")
        except OSError:
            # Домен: ATYP=3 + длина-байт + домен в ASCII (idna не нужен,
            # SOCKS5 RFC 1928 требует ASCII/UTF-8 байты, не punycode).
            host_bytes = target_host.encode("utf-8")
            if len(host_bytes) > 255:
                sock.close()
                return None
            request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + int(target_port).to_bytes(2, "big")
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


def _socks_https_head_status(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    timeout: float,
    path: str = "/",
) -> tuple[int, float] | None:
    """HEAD-запрос через SOCKS+SSL. Возвращает (http_status, latency_ms) или None.

    Ожидаем HTTP/2 200 или 302 (стандартный ответ api.telegram.org на HEAD /).
    """
    started = time.perf_counter()
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"HEAD {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            response = b""
            while b"\r\n" not in response:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            if not response.startswith(b"HTTP/"):
                return None
            line = response.split(b"\r\n", 1)[0]
            parts = line.split(b" ", 2)
            try:
                status = int(parts[1])
            except (IndexError, ValueError):
                return None
            return status, (time.perf_counter() - started) * 1000.0
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def _socks_https_get_body(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    timeout: float,
    max_bytes: int = 512 * 1024,
    extra_headers: dict[str, str] | None = None,
) -> tuple[bool, bytes, int]:
    """GET через SOCKS+SSL с телом ответа. Возвращает (ok, body, status).

    Нужен для Telegram-медиа фильтра: скачать HTML страницы t.me/s/<канал>
    (домен передаётся в SOCKS ATYP=0x03 — резолвит выход узла, hosts не
    участвует) и вытащить ссылки на видео.
    """
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return False, b"", 0
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            header_lines = [
                f"GET {path} HTTP/1.1\r\n",
                f"Host: {server_name}\r\n",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n",
                "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n",
                "Accept-Language: ru-RU,ru;q=0.9,en;q=0.6\r\n",
                "Connection: close\r\n",
            ]
            for key, value in (extra_headers or {}).items():
                header_lines.append(f"{key}: {value}\r\n")
            header_lines.append("\r\n")
            tls_sock.sendall("".join(header_lines).encode("ascii"))

            # Заголовки.
            buf = b""
            deadline = time.perf_counter() + timeout
            while b"\r\n\r\n" not in buf and time.perf_counter() < deadline:
                piece = tls_sock.recv(4096)
                if not piece:
                    break
                buf += piece
                if len(buf) > 128 * 1024:
                    break
            header_end = buf.find(b"\r\n\r\n")
            if header_end < 0 or not buf.startswith(b"HTTP/"):
                return False, b"", 0
            try:
                status = int(buf.split(b" ", 2)[1])
            except (IndexError, ValueError):
                return False, b"", 0
            headers_text = buf[:header_end].decode("latin-1", errors="replace").lower()
            is_chunked = "transfer-encoding: chunked" in headers_text

            initial = buf[header_end + 4 :]
            if is_chunked:
                # t.me отдаёт страницу с фиксированным Content-Length, но на
                # всякий случай поддерживаем chunked (best-effort).
                body = b""
                rest = initial
                while len(body) < max_bytes and time.perf_counter() < deadline:
                    while b"\r\n" not in rest:
                        piece = tls_sock.recv(8192)
                        if not piece:
                            return True, body[:max_bytes], status
                        rest += piece
                    size_line, rest = rest.split(b"\r\n", 1)
                    try:
                        size = int(size_line.split(b";")[0].strip(), 16)
                    except ValueError:
                        return True, body[:max_bytes], status
                    if size <= 0:
                        return True, body[:max_bytes], status
                    while len(rest) < size + 2:
                        piece = tls_sock.recv(min(65536, size + 2 - len(rest)))
                        if not piece:
                            return True, body[:max_bytes], status
                        rest += piece
                    body += rest[:size]
                    rest = rest[size + 2 :]
                return True, body[:max_bytes], status
            # Content-Length или connection-close.
            body = initial
            while len(body) < max_bytes and time.perf_counter() < deadline:
                piece = tls_sock.recv(min(65536, max_bytes - len(body)))
                if not piece:
                    break
                body += piece
            return True, body[:max_bytes], status
    except Exception:
        return False, b"", 0
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()

def _socks_https_latency(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    timeout: float,
    path: str = "/",
) -> float | None:
    started = time.perf_counter()
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            response = tls_sock.recv(32)
            if not response.startswith(b"HTTP/"):
                return None
            return (time.perf_counter() - started) * 1000.0
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()
def _socks_https_upload_kbps(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    max_bytes: int,
    timeout: float,
    *,
    sample_seconds: float,
) -> float | None:
    """POST-загрузка через SOCKS+SSL. Шлём max_bytes байт, меряем скорость.

    Cloudflare /__up принимает произвольное тело и отвечает 200. Возвращает КБ/с.
    """
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {max_bytes}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            started = time.perf_counter()
            chunk = b"\x00" * 65536
            sent = 0
            sample_deadline = started + max(0.5, float(sample_seconds))
            while sent < max_bytes and time.perf_counter() < sample_deadline:
                tls_sock.sendall(chunk)
                sent += len(chunk)
            elapsed = max(0.001, time.perf_counter() - started)
            # Ждём ответ (не обязательно), сбрасываем в 0.
            with contextlib.suppress(Exception):
                tls_sock.settimeout(1.0)
                tls_sock.recv(4096)
            return (sent / 1024.0) / elapsed
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()
def _socks_https_download_kbps(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    max_bytes: int,
    timeout: float,
    *,
    sample_seconds: float,
) -> float | None:
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            buffer = b""
            body_bytes = 0
            started: float | None = None
            deadline = time.perf_counter() + timeout
            sample_deadline: float | None = None
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
                        return None
                    status = headers.split(b" ", 2)[1:2]
                    if not status or not status[0].startswith(b"2"):
                        return None
                    body = buffer[header_end + 4 :]
                    body_bytes += len(body)
                    started = time.perf_counter()
                    sample_deadline = started + max(0.5, float(sample_seconds))
                    buffer = b""
                else:
                    body_bytes += len(chunk)
                if sample_deadline is not None and time.perf_counter() >= sample_deadline:
                    break
            if started is None or body_bytes <= 0:
                return None
            elapsed = max(0.001, time.perf_counter() - started)
            return (body_bytes / 1024.0) / elapsed
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()
