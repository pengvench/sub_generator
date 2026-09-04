"""Обход системного hosts-файла: DoH-резолв на IP-literal + прямой HTTPS.

Зачем
-----
В hosts-файле пользователя могут лежать подмены от «разблокирующих»
утилит (записи вида ``185.199.108.153 raw.githubusercontent.com`` или
``127.0.0.1 chatgpt.com``). Все ЛОКАЛЬНЫЕ инфраструктурные запросы
SubGenerator — DoH-preflight конвейера, загрузка suite.v2.json,
geoip-запросы к api.ip.sb, сетевая диагностика — обязаны видеть реальную
картину сети, а не подменённый hosts. Проверки ЧЕРЕЗ УЗЕЛ этому не
подвержены (домен цели резолвит выход узла), а вот локальные — да.

Как
---
1. **DoH-резолв на IP-literal**: DNS-запрос имени хоста уходит на
   ``https://1.1.1.1/dns-query`` (TLS с SNI ``cloudflare-dns.com``) или
   ``https://8.8.8.8/resolve`` (SNI ``dns.google``). Соединение
   открывается на literal IP, поэтому hosts-файл не участвует ни на одном
   шаге: ни для DNS-сервера, ни для резолва имени.
2. **direct_https_get**: соединение к резолвенному IP с SNI = имя хоста и
   заголовком ``Host:`` = имя хоста. TLS и HTTP семантически корректны,
   системный hosts не читается. Тело читается по ``Content-Length`` либо
   декодируется из ``chunked``.
3. **Кеш резолва 300 сек** (потокобезопасный): повторные запросы к тому же
   хосту не поднимают DoH заново.
4. **Graceful-деградация**: если DoH недоступен (жёстко заблокированная
   сеть), запрос выполняется обычным ``urllib.request.urlopen`` с флагом
   ``hosts_dependent=True`` — результат может зависеть от hosts, и
   вызывающий код это видит.

ВАЖНО (фикс по ходу Task 16): переданные ``headers`` ПОЛНОСТЬЮ ЗАМЕНЯЮТ
дефолтные, а не дополняют их. Дубль ``Accept: */*`` +
``Accept: application/dns-json`` cloudflare-dns.com отдавал 400 —
сервер считает два разных значения одного заголовка ошибкой запроса.
"""
from __future__ import annotations

import contextlib
import json
import logging
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# DoH-провайдеры, доступные по IP-literal: (ip, sni, path, описание).
# Соединение идёт на literal IP с указанным SNI — hosts не участвует.
DOH_PROVIDERS: tuple[tuple[str, str, str, str], ...] = (
    ("1.1.1.1", "cloudflare-dns.com", "/dns-query", "Cloudflare"),
    ("8.8.8.8", "dns.google", "/resolve", "Google"),
)

# Кеш резолва: host -> (ip, resolved_at). TTL 300 сек.
RESOLVE_CACHE_TTL = 300.0
_resolve_cache: dict[str, tuple[str, float]] = {}
_resolve_lock = threading.Lock()

# Дефолтные заголовки (используются ТОЛЬКО когда caller не передал свои).
_DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": "SubGenerator/1.0",
    "Accept": "*/*",
}

# Таймауты по умолчанию.
DOH_RESOLVE_TIMEOUT = 4.0
HTTPS_GET_TIMEOUT = 8.0


@dataclass
class HostsFreeResponse:
    """Ответ direct_https_get: IP-literal + SNI, мимо системного hosts."""

    ok: bool = False  # запрос выполнен (статус может быть любым)
    status: int = 0  # HTTP-статус (0 = соединение не установлено)
    body: bytes = b""
    url: str = ""
    ip: str = ""  # IP, к которому реально открыли соединение
    error: str = ""
    hosts_dependent: bool = False  # True = сработал urlopen-fallback
    elapsed_sec: float = 0.0
    headers: dict = field(default_factory=dict)

    def json(self):
        """Тело как JSON (или None при ошибке декодирования)."""
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            return None


# --------------------------------------------------------------------- resolve
def _doh_query(host: str, timeout: float) -> str | None:
    """Резолв имени через DoH-провайдеры на IP-literal (hosts не участвует).

    Перебирает DOH_PROVIDERS по порядку; возвращает первый A-ответ.
    """
    for ip, sni, path, label in DOH_PROVIDERS:
        try:
            response = _https_ip_get(
                ip,
                443,
                sni,
                host_header=sni,
                path=f"{path}?name={urllib.parse.quote(host)}&type=A",
                headers={"Accept": "application/dns-json"},
                timeout=timeout,
                max_bytes=16 * 1024,
            )
            if not response.ok or response.status != 200 or not response.body:
                continue
            payload = response.json()
            answers = (payload or {}).get("Answer") or []
            for answer in answers:
                try:
                    answer_type = int(answer.get("type", 0))
                except (TypeError, ValueError):
                    continue
                if answer_type == 1:
                    addr = str(answer.get("data", "")).strip()
                    if addr:
                        return addr
        except Exception as exc:
            logger.debug("hostres: DoH %s (%s) failed: %s", label, ip, exc)
    return None


def _is_ip_literal(host: str) -> bool:
    """Является ли хост literal IP-адресом (v4/v6)."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except (OSError, ValueError):
            continue
    return False


def resolve_ip(host: str, timeout: float = DOH_RESOLVE_TIMEOUT) -> str | None:
    """IP хоста мимо системного hosts (DoH на IP-literal + кеш 300 сек).

    Для literal IP возвращается как есть. Если DoH недоступен — None
    (вызывающий код решает, деградировать ли до urlopen).
    """
    host = (host or "").strip()
    if not host:
        return None
    if _is_ip_literal(host):
        return host

    now = time.monotonic()
    with _resolve_lock:
        cached = _resolve_cache.get(host)
        if cached and (now - cached[1]) < RESOLVE_CACHE_TTL:
            return cached[0]

    ip = _doh_query(host, timeout)
    if ip:
        with _resolve_lock:
            _resolve_cache[host] = (ip, time.monotonic())
    return ip


def clear_resolve_cache() -> None:
    """Сбросить кеш резолва (для тестов)."""
    with _resolve_lock:
        _resolve_cache.clear()


# --------------------------------------------------------------------- https
def _read_exact(sock: socket.socket, count: int) -> bytes:
    """Прочитать ровно count байт из сокета."""
    chunks = []
    remaining = max(0, count)
    while remaining > 0:
        chunk = sock.recv(min(remaining, 65536))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _parse_chunked(raw: bytes, max_bytes: int) -> bytes:
    """Декодировать chunked-тело из сырого буфера (до терминального 0-чанка)."""
    body = bytearray()
    pos = 0
    while len(body) < max_bytes and pos < len(raw):
        line_end = raw.find(b"\r\n", pos)
        if line_end < 0:
            break  # неполный фрейм — обрываемся по max_bytes/закрытию
        try:
            size = int(raw[pos:line_end].split(b";")[0].strip(), 16)
        except ValueError:
            break
        pos = line_end + 2
        if size == 0:
            break
        frame = raw[pos : pos + size]
        pos += size + 2  # данные + CRLF
        body += frame[: max(0, max_bytes - len(body))]
    return bytes(body)


def _https_ip_get(
    ip: str,
    port: int,
    sni: str,
    host_header: str,
    path: str,
    headers: dict[str, str],
    timeout: float,
    max_bytes: int,
) -> HostsFreeResponse:
    """HTTPS GET на literal IP с указанным SNI и заголовком Host.

    TLS-сертификат проверяется по SNI (обычная CA-верификация), соединение
    открывается на IP — системный hosts не читается.
    """
    started = time.perf_counter()
    result = HostsFreeResponse(url=f"https://{host_header}{path}", ip=ip)
    raw: socket.socket | None = None
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=sni) as tls:
            raw = None
            header_lines = [f"GET {path} HTTP/1.1", f"Host: {host_header}"]
            for name, value in headers.items():
                header_lines.append(f"{name}: {value}")
            header_lines.append("Connection: close")
            request = ("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii", errors="replace")
            tls.sendall(request)

            # Статус-строка + заголовки (читаем до \r\n\r\n).
            head = b""
            while b"\r\n\r\n" not in head:
                part = tls.recv(1)
                if not part:
                    raise OSError("connection closed before headers")
                head += part
                if len(head) > 64 * 1024:
                    raise OSError("response headers too large")
            head_part, _, body_prefix = head.partition(b"\r\n\r\n")
            lines = head_part.decode("iso-8859-1", errors="replace").split("\r\n")
            try:
                status = int(lines[0].split(" ")[1])
            except (IndexError, ValueError) as exc:
                raise OSError(f"bad status line: {lines[0]!r}") from exc

            response_headers: dict[str, str] = {}
            content_length: int | None = None
            chunked = False
            for line in lines[1:]:
                if ":" not in line:
                    continue
                name, _, value = line.partition(":")
                name = name.strip().lower()
                response_headers[name] = value.strip()
                if name == "content-length":
                    with contextlib.suppress(ValueError):
                        content_length = int(value.strip())
                elif name == "transfer-encoding" and "chunked" in value.lower():
                    chunked = True

            # Тело: дочитываем из сокета поверх уже прочитанного префикса.
            budget = max_bytes + (2 * 1024)  # запас на chunked-фреймы
            if content_length is not None:
                need = min(content_length, budget)
                raw_body = body_prefix[:budget]
                remaining = need - len(raw_body)
                if remaining > 0:
                    raw_body += _read_exact(tls, remaining)
            else:
                # chunked или «до закрытия»: копим сырые байты, chunked
                # распарсим из буфера целиком (Connection: close).
                raw_body = bytearray(body_prefix[:budget])
                while len(raw_body) < budget:
                    part = tls.recv(min(65536, budget - len(raw_body)))
                    if not part:
                        break
                    raw_body += part
                raw_body = bytes(raw_body)
            body = _parse_chunked(raw_body, max_bytes) if chunked else raw_body[:max_bytes]

            result.ok = True
            result.status = status
            result.body = body
            result.headers = response_headers
            result.elapsed_sec = time.perf_counter() - started
            return result
    except (socket.timeout, TimeoutError) as exc:
        result.error = f"timeout: {exc}"
        result.elapsed_sec = time.perf_counter() - started
        return result
    except OSError as exc:
        result.error = str(exc)
        result.elapsed_sec = time.perf_counter() - started
        return result
    finally:
        if raw is not None:
            with contextlib.suppress(OSError):
                raw.close()


# --------------------------------------------------------------------- public
def direct_https_get(
    url: str,
    timeout: float = HTTPS_GET_TIMEOUT,
    max_bytes: int = 256 * 1024,
    headers: dict[str, str] | None = None,
    method: str = "GET",
) -> HostsFreeResponse:
    """HTTPS GET к url мимо системного hosts-файла.

    Порядок:
    1. Парсим url; хост резолвим через DoH на IP-literal (кеш 300 сек).
    2. Открываем соединение на IP с SNI=хост и Host=хост.
    3. Если DoH недоступен — graceful-деградация на urlopen с флагом
       ``hosts_dependent=True`` (результат может зависеть от hosts).

    ``headers`` (если переданы) ПОЛНОСТЬЮ ЗАМЕНЯЮТ дефолтные заголовки —
    дополнение давало дубль Accept и 400 от cloudflare-dns.com.
    """
    started = time.perf_counter()
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        return HostsFreeResponse(ok=False, url=url, error=f"bad url: {exc}")

    scheme = (parts.scheme or "https").lower()
    host = (parts.hostname or "").strip()
    if not host:
        return HostsFreeResponse(ok=False, url=url, error="no host in url")
    port = parts.port or (443 if scheme == "https" else 80)
    if scheme != "https":
        return HostsFreeResponse(ok=False, url=url, error=f"unsupported scheme: {scheme}")

    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"

    # Заголовки: переданные ЗАМЕНЯЮТ дефолтные (фикс дубля Accept).
    request_headers = dict(headers) if headers else dict(_DEFAULT_HEADERS)

    ip = resolve_ip(host)
    if ip:
        try:
            return _https_ip_get(ip, port, host, host, path, request_headers, timeout, max_bytes)
        except Exception as exc:
            logger.debug("hostres: direct get %s via %s failed: %s", host, ip, exc)

    # Деградация: DoH недоступен или прямой путь упал — обычный urlopen.
    # Системный resolver (и hosts) здесь участвует — помечаем ответ.
    try:
        req = urllib.request.Request(url, headers=request_headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(max_bytes)
            return HostsFreeResponse(
                ok=True,
                status=int(getattr(resp, "status", 200) or 200),
                body=body,
                url=url,
                hosts_dependent=True,
                elapsed_sec=time.perf_counter() - started,
            )
    except urllib.error.HTTPError as exc:
        return HostsFreeResponse(
            ok=True,
            status=int(exc.code or 0),
            body=b"",
            url=url,
            error=f"HTTP {exc.code}",
            hosts_dependent=True,
            elapsed_sec=time.perf_counter() - started,
        )
    except Exception as exc:
        return HostsFreeResponse(
            ok=False,
            url=url,
            error=f"{type(exc).__name__}: {exc}",
            hosts_dependent=True,
            elapsed_sec=time.perf_counter() - started,
        )


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "https://cloudflare-dns.com/dns-query?name=google.com&type=A"
    )
    res = direct_https_get(
        target,
        timeout=6.0,
        max_bytes=8 * 1024,
        headers={"Accept": "application/dns-json"},
    )
    print(
        f"hostres: ok={res.ok} status={res.status} ip={res.ip or '-'} "
        f"hosts_dependent={res.hosts_dependent} err={res.error or '-'}"
    )
    print(f"body[:200]: {res.body[:200]!r}")
