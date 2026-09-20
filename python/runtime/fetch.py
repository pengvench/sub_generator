"""Загрузка тел подписок: локальные файлы, HTTP(S) с зеркалами, retry-таймауты,
SSL-контексты, gzip/декодирование тела, разворачивание прокси-обёрток
(p.kfwl.lol/https://real-host/sub -> запасной кандидат на прямую загрузку).

Транспортная цепочка на каждый URL-кандидат: Python urllib → системный
curl.exe (SChannel TLS + HTTP/2, непохожий на Python TLS-отпечаток) →
PowerShell Invoke-WebRequest (SChannel + системный прокси). DPI и защита
хостов (Akamai/Cloudflare) рвут соединения Python-стека (RemoteDisconnected),
пропуская браузеры и Go-клиенты (Karing/v2rayN на uTLS) — поэтому после
исчерпания urllib загрузка повторяется стеками, не похожими на Python."""
from __future__ import annotations


import contextlib
import gzip
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse, urlunsplit
from urllib.request import Request, urlopen

from .procs import _subprocess_no_window
from .types import SUBSCRIPTION_USER_AGENT

# Встроенный абсолютный URL внутри строки-обёртки (https://proxy/https://inner).
_EMBEDDED_URL_RE = re.compile(r"https?://", re.IGNORECASE)


def _fetch_text(
    url: str,
    *,
    timeout: float,
    log_sink: Callable[[str], None] | None = None,
) -> str:
    clean_url = str(url or "").strip()

    # Happ (Hiddify) зашифрованные подписки happ://cryptN/... — расшифровываем
    # (crypt..crypt4: RSA-блочно; crypt5: RSA-4096 + ChaCha20-Poly1305, ключи
    # вшиты в модуль) в обычный https:// URL и идём дальше по стандартному пути.
    # Причина неудачи расшифровки попадает в сообщение (видна в логе/отчёте).
    if clean_url.lower().startswith("happ://"):
        from .happ_decrypt import decrypt_happ_link
        happ_errors: list[str] = []
        plain_url = decrypt_happ_link(clean_url, errors=happ_errors)
        if not plain_url:
            detail = happ_errors[0] if happ_errors else "unsupported happ link"
            raise RuntimeError(
                "happ subscription decrypt failed: "
                f"{detail}"
            )
        if log_sink is not None:
            log_sink(f"[xray] happ subscription decrypted: {plain_url[:80]}")
        clean_url = plain_url

    # Локальный файл (кастомный кеш конфигов, выбранный пользователем):
    # читаем как есть, а декодирование base64 / извлечение только ссылок
    # выполняет _subscription_lines ниже по конвейеру.
    if clean_url.startswith("file://"):
        local_path = Path(clean_url[len("file://"):])
    else:
        local_path = Path(clean_url)
    if clean_url and local_path.exists() and local_path.is_file():
        try:
            data = local_path.read_bytes()
            if log_sink is not None:
                log_sink(f"[xray] reading local config file: {local_path}")
            return _decode_subscription_body(data)
        except OSError as exc:
            if log_sink is not None:
                log_sink(f"[xray] cannot read local config file {local_path}: {exc}")
            raise RuntimeError("local config file read failed") from exc

    errors: list[str] = []
    candidate_urls = _subscription_candidate_urls(clean_url)
    for index, candidate_url in enumerate(candidate_urls):
        if index and log_sink is not None:
            # Видно в логе, какой запасной кандидат (CDN-зеркало или
            # развёрнутая прокси-обёртка) подхватил загрузку.
            log_sink(f"[xray] source fetch fallback: {candidate_url}")
        body = _fetch_candidate_body(
            candidate_url,
            _subscription_headers(candidate_url),
            timeout,
            errors,
            log_sink=log_sink,
        )
        if body is not None:
            return body
    if log_sink is not None and errors:
        log_sink(f"[xray] source fetch attempts failed {clean_url}: {' | '.join(errors[:5])}")
    detail = "; ".join(errors[:5]) if errors else "no candidates"
    # Причины (host:RemoteDisconnected, host:HTTP_404, ...) — в самом сообщении:
    # вызывающий код пишет их в лог/отчёт вместо безликого "fetch failed".
    raise RuntimeError(f"subscription fetch failed: {detail}")


def _fetch_candidate_body(
    url: str,
    headers: dict[str, str],
    timeout: float,
    errors: list[str],
    log_sink: Callable[[str], None] | None = None,
) -> str | None:
    """Все попытки загрузки одного кандидата.

    Цепочка транспортов: (1) urllib-лестница растущих таймаутов, где
    незаверенный SSL-контекст подключается только при TLS-ошибке; (2) системный
    curl.exe — другой TLS-отпечаток и HTTP/2; (3) PowerShell — системный
    прокси и SChannel. Возвращает тело подписки или None, когда кандидат
    исчерпан всеми транспортами.
    """
    for current_timeout in _subscription_timeouts(timeout):
        for context in _subscription_ssl_contexts():
            try:
                req = Request(url, headers=headers)
                with urlopen(req, timeout=current_timeout, context=context) as resp:
                    encoding = str(resp.headers.get("Content-Encoding", "") or "")
                    return _decode_subscription_body(resp.read(), encoding=encoding)
            except HTTPError as exc:
                _record_fetch_error(errors, url, f"HTTP_{exc.code}")
                if exc.code < 500:
                    # 4xx — окончательный отказ (нет прав / не существует):
                    # перебор таймаутов и SSL-контекстов исход не изменит,
                    # сразу переходим к следующему кандидату.
                    return None
                # 5xx — сервер или апстрим прокси-обёртки может быть перегружен:
                # TLS уже успешен (незаверенный контекст ничего не добавит), но
                # следующие таймауты лестницы дают серверу ещё один шанс.
                break
            except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
                _record_fetch_error(errors, url, type(exc).__name__)
                if not _error_is_tls(exc):
                    # Обрыв соединения / TCP / DNS — результат не зависит от
                    # проверки сертификата, второй контекст не пробуем.
                    break
            except Exception as exc:
                _record_fetch_error(errors, url, type(exc).__name__)
    # 2) Системный curl: TLS-отпечаток SChannel + HTTP/2 — не похож на Python
    # (как браузер или Karing на Go/uTLS). Обходит DPI-блокировки, которыми
    # отсекается urllib (RemoteDisconnected при живом хосте).
    body = _fetch_body_via_system_curl(url, timeout, errors, log_sink)
    if body is not None:
        return body
    # 3) PowerShell IWR: SChannel + системный прокси (вкл. автоконфигурацию) —
    # стек, ближайший к браузеру. Последний резерв на Windows.
    body = _fetch_body_via_powershell(url, timeout, errors, log_sink)
    if body is not None:
        return body
    return None


def _record_fetch_error(errors: list[str], url: str, label: str) -> None:
    marker = f"{urlparse(url).netloc or '?'}:{label}"
    if marker not in errors:
        errors.append(marker)


def _error_is_tls(exc: BaseException) -> bool:
    """Ошибка уровня TLS (рукопожатие/сертификат) — кандидат на повтор
    с незаверенным контекстом. urllib оборачивает TLS-сбои в URLError(reason=...),
    поэтому смотрим и цепочку reason."""
    if isinstance(exc, ssl.SSLError):
        return True
    reason = getattr(exc, "reason", None)
    if isinstance(reason, BaseException):
        return _error_is_tls(reason)
    return False


def _subscription_headers(url: str) -> dict[str, str]:
    # ВАЖНО: не задаём Host вручную. urllib сам выставляет корректный Host для
    # каждого запроса, включая редиректы (github.com -> raw.githubusercontent.com).
    # Ручной Host не обновляется при 302 и ломает редирект: GitHub отвечает 500.
    return {
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
        "Connection": "close",
        "User-Agent": SUBSCRIPTION_USER_AGENT,
        "X-Device-Locale": "en",
        "X-Device-OS": "Windows",
    }


def _subscription_timeouts(timeout: float) -> list[float]:
    # Прокси-обёртки (p.kfwl.lol и т.п.) по HTTP/1.1 отдают первый байт подолгу
    # (сами синхронно ходят за внутренним URL — до ~15с), поэтому лестница
    # начинается с 10с и растёт до 45с; раньше 8с убивали даже живые обёртки.
    base = max(3.0, float(timeout or 8.0))
    values = [max(base, 10.0), max(base, 20.0), max(base, 45.0)]
    out: list[float] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def _subscription_ssl_contexts() -> list[ssl.SSLContext | None]:
    contexts: list[ssl.SSLContext | None] = [None]
    with contextlib.suppress(Exception):
        contexts.append(ssl._create_unverified_context())
    return contexts


def _subscription_candidate_urls(url: str) -> list[str]:
    target = str(url or "").strip()
    if not target:
        return []
    urls = [target]
    with contextlib.suppress(Exception):
        parsed = urlparse(target)
        host = str(parsed.netloc or "").strip().lower()
        parts = [part for part in str(parsed.path or "").split("/") if part]
        if host == "raw.githubusercontent.com" and len(parts) >= 5 and parts[2] == "refs" and parts[3] == "heads":
            owner = parts[0]
            repo = parts[1]
            branch = parts[4]
            tail = parts[5:]
            canonical_path = "/" + "/".join([owner, repo, branch] + tail)
            canonical = urlunsplit((parsed.scheme or "https", parsed.netloc, canonical_path, parsed.query or "", ""))
            if canonical not in urls:
                urls.append(canonical)
            jsd_path = "/gh/" + "/".join([owner, repo + "@" + branch] + tail)
            for cdn_host in ("cdn.jsdelivr.net", "gcore.jsdelivr.net", "fastly.jsdelivr.net"):
                cdn_url = urlunsplit(("https", cdn_host, jsd_path, parsed.query or "", ""))
                if cdn_url not in urls:
                    urls.append(cdn_url)
    # Прокси-обёртки разворачиваем ПОСЛЕДНИМИ: пользователь явно указал обёртку,
    # внутренний адрес — запасной вариант на случай, когда обёртка недоступна.
    _append_unwrapped_proxy_urls(urls, target)
    return urls


def _append_unwrapped_proxy_urls(urls: list[str], target: str) -> None:
    """Разворот прокси-обёрток вида https://p.kfwl.lol/https://real/sub.

    Обёртка-просмотрщик и внутренний адрес живут на разных IP: в сетях, где
    обёртка блокируется на транспортном уровне (RemoteDisconnected/URLError),
    внутренний адрес часто доступен напрямую — и наоборот. Каждый развёрнутый
    URL становится запасным кандидатом загрузки. Вложенные обёртки обрабатываются
    рекурсивно, URL-кодированные (https%3A%2F%2F...) — после декодирования пути.
    """
    visited: set[str] = set()

    def unwrap(current: str) -> None:
        current = str(current or "").strip()
        if not current or current in visited:
            return
        visited.add(current)
        inner = _embedded_url_in(current)
        if inner:
            if inner not in urls:
                urls.append(inner)
            unwrap(inner)
            return
        # URL-кодированная обёртка: декодируем путь и ищем вложенный URL заново.
        with contextlib.suppress(Exception):
            parsed = urlparse(current)
            decoded_path = unquote(parsed.path)
            if decoded_path != parsed.path:
                decoded = urlunsplit(
                    (parsed.scheme, parsed.netloc, decoded_path, parsed.query or "", parsed.fragment or "")
                )
                unwrap(decoded)

    unwrap(target)


def _embedded_url_in(url: str) -> str:
    """Второй (встроенный) абсолютный URL внутри строки обёртки, если он есть."""
    positions = [match.start() for match in _EMBEDDED_URL_RE.finditer(url)]
    if len(positions) < 2:
        return ""
    inner = url[positions[1]:].strip()
    if not inner or inner == url:
        return ""
    with contextlib.suppress(Exception):
        netloc = urlparse(inner).netloc
        if netloc and "." in netloc:
            return inner
    return ""


def _decode_subscription_body(raw: bytes, *, encoding: str = "") -> str:
    data = bytes(raw or b"")
    if data[:2] == b"\x1f\x8b" or "gzip" in str(encoding or "").lower():
        with contextlib.suppress(Exception):
            data = gzip.decompress(data)
    return data.decode("utf-8", errors="replace")


# ------------------------------------------------------------------ транспорты
# Кеш discovered-состояния системного curl: путь + поддержка HTTP/2.
_CURL_CACHE: dict[str, object] = {}

# Коды завершения curl, означающие TLS/сертификатные сбои → повтор с -k.
_CURL_SSL_EXIT_CODES = frozenset({35, 53, 54, 60, 66, 77, 90, 91})

# Человекочитаемые метки для типовых кодов завершения curl.
_CURL_EXIT_LABELS = {
    6: "curl_DNS",
    7: "curl_Connect",
    22: "curl_HTTP",
    26: "curl_Read",
    28: "curl_Timeout",
    47: "curl_Redirects",
    56: "curl_Recv",
}


def _system_curl_info() -> tuple[str, bool]:
    """Путь к системному curl и поддержка HTTP/2 (кешируется).

    Windows 10 1803+ поставляет C:\\Windows\\System32\\curl.exe (SChannel TLS,
    HTTP/2). Это сетевой стек, не похожий на Python — обход TLS-отпечатковых
    блокировок, которыми urllib (HTTP/1.1) отсекается. В PATH может лежать и
    curl из git-for-windows — тоже подходит (тоже не Python).
    """
    if "info" in _CURL_CACHE:
        return _CURL_CACHE["info"]  # type: ignore[return-value]
    path = ""
    for candidate in (r"C:\Windows\System32\curl.exe", r"C:\Windows\SysWOW64\curl.exe"):
        if candidate and os.path.isfile(candidate):
            path = candidate
            break
    if not path:
        found = shutil.which("curl")
        if found and Path(found).name.lower().startswith("curl"):
            path = found
    http2 = False
    if path:
        try:
            proc = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=10.0,
                creationflags=_subprocess_no_window(),
            )
            http2 = proc.returncode == 0 and "HTTP2" in f"{proc.stdout or ''}{proc.stderr or ''}"
        except (OSError, subprocess.SubprocessError):
            path = ""
    info = (path, http2)
    _CURL_CACHE["info"] = info
    return info


def _fetch_body_via_system_curl(
    url: str,
    timeout: float,
    errors: list[str],
    log_sink: Callable[[str], None] | None,
) -> str | None:
    """Загрузка тела системным curl (SChannel TLS, HTTP/2).

    Транспорт для сетей, где DPI/защита хоста рвёт соединения Python-стека:
    curl не похож на Python ни по TLS-отпечатку, ни по HTTP-версии. При
    TLS-сбоях — повтор с -k (без проверки сертификата); при отсутствии
    поддержки --http2 — повтор без него. Возвращает декодированное тело
    или None (причины — в errors).
    """
    path, http2 = _system_curl_info()
    if not path:
        return None
    max_time = _subscription_timeouts(timeout)[-1]
    connect_timeout = min(10.0, max_time)
    fd, tmp_path = tempfile.mkstemp(prefix="subgen_curl_", suffix=".body")
    os.close(fd)

    def run_curl(extra_args: list[str], use_http2: bool) -> tuple[int, str, str]:
        argv = [
            path,
            "-sS",
            "-L",
            "--max-redirs",
            "10",
            "--connect-timeout",
            f"{connect_timeout:.0f}",
            "--max-time",
            f"{max_time:.0f}",
            "-A",
            SUBSCRIPTION_USER_AGENT,
            "-H",
            "Accept: */*",
            "--compressed",
        ]
        if use_http2:
            argv.append("--http2")
        argv.extend(extra_args)
        argv.extend(["-o", tmp_path, "-w", "%{http_code}", url])
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=max_time + 30.0,
                creationflags=_subprocess_no_window(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return -1, "", type(exc).__name__
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "")[-200:]

    try:
        use_h2 = http2
        rc, code_str, stderr = run_curl([], use_h2)
        if rc == 2 and use_h2:
            # Старый curl не знает --http2 (exit 2 — нераспознанная опция).
            use_h2 = False
            rc, code_str, stderr = run_curl([], use_h2)
        if rc in _CURL_SSL_EXIT_CODES:
            # TLS/сертификат — аналог незаверенного контекста urllib.
            rc, code_str, stderr = run_curl(["-k"], use_h2)
        if rc == 0:
            http_code = 0
            with contextlib.suppress(Exception):
                http_code = int(str(code_str).splitlines()[-1] or "0")
            try:
                body = Path(tmp_path).read_bytes()
            except OSError:
                body = b""
            if 200 <= http_code < 400:
                if not body:
                    _record_fetch_error(errors, url, "curl_EmptyBody")
                    return None
                if log_sink is not None:
                    via = "curl HTTP/2" if use_h2 else "curl"
                    log_sink(f"[xray] source fetch via system {via} fallback: {url}")
                return _decode_subscription_body(body)
            if http_code >= 400:
                _record_fetch_error(errors, url, f"HTTP_{http_code}")
                return None
            _record_fetch_error(errors, url, "curl_NoStatus")
            return None
        if rc == -1:
            _record_fetch_error(errors, url, f"curl_{stderr or 'SpawnFail'}")
        else:
            _record_fetch_error(errors, url, _CURL_EXIT_LABELS.get(rc, f"curl_Exit{rc}"))
        return None
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)


def _powershell_exe() -> str:
    """Путь к PowerShell (powershell/pwsh) на Windows, иначе ''.

    Выделено в функцию для подмены в тестах (на отличных от Windows
    платформах транспорт отключён целиком).
    """
    if sys.platform != "win32":
        return ""
    for name in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        found = shutil.which(name)
        if found:
            return found
    return ""


def _fetch_body_via_powershell(
    url: str,
    timeout: float,
    errors: list[str],
    log_sink: Callable[[str], None] | None,
) -> str | None:
    """Загрузка тела через PowerShell Invoke-WebRequest (только Windows).

    Ближайший к браузеру стек: SChannel TLS + системный прокси (включая
    автоконфигурацию), тогда как urllib понимает только статический прокси
    из реестра. Последний резерв, если urllib и curl не прошли. Ошибки HTTP
    кодируются кодом завершения 2000+<http_code>.
    """
    exe = _powershell_exe()
    if not exe:
        return None
    max_time = int(max(1, _subscription_timeouts(timeout)[-1]))
    fd, tmp_path = tempfile.mkstemp(prefix="subgen_ps_", suffix=".body")
    os.close(fd)
    try:
        script = (
            "$ProgressPreference='SilentlyContinue';"
            "try{"
            f"Invoke-WebRequest -Uri '{url.replace(chr(39), chr(39)*2)}' "
            f"-UserAgent '{SUBSCRIPTION_USER_AGENT}' "
            f"-TimeoutSec {max_time} -UseBasicParsing "
            f"-OutFile '{tmp_path.replace(chr(39), chr(39)*2)}'"
            "}catch{"
            "$c=0;"
            "try{$c=[int]$_.Exception.Response.StatusCode}catch{};"
            "if($c -gt 0){exit(2000+$c)}"
            "exit 1"
            "}"
        )
        try:
            proc = subprocess.run(
                [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                timeout=max_time + 60.0,  # холодный старт PS 2-5с + запас
                creationflags=_subprocess_no_window(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            _record_fetch_error(errors, url, f"PS_{type(exc).__name__}")
            return None
        if proc.returncode == 0:
            try:
                body = Path(tmp_path).read_bytes()
            except OSError:
                body = b""
            if not body:
                _record_fetch_error(errors, url, "PS_EmptyBody")
                return None
            if log_sink is not None:
                log_sink(f"[xray] source fetch via powershell fallback: {url}")
            return _decode_subscription_body(body)
        if 2000 < proc.returncode < 3000:
            _record_fetch_error(errors, url, f"HTTP_{proc.returncode - 2000}")
            return None
        _record_fetch_error(errors, url, "PS_Failed")
        return None
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
