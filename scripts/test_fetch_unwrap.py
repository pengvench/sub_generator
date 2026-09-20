#!/usr/bin/env python3
"""Тесты фиксов загрузки подписок (fetch.py):

1. Разворот прокси-обёрток (p.kfwl.lol/https://inner) в запасных кандидатов,
   включая вложенные и URL-кодированные обёртки.
2. Лестница таймаутов 10/20/45с (раньше 8/15/30 — убивала медленные обёртки).
3. Повтор с незаверенным SSL-контекстом только при TLS-ошибках.
4. HTTP 4xx — сразу следующий кандидат; 5xx — повтор на следующих таймаутах.
5. Причины сбоев (host:RemoteDisconnected и т.п.) — в сообщении RuntimeError.
6. Парсинг тел: HTML-просмотрщик (kfwl) со ссылками в JSON и base64-подписки.

Все HTTP-сценарии — на фейковом urlopen (без сети), как в test_wave2_fixes.py.
"""
from __future__ import annotations

import base64
import gzip
import http.client
import py_compile
import ssl
import sys
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from runtime import fetch as F  # noqa: E402
from runtime.parse import _subscription_lines  # noqa: E402

# Транспорты curl/PowerShell отключаем: этот сьют проверяет urllib-логику и
# порядок кандидатов; реальный curl из песочницы нашёлся бы и ходил в сеть.
F._CURL_CACHE["info"] = ("", False)
F._powershell_exe = lambda: ""  # noqa: E731

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


# ---------------------------------------------------------------- фейковый HTTP

class FakeResponse:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None):
        self._body = body
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args) -> bool:
        return False


class FetchRecorder:
    """Подмена F.urlopen: выдаёт outcomes по очереди, пишет все вызовы."""

    def __init__(self, outcomes: list):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    def __call__(self, req, timeout=None, context=None):
        self.calls.append(
            {
                "url": req.full_url,
                "timeout": timeout,
                "context": context,
                "headers": {k.lower(): v for k, v in req.headers.items()},
            }
        )
        if not self.outcomes:
            raise AssertionError(f"unexpected extra urlopen call #{len(self.calls)}")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def with_recorder(outcomes: list) -> tuple[FetchRecorder, str | None]:
    """Устанавливает фейковый urlopen, возвращает (recorder, error-or-body)."""
    rec = FetchRecorder(outcomes)
    F.urlopen = rec
    return rec


def restore_urlopen() -> None:
    F.urlopen = __import__("urllib.request", fromlist=["urlopen"]).urlopen


KFWL_URL = "https://p.kfwl.lol/https://freevpnhappcluchi.duckdns.org/sub/o20pq89rdo9e7afo"
INNER_URL = "https://freevpnhappcluchi.duckdns.org/sub/o20pq89rdo9e7afo"

print("== A. Кандидаты URL: разворот прокси-обёрток ==")

cands = F._subscription_candidate_urls(KFWL_URL)
check("A1 kfwl-обёртка -> 2 кандидата", len(cands) == 2, str(cands))
check("A1b внутренний URL извлечён верно", cands[1] == INNER_URL, str(cands))

cands = F._subscription_candidate_urls("https://a.proxy/https://b.proxy/https://real.host/sub/path")
check(
    "A2 вложенная двойная обёртка -> 3 кандидата",
    cands == [
        "https://a.proxy/https://b.proxy/https://real.host/sub/path",
        "https://b.proxy/https://real.host/sub/path",
        "https://real.host/sub/path",
    ],
    str(cands),
)

cands = F._subscription_candidate_urls(
    "https://p.kfwl.lol/https%3A%2F%2Ffreevpnhappcluchi.duckdns.org%2Fsub%2Fx"
)
check(
    "A3 URL-кодированная обёртка -> прямой внутренний URL",
    len(cands) == 2 and cands[1] == "https://freevpnhappcluchi.duckdns.org/sub/x",
    str(cands),
)

cands = F._subscription_candidate_urls("https://plain.example/sub/list.txt")
check("A4 обычный URL -> 1 кандидат, фантомов нет", cands == ["https://plain.example/sub/list.txt"], str(cands))

GH = "https://raw.githubusercontent.com/owner/repo/refs/heads/main/sub.txt"
cands = F._subscription_candidate_urls(GH)
check(
    "A5 github raw -> каноничный + 3 CDN-зеркала (регрессия)",
    len(cands) == 5 and cands[1] == "https://raw.githubusercontent.com/owner/repo/main/sub.txt"
    and cands[2].startswith("https://cdn.jsdelivr.net/gh/owner/repo@main/"),
    str(cands),
)

print("== B. Лестница таймаутов ==")
check("B1 timeout=8 -> [10, 20, 45]", F._subscription_timeouts(8.0) == [10.0, 20.0, 45.0])
check("B2 timeout=60 -> [60]", F._subscription_timeouts(60.0) == [60.0])
check("B3 timeout=0 -> [10, 20, 45]", F._subscription_timeouts(0.0) == [10.0, 20.0, 45.0])

print("== C. Классификация TLS-ошибок ==")
check("C1 ssl.SSLError -> TLS", F._error_is_tls(ssl.SSLError("handshake")))
check("C2 ssl.SSLEOFError -> TLS", F._error_is_tls(ssl.SSLEOFError("eof")))
check("C3 URLError(reason=SSLError) -> TLS", F._error_is_tls(URLError(ssl.SSLError("x"))))
check("C4 URLError(reason=ConnectionResetError) -> не TLS", not F._error_is_tls(URLError(ConnectionResetError())))
check("C5 RemoteDisconnected -> не TLS", not F._error_is_tls(http.client.RemoteDisconnected("closed")))
check("C6 URLError(reason=str) -> не TLS", not F._error_is_tls(URLError("dns failure")))

print("== D. Поведенческие сценарии (фейковый urlopen) ==")

# Транспортный слой возвращает тело как есть (base64/HTML разбирает
# _subscription_lines выше по конвейеру), поэтому фейковые тела — плоский текст.
BODY = b"vless://uuid@host.ru:443?encryption=none#node1\n"

# D1: обёртка рвёт соединение на всех таймаутах (сеть блокирует прокси),
# внутренний URL отвечает сразу — тело должно вернуться.
rec = with_recorder(
    [http.client.RemoteDisconnected("closed")] * 3 + [FakeResponse(BODY)]
)
try:
    text = F._fetch_text(KFWL_URL, timeout=8.0)
    check("D1 фолбэк на внутренний URL вернул тело", text.startswith("vless://"), repr(text[:40]))
    check("D1b всего 4 запроса (3 обёртка + 1 внутренний)", len(rec.calls) == 4, str(len(rec.calls)))
    check(
        "D1c таймауты лестницы [10,20,45] и 10 для внутреннего",
        [c["timeout"] for c in rec.calls] == [10.0, 20.0, 45.0, 10.0],
        str([c["timeout"] for c in rec.calls]),
    )
    check(
        "D1d незаверенный контекст для сетевых ошибок НЕ используется",
        all(c["context"] is None for c in rec.calls),
        str([bool(c["context"]) for c in rec.calls]),
    )
    check(
        "D1e UA и заголовки дошли до запроса",
        rec.calls[0]["headers"].get("user-agent") == "v2rayN/6.23 MTProxyAutoSwitch/1.0"
        and rec.calls[0]["headers"].get("connection") == "close"
        and rec.calls[0]["headers"].get("accept-encoding") == "gzip",
        str(rec.calls[0]["headers"]),
    )
finally:
    restore_urlopen()

# D2: 404 на обёртке — сразу следующий кандидат, без перебора таймаутов.
rec = with_recorder(
    [HTTPError(KFWL_URL, 404, "Not Found", None, None), FakeResponse(BODY)]
)
try:
    text = F._fetch_text(KFWL_URL, timeout=8.0)
    check("D2 404 -> мгновенный фолбэк, тело получено", text.startswith("vless://"))
    check("D2b только 2 запроса (404 + успех)", len(rec.calls) == 2, str(len(rec.calls)))
finally:
    restore_urlopen()

# D3: 503 на обёртке — по одному запросу на таймаут (TLS уже успешен,
# контексты не перебираются), затем фолбэк.
rec = with_recorder(
    [HTTPError(KFWL_URL, 503, "Slow Origin", None, None)] * 3 + [FakeResponse(BODY)]
)
try:
    text = F._fetch_text(KFWL_URL, timeout=8.0)
    check("D3 503x3 -> фолбэк, тело получено", text.startswith("vless://"))
    check("D3b 4 запроса: 3 таймаута обёртки + внутренний", len(rec.calls) == 4, str(len(rec.calls)))
    check("D3c все контексты verified", all(c["context"] is None for c in rec.calls))
finally:
    restore_urlopen()

# D4: TLS-ошибка (просроченный сертификат) -> повтор с незаверенным контекстом.
rec = with_recorder(
    [URLError(ssl.SSLError("CERTIFICATE_VERIFY_FAILED")), FakeResponse(BODY)]
)
try:
    text = F._fetch_text("https://plain.example/sub", timeout=8.0)
    check("D4 TLS-ошибка -> повтор без проверки сертификата принёс тело", text.startswith("vless://"))
    check("D4b 2 запроса, второй с незаверенным контекстом",
          len(rec.calls) == 2 and rec.calls[1]["context"] is not None,
          str([bool(c["context"]) for c in rec.calls]))
finally:
    restore_urlopen()

# D5: все кандидаты мертвы -> RuntimeError с причинами, логи фолбэка и ошибок.
logs: list[str] = []
rec = with_recorder(
    [http.client.RemoteDisconnected("closed")] * 3 + [URLError("connection refused")] * 3
)
try:
    try:
        F._fetch_text(KFWL_URL, timeout=8.0, log_sink=logs.append)
        check("D5 RuntimeError поднят", False)
    except RuntimeError as exc:
        msg = str(exc)
        check("D5 RuntimeError с причинами", "subscription fetch failed" in msg
              and "p.kfwl.lol:RemoteDisconnected" in msg
              and "freevpnhappcluchi.duckdns.org:URLError" in msg, msg)
    check("D5b лог: фолбэк на внутренний URL", any("source fetch fallback" in l and INNER_URL in l for l in logs),
          str(logs))
    check("D5c лог: сводка неудачных попыток", any("source fetch attempts failed" in l for l in logs), str(logs))
finally:
    restore_urlopen()

# D6: локальный файл по-прежнему читается без сети.
with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
    tmp.write(BODY)
    tmp_name = tmp.name
try:
    text = F._fetch_text(tmp_name, timeout=8.0)
    check("D6 локальный файл -> тело", text.startswith("vless://"), repr(text[:40]))
finally:
    Path(tmp_name).unlink(missing_ok=True)

# D7: gzip-ответ распаковывается.
rec = with_recorder([FakeResponse(gzip.compress(BODY), {"Content-Encoding": "gzip"})])
try:
    text = F._fetch_text("https://plain.example/sub", timeout=8.0)
    check("D7 gzip-тело распаковано", text.startswith("vless://"), repr(text[:40]))
finally:
    restore_urlopen()

print("== E. Парсинг реальных типов тел ==")

KFWL_HTML = """<!DOCTYPE html>
<html><head><title>kfwl · подписка</title></head>
<script>
const nodes = [
 {"port": 443, "uuid": "4054fdc2-ee80-4419-8a8e-d937df4719e2",
  "raw": "vless://4054fdc2-ee80-4419-8a8e-d937df4719e2@qq.utiltools.ru:443?encryption=none#QQ"},
 {"port": 2027, "uuid": "579f0893-e6f9-4036-86a1-7c10aa2d24ea",
  "raw": "vless://579f0893-e6f9-4036-86a1-7c10aa2d24ea@msk2.example.com:2027?encryption=none#MSK2"}
];
</script></html>"""
lines = _subscription_lines(KFWL_HTML)
check("E1 HTML-просмотрщик kfwl -> ссылки извлечены", len(lines) == 2 and lines[0].startswith("vless://4054"), str(lines))

b64_body = base64.b64encode(
    b"vless://a@h1.ru:443?encryption=none#n1\nvless://b@h2.ru:8443?encryption=none#n2\n"
).decode()
lines = _subscription_lines(b64_body)
check("E2 base64-подписка -> 2 ссылки", len(lines) == 2 and lines[0].startswith("vless://a@h1.ru"), str(lines))

ELIX_B64 = "aHlzdGVyaWEyOi8vdWlkQG5ld2x0ZS5raWhzdXloZjhqa2l1Z3N4Yi5jZmQ6NDQzLz9zbmk9aG9zdCZmcD10bHMjTGluaw=="
lines = _subscription_lines(ELIX_B64)
check("E3 base64 hysteria2 (panel.elix.lol) -> ссылка", len(lines) == 1 and lines[0].startswith("hysteria2://"), str(lines))

print("== F. Компиляция и сигнатуры ==")
try:
    py_compile.compile(str(REPO / "python" / "runtime" / "fetch.py"), doraise=True)
    check("F1 fetch.py компилируется", True)
except py_compile.PyCompileError as exc:
    check("F1 fetch.py компилируется", False, str(exc))

for name in ("_fetch_text", "_subscription_candidate_urls", "_subscription_headers",
             "_subscription_ssl_contexts", "_subscription_timeouts", "_decode_subscription_body"):
    check(f"F2 экспорт {name} сохранён", hasattr(F, name))

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
