#!/usr/bin/env python3
"""Тесты транспортной цепочки загрузки подписок (fetch.py):

urllib → системный curl.exe → PowerShell Invoke-WebRequest.

Проверяет: сборку argv curl (UA, --http2, -o, URL последним аргументом),
маппинг кодов завершения curl (DNS/Connect/Timeout/SSL), повтор с -k при
TLS-сбоях, повтор без --http2 на старых curl, HTTP 4xx как терминальный
отказ кандидата, PowerShell-скрипт (кавычки, коды 2000+HTTP), порядок
транспортов и кандидатов, очистку временных файлов, полноту маркеров ошибок.

Всё герметично: subprocess.run и urlopen подменяются фейками, сети нет.
"""
from __future__ import annotations

import http.client
import py_compile
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from runtime import fetch as F  # noqa: E402
from runtime.types import SUBSCRIPTION_USER_AGENT  # noqa: E402

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


# ------------------------------------------------------------------ фейки

class FakeResponse:
    def __init__(self, body: bytes):
        self._body = body
        self.headers = {}

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeProc:
    """Заготовка subprocess.CompletedProcess; body пишется в файл из -o."""

    def __init__(self, returncode=0, stdout="", stderr="", body: bytes | None = None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.body = body


class FakeRun:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []
        self.tmp_files: list[str] = []

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": list(argv), "kwargs": kwargs})
        if not self.outcomes:
            raise AssertionError(f"unexpected subprocess call #{len(self.calls)}: {argv[:4]}")
        out = self.outcomes.pop(0)
        if isinstance(out, BaseException):
            raise out
        if getattr(out, "body", None) is not None:
            if "-o" in argv:
                # curl: тело в файл из -o <path>
                out_path = argv[argv.index("-o") + 1]
            else:
                # PowerShell: путь в -OutFile '<path>' внутри скрипта
                script = argv[argv.index("-Command") + 1]
                out_path = script.split("-OutFile '", 1)[1].split("'", 1)[0]
            Path(out_path).write_bytes(out.body)
            self.tmp_files.append(out_path)
        return out


class FakeUrlopen:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls: list = []

    def __call__(self, req, timeout=None, context=None):
        self.calls.append({"url": req.full_url, "timeout": timeout, "context": context})
        if not self.outcomes:
            raise AssertionError("unexpected extra urlopen call")
        out = self.outcomes.pop(0)
        if isinstance(out, BaseException):
            raise out
        return out


class Env:
    """Установка фейков + гарантированное восстановление."""

    def __init__(self, *, urlopen_outcomes=(), run_outcomes=(), curl=("", False), ps=""):
        self._real_urlopen = F.urlopen
        self._real_run = F.subprocess.run
        self._real_ps = F._powershell_exe
        self.urlopen = FakeUrlopen(urlopen_outcomes)
        self.run = FakeRun(run_outcomes)
        F.urlopen = self.urlopen
        F.subprocess.run = self.run
        F._CURL_CACHE["info"] = curl
        F._powershell_exe = lambda: ps

    def __enter__(self):
        return self

    def __exit__(self, *args):
        F.urlopen = self._real_urlopen
        F.subprocess.run = self._real_run
        F._powershell_exe = self._real_ps
        F._CURL_CACHE.pop("info", None)
        return False


BODY = b"vless://uuid@host.ru:443?encryption=none#node1\n"
URL = "https://plain.example/sub/list.txt"
KFWL_URL = "https://p.kfwl.lol/https://freevpnhappcluchi.duckdns.org/sub/o20pq89rdo9e7afo"
INNER_URL = "https://freevpnhappcluchi.duckdns.org/sub/o20pq89rdo9e7afo"
DISCONNECTED = http.client.RemoteDisconnected("closed")


def curl_ok(body: bytes = BODY, code: str = "200", extra: dict | None = None):
    proc = FakeProc(returncode=0, stdout=code, body=body)
    for key, value in (extra or {}).items():
        setattr(proc, key, value)
    return proc


print("== T. Системный curl как транспорт ==")

# T1: urllib рвётся (DPI), curl вывозит — сквозной сценарий пользователя.
logs: list[str] = []
with Env(urlopen_outcomes=[DISCONNECTED] * 3, run_outcomes=[curl_ok()], curl=("/fake/curl", True)) as env:
    text = F._fetch_text(URL, timeout=8.0, log_sink=logs.append)
    check("T1 curl подобрал после обрыва urllib, тело получено", text.startswith("vless://"), repr(text[:40]))
    check("T1b urllib сделал 3 попытки (лестница)", len(env.urlopen.calls) == 3)
    check("T1c curl вызван 1 раз", len(env.run.calls) == 1, str(len(env.run.calls)))
    argv = env.run.calls[0]["argv"]
    check("T1d argv[0] — путь curl", argv[0] == "/fake/curl", str(argv[:2]))
    check("T1e --http2 передан (поддержка есть)", "--http2" in argv)
    check("T1f UA приложения передан через -A", argv[argv.index("-A") + 1] == SUBSCRIPTION_USER_AGENT)
    check("T1g URL — последний аргумент, без shell", argv[-1] == URL and "shell" not in env.run.calls[0]["kwargs"])
    check("T1h таймауты --max-time 45 (верх лестницы)", argv[argv.index("--max-time") + 1] == "45")
    check(
        "T1i лог отмечает транспорт: system curl HTTP/2 fallback",
        any("via system curl HTTP/2 fallback" in l and URL in l for l in logs),
        str(logs),
    )
    tmp = env.run.tmp_files[0]
    check("T1j временный файл тела удалён", not Path(tmp).exists())

# T2: curl получает 404 — кандидат мёртв, TransportError с HTTP_404.
with Env(urlopen_outcomes=[DISCONNECTED] * 3, run_outcomes=[curl_ok(b"Not Found", "404")], curl=("/fake/curl", True)):
    try:
        F._fetch_text(URL, timeout=8.0)
        check("T2 RuntimeError поднят (404)", False)
    except RuntimeError as exc:
        check("T2 RuntimeError с HTTP_404", "HTTP_404" in str(exc), str(exc))
        check("T2b и исходный RemoteDisconnected тоже в причинах", "RemoteDisconnected" in str(exc), str(exc))

# T3: TLS-сбой curl (exit 60) — повтор с -k вывозит.
with Env(
    urlopen_outcomes=[DISCONNECTED] * 3,
    run_outcomes=[FakeProc(returncode=60, stderr="SSL cert problem"), curl_ok()],
    curl=("/fake/curl", False),
) as env:
    text = F._fetch_text(URL, timeout=8.0)
    check("T3 TLS exit 60 -> повтор с -k принёс тело", text.startswith("vless://"))
    check("T3b второй вызов с -k", len(env.run.calls) == 2 and "-k" in env.run.calls[1]["argv"])

# T4: старый curl без --http2 (exit 2) — повтор без опции.
with Env(
    urlopen_outcomes=[DISCONNECTED] * 3,
    run_outcomes=[FakeProc(returncode=2, stderr="curl: option --http2: is unknown"), curl_ok()],
    curl=("/fake/curl", True),
) as env:
    logs2: list[str] = []
    text = F._fetch_text(URL, timeout=8.0, log_sink=logs2.append)
    check("T4 exit 2 -> повтор без --http2 принёс тело", text.startswith("vless://"))
    check("T4b во втором вызове нет --http2", len(env.run.calls) == 2 and "--http2" not in env.run.calls[1]["argv"])
    check("T4c лог честный: без HTTP/2", any("via system curl fallback" in l for l in logs2), str(logs2))

# T5: curl timeout (exit 28) — без -k-повтора, маркер curl_Timeout.
with Env(
    urlopen_outcomes=[DISCONNECTED] * 3,
    run_outcomes=[FakeProc(returncode=28, stderr="Operation timed out")],
    curl=("/fake/curl", True),
) as env:
    try:
        F._fetch_text(URL, timeout=8.0)
        check("T5 RuntimeError поднят (timeout)", False)
    except RuntimeError as exc:
        check("T5 маркер curl_Timeout в причинах", "curl_Timeout" in str(exc), str(exc))
    check("T5b curl вызван 1 раз (28 не TLS)", len(env.run.calls) == 1, str(len(env.run.calls)))

# T6: DNS-сбой curl (exit 6) — маркер curl_DNS, дальше PS (выключен).
with Env(urlopen_outcomes=[DISCONNECTED] * 3, run_outcomes=[FakeProc(returncode=6)], curl=("/fake/curl", False)):
    try:
        F._fetch_text(URL, timeout=8.0)
        check("T6 RuntimeError поднят (DNS)", False)
    except RuntimeError as exc:
        check("T6 маркер curl_DNS в причинах", "curl_DNS" in str(exc), str(exc))

# T7: curl вернул 200 с пустым телом — curl_EmptyBody, не пустой успех.
with Env(urlopen_outcomes=[DISCONNECTED] * 3, run_outcomes=[FakeProc(returncode=0, stdout="200")], curl=("/fake/curl", False)):
    try:
        F._fetch_text(URL, timeout=8.0)
        check("T7 RuntimeError поднят (пустое тело)", False)
    except RuntimeError as exc:
        check("T7 маркер curl_EmptyBody", "curl_EmptyBody" in str(exc), str(exc))

# T8: spawn curl падает исключением — маркер с именем исключения.
with Env(urlopen_outcomes=[DISCONNECTED] * 3, run_outcomes=[OSError("no such file")], curl=("/fake/curl", False)):
    try:
        F._fetch_text(URL, timeout=8.0)
        check("T8 RuntimeError поднят (spawn fail)", False)
    except RuntimeError as exc:
        check("T8 маркер curl_OSError", "curl_OSError" in str(exc), str(exc))

print("== P. PowerShell как транспорт (фейковый exe) ==")

# P1: urllib и curl не прошли, PS вывозит.
logs3: list[str] = []
with Env(
    urlopen_outcomes=[DISCONNECTED] * 3,
    run_outcomes=[FakeProc(returncode=60), FakeProc(returncode=28)],
    curl=("/fake/curl", False),
    ps="/fake/powershell.exe",
) as env:
    # urlopen 3 обрыва; curl: TLS(60) -> -k retry(28); затем PS:
    env.run.outcomes.append(FakeProc(returncode=0, body=b"vless://ps@host:443#ps\n"))
    text = F._fetch_text(URL, timeout=8.0, log_sink=logs3.append)
    check("P1 PS подобрал последним, тело получено", text.startswith("vless://ps@"), repr(text[:40]))
    ps_calls = [c for c in env.run.calls if c["argv"][0] == "/fake/powershell.exe"]
    check("P1b powershell вызван 1 раз", len(ps_calls) == 1)
    argv = ps_calls[0]["argv"]
    check("P1c argv: -NoProfile -ExecutionPolicy Bypass -Command", argv[1:5] == ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"], str(argv[:6]))
    script = argv[5]
    check("P1d скрипт: Invoke-WebRequest с URL в одинарных кавычках", f"Invoke-WebRequest -Uri '{URL}'" in script, script[:120])
    check("P1e скрипт: UA и UseBasicParsing", SUBSCRIPTION_USER_AGENT in script and "-UseBasicParsing" in script)
    check("P1f скрипт: TimeoutSec 45", "-TimeoutSec 45" in script)
    check("P1g лог отмечает: via powershell fallback", any("via powershell fallback" in l for l in logs3), str(logs3))

# P2: PS ловит HTTP 404 (exit 2000+404).
with Env(urlopen_outcomes=[DISCONNECTED] * 3, run_outcomes=[], curl=("", False), ps="/fake/powershell.exe") as env:
    env.run.outcomes.append(FakeProc(returncode=2404))
    try:
        F._fetch_text(URL, timeout=8.0)
        check("P2 RuntimeError поднят (404 от PS)", False)
    except RuntimeError as exc:
        check("P2 маркер HTTP_404 из PS", "HTTP_404" in str(exc), str(exc))

# P3: PS пустой файл (exit 0, тела нет).
with Env(urlopen_outcomes=[DISCONNECTED] * 3, run_outcomes=[], curl=("", False), ps="/fake/powershell.exe") as env:
    env.run.outcomes.append(FakeProc(returncode=0))
    try:
        F._fetch_text(URL, timeout=8.0)
        check("P3 RuntimeError поднят (PS пусто)", False)
    except RuntimeError as exc:
        check("P3 маркер PS_EmptyBody", "PS_EmptyBody" in str(exc), str(exc))

# P4: PS общий сбой (exit 1).
with Env(urlopen_outcomes=[DISCONNECTED] * 3, run_outcomes=[], curl=("", False), ps="/fake/powershell.exe") as env:
    env.run.outcomes.append(FakeProc(returncode=1))
    try:
        F._fetch_text(URL, timeout=8.0)
        check("P4 RuntimeError поднят (PS сбой)", False)
    except RuntimeError as exc:
        check("P4 маркер PS_Failed", "PS_Failed" in str(exc), str(exc))

print("== I. Интеграция транспортов и кандидатов ==")

# I1: обёртка kfwl — urllib и curl мертвы, внутренний URL жив через urllib.
with Env(
    urlopen_outcomes=[DISCONNECTED] * 3 + [FakeResponse(BODY)],
    run_outcomes=[FakeProc(returncode=7)],
    curl=("/fake/curl", True),
) as env:
    text = F._fetch_text(KFWL_URL, timeout=8.0)
    check("I1 развёрнутый кандидат подобрал после смерти обёртки", text.startswith("vless://"))
    check(
        "I1b порядок: 3 urllib обёртки -> curl обёртки -> urllib внутренний",
        [c["url"][:30] for c in env.urlopen.calls] == [KFWL_URL[:30]] * 3 + [INNER_URL[:30]]
        and len(env.run.calls) == 1,
        str(env.urlopen.calls),
    )

# I2: обёртка умирает на urllib, curl обёртки вывозит — до внутреннего не доходит.
with Env(
    urlopen_outcomes=[DISCONNECTED] * 3,
    run_outcomes=[curl_ok(b"vless://via-curl@wrapper:443#w\n")],
    curl=("/fake/curl", True),
) as env:
    text = F._fetch_text(KFWL_URL, timeout=8.0)
    check("I2 curl обёртки вывозит раньше внутреннего URL", text.startswith("vless://via-curl@"))
    check("I2b внутренний URL не запрашивался", len(env.urlopen.calls) == 3)

# I3: курла нет, PS нет — чистый urllib без регрессий (как до фикса).
with Env(urlopen_outcomes=[DISCONNECTED] * 3 + [FakeResponse(BODY)]):
    text = F._fetch_text(KFWL_URL, timeout=8.0)
    check("I3 без транспортов фолбэк кандидатов работает как раньше", text.startswith("vless://"))

# I4: 4xx из urllib на обёртке -> curl тоже пробуется ДО следующего кандидата.
with Env(
    urlopen_outcomes=[HTTPError(KFWL_URL, 404, "Not Found", None, None), FakeResponse(BODY)],
    run_outcomes=[FakeProc(returncode=7)],
    curl=("/fake/curl", False),
) as env:
    text = F._fetch_text(KFWL_URL, timeout=8.0)
    check("I4 после 404 urllib тело приходит со следующего кандидата", text.startswith("vless://"))
    check("I4b после 404 curl НЕ вызывается (сервер ответил — транспорт ни при чём)",
          len(env.urlopen.calls) == 2 and len(env.run.calls) == 0,
          f"urlopen={len(env.urlopen.calls)} run={len(env.run.calls)}")

print("== F. Компиляция и сигнатуры ==")
try:
    py_compile.compile(str(REPO / "python" / "runtime" / "fetch.py"), doraise=True)
    check("F1 fetch.py компилируется", True)
except py_compile.PyCompileError as exc:
    check("F1 fetch.py компилируется", False, str(exc))

for name in ("_fetch_text", "_fetch_candidate_body", "_fetch_body_via_system_curl",
             "_fetch_body_via_powershell", "_system_curl_info", "_powershell_exe",
             "_subscription_candidate_urls", "_subscription_headers",
             "_subscription_ssl_contexts", "_subscription_timeouts",
             "_decode_subscription_body", "_record_fetch_error", "_error_is_tls"):
    check(f"F2 экспорт {name} на месте", hasattr(F, name))

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
