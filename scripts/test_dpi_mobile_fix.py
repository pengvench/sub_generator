# -*- coding: utf-8 -*-
"""Тесты фикса DPI-сьюта для мобильных сетей (инцидент 2026-09-02), v8.2.

Причина инцидента: мобильный прогон 13:16-16:18 забраковал все 106 нод на
DPI-этапе (suite=0-1/24 при пороге 0.75), потому что:
  1) таймаут пробы 5с откалиброван под широкополосный доступ, а проба — это
     ~6-8 RTT сквозного пути (мобильный RTT через туннель ~2с);
  2) «медленный канал» классифицировался как LIKELY_BLOCKED;
  3) telegram-проверка (главный критерий пользователя) стояла ПОСЛЕ
     DPI-гейта и вообще не выполнилась (0 нод проверено).

v8.2 = v8.1 (ai_geo/hostres/тумблеры) + мобильный фикс. Тестируем:
  - effective_suite_params: адаптивный таймаут/slow-mode/кап/идемпотентность;
  - _median_initial_latency: p50 по initial_check (на реальном мобильном
    отчёте p50=1977);
  - _post_payload_probe: честная классификация write-timeout (FAIL slow_link,
    не BLOCKED) и read-freeze (BLOCKED);
  - _run_zapret_checks: slow-mode режет цели/выключает http, rtt-детали;
  - checkers/dpi.py: rtt_hint_ms течёт в сьют на том же core-процессе;
  - pipeline: порядок этапов (telegram ДО DPI), сетевой профиль в отчёте;
  - регресс v8.1: ai_geo.py на месте, тумблер ИИ-гео в UI, STAGE_ORDER
    синхронизирован с recheck_page.

Запуск: python3 scripts/test_dpi_mobile_fix.py <путь_к_исходнику>
"""
from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

REPO_ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent.parent))
# Объединённая структура: пакеты лежат в <репо>/python.
ROOT = REPO_ROOT if (REPO_ROOT / "subgen").exists() else REPO_ROOT / "python"
sys.path.insert(0, str(ROOT))

import checkers.base as base  # noqa: E402
import checkers.zapret as zapret  # noqa: E402
import subgen.pipeline as pipeline  # noqa: E402

MOBILE_REPORT = Path("/home/z/my-project/subgen/mob_run_data/data/report.json")

PASS = 0
FAIL = 0


def check(name: str, cond: bool, extra: str = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {extra}")


# ---------------------------------------------------------------------------
# 1. effective_suite_params
# ---------------------------------------------------------------------------
print("== effective_suite_params ==")

p = zapret.effective_suite_params(0)
check("без хинта: дефолт 5с/0.75/8 целей/http on",
      p["timeout"] == 5.0 and p["min_score"] == 0.75 and p["max_targets"] == 8
      and p["run_http_test"] is True and p["slow_mode"] is False, str(p))

p = zapret.effective_suite_params(300)
check("быстрая сеть (300мс): без изменений",
      p["timeout"] == 5.0 and p["slow_mode"] is False, str(p))

p = zapret.effective_suite_params(1977)  # p50 мобильного прогона
check("мобильная (1977мс): таймаут ~8*RTT",
      abs(p["timeout"] - 1977 / 1000 * 8) < 0.01, str(p))
check("мобильная: slow-mode (4 цели, без http, порог 0.5)",
      p["slow_mode"] is True and p["max_targets"] == 4
      and p["run_http_test"] is False and p["min_score"] == 0.5, str(p))

p = zapret.effective_suite_params(4000)
check("кап 20с", p["timeout"] == 20.0, str(p))

p = zapret.effective_suite_params(2000, timeout=25.0)
check("явный больший таймаут не урезается", p["timeout"] == 25.0, str(p))

p1 = zapret.effective_suite_params(1977)
p2 = zapret.effective_suite_params(1977, timeout=p1["timeout"],
                                   min_score=p1["min_score"],
                                   max_targets=p1["max_targets"],
                                   run_http_test=p1["run_http_test"])
check("идемпотентность (двойная адаптация = одна)",
      abs(p1["timeout"] - p2["timeout"]) < 0.01 and p2["max_targets"] == 4
      and p2["min_score"] == 0.5 and p2["run_http_test"] is False, str(p2))

check("ZAPRET_TIMEOUT_MAX поднят до 20с (v8.1 был 15с)", zapret.ZAPRET_TIMEOUT_MAX == 20.0)

# ---------------------------------------------------------------------------
# 2. _median_initial_latency
# ---------------------------------------------------------------------------
print("== _median_initial_latency ==")
f = pipeline._median_initial_latency
check("нечёт: медиана", f({"a": {"latency_ms": 100}, "b": {"latency_ms": 300}, "c": {"latency_ms": 200}}) == 200.0)
check("чёт: среднее двух центральных", f({"a": {"latency_ms": 100}, "b": {"latency_ms": 100}, "c": {"latency_ms": 400}, "d": {"latency_ms": 500}}) == 250.0)
check("пусто -> 0", f({}) == 0.0 and f(None) == 0.0)
check("None-латентности пропускаются", f({"a": {"latency_ms": None}, "b": {"latency_ms": 900}}) == 900.0)
check("failed-узлы без latency не влияют", f({"ok": {"latency_ms": 50}, "fail": {}}) == 50.0)

if MOBILE_REPORT.exists():
    report = json.loads(MOBILE_REPORT.read_text(encoding="utf-8"))
    nodes = report["initial_check"]["nodes"]
    p50 = f(nodes)
    check("реальный мобильный отчёт: p50 около 1977", 1900 <= p50 <= 2050, f"p50={p50}")
    check("в отчёте юзера сьюта ещё НЕ адаптивна (порог 0.75) — потому и 106/106 FAIL",
          report.get("dpi", {}).get("suite", {}).get("min_score", 0.75) == 0.75)
else:
    print(f"  skip реальный отчёт не найден: {MOBILE_REPORT}")


# ---------------------------------------------------------------------------
# 3. _post_payload_probe: классификация проб (моки сокетов)
# ---------------------------------------------------------------------------
print("== _post_payload_probe ==")


class FakeTlsSock:
    """Скриптованный TLS-сокет: sendall/recv по сценарию."""

    def __init__(self, *, send_ok=True, stall_after=None, recv_first=None,
                 recv_timeout_after=None):
        self.sent_total = 0
        self.stall_after = stall_after
        self.send_ok = send_ok
        self.recv_first = recv_first
        self.recv_timeout_after = recv_timeout_after
        self._recv_calls = 0
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def sendall(self, data):
        if self.stall_after is not None and self.sent_total + len(data) > self.stall_after:
            # Стоячая отправка: блокировка без прогресса на весь таймаут.
            time.sleep(self.timeout or 0.3)
            raise socket.timeout
        if not self.send_ok:
            raise ConnectionResetError("reset by peer")
        self.sent_total += len(data)

    def recv(self, n):
        self._recv_calls += 1
        if self.recv_timeout_after is not None:
            # Ответ не приходит: recv блокируется на весь таймаут.
            time.sleep(self.recv_timeout_after)
            raise socket.timeout
        if self._recv_calls == 1 and self.recv_first:
            return self.recv_first
        return b""


def run_probe(fake, timeout=0.4, payload=8192):
    """Прогнать _post_payload_probe с подменёнными base-функциями."""
    orig_open = base._socks_open_connection
    orig_wrap = base._wrap_tls_version
    base._socks_open_connection = lambda *a, **k: object()
    base._wrap_tls_version = lambda raw, host, t, **k: fake
    try:
        return zapret._post_payload_probe(
            "127.0.0.1", 1080, "example.com", zapret.PROTO_HTTP11,
            timeout, payload_bytes=payload,
        )
    finally:
        base._socks_open_connection = orig_open
        base._wrap_tls_version = orig_wrap


# a) успешная проба: ответ с HTTP-кодом
res = run_probe(FakeTlsSock(recv_first=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
check("OK-проба: статус OK, http_code=200, send_sec записан",
      res.status == zapret.STATUS_OK and res.http_code == 200 and res.send_sec > 0,
      f"status={res.status} code={res.http_code} send_sec={res.send_sec}")
check("OK-проба: up_bytes = полный payload",
      res.up_bytes == 8192 + len(b"POST / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: SubGenerator/1.0\r\nContent-Type: application/octet-stream\r\nContent-Length: 8192\r\nConnection: close\r\n\r\n"),
      f"up={res.up_bytes}")

# b) write-stall (DPI-фриз отправки): раньше давал LIKELY_BLOCKED и исключался
#    из знаменателя — теперь честный FAIL slow_link (в знаменателе).
fake = FakeTlsSock(stall_after=20 * 1024)
fake.timeout = 0.4
res = run_probe(fake, timeout=0.4, payload=64 * 1024)
check("write-stall: FAIL (в знаменателе), а не LIKELY_BLOCKED",
      res.status == zapret.STATUS_FAIL and "slow_link" in res.detail,
      f"status={res.status} detail={res.detail}")
check("write-stall: send_sec ~ таймаут (блокировка без прогресса)",
      res.send_sec >= 0.35, f"send_sec={res.send_sec}")

# c) read-freeze: весь payload отправлен быстро, ответ не приходит весь
#    таймаут -> классический LIKELY_BLOCKED.
fake = FakeTlsSock(recv_timeout_after=0.45)
res = run_probe(fake, timeout=0.4, payload=8192)
check("read-freeze: LIKELY_BLOCKED сохранён (sent fast, down=0, time>=timeout)",
      res.status == zapret.STATUS_BLOCKED and res.down_bytes == 0,
      f"status={res.status} time={res.time_sec:.2f}")
check("read-freeze: полная отправка зафиксирована", res.up_bytes >= 8192, f"up={res.up_bytes}")

# d) socks-недоступность: FAIL socks_failed
orig_open = base._socks_open_connection
base._socks_open_connection = lambda *a, **k: None
try:
    res = zapret._post_payload_probe("127.0.0.1", 1080, "example.com", zapret.PROTO_HTTP11, 0.4)
finally:
    base._socks_open_connection = orig_open
check("socks_failed: FAIL", res.status == zapret.STATUS_FAIL and res.detail == "socks_failed",
      f"status={res.status} detail={res.detail}")


# ---------------------------------------------------------------------------
# 4. _run_zapret_checks: slow-mode и детали
# ---------------------------------------------------------------------------
print("== _run_zapret_checks ==")
targets = [zapret.ZapretTarget(id=str(i), provider=f"p{i}", country="X", host=f"h{i}.com")
           for i in range(8)]
probe_calls = []


def fake_probe_target(socks_host, socks_port, t, timeout):
    probe_calls.append((t.host, timeout))
    ok = t.host in ("h0.com", "h1.com", "h2.com")
    probes = [zapret.ZapretProbeResult(protocol=pr, status=zapret.STATUS_OK if ok else zapret.STATUS_FAIL,
                                       http_code=200 if ok else 0, up_bytes=65536, down_bytes=100 if ok else 0,
                                       time_sec=0.2, send_sec=0.05, detail="" if ok else "slow_link")
              for pr in zapret.PROTOCOLS]
    return {"id": t.id, "provider": t.provider, "country": t.country, "host": t.host,
            "blocked": False, "ok": ok, "probes": [p.row() for p in probes]}


# baseline-замер (HEAD через узел) тоже мокаем: 127.0.0.1:1080 в тестовой
# среде недоступен, а ждать реального socks_failed не хочется.
def fake_head_probe(socks_host, socks_port, host, protocol, timeout):
    return zapret.ZapretProbeResult(protocol=protocol, status=zapret.STATUS_OK,
                                    http_code=200, up_bytes=100, down_bytes=100,
                                    time_sec=0.3, send_sec=0.1, detail="")


orig_pt = zapret._probe_target
zapret._probe_target = fake_probe_target
orig_hd = zapret._head_http_probe
zapret._head_http_probe = fake_head_probe
try:
    # Нормальная сеть: 8 целей, http-тест замокан тоже (не вызовется —
    # подменим _http_test_host, чтобы не ходить в сеть).
    orig_ht = zapret._http_test_host
    zapret._http_test_host = lambda *a, **k: zapret.ZapretHttpResult(host="x", probes=[])
    try:
        res_norm = zapret._run_zapret_checks("127.0.0.1", 1080, list(targets), 5.0, True)
        res_slow = zapret._run_zapret_checks("127.0.0.1", 1080, list(targets), 5.0, True,
                                             rtt_hint_ms=1977.0)
    finally:
        zapret._http_test_host = orig_ht
finally:
    zapret._probe_target = orig_pt
    zapret._head_http_probe = orig_hd

check("нормальная сеть: 8 целей x 3 = 24 пробы, timeout 5с",
      res_norm.total_probes == 24 and res_norm.details["timeout"] == 5.0
      and res_norm.details["slow_mode"] is False,
      f"probes={res_norm.total_probes} details={res_norm.details}")
check("нормальная сеть: score 9/24=0.375 < 0.75 -> не принят",
      not res_norm.accepted and abs(res_norm.score - 0.375) < 0.01,
      f"score={res_norm.score}")

check("slow-mode: цели обрезаны до 4 (12 проб), порог 0.5",
      res_slow.total_probes == 12 and res_slow.min_score == 0.5
      and res_slow.details["slow_mode"] is True
      and abs(res_slow.details["rtt_hint_ms"] - 1977.0) < 0.01,
      f"probes={res_slow.total_probes} details={res_slow.details}")
check("slow-mode: 3 ok-цели из 4 -> score 0.75 >= 0.5 -> принят",
      res_slow.accepted and abs(res_slow.score - 0.75) < 0.01,
      f"score={res_slow.score} accepted={res_slow.accepted}")
check("slow-mode: send_sec прокинут в rows",
      all("send_sec" in pr for row in res_slow.targets for pr in row["probes"]))

# ---------------------------------------------------------------------------
# 5. checkers/dpi.py: rtt_hint_ms течёт в сьют (тот же core-процесс)
# ---------------------------------------------------------------------------
print("== checkers/dpi.py ==")
dpi_src = (ROOT / "checkers" / "dpi.py").read_text(encoding="utf-8")
check("check_node_dpi_detailed принимает rtt_hint_ms",
      "rtt_hint_ms: float = 0.0" in dpi_src and "rtt_hint_ms=rtt_hint_ms" in dpi_src)
check("сьют зовётся на том же core-процессе с rtt-хинтом",
      "_run_zapret_checks(" in dpi_src and dpi_src.count("rtt_hint_ms") >= 3)
check("амнистия suite_slow_network сохранена (v8.1)",
      "suite_slow_network" in dpi_src and "DPI_SUITE_SLOW_MIN_PROBES" in dpi_src)

# ---------------------------------------------------------------------------
# 6. Структура pipeline: порядок этапов и отчёт
# ---------------------------------------------------------------------------
print("== pipeline structure ==")
src = (ROOT / "subgen" / "pipeline.py").read_text(encoding="utf-8")

pos_initial = src.find("initial_check_report = {")
pos_network = src.find("network_rtt_ms = _median_initial_latency(")
pos_tg = src.find("# Продвинутая Telegram-проверка")
pos_dpi = src.find("# DPI-проверка (обход блокировок)")
pos_tg_report = src.find("telegram_pro_report = {")

check("сетевой профиль считается сразу после initial_check",
      0 < pos_initial < pos_network < pos_tg, f"{pos_initial}<{pos_network}<{pos_tg}")
check("telegram-проверка стоит ДО DPI-этапа",
      0 < pos_tg < pos_dpi, f"tg={pos_tg} dpi={pos_dpi}")
check("telegram-блок завершается до DPI (отчёт tg выше dpi)",
      0 < pos_tg_report < pos_dpi, f"tg_report={pos_tg_report} dpi={pos_dpi}")
check("кэш dpi хранит итог классика+сьют (res.row)",
      "cache_result(w.node.raw_url, \"dpi\", passed, res.row()" in src)
check("suite встроен в DPI-этап (log-строка как у юзера)",
      "suite=on (zapret-методика" in src)
check("DPI+suite-файлы сохраняются из DPI-этапа",
      "DPI+suite-passed" in src)
check("отчёт содержит network-профиль",
      '"network": network_report' in src)
check("отчёт содержит dpi-секцию",
      '"dpi": dpi_report' in src)
check("регистрация этапов: telegram раньше dpi",
      0 < src.find('add_stage("telegram_pro"') < src.find('add_stage("dpi"'))
check("адаптивный таймаут Telegram от RTT",
      "network_rtt_ms / 1000.0 * 6.0" in src)
check("rtt_hint передаётся в DPI-проверку из конвейера",
      "rtt_hint_ms=network_rtt_ms" in src)
check("параметры сьюта адаптируются в конвейере (баннер/отчёт)",
      "suite_params = effective_suite_params(" in src)
check("нет отдельного zapret-этапа (v8.1: сьют внутри DPI, алиас на dpi)",
      "elif args.zapret_check:" not in src and "suite_ran_in_dpi" not in src)

# ---------------------------------------------------------------------------
# 7. Регресс v8.1: ai_geo и UI (инцидент «пропал тумблер нейросетей»)
# ---------------------------------------------------------------------------
print("== v8.1 regress (ai_geo / UI) ==")
check("checkers/ai_geo.py на месте", (ROOT / "checkers" / "ai_geo.py").exists())
check("checkers/hostres.py на месте", (ROOT / "checkers" / "hostres.py").exists())
check("bin/xray.exe и bin/sing-box.exe в сборке",
      (REPO_ROOT / "bin" / "xray.exe").exists() and (REPO_ROOT / "bin" / "sing-box.exe").exists())

start_page = (ROOT / "ui" / "pages" / "start_page.py").read_text(encoding="utf-8")
check("тумблер ИИ-гео в UI (ai_strict) не потерян",
      "toggle_ai_strict" in start_page and "ИИ-гео" in start_page)
check("zapret-тьюмблер старой версии НЕ вернулся (v8.1: сьют = часть DPI)",
      "toggle_zapret" not in start_page)

recheck_page = (ROOT / "ui" / "pages" / "recheck_page.py").read_text(encoding="utf-8")
check("STAGE_ORDER синхронизирован с recheck_page (включая новый порядок)",
      set(pipeline.STAGE_ORDER) == {"ping", "initial", "telegram_pro", "dpi", "dpi_active",
                                    "ai_geo", "route", "resilience", "recheck"}
      and pipeline.STAGE_ORDER.index("telegram_pro") < pipeline.STAGE_ORDER.index("dpi"))
check("recheck_page: telegram_pro стоит до dpi в списке UI",
      recheck_page.find('("telegram_pro"') < recheck_page.find('("dpi"'))

# ---------------------------------------------------------------------------
# 8. Синтаксис/импорт затронутых модулей
# ---------------------------------------------------------------------------
print("== import ==")
try:
    import importlib
    importlib.reload(zapret)
    importlib.reload(pipeline)
    check("модули перезагружаются без ошибок", True)
except Exception as exc:  # noqa: BLE001
    check("модули перезагружаются без ошибок", False, str(exc))

print()
print(f"ИТОГО [{ROOT.name}]: {PASS} ok, {FAIL} FAIL")
sys.exit(1 if FAIL else 0)
