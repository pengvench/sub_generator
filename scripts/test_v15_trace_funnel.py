#!/usr/bin/env python3
"""v15: тесты фиксов по анализу лог.zip (2026-09-19).

Покрывает:
  1. FunnelTracker — воронка потерь по подпискам (register/checkpoint/
     funnel_for_source/lost_at/report/write_log).
  2. Пропагация upload_kbps/tg_media_kbps из telegram-pro в экспорт
     (баг «upload_kbps: null, tg_media_kbps: null» при живых замерах).
  3. _node_source_url: discovered-узлы (голые XrayNode) больше не дают
     «(источник неизвестен)» — счётчик discovered в sources_report.
  4. Resilience: rtt_hint передаётся ВСЕГДА (не только >=1200мс).
  5. route.py: допуск ОДНОГО потерянного зонда (5 зондов: 1/5 = ок, 2/5 = fail).
  6. probing._wait_socks_port: ожидание порта вместо слепого sleep(0.2);
     quick-пинг использует его; per-target timeout 2.5с.
  7. configs: xhttp БЕЗ mux + passthrough extra; mux остаётся для tcp/vision.
  8. types._safe_fingerprint: fp=chrome из ссылки НЕ подменяется.
  9. trace.log/секция trace в report.json пишутся конвейером.
"""
from __future__ import annotations

import sys
import json
import re
import time
import socket
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))


def main() -> int:
    print("== 1. FunnelTracker: воронка ==")
    from subgen.trace import FunnelTracker, trace_key, node_source, STAGES
    from runtime.parse import parse_node_link

    raw = [
        ("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?type=tcp#A1", "https://sub-a"),
        ("vless://22222222-2222-2222-2222-222222222222@5.6.7.8:443?type=tcp#B1", "https://sub-b"),
        ("vless://33333333-3333-3333-3333-333333333333@9.10.11.12:443?type=tcp#C1", "https://sub-c"),
    ]
    nodes = [parse_node_link(u, source_url=s) for u, s in raw]

    class Wrap:
        def __init__(self, node):
            self.node = node

    t = FunnelTracker()
    n_added = t.register(nodes)
    check("register возвращает число новых", n_added == 3, str(n_added))
    check("повторная регистрация идемпотентна", t.register(nodes) == 0)

    t.checkpoint("quick", [Wrap(nodes[0]), Wrap(nodes[1])], {trace_key(nodes[2]): "quick_ping_failed"})
    t.checkpoint("max_ping", [Wrap(nodes[0]), Wrap(nodes[1])])
    t.checkpoint("initial", [Wrap(nodes[0])], {trace_key(nodes[1]): "connection_failed"})
    for st in ("telegram", "services", "resilience", "ai_geo", "recheck", "exported"):
        t.checkpoint(st, [Wrap(nodes[0])])

    fa = t.funnel_for_source("https://sub-a")
    check("полностью прошедший узел: все стадии = 1", all(v == 1 for v in fa.values()), str(fa))
    fb = t.funnel_for_source("https://sub-b")
    check("узел, умерший на initial: quick/max_ping/initial=1, дальше 0",
          fb["quick"] == 1 and fb["max_ping"] == 1 and fb["initial"] == 1 and fb["telegram"] == 0
          and fb["exported"] == 0, str(fb))
    fc = t.funnel_for_source("https://sub-c")
    check("узел, умерший на quick: quick=1, max_ping=0", fc["quick"] == 1 and fc["max_ping"] == 0, str(fc))
    lb = t.lost_at("https://sub-b")
    check("lost_at: стадия+причина", lb == {"initial": {"connection_failed": 1}}, str(lb))
    lc = t.lost_at("https://sub-c")
    check("lost_at для quick-отвала", lc == {"quick": {"quick_ping_failed": 1}}, str(lc))

    rep = t.report()
    check("report: stages по порядку", rep["stages"] == STAGES)
    check("report: 3 источника", len(rep["sources"]) == 3)
    finals = {s["source"]: s["final"] for s in rep["sources"]}
    check("report: final по источникам", finals == {"https://sub-a": 1, "https://sub-b": 0, "https://sub-c": 0})
    keys = {n["key"]: n for n in rep["nodes"]}
    check("report.nodes: только дошедшие до quick или отвалившиеся позже",
          set(keys) == {trace_key(nodes[0]), trace_key(nodes[1])}, str(set(keys)))
    check("report.nodes: причина отвала сохранена",
          keys[trace_key(nodes[1])]["reason"] == "connection_failed")
    check("report.nodes: dropped_at сохранён",
          keys[trace_key(nodes[1])]["dropped_at"] == "initial")

    tmpdir = Path(tempfile.mkdtemp())
    log_path = tmpdir / "trace.log"
    t.write_log(log_path, header="тест")
    content = log_path.read_text(encoding="utf-8")
    check("trace.log: заголовок воронки", "ТРАССИРОВКА ПОДПИСОК" in content)
    check("trace.log: секция «ГДЕ ОТВАЛИЛИСЬ»", "ГДЕ ОТВАЛИЛИСЬ" in content)
    check("trace.log: точечные потери после quick", "ОТВАЛИЛИСЬ ПОСЛЕ QUICK-ПИНГА" in content)
    check("trace.log: причина в точечных потерях", "connection_failed" in content)
    check("trace.log: источник в таблице", "https://sub-b" in content)
    s = t.summary_line("exported")
    check("summary_line: живых из зарегистрированных", "живых 1 из 3" in s, s)

    print("== 2. Пропагация upload/tg_media в экспорт ==")
    from runtime.types import XrayProbeResult

    w = XrayProbeResult(nodes[0], True, "ready", 100.0, 1, 1, "xray")
    res = XrayProbeResult(nodes[0], True, "ready", 100.0, 1, 1, "xray")
    # то, что делает v15-патч в pipeline: метрики этапа пишутся в узел
    res.upload_kbps = 6124.5
    res.tg_media_kbps = 7045.9
    if res.upload_kbps is not None:
        w.upload_kbps = float(res.upload_kbps)
    if res.tg_media_kbps is not None:
        w.tg_media_kbps = float(res.tg_media_kbps)
    check("метрики записываются в item", w.upload_kbps == 6124.5 and w.tg_media_kbps == 7045.9)

    from subgen.geo import serialize_working
    w.ai_geo_country = "DE"  # слепок страны — geo-lookup не нужен
    rows = serialize_working([w], {}, [time.time()], timeout=1.0, progress=lambda *a: None)
    check("serialize_working подхватывает метрики",
          rows[0]["upload_kbps"] == 6124.5 and rows[0]["tg_media_kbps"] == 7045.9,
          str(rows[0].get("upload_kbps")) + " " + str(rows[0].get("tg_media_kbps")))

    # исходник конвейера содержит пропагацию (охрана от отката)
    src = (ROOT / "python" / "subgen" / "pipeline.py").read_text(encoding="utf-8")
    check("pipeline: w.upload_kbps = float(res.upload_kbps)",
          re.search(r"w\.upload_kbps\s*=\s*float\(res\.upload_kbps\)", src) is not None)
    check("pipeline: w.tg_media_kbps = float(res.tg_media_kbps)",
          re.search(r"w\.tg_media_kbps\s*=\s*float\(res\.tg_media_kbps\)", src) is not None)

    print("== 3. _node_source_url: голые XrayNode ==")
    from subgen.pipeline import _node_source_url
    check("XrayNode напрямую", _node_source_url(nodes[1]) == "https://sub-b",
          _node_source_url(nodes[1]))
    check("обёртка XrayProbeResult", _node_source_url(w) == "https://sub-a",
          _node_source_url(w))

    from subgen.pipeline import _build_sources_report
    rep2 = _build_sources_report(["https://sub-a", "https://sub-b", "https://sub-c"],
                                 [nodes[0], nodes[1], nodes[2]], [w])
    by_src = {e["source"]: e for e in rep2["nodes"]}
    check("sources_report: discovered у источника B = 1 (был 0)",
          by_src["https://sub-b"]["discovered"] == 1, str(by_src["https://sub-b"]))
    check("sources_report: exported у A = 1", by_src["https://sub-a"]["exported"] == 1)
    check("sources_report: B не «пустой» (была empty=True)",
          by_src["https://sub-b"]["empty"] is False)

    print("== 4. Resilience rtt_hint всегда ==")
    check("pipeline: порог >= SLOW_NETWORK_RTT_MS только для timeout-адаптации",
          re.search(r"if network_rtt_ms and network_rtt_ms > 0:\s*\n\s*resilience_rtt_hint = network_rtt_ms",
                    src) is not None)
    check("pipeline: старый гейт >= SLOW_NETWORK_RTT_MS на rtt_hint убран",
          re.search(r"network_rtt_ms >= SLOW_NETWORK_RTT_MS:\s*\n\s*resilience_rtt_hint", src) is None)
    # симуляция порогов: p50=804мс
    from checkers.route import route_thresholds
    th = route_thresholds(804.0)
    check("пороги масштабируются от p50=804: avg<=804", th["avg_ms"] == 804.0, str(th))
    check("пороги масштабируются от p50=804: p95<=1206", th["p95_ms"] == 1206.0, str(th))
    check("пороги масштабируются от p50=804: jitter<=201", th["jitter_ms"] == 201.0, str(th))
    th0 = route_thresholds(None)
    check("без хинта — базовые пороги", th0["avg_ms"] == 500.0 and th0["jitter_ms"] == 80.0)

    print("== 5. route: допуск одного потерянного зонда ==")
    from checkers.route import _run_route

    class FakeSocks:
        """Эмуляция SOCKS-порта: отвечает на k из n замеров."""

        def __init__(self, port, ok_count, total, rtt_ms=300.0):
            self.port = port
            self.ok_count = ok_count
            self.total = total
            self.rtt = rtt_ms
            self.served = 0

    # _run_route меряет через _rtt_probe(socks_host, socks_port, timeout) —
    # подменим его монкипатчем на детерминированный
    import checkers.route as route_mod

    orig_rtt = route_mod._rtt_probe
    try:
        state = {"ok": 0}

        def fake_rtt(host, port, timeout, **kw):
            state["ok"] += 1
            # 5 зондов: один (3-й) «теряется»
            if state["ok"] == 3:
                return None
            return 300.0

        route_mod._rtt_probe = fake_rtt
        res5 = _run_route("127.0.0.1", 1, 3.0, probes=5)
        check("5 зондов, 1 потерян (20%): узел ЖИВ (был high_loss)",
              res5.accepted is True and res5.reason == "ready",
              f"accepted={res5.accepted} reason={res5.reason} loss={res5.loss}")

        state["ok"] = 0

        def fake_rtt2(host, port, timeout, **kw):
            state["ok"] += 1
            if state["ok"] in (2, 4):
                return None
            return 300.0

        route_mod._rtt_probe = fake_rtt2
        res52 = _run_route("127.0.0.1", 1, 3.0, probes=5)
        check("5 зондов, 2 потеряны (40%): узел мёртв (high_loss)",
              res52.accepted is False and res52.reason == "high_loss",
              f"accepted={res52.accepted} reason={res52.reason}")
    finally:
        route_mod._rtt_probe = orig_rtt

    print("== 6. _wait_socks_port ==")
    from runtime.probing import _wait_socks_port, _SOCKS_PORT_WAIT_SEC

    check("потолок ожидания порта 2.5с", _SOCKS_PORT_WAIT_SEC == 2.5)

    class FakeProc:
        def poll(self):
            return None

    # порт открывается через 0.4с
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    def opener():
        time.sleep(0.4)
        try:
            conn, _ = srv.accept()
            conn.close()
        except OSError:
            pass  # сервер могли закрыть раньше — не важно

    th_ = threading.Thread(target=opener, daemon=True)
    th_.start()
    t0 = time.monotonic()
    ok = _wait_socks_port(FakeProc(), port, timeout=2.5)
    dt = time.monotonic() - t0
    check("порт поднялся позже 0.2с — ожидание дождалось", ok is True, f"dt={dt:.2f}s")
    check("ожидание завершилось сразу после listen", dt < 0.8, f"dt={dt:.2f}s")
    srv.close()

    # порт никогда не поднимется
    t0 = time.monotonic()
    ok2 = _wait_socks_port(FakeProc(), 1, timeout=0.4)  # порт 1 — никто не слушает
    dt2 = time.monotonic() - t0
    check("порт не поднялся → False за ~timeout", ok2 is False and dt2 < 0.8, f"dt={dt2:.2f}s")

    # быстрый отказ: процесс упал
    class DeadProc:
        def poll(self):
            return 1

    t0 = time.monotonic()
    ok3 = _wait_socks_port(DeadProc(), 1, timeout=2.5)
    check("процесс упал → False мгновенно", ok3 is False and time.monotonic() - t0 < 0.3)

    # quick-ping использует ожидание порта
    srcp = (ROOT / "python" / "runtime" / "probing.py").read_text(encoding="utf-8")
    check("quick-ping зовёт _wait_socks_port",
          "_wait_socks_port(proc, port, _SOCKS_PORT_WAIT_SEC)" in srcp)
    check("слепой sleep(0.2) убран из quick-ping", "time.sleep(0.2)\n" not in srcp)
    check("per-target timeout 2.5с", "min(2.5," in srcp)
    check("причина core_not_listening различается", "core_not_listening" in srcp)

    # with_node_process тоже ждёт порт
    srcs = (ROOT / "python" / "runtime" / "stress.py").read_text(encoding="utf-8")
    check("with_node_process ждёт порт (_wait_socks_port)",
          "_wait_socks_port(proc, port, 2.5)" in srcs)
    check("слепой sleep(0.4) убран из with_node_process", "time.sleep(0.4)" not in srcs)

    print("== 7. configs: xhttp без mux + extra ==")
    from runtime.configs import _xray_config, _xray_outbound

    xhttp_url = ("vless://79311970-7c2a-43aa-8675-61e89db523af@151.101.213.145:443"
                 "?security=tls&type=xhttp&path=%2F&host=oh1.global.ssl.fastly.net"
                 "&mode=packet-up"
                 "&extra=%7B%22scMaxEachPostBytes%22%3A%221000000%22%2C%22scMaxConcurrentPosts%22%3A100%7D"
                 "&sni=accounts.fastly.com&fp=chrome&alpn=h3#happ")
    node = parse_node_link(xhttp_url, source_url="test")
    ob = _xray_outbound(node)
    check("xhttp: mux ВЫКЛЮЧЕН", "mux" not in ob, str(ob.get("mux")))
    xs = ob["streamSettings"].get("xhttpSettings", {})
    check("xhttp: extra прокинут", xs.get("extra", {}).get("scMaxConcurrentPosts") == 100, str(xs.get("extra")))
    check("xhttp: mode прокинут", xs.get("mode") == "packet-up")

    tcp_url = ("vless://e6910e16-0d75-4f74-89c6-2f9226d6b41e@test.example.com:443"
               "?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality"
               "&sni=promokod.com&fp=qq&pbk=X&sid=50#de")
    node2 = parse_node_link(tcp_url, source_url="test")
    ob2 = _xray_outbound(node2)
    check("tcp+vision: mux остался", "mux" in ob2 and ob2["mux"]["concurrency"] == -1)

    ws_url = ("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@5.6.7.8:443"
              "?type=ws&security=tls&path=%2Fws#ws")
    node3 = parse_node_link(ws_url, source_url="test")
    ob3 = _xray_outbound(node3)
    check("ws: mux остался (concurrency 8)", "mux" in ob3 and ob3["mux"]["concurrency"] == 8)

    spl = xhttp_url.replace("type=xhttp", "type=splithttp")
    node4 = parse_node_link(spl, source_url="test")
    ob4 = _xray_outbound(node4)
    check("splithttp: mux ВЫКЛЮЧЕН", "mux" not in ob4)
    check("splithttp: extra прокинут",
          ob4["streamSettings"].get("splithttpSettings", {}).get("extra", {}).get("scMaxEachPostBytes") == "1000000")

    print("== 8. fp из ссылки не подменяется ==")
    from runtime.types import _safe_fingerprint
    check("fp=chrome сохраняется", _safe_fingerprint("chrome") == "chrome")
    check("fp=firefox сохраняется", _safe_fingerprint("firefox") == "firefox")
    check("fp=qq сохраняется (валидный пресет uTLS)", _safe_fingerprint("qq") == "qq")
    check("пустой fp → firefox", _safe_fingerprint("") == "firefox")
    check("неизвестный fp → firefox", _safe_fingerprint("somesynthetic") == "firefox")
    tls_fp = ob["streamSettings"]["tlsSettings"]["fingerprint"]
    check("в конфиге xhttp fp=chrome (как в ссылке Happ)", tls_fp == "chrome", tls_fp)

    print("== 9. Проводка trace в конвейере/отчёте/UI ==")
    check("pipeline: импорт FunnelTracker", "from subgen.trace import FunnelTracker" in src)
    check("pipeline: регистрация discovered", "tracker.register(discovered)" in src)
    for stage in ("quick", "max_ping", "initial", "telegram", "services", "resilience", "ai_geo", "recheck", "exported"):
        check(f"pipeline: чекпойнт {stage}", f'tracker.checkpoint("{stage}"' in src)
    check("pipeline: trace.log пишется", "trace_log_path" in src and "trace.log" in src)
    check("pipeline: секция trace в report.json", '"trace": trace_report' in src)
    check("pipeline: воронка вливается в sources_report", 'entry["funnel"]' in src)
    check("pipeline: причины quick-отвала из rejected", "quick_drop_reasons" in src)

    app_src = (ROOT / "python" / "ui" / "app.py").read_text(encoding="utf-8")
    check("app.py: колонка «отвалились» в диалоге источников", "отвалились" in app_src)
    check("app.py: _lost_summary читает lost_at", "_lost_summary" in app_src and "lost_at" in app_src)

    # компиляция всех изменённых файлов
    import py_compile
    ok_all = True
    for f in ("python/subgen/trace.py", "python/subgen/pipeline.py", "python/checkers/route.py",
              "python/runtime/probing.py", "python/runtime/stress.py",
              "python/runtime/configs.py", "python/runtime/types.py", "python/ui/app.py"):
        try:
            py_compile.compile(str(ROOT / f), doraise=True)
        except Exception as exc:  # noqa: BLE001
            ok_all = False
            print(f"    compile FAIL {f}: {exc}")
    check("компиляция всех изменённых файлов", ok_all)

    print(f"\n=== v15 trace/funnel: {PASS} PASS, {FAIL} FAIL ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
