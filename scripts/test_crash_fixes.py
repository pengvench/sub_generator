"""Верификация фиксов краша «2026-09-16: приложение тупо крашнулось на
середине теста» (лог.zip пользователя, прогон 20:22→22:57, обрыв на
«[telegram-pro] pool#0 не стартовал — fallback»).

Диагностированный каскад:
  B) singbox_convert._normalize_reality_pbk приводил url-safe base64 к std
     ('-'→'+'): sing-box декодирует public_key через base64.RawURLEncoding
     и отвергает '+' — ДВА упавших пула это доказывают (outbound[14] byte 26
     = позиция первого '+', 109/122 reality-ключей со std-символами).
     => каждый пул с reality-нодой не стартовал, 200 узлов батча уходили
        в per-node fallback;
  A) base.run_with_node поднимал ПОЛНЫЙ XrayCoreRuntime на каждый узел:
     atexit.register (экземпляр живёт вечно) × _load_cached_results
     (873+16650 записей ≈ 20-30 МБ на узел) ≈ 5-6 ГБ удержанной памяти
     + spawn PowerShell на каждый узел + чтение ОБЩЕГО pid-файла с
     терминацией чужого PID (при реюзе — убийство невинного процесса).
     => нативный краш без traceback на ~247-м узле;
  C) один битый outbound ронял весь батч — теперь исключается по индексу
     из ошибки sing-box check, конфиг перестраивается, check повторяется;
  D) исключение одного узла в fallback-циклах прерывало весь этап;
  E) отчёт писался только в конце прогона — краш оставлял «пустые цифры»
     в окне результатов; теперь в начале пишется pending-отчёт.

Запуск: python3 scripts/test_crash_fixes.py  (из корня репозитория).
"""
from __future__ import annotations

import ast
import base64 as b64
import gc
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import weakref
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

ROOT = Path("/home/z/my-project/sub_generator/python")
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail else ""))


# Реальные ключи из упавших конфигов пользователя (sb-pool-*-failed.json).
USER_KEY_0 = "OINuDFEDTdmtFR8QRxAZfQIMPA+wJxfGN1LjB3TFUHo"   # byte 26 = '+'
USER_KEY_200 = "TgaE+83sqLrJ6auwPP2Nq7vDO/xuFqa6uMnG4Au18jg"  # byte 4 = '+'

# ------------------------------------------------- 1. Fix B: pbk → url-safe
from singbox_convert import _normalize_reality_pbk, sing_box_outbound  # noqa: E402


def _urlsafe_ok(text: str) -> bool:
    if not text or "+" in text or "/" in text or "=" in text:
        return False
    if not all(c.isalnum() or c in "-_" for c in text):
        return False
    try:
        b64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
        return True
    except Exception:
        return False


norm0 = _normalize_reality_pbk(USER_KEY_0)
norm200 = _normalize_reality_pbk(USER_KEY_200)
check("B1. ключ пользователя (пул#0, byte 26) → url-safe",
      _urlsafe_ok(norm0) and norm0 == USER_KEY_0.replace("+", "-"),
      f"{USER_KEY_0!r} → {norm0!r}")
check("B2. ключ пользователя (пул#200, byte 4) → url-safe",
      _urlsafe_ok(norm200) and norm200 == USER_KEY_200.replace("+", "-").replace("/", "_"),
      f"→ {norm200!r}")

urlsafe_key = "OINuDFEDTdmtFR8QRxAZfQIMPA-wJxfGN1LjB3TFUHo"
check("B3. url-safe ключ проходит без изменений",
      _normalize_reality_pbk(urlsafe_key) == urlsafe_key)

std_key = "abc+/abc="
check("B4. std-ключ конвертируется в url-safe",
      _urlsafe_ok(_normalize_reality_pbk(std_key)))

padded_key = "OINuDFEDTdmtFR8QRxAZfQIMPA-wJxfGN1LjB3TFUHo=="
check("B5. padding срезается",
      _normalize_reality_pbk(padded_key) == urlsafe_key)

check("B6. мусор → '' (узел unsupported, не валит батч)",
      _normalize_reality_pbk("-") == "" and _normalize_reality_pbk("abc!") == "")

check("B7. пустой → пустой (без исключения)",
      _normalize_reality_pbk("") == "" and _normalize_reality_pbk(None) == "")

# Все reality-ключи из РЕАЛЬНЫХ упавших конфигов теперь валидны.
failed_cfgs = list(Path("/home/z/my-project/upload/log_extracted/.runtime_cache").glob("sb-pool-*-failed.json"))
if failed_cfgs:
    total = fixed = 0
    for cfg_path in failed_cfgs:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        for ob in cfg.get("outbounds", []):
            pk = ((ob.get("tls") or {}).get("reality") or {}).get("public_key")
            if not pk:
                continue
            total += 1
            # «Расконвертируем» обратно в исходный вид (инвариант алфавита
            # при конвертации туда-обратно не меняет декодируемость) и
            # прогоняем через новый нормализатор.
            if _urlsafe_ok(_normalize_reality_pbk(pk)):
                fixed += 1
    check("B8. все reality-ключи обоих упавших конфигов проходят",
          total > 0 and fixed == total, f"{fixed}/{total}")
else:
    check("B8. все reality-ключи обоих упавших конфигов проходят", False,
          "sb-pool-*-failed.json не найдены — лог.zip не распакован")

# End-to-end: sing_box_outbound эмитит url-safe public_key.
# ВАЖНО: '+' в query URL парсится parse_qs'ом как пробел — ключ с '+'
# приходит из подписок в %2B-кодировке (так было и у пользователя).
from xray_runtime import parse_node_link  # noqa: E402

bad_node_url = (
    "vless://01a21e01-6098-4c3b-a6fd-1a04d64d0c7f@50.7.193.140:443"
    f"?security=reality&pbk={quote(USER_KEY_0, safe='')}&sni=os.betust.net&type=tcp"
    "&flow=xtls-rprx-vision&fp=firefox#outbound14-case"
)
bad_node = parse_node_link(bad_node_url)
ob, reason = sing_box_outbound(bad_node, tag="proxy-test")
pk_emitted = ((ob or {}).get("tls") or {}).get("reality") or {}
check("B9. sing_box_outbound эмитит url-safe public_key (кейс outbound[14])",
      ob is not None and _urlsafe_ok(pk_emitted.get("public_key", "")),
      f"reason={reason}, pk={pk_emitted.get('public_key')!r}")

# ------------------------------------------------- 2. Fix A: lightweight runtime
from xray_runtime import XrayRuntimeConfig, XrayCoreRuntime  # noqa: E402

tmp = Path(tempfile.mkdtemp(prefix="crashfix-"))
out_dir = tmp / "cache"
out_dir.mkdir(parents=True, exist_ok=True)

# Кеш «прошлого прогона» — как у пользователя (working 873 / rejected 16650
# — здесь уменьшенные, чтобы тест шёл быстро; инвариант тот же).
working_rows = [
    {
        "url": f"vless://01a21e01-6098-4c3b-a6fd-1a04d64d0c7f@10.0.0.{i}:443"
                  f"?security=reality&pbk={urlsafe_key}&type=tcp#w{i}",
        "accepted": True, "reason": "ready", "latency_ms": 100 + i,
        "runtime": "xray", "source": "test",
        "fully_checked": i % 2 == 0,
    }
    for i in range(200)
]
rejected_rows = [
    {
        "url": f"vless://01a21e01-6098-4c3b-a6fd-1a04d64d0c7f@11.0.{i // 250}.{i % 250}:443"
               f"?security=reality&pbk={urlsafe_key}&type=tcp#r{i}",
        "accepted": False, "reason": "quick_ping_failed", "latency_ms": None,
        "runtime": "xray", "source": "test",
    }
    for i in range(3000)
]
(out_dir / "xray_working.json").write_text(json.dumps(working_rows), encoding="utf-8")
(out_dir / "xray_rejected.json").write_text(json.dumps(rejected_rows), encoding="utf-8")


def _mk_runtime(lightweight: bool) -> XrayCoreRuntime:
    return XrayCoreRuntime(
        XrayRuntimeConfig(subscription_urls=[], probe_workers=1,
                          probe_timeout_sec=5.0, max_servers=0),
        root_dir=REPO, out_dir=out_dir, log_sink=lambda msg: None,
        lightweight=lightweight,
    )


import atexit as _atexit  # noqa: E402

before = _atexit._ncallbacks()
rt_light = _mk_runtime(lightweight=True)
after_light = _atexit._ncallbacks()
check("A1. lightweight НЕ регистрирует atexit", before == after_light,
      f"atexit: {before} → {after_light}")

rt_full = _mk_runtime(lightweight=False)
after_full = _atexit._ncallbacks()
check("A2. полный runtime регистрирует atexit (как раньше)",
      after_full == after_light + 1)

check("A3. lightweight НЕ грузит кеши (memory-bomb отключён)",
      rt_light.last_working == [] and rt_light.last_rejected == []
      and rt_light.ping_candidates == [])
check("A4. полный runtime грузит кеши (поведение сохранено)",
      len(rt_full.last_working) == 100 and len(rt_full.ping_candidates) == 100
      and len(rt_full.last_rejected) == 3000)

# GC: lightweight умирает без ссылки; полный — прибит к atexit навечно.
wref_light = weakref.ref(rt_light)
del rt_light
gc.collect()
check("A5. lightweight собирается GC (утечки экземпляров нет)",
      wref_light() is None)
wref_full = weakref.ref(rt_full)
del rt_full
gc.collect()
check("A6. полный runtime удерживается atexit (наблюдаемая утечка ДО фикса)",
      wref_full() is not None)

# stop() lightweight не трогает ОБЩИЙ pid-файл и не убивает чужой процесс.
sleeper = subprocess.Popen(["sleep", "60"])
(out_dir / "xray_runtime.pid").write_text(
    json.dumps({"pid": sleeper.pid, "binary": "sleep", "config": "x",
                "started_at": time.time()}), encoding="utf-8")
pid_file_existed = (out_dir / "xray_runtime.pid").exists()

rt_guard = _mk_runtime(lightweight=True)
rt_guard.stop()
sleeper_alive = sleeper.poll() is None
pid_file_still = (out_dir / "xray_runtime.pid").exists()
check("A7. lightweight stop() НЕ убивает PID из общего pid-файла",
      sleeper_alive,
      f"sleeper pid={sleeper.pid} alive={sleeper_alive}")
check("A8. lightweight stop() НЕ удаляет общий pid-файл",
      pid_file_existed and pid_file_still)
job_after = getattr(rt_guard, "_job_handle", "missing")
check("A9. lightweight stop() закрывает job и НЕ создаёт новый",
      job_after is None, f"_job_handle={job_after!r}")

# Полный runtime по-прежнему чистит pid-файл (владелец состояния).
rt_owner = _mk_runtime(lightweight=False)
rt_owner.stop()
owner_unlinked = not (out_dir / "xray_runtime.pid").exists()
check("A10. полный stop() чистит pid-файл (поведение владельца)",
      owner_unlinked)
sleeper.poll()  # мог быть убит полным stop() — штатно
if sleeper.poll() is None:
    sleeper.kill()
sleeper.wait()

# _cleanup_stale_processes (PowerShell на Windows) не вызывается для lightweight.
with patch.object(XrayCoreRuntime, "_cleanup_stale_processes",
                  wraps=XrayCoreRuntime._cleanup_stale_processes) as spy:
    _mk_runtime(lightweight=True)
    check("A11. lightweight НЕ вызывает _cleanup_stale_processes (PowerShell)",
          spy.call_count == 0, f"calls={spy.call_count}")

# Замер удержанной памяти (информационный, но с порогом).
def _rss_mb() -> float:
    with open("/proc/self/status", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024.0
    return -1.0


gc.collect()
base_rss = _rss_mb()
held: list[XrayCoreRuntime] = []
for _ in range(30):
    held.append(_mk_runtime(lightweight=False))
gc.collect()
full_rss = _rss_mb()
del held
gc.collect()
light_rss = _rss_mb()
for _ in range(30):
    r = _mk_runtime(lightweight=True)
    del r
gc.collect()
light2_rss = _rss_mb()
full_growth = max(0.0, full_rss - base_rss)
light_growth = max(0.0, light2_rss - light_rss)
check("A12. память: 30 полных runtime удерживают на порядок больше",
      full_growth > 1.0 and light_growth < max(1.0, full_growth * 0.25),
      f"полные +{full_growth:.1f} МБ (≈{full_growth/30:.2f}/шт, "
      f"на 246 узлах ≈ {full_growth/30*246/1024:.1f} ГБ) vs "
      f"lightweight +{light_growth:.1f} МБ")

# ------------------------------------------- 3. Fix C: пул исключает битые outbound
from runtime.singbox_pool import SingBoxBatchPool  # noqa: E402


def _mknode(pbk: str | None, i: int, port: int = 443):
    q = f"?security=reality&pbk={quote(pbk, safe='')}&type=tcp&flow=xtls-rprx-vision" if pbk else "?type=tcp"
    return parse_node_link(
        f"vless://01a21e01-6098-4c3b-a6fd-1a04d64d0c7f@10.1.0.{i}:{port}{q}#n{i}"
    )


good1, bad, good2 = _mknode(urlsafe_key, 1), _mknode(USER_KEY_0, 2), _mknode(None, 3)
pool = SingBoxBatchPool([good1, bad, good2], root_dir=REPO, batch_id=0,
                        sing_box_binary_path="/bin/true", log_sink=lambda m: None)
cfg_obs = pool._config["outbounds"]
bad_idx = next(i for i, ob in enumerate(cfg_obs)
               if ob.get("tag") == pool._node_key_to_tag[bad.key])
dropped = pool._drop_outbound_at(bad_idx)
check("C1. _drop_outbound_at исключает узел и возвращает его key",
      dropped == bad.key and bad.key in pool.unsupported_keys)
check("C2. селектор перестроен без тега битого узла",
      all(t != f"proxy-{bad_idx+1}" for t in cfg_obs[-3]["outbounds"])
      and len(pool._node_key_to_tag) == 2)
check("C3. _drop_outbound_at(selector-индекс) → None (шаблон не трогаем)",
      pool._drop_outbound_at(len(cfg_obs) - 3) is None)
check("C4. _proxy_outbound_count считает только прокси",
      pool._proxy_outbound_count() == 2)

m14 = re.search(r"outbound\[(\d+)\]",
                "FATAL[0000] initialize outbound[14]: decode public_key: "
                "illegal base64 data at input byte 26")
m0 = re.search(r"outbound\[(\d+)\]",
               "FATAL[0000] initialize outbound[0]: decode public_key: "
               "illegal base64 data at input byte 4")
check("C5. парсер индекса из ошибок sing-box (из лога пользователя)",
      m14 is not None and m14.group(1) == "14" and m0 is not None and m0.group(1) == "0")

# Интеграционно: фейковый sing-box, чек падает на узле с портом 4143
# (имитация несовместимости, о которой конвертер не знает) — пул должен
# исключить битый outbound и СТАРТОВАТЬ, а не свалить весь батч в fallback.
BAD_PORT = 4143
good1p, badp, good2p = (_mknode(urlsafe_key, 1, 8443),
                        _mknode(urlsafe_key, 2, BAD_PORT),
                        _mknode(None, 3, 9443))
fake_bin = tmp / "fake-sing-box"
fake_bin.write_text(
    "#!/usr/bin/env python3\n"
    "import json, sys\n"
    "if len(sys.argv) > 2 and sys.argv[1] == 'check':\n"
    "    cfg = json.load(open(sys.argv[3], encoding='utf-8'))\n"
    "    for i, ob in enumerate(cfg.get('outbounds', [])):\n"
    "        if ob.get('server_port') == 4143:\n"
    "            sys.stderr.write(f'FATAL[0000] initialize outbound[{i}]: "
    "decode public_key: illegal base64 data at input byte 4\\n')\n"
    "            sys.exit(1)\n"
    "    sys.exit(0)\n"
    "import time; time.sleep(60)\n",
    encoding="utf-8",
)
fake_bin.chmod(0o755)

pool2 = SingBoxBatchPool([good1p, badp, good2p], root_dir=REPO, batch_id=7,
                         sing_box_binary_path=str(fake_bin),
                         log_sink=lambda m: None)
logs: list[str] = []
pool2._log = logs.append
with patch.object(SingBoxBatchPool, "_wait_clash_api",
                  lambda self, timeout=3.0: True):
    started = pool2.start()
try:
    check("C6. пул стартует после исключения битого outbound (интеграция)",
          started and pool2.is_started(),
          "; ".join(logs))
    check("C7. битый узел помечен unsupported (уйдёт через xray-путь)",
          badp.key in pool2.unsupported_keys
          and good1p.key not in pool2.unsupported_keys
          and good2p.key not in pool2.unsupported_keys)
    conf = json.loads(Path(pool2._config_path).read_text(encoding="utf-8"))
    pks = [((ob.get("tls") or {}).get("reality") or {}).get("public_key")
           for ob in conf["outbounds"]]
    check("C8. в стартовавшем конфиге только валидные ключи",
          all(_urlsafe_ok(pk) for pk in pks if pk))
finally:
    pool2.stop()

# --------------------------- 4. Fix D: fallback-циклы глотают сбой узла
src_pipeline = (ROOT / "subgen" / "pipeline.py").read_text(encoding="utf-8")
tree = ast.parse(src_pipeline)


def _func_def(name: str) -> ast.FunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _has_cancel_reraise(fn: ast.FunctionDef) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.ExceptHandler):
            raises = [n for n in ast.walk(node) if isinstance(n, ast.Raise)]
            checks = [n for n in ast.walk(node)
                      if isinstance(n, ast.Constant) and "refresh_cancelled" in str(n.value)]
            if raises and checks:
                return True
    return False


fn_init = _func_def("_check_one_via_fallback")
fn_tg = _func_def("_check_tg_via_fallback")
check("D1. _check_one_via_fallback: try/except + проброс refresh_cancelled",
      fn_init is not None and _has_cancel_reraise(fn_init))
check("D2. _check_tg_via_fallback: try/except + проброс refresh_cancelled",
      fn_tg is not None and _has_cancel_reraise(fn_tg))

# --------------------------- 5. Fix E: pending-отчёт + честный диалог
pending_writes = []
for node in ast.walk(tree):
    if (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "write_report"):
        for arg in node.args:
            if isinstance(arg, ast.Dict):
                for k, v in zip(arg.keys, arg.values):
                    if (isinstance(k, ast.Constant) and k.value == "pending"
                            and isinstance(v, ast.Constant) and v.value is True):
                        pending_writes.append(node.lineno)
check("E1. pipeline пишет pending-отчёт в начале прогона",
      len(pending_writes) == 1, f"строки: {pending_writes}")

src_app = (ROOT / "ui" / "app.py").read_text(encoding="utf-8")
tree_app = ast.parse(src_app)
fn_dlg = _func_def("_show_results_dialog") if False else next(
    (n for n in ast.walk(tree_app)
     if isinstance(n, ast.FunctionDef) and n.name == "_show_results_dialog"), None)
dlg_refs_pending = fn_dlg is not None and any(
    isinstance(n, ast.Constant) and n.value == "pending" for n in ast.walk(fn_dlg))
check("E2. диалог результатов помечает незавершённый прогон",
      dlg_refs_pending)

# --------------------------- 6. Смоук-импорты изменённых модулей
for mod in ("singbox_convert", "runtime.core", "runtime.lifecycle",
            "runtime.singbox_pool", "checkers.base", "subgen.pipeline",
            "ui.app"):
    try:
        if mod == "ui.app":
            # customtkinter отсутствует в headless-песочнице — проверяем AST.
            ast.parse((ROOT / "ui" / "app.py").read_text(encoding="utf-8"))
        else:
            __import__(mod)
        check(f"I1. импорт/парс {mod}", True)
    except Exception as exc:  # noqa: BLE001
        check(f"I1. импорт/парс {mod}", False, str(exc))

shutil.rmtree(tmp, ignore_errors=True)

# --------------------------- итог
print()
passed = sum(1 for _, ok, _ in results if ok)
print(f"ИТОГО: {passed}/{len(results)} PASS")
sys.exit(0 if passed == len(results) else 1)
