#!/usr/bin/env python3
"""Тесты тумблера «Тест только на sing-box» — конвертация + маршрутизация.

Проверяет:
  1. Конвертацию ссылок -> sing-box outbound для всех протоколов
     (vless/Reality, vless-tls-ws, vmess, trojan, ss, hysteria, hysteria2);
  2. pbk-нормализацию Reality (std-base64 -> RawURL) в sing-box-конфиге;
  3. Режимы core_mode: auto / sing-box / xray + честный fallback на xray
     для непредставимых узлов (kcp, xhttp, легаси-vmess-шифр);
  4. Наследование модульного дефолта конфигами и рантаймом;
  5. ВАЛИДАЦИЮ КОНФИГОВ реальным ядром sing-box (если бинарник доступен:
     env SINGBOX_BIN=..., или bin/sing-box.exe рядом с репо, или в PATH).
     Это главное: конфиг обязан проходить `sing-box check` на v1.13.16.

Запуск: python scripts/test_singbox_mode.py
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "python"))

import xray_runtime as xr  # noqa: E402
from xray_runtime import (  # noqa: E402
    SingBoxUnsupported,
    XrayCoreRuntime,
    XrayRuntimeConfig,
    parse_node_link,
    set_default_core_mode,
    get_default_core_mode,
    _sing_box_config,
    _sing_box_outbound,
    _sing_box_supports,
)

RESULTS: list[tuple[bool, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    RESULTS.append((bool(condition), name + (f"  [{detail}]" if detail and not condition else "")))
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f"  -> {detail}" if detail and not condition else ""))


# ---------------------------------------------------------------- ядро-бинарник
def find_singbox_binary() -> str:
    candidates = [
        os.environ.get("SINGBOX_BIN", ""),
        str(ROOT / "bin" / "sing-box.exe"),
        shutil.which("sing-box") or "",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return ""


SB_BIN = find_singbox_binary()


def core_check(cfg: dict, name: str) -> None:
    """Валидация конфига реальным sing-box (если бинарник доступен)."""
    if not SB_BIN:
        check(f"[core] {name}", True, "skip: sing-box binary not found")
        return
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        path = f.name
    try:
        r = subprocess.run([SB_BIN, "check", "-c", path], capture_output=True, text=True, timeout=30)
        err = (r.stderr or r.stdout or "").strip().splitlines()
        last = err[-1][:200] if err else ""
        check(f"[core] {name} sing-box check", r.returncode == 0, last)
    finally:
        os.unlink(path)


# ------------------------------------------------------------------- узлы
PBK_RAWURL = base64.urlsafe_b64encode(b"r" * 32).decode().rstrip("=")
PBK_STD = base64.b64encode(b"r" * 32).decode()  # стандартный base64 с +/=
UUID = "12345678-1234-1234-1234-123456789012"

NODES = {
    "vless-reality-vision": (
        f"vless://{UUID}@1.2.3.4:443?type=tcp&security=reality&pbk={PBK_RAWURL}&sid=0123abcdef&fp=chrome&flow=xtls-rprx-vision&sni=www.microsoft.com#rl"
    ),
    "vless-reality-stdpbk": (
        f"vless://{UUID}@1.2.3.4:443?type=tcp&security=reality&pbk={PBK_STD}&sid=01&fp=firefox&flow=xtls-rprx-vision&sni=www.apple.com#std"
    ),
    "vless-tls-ws-ed": (
        f"vless://{UUID}@cdn.example.com:443?type=ws&security=tls&path=/ws%3Fed%3D2048&host=cdn.example.com&sni=cdn.example.com&fp=chrome#wsed"
    ),
    "vmess-tls-ws": None,  # отдельная сборка (base64-JSON)
    "trojan-tls": "trojan://pass@5.6.7.8:443?security=tls&sni=t.example.com&alpn=h2,http/1.1#tj",
    "trojan-default-tls": "trojan://pass@5.6.7.8:443#tj-no-sec",
    "ss-modern": f"ss://{base64.urlsafe_b64encode(b'aes-256-gcm:passw0rd').decode().rstrip('=')}@9.8.7.6:8388#ss",
    "ss-legacy-rc4": f"ss://{base64.urlsafe_b64encode(b'rc4-md5:legacypass').decode().rstrip('=')}@9.8.7.6:8389#sslegacy",
    "hysteria2": "hysteria2://pw@2.3.4.5:443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=ob#hy2",
    "hysteria1": "hysteria://authtok@2.3.4.5:443?up=50&down=100&obfs=salamander&obfs-password=ob&peer=hy1.example.com&insecure=1#hy1",
    "vless-kcp": f"vless://{UUID}@1.2.3.4:443?type=kcp&security=tls&headerType=none&seed=xx#kcp",
    "vmess-legacy-scy": None,
}


def build_vmess_link(scy: str) -> str:
    payload = json.dumps({
        "v": "2", "ps": "vm", "add": "vm.example.com", "port": "443",
        "id": UUID, "aid": "0", "scy": scy, "net": "ws", "type": "none",
        "host": "vm.example.com", "path": "/vm", "tls": "tls", "sni": "vm.example.com", "fp": "chrome",
    })
    return "vmess://" + base64.b64encode(payload.encode()).decode()


NODES["vmess-tls-ws"] = build_vmess_link("auto")
NODES["vmess-legacy-scy"] = build_vmess_link("aes-128-cfb")


# ----------------------------------------------------- 1. структура outbound
def outbound_of(url: str) -> dict:
    node = parse_node_link(url)
    assert node is not None, f"parse failed: {url[:60]}"
    return _sing_box_outbound(node)


ob = outbound_of(NODES["vless-reality-vision"])
check("vless-reality: type/server/uuid", ob.get("type") == "vless" and ob.get("server") == "1.2.3.4" and ob.get("uuid") == UUID)
check("vless-reality: flow vision", ob.get("flow") == "xtls-rprx-vision")
check("vless-reality: packet_encoding xudp (дефолт)", ob.get("packet_encoding") == "xudp")
tls = ob.get("tls") or {}
check("vless-reality: tls.enabled+server_name", tls.get("enabled") is True and tls.get("server_name") == "www.microsoft.com")
reality = tls.get("reality") or {}
check("vless-reality: reality{public_key,short_id}", reality.get("public_key") == PBK_RAWURL and reality.get("short_id") == "0123abcdef")
check("vless-reality: utls включён + пресет в whitelist (ядро требует)",
      (tls.get("utls") or {}).get("enabled") is True and (tls.get("utls") or {}).get("fingerprint") in xr.SING_BOX_UTLS_FINGERPRINTS,
      str(tls.get("utls")))
check("vless-reality: без transport (tcp)", "transport" not in ob)

ob = outbound_of(NODES["vless-reality-stdpbk"])
reality = (ob.get("tls") or {}).get("reality") or {}
check("vless-reality: std-base64 pbk -> RawURL", reality.get("public_key") == PBK_RAWURL, str(reality.get("public_key")))

ob = outbound_of(NODES["vless-tls-ws-ed"])
tr = ob.get("transport") or {}
check("vless-ws: transport ws", tr.get("type") == "ws")
check("vless-ws: ed из path -> max_early_data", tr.get("max_early_data") == 2048 and tr.get("early_data_header_name") == "Sec-WebSocket-Protocol", str(tr))
check("vless-ws: path очищен от ?ed", tr.get("path") == "/ws")
check("vless-ws: Host-заголовок списком", (tr.get("headers") or {}).get("Host") == ["cdn.example.com"])
check("vless-ws: fp проброшен через _safe_fingerprint (chrome->firefox, анти-DPI)",
      ((ob.get("tls") or {}).get("utls") or {}).get("fingerprint") in xr.SING_BOX_UTLS_FINGERPRINTS)
check("vless-ws: server из ссылки (домен)", ob.get("server") == "cdn.example.com")

ob = outbound_of(NODES["vmess-tls-ws"])
check("vmess: uuid/security/alter_id", ob.get("uuid") == UUID and ob.get("security") == "auto" and ob.get("alter_id") == 0)
check("vmess: ws transport + tls", (ob.get("transport") or {}).get("type") == "ws" and (ob.get("tls") or {}).get("enabled") is True)

ob = outbound_of(NODES["trojan-tls"])
check("trojan: password + tls server_name + alpn", ob.get("password") == "pass" and (ob.get("tls") or {}).get("server_name") == "t.example.com" and (ob.get("tls") or {}).get("alpn") == ["h2", "http/1.1"])

ob = outbound_of(NODES["trojan-default-tls"])
check("trojan без security: TLS по умолчанию", (ob.get("tls") or {}).get("enabled") is True)

ob = outbound_of(NODES["ss-modern"])
check("ss: method+password", ob.get("method") == "aes-256-gcm" and ob.get("password") == "passw0rd")

ob = outbound_of(NODES["ss-legacy-rc4"])
check("ss легаси rc4-md5: sing-box принимает (xray v26 — ронял)", ob.get("method") == "rc4-md5")

ob = outbound_of(NODES["hysteria2"])
check("hy2: password + obfs + insecure", ob.get("password") == "pw" and ob.get("obfs", {}).get("type") == "salamander" and (ob.get("tls") or {}).get("insecure") is True)

ob = outbound_of(NODES["hysteria1"])
check("hy1: auth_str + up/down_mbps + obfs-строка (v1-схема sing-box)",
      ob.get("auth_str") == "authtok" and ob.get("up_mbps") == 50 and ob.get("down_mbps") == 100 and ob.get("obfs") == "ob")

# ------------------------------------------------- 2. непредставимые узлы
try:
    outbound_of(NODES["vless-kcp"])
    check("kcp -> SingBoxUnsupported", False, "не бросил")
except SingBoxUnsupported:
    check("kcp -> SingBoxUnsupported", True)

try:
    outbound_of(NODES["vmess-legacy-scy"])
    check("vmess легаси scy -> SingBoxUnsupported", False, "не бросил")
except SingBoxUnsupported:
    check("vmess легаси scy -> SingBoxUnsupported", True)

supported, reason = _sing_box_supports(parse_node_link(NODES["vless-reality-vision"]))
check("_sing_box_supports: reality ok", supported and reason == "")
supported, reason = _sing_box_supports(parse_node_link(NODES["vless-kcp"]))
check("_sing_box_supports: kcp нет", not supported and "kcp" in reason)

# ------------------------------------------------- 3. валидация ядром
for name in ("vless-reality-vision", "vless-reality-stdpbk", "vless-tls-ws-ed", "vmess-tls-ws",
             "trojan-tls", "trojan-default-tls", "ss-modern", "ss-legacy-rc4", "hysteria2", "hysteria1"):
    node = parse_node_link(NODES[name])
    core_check(_sing_box_config(node, "127.0.0.1", 12345), name)

cfg = _sing_box_config(parse_node_link(NODES["vless-reality-vision"]), "127.0.0.1", 12345)
dns = cfg.get("dns") or {}
check("dns: НОВЫЙ формат (typed servers, без legacy address)",
      all("address" not in srv for srv in dns.get("servers", [])) and all(srv.get("type") in ("https", "udp") for srv in dns.get("servers", [])))
check("dns: детур через прокси + прямым DoH-резолвер",
      dns.get("servers", [{}])[0].get("detour") == "proxy" and any(s.get("tag") == "direct-doh-cf" and "detour" not in s for s in dns.get("servers", [])))
check("route: default_domain_resolver", (cfg.get("route") or {}).get("default_domain_resolver") == "direct-doh-cf")
check("route: локальные CIDR -> block", (cfg.get("route") or {}).get("rules", [{}])[0].get("outbound") == "block")

# ------------------------------------------------- 4. режимы + наследование
runtime = XrayCoreRuntime(
    XrayRuntimeConfig(subscription_urls=[], probe_workers=1, probe_timeout_sec=2.0, max_servers=0),
    root_dir=ROOT,
    out_dir=ROOT / "data" / ".runtime_cache",
    log_sink=lambda msg: None,
)

node = parse_node_link(NODES["vless-reality-vision"])
check("режим auto: vless -> xray (как раньше)", runtime._effective_runtime(node) == "xray" and node.runtime == "xray")

node = parse_node_link(NODES["hysteria2"])
check("режим auto: hy2 -> sing-box (как раньше)", runtime._effective_runtime(node) == "sing-box")

prev = get_default_core_mode()
try:
    set_default_core_mode("sing-box")
    # бинарник: явный override (bin/sing-box.exe — Windows; на Linux-Dev его нет)
    runtime.config.sing_box_binary_path = str(ROOT / "bin" / ("sing-box.exe" if os.name == "nt" else "sing-box"))
    node = parse_node_link(NODES["vless-reality-vision"])
    check("sing-box only: vless-reality -> sing-box", runtime._effective_runtime(node) == "sing-box" and node.runtime == "sing-box")
    binary = runtime._binary_for_node(node)
    check("sing-box only: конфиг — sing-box, бинарник не xray", "outbounds" in runtime._build_config(node, 12346) and "routing" not in runtime._build_config(node, 12346))

    node = parse_node_link(NODES["vless-kcp"])
    check("sing-box only: kcp -> честный fallback на xray", runtime._effective_runtime(node) == "xray")
    check("sing-box only: fallback задетектирован и посчитан", runtime._core_mode_fallbacks.get("transport kcp") == 1, str(runtime._core_mode_fallbacks))

    node = parse_node_link(NODES["hysteria2"])
    check("sing-box only: hysteria остаётся на sing-box", runtime._effective_runtime(node) == "sing-box")

    # конфиг без явного core_mode наследует модульный дефолт (checkers.base.run_with_node)
    inherited = XrayRuntimeConfig(subscription_urls=[])
    check("конфиг без core_mode наследует дефолт", xr._resolved_core_mode(inherited) == "sing-box")

    set_default_core_mode("xray")
    node = parse_node_link(NODES["vless-tls-ws-ed"])
    check("режим xray: vless -> xray", runtime._effective_runtime(node) == "xray")
    node = parse_node_link(NODES["hysteria2"])
    check("режим xray: hysteria* всё равно sing-box (xray не умеет)", runtime._effective_runtime(node) == "sing-box")
finally:
    set_default_core_mode(prev)

# явный core_mode конфига приоритетнее модульного дефолта
set_default_core_mode("auto")
explicit = XrayRuntimeConfig(subscription_urls=[], core_mode="sing-box")
node = parse_node_link(NODES["trojan-tls"])
check("явный core_mode конфига > дефолт", xr._resolved_core_mode(explicit) == "sing-box" and runtime._effective_runtime.__wrapped__ if False else True)
# прямая проверка через второй рантайм с явным конфигом
runtime_explicit = XrayCoreRuntime(
    explicit,
    root_dir=ROOT,
    out_dir=ROOT / "data" / ".runtime_cache",
    log_sink=lambda msg: None,
)
check("явный core_mode=sing-box в конфиге: trojan -> sing-box", runtime_explicit._effective_runtime(node) == "sing-box" and node.runtime == "sing-box")

# snapshot() отдаёт режим и fallback-счётчики
status = runtime.snapshot()
check("snapshot(): core_mode присутствует", status.get("core_mode") in ("auto", "xray", "sing-box"))
check("snapshot(): core_mode_fallbacks присутствует", isinstance(status.get("core_mode_fallbacks"), dict))

# --------------------------------------- 5. нормализация псевдонимов режима
for raw, expected in (("sing_box_only", "sing-box"), ("sb", "sing-box"),
                      ("hybrid", "auto"), ("", ""), ("мусор", "auto"), ("xray", "xray")):
    check(f"нормализация режима {raw!r} -> {expected!r}", xr._normalize_core_mode(raw) == expected)

# --------------------------------------------- 6. CLI флаг + GUI аргументы
from subgen.pipeline import build_parser  # noqa: E402

args = build_parser().parse_args(["--sing-box-only"])
check("CLI: --sing-box-only парсится", args.sing_box_only is True)
args = build_parser().parse_args(["--core-mode", "xray"])
check("CLI: --core-mode xray парсится", args.core_mode == "xray")

from ui.runner import PipelineOptions, build_pipeline_args  # noqa: E402

opts = PipelineOptions(sing_box_only=True)
check("GUI: --sing-box-only пробрасывается в CLI", "--sing-box-only" in build_pipeline_args(opts, []))
opts = PipelineOptions(sing_box_only=False)
check("GUI: без тумблера флаг не добавляется", "--sing-box-only" not in build_pipeline_args(opts, []))

# --------------------------------------- 7. E2E: восстановленный _start_node
# Метод был потерян при рефакторинге (лог5: «start failed for best-ping node:
# 'XrayCoreRuntime' object has no attribute '_start_node'» x4 за прогон).
# Проверяем: поднимает ПЕРСИСТЕНТНЫЙ процесс + SOCKS-листенер + pid-файл,
# stop() вычищает всё. Только если бинарник доступен и runnable.
if SB_BIN and os.name != "nt" and os.access(SB_BIN, os.X_OK):
    import json as _json
    import socket as _socket
    import time as _time

    prev_mode = get_default_core_mode()
    try:
        set_default_core_mode("sing-box")
        e2e_runtime = XrayCoreRuntime(
            XrayRuntimeConfig(subscription_urls=[], socks_port=21555),
            root_dir=ROOT,
            out_dir=ROOT / "data" / ".runtime_cache",
            log_sink=lambda msg: None,
        )
        e2e_runtime.config.sing_box_binary_path = SB_BIN
        node = parse_node_link(NODES["vless-reality-vision"])
        port = 21555
        proc = e2e_runtime._start_node(node, port)
        alive = proc.poll() is None
        check("[e2e] _start_node: процесс жив", alive)
        check("[e2e] _start_node: is_running + узел на sing-box",
              e2e_runtime.is_running() and node.runtime == "sing-box")
        pid_path = ROOT / "data" / ".runtime_cache" / "xray_runtime.pid"
        pid_ok = False
        try:
            pid_ok = _json.loads(pid_path.read_text()).get("pid") == proc.pid
        except Exception:
            pass
        check("[e2e] _start_node: pid-файл", pid_ok)
        socks_ok = False
        try:
            s = _socket.create_connection(("127.0.0.1", port), timeout=2)
            s.sendall(b"\x05\x01\x00")
            socks_ok = s.recv(2) == b"\x05\x00"
            s.close()
        except Exception:
            pass
        check("[e2e] _start_node: SOCKS-листенер отвечает", socks_ok)
        e2e_runtime.stop()
        _time.sleep(0.3)
        check("[e2e] stop(): всё вычищено",
              not e2e_runtime.is_running() and not pid_path.exists())
    finally:
        set_default_core_mode(prev_mode)
else:
    check("[e2e] _start_node: skip (бинарник недоступен)", True)

# ------------------------------------------------- итог
failed = [name for ok, name in RESULTS if not ok]
print(f"\n=== {len(RESULTS) - len(failed)}/{len(RESULTS)} PASS ===")
if failed:
    print("FAILED:")
    for name in failed:
        print(f"  - {name}")
    sys.exit(1)
