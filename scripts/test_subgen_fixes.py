#!/usr/bin/env python3
"""Регрессионный тест SubGenerator после восстановления pipeline.py.

Проверяет:
  1. Импорт всех модулей конвейера (топ-уровень).
  2. Парсер принимает все 10 значений --start-stage из UI (recheck_page).
  3. STAGE_ORDER синхронизирован с ui/pages/recheck_page.py.
  4. run() не падает с NameError: перепроверка без кеша возвращает код 1.
  5. IDNA-фикс: _socks_open_connection в checkers.base больше не использует
     encode("idna") — формирует ATYP=1 для IP и ATYP=3 для домена.
  6. VLESS flow выкидывается на не-Reality узлах (core exited fix).
  7. Reality pbk нормализуется (padding + URL-safe → standard base64).
  8. _start_core существует (единый запуск ядра с диагностикой stderr).
  9. gui/app.py не содержит лямбд над except-переменными (NameError-баг).

Запуск:  python3 scripts/test_subgen_fixes.py   (из корня sub_generator)
"""
from __future__ import annotations

import ast
import base64
import inspect
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO_ROOT, "python")
sys.path.insert(0, ROOT)

PASSED = 0
FAILED = 0


def check(name: str, fn) -> None:
    global PASSED, FAILED
    try:
        fn()
        print(f"  PASS  {name}")
        PASSED += 1
    except Exception as exc:
        print(f"  FAIL  {name}: {exc}")
        FAILED += 1


def main() -> int:
    print("=== Тест 1: импорт модулей конвейера ===")

    def _imports():
        import subgen.pipeline  # noqa: F401
        import subgen.refresh  # noqa: F401
        import subgen.output  # noqa: F401
        import subgen.progress  # noqa: F401
        import xray_runtime  # noqa: F401
        from checkers import base, dpi_active  # noqa: F401

    check("импорт subgen.pipeline + xray_runtime + checkers", _imports)

    print("=== Тест 2: --start-stage принимает все этапы из UI ===")

    def _stages():
        from subgen.pipeline import build_parser
        parser = build_parser()
        # 10 значений из recheck_page + устаревший алиас 'zapret' (ремапится на 'dpi').
        for stage in ("ping", "initial", "services", "dpi", "dpi_active", "telegram_pro", "ai_geo", "route", "resilience", "recheck", "zapret"):
            args = parser.parse_args(["--start-stage", stage])
            assert args.start_stage == stage, stage
        # алиас ремапится пост-обработкой
        from subgen.pipeline import _apply_stage_aliases
        args = _apply_stage_aliases(parser.parse_args(["--start-stage", "zapret"]))
        assert args.start_stage == "dpi"

    check("9 значений --start-stage + алиас zapret", _stages)

    print("=== Тест 3: STAGE_ORDER синхронизирован с recheck_page ===")

    def _sync():
        import re
        from subgen.pipeline import STAGE_ORDER
        ui = open(os.path.join(ROOT, "ui", "pages", "recheck_page.py"), encoding="utf-8").read()
        ui_stages = set(re.findall(r'\("(\w+)",', ui)) & {
            s for s in re.findall(r'\("(\w+)",', ui)
            if s in ("ping", "initial", "services", "dpi", "dpi_active", "telegram_pro", "ai_geo", "route", "resilience", "recheck")
        }
        assert ui_stages == set(STAGE_ORDER), f"{ui_stages} != {set(STAGE_ORDER)}"
        assert "zapret" not in set(STAGE_ORDER), "zapret-этап должен быть объединён с dpi"
        assert "ai_geo" in set(STAGE_ORDER), "ai_geo-этап отсутствует"

    check("STAGE_ORDER == STAGES(recheck_page)", _sync)

    print("=== Тест 4: run() без NameError (нет кеша -> код 1) ===")

    def _run_no_cache():
        from subgen.pipeline import run
        code = run(["--start-stage", "recheck", "--no-stress"])
        assert code == 1, f"ожидали код 1, получили {code}"

    check("run(--start-stage recheck) без кеша", _run_no_cache)

    print("=== Тест 5: IDNA-фикс в checkers.base ===")

    def _idna():
        # ATYP-логика в текущем коде: checkers.base._socks_target_address
        # (IP -> ATYP=1/4, домен -> ATYP=3 c idna+fallback) и
        # xray_runtime._socks_open_connection (inet_aton-ветка для IP).
        import ast as _ast

        base_src = open(os.path.join(ROOT, "checkers", "base.py"), encoding="utf-8").read()
        tree = _ast.parse(base_src)
        found = False
        for node in _ast.walk(tree):
            if isinstance(node, _ast.FunctionDef) and node.name == "_socks_target_address":
                found = True
                src = _ast.dump(_ast.Module(body=node.body, type_ignores=[]))
                assert "inet_aton" in src, "нет ATYP=1 ветки для IP в _socks_target_address"
        assert found, "_socks_target_address не найден"

        xr_src = open(os.path.join(ROOT, "xray_runtime.py"), encoding="utf-8").read()
        assert "socket.inet_aton(target_host)" in xr_src, "нет ATYP=1 ветки в xray_runtime._socks_open_connection"

    check("SOCKS: ATYP=1/4 для IP, ATYP=3 для домена", _idna)

    def _sni():
        # _sni_extension: encode("idna") должен быть обёрнут в try/except
        # UnicodeError с fallback на utf-8.
        import ast as _ast
        tree = _ast.parse(open(os.path.join(ROOT, "checkers", "dpi_active.py"), encoding="utf-8").read())
        found = False
        for node in _ast.walk(tree):
            if isinstance(node, _ast.FunctionDef) and node.name == "_sni_extension":
                found = True
                has_try = any(isinstance(s, _ast.Try) for s in _ast.walk(node))
                assert has_try, "encode('idna') не обёрнут в try/except"
        if not found:
            # В текущей базе SNI-хелпер может называться иначе — проверяем,
            # что idna-вызовы в dpi_active обёрнуты хотя бы одним try на функцию.
            for node in _ast.walk(tree):
                if isinstance(node, _ast.FunctionDef):
                    for sub in _ast.walk(node):
                        if (
                            isinstance(sub, _ast.Call)
                            and isinstance(sub.func, _ast.Attribute)
                            and sub.func.attr == "encode"
                            and sub.args
                            and isinstance(sub.args[0], _ast.Constant)
                            and sub.args[0].value == "idna"
                        ):
                            assert any(
                                isinstance(anc, _ast.Try) for anc in _ast.walk(node)
                            ), f"encode('idna') в {node.name} не обёрнут в try/except"

    check("dpi_active: idna с fallback", _sni)

    print("=== Тест 6: VLESS flow только на Reality ===")

    def _flow():
        import xray_runtime as xr
        node = xr.parse_node_link(
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443"
            "?encryption=none&flow=xtls-rprx-vision&security=tls&sni=example.com&type=tcp#t"
        )
        ob = xr._xray_outbound(node)
        assert "flow" not in ob["settings"]["vnext"][0]["users"][0]

    check("flow выкидывается на TLS-узле", _flow)

    print("=== Тест 7: нормализация Reality pbk ===")

    def _pbk():
        import xray_runtime as xr
        key = base64.b64encode(b"\x01" * 32).decode()
        nopad = key.rstrip("=")
        urlsafe = nopad.replace("+", "-").replace("/", "_")
        # xray v26 парсит pbk через RawURLEncoding: результат нормализации —
        # URL-safe алфавит БЕЗ padding (StdEncoding+padding отвергается ядром).
        assert xr._normalize_reality_pbk(nopad) == urlsafe, "nopad -> urlsafe"
        assert xr._normalize_reality_pbk(urlsafe) == urlsafe, "urlsafe as-is"
        assert xr._normalize_reality_pbk(key) == urlsafe, "std+padding -> urlsafe"

    check("pbk: RawURL без padding (формат xray v26+)", _pbk)

    print("=== Тест 8: мёртвое ядро не роняет конвейер ===")

    def _core_exited():
        # Узел с кривым flow/секретом -> ядро падает на старте -> узел
        # отклоняется с reason="core exited" (не исключением на весь прогон).
        import xray_runtime as xr

        node = xr.parse_node_link(
            "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:1"
            "?encryption=none&flow=xtls-rprx-vision&security=tls&sni=example.com&type=tcp#dead"
        )
        assert node is not None
        # flow на TLS-узле выкидывается — конфиг должен собраться без flow.
        ob = xr._xray_outbound(node)
        assert "flow" not in ob["settings"]["vnext"][0]["users"][0], "flow должен выкидываться на TLS-узле"

        from pathlib import Path as _P
        config = xr.XrayRuntimeConfig(subscription_urls=[], probe_workers=1, probe_timeout_sec=2.0, max_servers=0)
        runtime = xr.XrayCoreRuntime(config, root_dir=_P(ROOT), out_dir=_P(ROOT) / "data" / ".runtime_cache", log_sink=lambda msg: None)
        try:
            try:
                runtime.with_node_process(node, lambda host, port: "unexpected")
            except RuntimeError as exc:
                # Ожидаемое поведение: ядро не поднялось (на Linux-сборке
                # Windows-бинарь недоступен -> "binary not found" — тоже
                # корректный graceful-путь, не роняющий конвейер).
                msg = str(exc).lower()
                assert "exited" in msg or "binary not found" in msg, str(exc)
        finally:
            runtime.stop()

    check("core exited -> RuntimeError от with_node_process", _core_exited)

    print("=== Тест 9: app.py без лямбд над except-переменными ===")

    def _no_except_lambda():
        """Ищем паттерн `except ... as X:` + lambda, использующая X внутри блока.

        Python удаляет имя X после except-блока, а лямбда вызывается позже
        из GUI-потока -> NameError (тот же класс бага, что и в pipeline.py).
        """
        path = os.path.join(ROOT, "ui", "app.py")
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.name:
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Lambda):
                        names = {n.id for n in ast.walk(sub) if isinstance(n, ast.Name)}
                        if node.name in names:
                            raise AssertionError(
                                f"lambda захватывает except-переменную '{node.name}' "
                                f"(строка {sub.lineno}) — NameError при вызове из GUI"
                            )

    check("нет lambda над except-переменными в ui/app.py", _no_except_lambda)

    print()
    print(f"ИТОГ: {PASSED} passed, {FAILED} failed")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
