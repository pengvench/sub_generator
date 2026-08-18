# -*- coding: utf-8 -*-
"""Временная диагностика: проверить импорт всех подписок из sources.txt."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from xray_runtime import _collect_from_source  # noqa: E402


def main() -> int:
    sources_file = ROOT / "sources.txt"
    sources = [
        line.strip()
        for line in sources_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    print(f"Всего подписок в sources.txt: {len(sources)}")
    print("=" * 100)

    logs: list[str] = []
    results: list[tuple[str, int, bool]] = []

    def log(msg: str) -> None:
        logs.append(msg)

    def on_result(url: str, ok: bool) -> None:
        results.append((url, 0, ok))

    for i, source in enumerate(sources, 1):
        logs.clear()
        results.clear()
        try:
            nodes = _collect_from_source(
                source,
                timeout=8.0,
                per_source_limit=0,
                log_sink=log,
                on_source_result=on_result,
            )
            ok = bool(nodes)
            status = "OK " if ok else "EMPTY/FAIL"
            print(f"[{i:2}/{len(sources)}] {status} nodes={len(nodes):4} | {source}")
            for line in logs:
                print(f"       {line}")
        except Exception as exc:  # noqa: BLE001
            print(f"[{i:2}/{len(sources)}] EXC {type(exc).__name__}: {exc} | {source}")
            for line in logs:
                print(f"       {line}")

    print("=" * 100)
    print("Готово. Смотри вывод выше.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
