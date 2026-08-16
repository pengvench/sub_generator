# -*- coding: utf-8 -*-
"""Проверка синтаксиса изменённых Python-файлов после объединения telegram/telegram_pro."""
import py_compile
import sys

files = [
    "subgen/pipeline.py",
    "ui/runner.py",
    "ui/pages/start_page.py",
]

ok = True
for f in files:
    try:
        py_compile.compile(f, doraise=True)
        print(f"OK: {f}")
    except py_compile.PyCompileError as e:
        ok = False
        print(f"FAIL: {f}")
        print(e)

print("PY_COMPILE_OK" if ok else "PY_COMPILE_FAIL")
sys.exit(0 if ok else 1)
