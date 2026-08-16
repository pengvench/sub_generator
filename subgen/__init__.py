"""Пакет sub_generator: модульная реализация сборки подписок.

Модули:
- config     — константы, пути (data/), флаги стран, crypt-кодирование.
- logging    — лог в stdout + data/run.log.
- progress   — единый прогресс через PowerShell Write-Progress.
- geo        — geoip lookup, кеш, назначение имён узлов.
- output     — запись подписок, отчётов, кеша.
- refresh    — сборка узлов и полная проверка через XrayCoreRuntime.
- pipeline   — основной конвейер main().
"""
from __future__ import annotations

from subgen.config import DATA_DIR
from subgen.pipeline import main
