# Структура репозитория SubGenerator (ПК-версия, v1.2)

## Принцип

Репозиторий — чистая ПК-версия (Windows). Весь Python-код лежит в `python/`.
В корне — только соурс (`generate.py`) и батник на сборку
(`build_release.bat`); всё остальное разложено по папкам.

```
sub_generator/
├── generate.py                  # СОУРС: единая точка входа.
│                                #   без аргументов — GUI, с аргументами/--cli — конвейер
├── build_release.bat            # БАТНИК: сборка ПК (PyInstaller -> build\*.exe)
├── .gitignore
│
├── python/                      # PYTHON-СОУРС
│   ├── subgen/                  #   конвейер: pipeline, settings, geo, config…
│   │   └── config.py            #     ROOT: exe-каталог | корень репо
│   ├── checkers/                #   проверщики: dpi, zapret-suite, telegram_pro, ai_geo,
│   │                            #   tg_media, initial_check, resilience, net_diagnostic…
│   ├── ui/                      #   GUI (customtkinter): main, app, runner, pages/*
│   └── xray_runtime.py          #   рантайм ядер (xray/sing-box)
│
├── scripts/                     # СБОРКА/ЗАПУСК/ТЕСТЫ
│   ├── SubGenerator.spec        #   PyInstaller: GUI (пути относительные)
│   ├── SubGenerator-cli.spec    #   PyInstaller: CLI
│   ├── run_sub_generator.bat    #   one-click запуск конвейера (PowerShell-обёртка)
│   ├── run_sub_generator.ps1    #   прогресс-бар + лог в data\run.log
│   ├── run_filter_sources.bat   #   фильтрация мусорных подписок
│   ├── download_cores.py        #   обновление ядер ПК (bin/xray.exe, bin/sing-box.exe)
│   └── test_*.py                #   тесты конвейера (v8.1/v8.2)
│
├── tools/                       # УТИЛИТЫ (диагностика подписок, иконки)
│   ├── _filter_sources.py       #   фильтр sources.txt по рабочим/отбракованным
│   └── _diag_sources.py, _make_icon.py, _check_*.py
│
├── assets/                      # РЕСУРСЫ СБОРКИ
│   └── icon.ico                 #   иконка exe / окна GUI
│
├── bin/                         # ЯДРА (Windows)
│   ├── xray.exe                 #   Xray-core
│   ├── sing-box.exe             #   sing-box
│   └── CORE_VERSIONS.txt        #   версии ядер
│
├── data/                        # RUNTIME-ДАННЫЕ (создаётся/пополняется)
│   ├── sources.txt              #   список подписок (редактируется в UI; git-исключение
│   │                            #   только для результатов, sources.txt хранится)
│   └── report.json, run.log, settings.json, geo_cache.json,
│       working.txt, .runtime_cache/…  # появляется после прогонов
│
└── docs/                        # ДОКУМЕНТАЦИЯ
    ├── README.md                #   главный README (этот каталог)
    └── STRUCTURE.md             #   этот файл
```

## Как разрешаются пути

| Механизм | ПК (исходники) | ПК (собранный exe) |
|---|---|---|
| Каталог Python-кода | `python/` (через `generate.py` — bootstrap) | вшит PyInstaller'ом (`pathex=python/`) |
| Корень данных (`data/`) | `subgen.config.ROOT` = корень репо | каталог рядом с exe |
| Ядра (`bin/`) | `<корень>/bin/xray.exe` | `_MEIPASS/bin/` + каталог рядом с exe |
| Точка входа | `python generate.py [--cli …]` | `SubGenerator.exe` / `SubGenerator-CLI.exe` |
| GUI | `python/ui` (customtkinter) | вшит |

Разрешение путей — каскадом, без магии окружения:

1. `subgen/config.py::_app_root()` — exe-каталог (frozen) или корень репо
   (`python/subgen` → на три уровня вверх);
2. `xray_runtime.py::_resolve_binary()` — `_MEIPASS/bin`, `<root>/bin`,
   каталог модуля и его родитель, затем `shutil.which`.

## Миграция со старой структуры (что куда переехало)

| Было в корне | Стало |
|---|---|
| `generate.py` | `generate.py` (осталось, умная точка входа GUI/CLI) |
| `build_release.bat` | `build_release.bat` (пути обновлены) |
| `xray_runtime.py` | `python/xray_runtime.py` |
| `checkers/` | `python/checkers/` |
| `subgen/` | `python/subgen/` |
| `ui/` | `python/ui/` |
| `sources.txt` | `data/sources.txt` |
| `README.md` | `docs/README.md` |
| `icon.ico` | `assets/icon.ico` |
| `download_cores.py` | `scripts/download_cores.py` (качает windows-сборки в `bin/`) |
| `scripts/`, `tools/`, `bin/`, `data/` | на месте |

Выпилено в v1.2 (возврат к чистой ПК-версии): `android/` (Gradle +
Chaquopy-проект), `build_apk.bat`, `python/android_bridge.py`,
`python/cacert.pem`, env-патчи `SUBGEN_ROOT`/`SUBGEN_BIN_DIR`,
`subgen/warp.py`, `ui/pages/warp_page.py`, зависимость `cryptography`.

## Сборка

```bat
build_release.bat
```

Требуется Python 3.12+ с `pip install pyinstaller customtkinter darkdetect`.
Результат: `build\SubGenerator.exe`, `build\SubGenerator-CLI.exe`,
`build\run_sub_generator.bat|.ps1`, `build\icon.ico`, `build\sources.txt`.

Запуск из исходников:

```bat
python generate.py            :: GUI
python generate.py --cli --workers 32 --dpi-check --dpi-siberian
```

Обновление ядер перед сборкой:

```bat
python scripts\download_cores.py    :: свежие xray.exe + sing-box.exe в bin\
```
