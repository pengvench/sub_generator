# Структура репозитория SubGenerator (ПК-версия, v1.3.2)

## Принцип

Репозиторий — чистая ПК-версия (Windows). Весь Python-код лежит в `python/`.
В корне — соурс (`generate.py`), батник на сборку (`build_release.bat`)
и `sources.txt` (пользовательский список подписок, хранится в git);
`data/` — ТОЛЬКО рантайм-мусор (логи, кеш, отчёты), создаётся при
запуске, в git не входит. Всё остальное разложено по папкам.

```
sub_generator/
├── generate.py                  # СОУРС: единая точка входа.
│                                #   без аргументов — GUI, с аргументами/--cli — конвейер
├── build_release.bat            # БАТНИК: сборка ПК (PyInstaller -> build\*.exe)
├── sources.txt                  # СПИСОК ПОДПИСОК (единственный, в корне;
│                                #   в сборке — рядом с exe; редактируется в UI)
├── .gitignore                   #   data/ игнорируется ЦЕЛИКОМ (рантайм)
│
├── python/                      # PYTHON-СОУРС
│   ├── subgen/                  #   конвейер: pipeline, baseline (замер сети
│   │   │                        #   по белым RU-сервисам: Яндекс.Интернетометр/
│   │   │                        #   tele2/speedtest.ru-движок Билайна; без CF),
│   │   │                        #   autoselect (конфиг-балансер), settings, geo, config…
│   │   └── config.py            #     ROOT: exe-каталог | корень репо
│   ├── checkers/                #   проверщики: dpi, zapret-suite, telegram_pro, ai_geo,
│   │                            #   initial_check, resilience, net_diagnostic (единая
│   │                            #   диагностика для GUI и конвейера; TUN удалён)…
│   ├── runtime/                 #   ПАКЕТ ДВИЖКА (v1.3: бывший god-файл
│   │   │                        #   xray_runtime.py, 4765 строк -> 11 модулей)
│   │   ├── types.py             #     константы + XrayNode/XrayProbeResult/Config
│   │   ├── uritools.py          #     канонизация URI (дедуп-текст, base64)
│   │   ├── parse.py             #     парсинг ссылок/подписок (plain/b64/JSON/Clash)
│   │   ├── fetch.py             #     загрузка тел подписок (зеркала, SSL, gzip)
│   │   ├── netsocks.py          #     SOCKS5 + HTTP(S) поверх SOCKS
│   │   ├── probes_ping.py       #     TCP/UDP-пинги (предфильтр без ядра)
│   │   ├── probes_telegram.py   #     MTProto-латентность + медиа-фильтр t.me/s/
│   │   ├── probes_speed.py      #     NDT7/Cloudflare/OVH/Tele2 замеры скорости
│   │   │                        #     (ЧЕРЕЗ туннель узла — CF там корректен;
│   │   │                        #     в ПРЯМОМ замере baseline.py CF не используется)
│   │   ├── configs.py           #     сборка конфигов xray/sing-box
│   │   ├── procs.py             #     Job Objects, терминация процессов
│   │   └── core.py              #     XrayCoreRuntime + collect_subscription_nodes
│   ├── ui/                      #   GUI (customtkinter): main, app, runner, pages/*
│   └── xray_runtime.py          #   ФАСАД над пакетом runtime/ (совместимость
│                                #   прежних импортов `from xray_runtime import …`)
│
├── scripts/                     # СБОРКА/ЗАПУСК/ТЕСТЫ
│   ├── SubGenerator.spec        #   PyInstaller: GUI (пути относительные)
│   ├── SubGenerator-cli.spec    #   PyInstaller: CLI
│   ├── run_sub_generator.bat    #   one-click запуск конвейера (PowerShell-обёртка)
│   ├── run_sub_generator.ps1    #   прогресс-бар + лог в data\run.log
│   ├── run_filter_sources.bat   #   фильтрация мусорных подписок
│   ├── download_cores.py        #   обновление ядер ПК (bin/xray.exe, bin/sing-box.exe)
│   └── test_*.py                #   тесты конвейера (v8.1/v8.2/v1.3-task17)
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
├── data/                        # RUNTIME-МУСОР (создаётся при запуске, в git
│                                #   и в архив репо НЕ входит: логи, кеш,
│                                #   отчёты, settings, baseline_last,
│   └── report.json, run.log, settings.json, geo_cache.json,
│       baseline_last.json, autoselect_xray.json, autoselect_singbox.json,
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
2. `runtime/procs.py::_resolve_binary()` — `_MEIPASS/bin`, `<root>/bin`,
   каталог модуля и его родитель, затем `shutil.which`
   (реэкспортирован фасадом `xray_runtime`).

## Миграция со старой структуры (что куда переехало)

| Было в корне | Стало |
|---|---|
| `generate.py` | `generate.py` (осталось, умная точка входа GUI/CLI) |
| `build_release.bat` | `build_release.bat` (пути обновлены) |
| `xray_runtime.py` | `python/xray_runtime.py` — фасад над `python/runtime/` (v1.3) |
| `runtime/` | `python/runtime/` — движок проверки узлов (11 модулей) |
| `checkers/` | `python/checkers/` (tg_media.py удалён — дубль проб; без TUN) |
| `subgen/` | `python/subgen/` |
| `ui/` | `python/ui/` |
| `sources.txt` | `sources.txt` (корень; v1.0–v1.3.1 лежал в `data/`, v1.3.2 вернул в корень) |
| `README.md` | `docs/README.md` |
| `icon.ico` | `assets/icon.ico` |
| `download_cores.py` | `scripts/download_cores.py` (качает windows-сборки в `bin/`) |
| `scripts/`, `tools/`, `bin/`, `data/` | на месте |

Выпилено в v1.2 (возврат к чистой ПК-версии): `android/` (Gradle +
Chaquopy-проект), `build_apk.bat`, `python/android_bridge.py`,
`python/cacert.pem`, env-патчи `SUBGEN_ROOT`/`SUBGEN_BIN_DIR`,
`subgen/warp.py`, `ui/pages/warp_page.py`, зависимость `cryptography`.

## Изменения v1.3.2 (структура)

- `sources.txt` — в КОРНЕ репозитория (был в `data/` с v1.0); файл
  единственный, дублей нет. `data/` — только рантайм-артефакты,
  игнорируется git целиком (в т.ч. `sources.txt` туда больше не пишется).
- Спеки PyInstaller кладут `sources.txt` в корень бандла (рядом с exe),
  сборщик больше не создаёт `build\data\sources.txt`.
- Страница «Диагностика» (`ui/pages/diag_page.py`) дополнилась
  спидтест-прогоном (использует `subgen/baseline.py` — тот же каскад
  белых сервисов, что и в конвейере).
- `subgen/baseline.py`: кэп быстрого канала `BASELINE_CAP_MBITS = 100.0`
  — замер ≥ 100 Мбит/с не применяется к порогам (пороги UI как есть).

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
