# SubGenerator

Standalone-решение для сборки и проверки VPN-конфигов из подписок. Загружает
подписки, проверяет узлы на живучесть, тестирует обход блокировок и формирует
итоговую подписку (`subs.txt`), готовую для импорта в Karing, Hiddify, happ,
v2rayN.

**ПК-версия (Windows)**. Весь Python-код (конвейер, проверщики, рантайм ядер)
лежит в `python/`; запуск — напрямую из исходников (`generate.py`) или
сборкой в exe через PyInstaller (`build_release.bat`).

## Дисклеймер

Проект создан **исключительно в целях тестирования и научного интереса**:
изучение поведения сетевых протоколов, фильтрации трафика и устойчивости
конфигураций в контролируемой среде.

Автор не призывает и не содействует использованию инструмента в нарушение
законов или правил вашего региона. Используйте только в разрешённых целях
и только с подписками, на работу с которыми у вас есть право.

---

## Структура репозитория

В корне — только соурс и батники на сборку:

```
sub_generator/
├── generate.py           # единая точка входа (GUI / --cli)
├── build_release.bat     # сборка Windows-версии (PyInstaller)
├── python/               # Python-соурс: subgen/, checkers/, ui/
├── scripts/              # PyInstaller-спеки, ранеры, тесты, download_cores
├── tools/                # утилиты фильтрации/диагностики подписок
├── assets/               # icon.ico
├── bin/                  # ядра: xray.exe, sing-box.exe
├── data/                 # runtime: sources.txt, отчёты, кеш (создаётся)
└── docs/                 # этот README + STRUCTURE.md
```

Подробная схема — в [STRUCTURE.md](STRUCTURE.md).

## Возможности

- GUI (customtkinter) и консольный режим (`--cli`).
- Поддержка vless, vmess, trojan, shadowsocks, hysteria, hy2.
- Парсинг подписок: plain text, base64, Clash YAML, JSON.
- Дедупликация конфигов (протокол, хост, порт, нормализованный URL).
- TCP/UDP-ping для быстрого отсева мёртвых узлов (до 256 потоков).
- Проверка Telegram, ChatGPT, Instagram, скорости download/upload.
- DPI-проверки: DPI (+ Zapret-suite внутри), DPI-active, Resilience.
- ИИ-гео слепок (обязательный этап): страна exit-IP глазами
  Gemini/OpenAI (CF trace `loc=`) — источник флага в подписке; опция
  strict исключает узлы со слепком РФ.
- Telegram-медиа фильтр (обязательный): каждый узел реально качает
  видео из Telegram (t.me/s/, >= 512 КБ/с).
- Игнорирование системного hosts-файла во всех проверках.
- Диагностика сети: UDP DNS, DoH, HTTPS, заблокированные медиа, TUN.
- Перепроверка с любого из 9 этапов (по сохранённому кешу).
- Сохранение настроек между запусками.

## Установка и запуск

### Из исходников

Требования: Python 3.12+, Windows 10/11 64-bit, права администратора
(управление процессами xray/sing-box), 16+ ГБ RAM.

```bat
pip install pyinstaller customtkinter darkdetect
python generate.py                       :: GUI
python generate.py --cli --help          :: консольный конвейер
```

### Сборка exe

```bat
build_release.bat
```

Результат в `build\`:
- `SubGenerator.exe` — GUI (запрашивает права админа автоматически);
- `SubGenerator-CLI.exe` — консольный режим (запрашивает права админа);
- `run_sub_generator.bat` / `.ps1` — one-click прогон с прогресс-баром;
- `sources.txt` — список подписок (редактируется в UI).

### Обновление ядер

Ядра `bin/xray.exe` и `bin/sing-box.exe` уже в репозитории. Обновление
до свежих релизов Xray-core / sing-box:

```bat
python scripts\download_cores.py                    :: последние релизы
python scripts\download_cores.py 26.3.27 1.13.16    :: конкретные версии
```

## Использование

### 1. Подписки

На странице «Подписки» добавьте URL подписок. Поддерживаются прямые
ссылки на `.txt`, `.yaml`, `.json`, base64, Clash YAML (`proxies:`),
локальный файл («Свой файл конфигов»).

### 2. Тестирование

Основные параметры (по умолчанию → смысл):

| Параметр | По умолчанию | Описание |
|---|---|---|
| Потоков | 32 | Параллельных проверок |
| Таймаут | 15 сек | На узел |
| Макс. пинг | 1500 мс | Отсев по задержке |
| Мин. скорость | 3000 КБ/с | Для 1080p видео |

Этапы конвейера (последовательность, v8.2):

1. **ping** — TCP/UDP-отсев мёртвых портов;
2. **initial** — TCP+HTTP HEAD доступность;
3. **telegram_pro** — MTProto connect/auth + upload (главный критерий);
4. **dpi** — DPI (+ Zapret-suite, один core-процесс на узел);
5. **dpi_active** — SNI-варианты/фрагментация/ECH/TLS 1.2-1.3;
6. **ai_geo** — ИИ-гео слепок (CF trace `loc=`);
7. **route** — трассировка маршрута;
8. **resilience** — живучесть в условиях блокировок;
9. **recheck** — финальный спидтест (+ медиа-фильтр t.me/s/).

### 3. Перепроверка

Страница «Перепроверка»: запускает проверку с выбранного этапа по
сохранённым рабочим конфигам из `data/.runtime_cache/` — без пинга и
стресс-теста.

### 4. Диагностика

Страница «Диагностика»: UDP DNS (порт 53), DoH, HTTPS connectivity,
прямая доступность ChatGPT/Instagram, наличие/готовность TUN-адаптера —
видно, на каком этапе отваливается соединение.

### 5. Результаты

`data/subs.txt` (base64-подписка), `data/working.txt` (конфиги построчно),
`data/report.json` (полный отчёт с цифрами по этапам и сетевым профилем).
На «Главной» — кнопка «Поделиться результатом».

## CLI

```bat
SubGenerator-CLI.exe --workers 32 --timeout 15 --dpi-check --dpi-siberian
```

| Параметр | Описание |
|---|---|
| `--workers N` | Потоков (32 по умолчанию) |
| `--timeout N` | Таймаут на узел, сек |
| `--dpi-check` | DPI ЦЕЛИКОМ: alive + tcp 16-20 + siberian + CIDR + Zapret-suite |
| `--dpi-active` | Активная DPI-проверка протокола (+ `--dpi-active-timeout`) |
| `--ai-strict` | ИИ-гео: исключить узлы со слепком РФ |
| `--ai-timeout N` | Таймаут ИИ-гео запроса, сек (по умолчанию 6) |
| `--custom-file PATH` | Свой файл конфигов вместо подписок |
| `--no-stress` | Без спидтеста |
| `--start-stage STAGE` | Перепроверка с любого из 9 этапов |

Полный список: `SubGenerator-CLI.exe --help`.

## Файлы и каталоги

```
sub_generator/
├── python/                   # соурс: subgen/, checkers/, ui/
├── bin/                      # ядра (xray.exe, sing-box.exe)
├── data/
│   ├── sources.txt           # список подписок (редактируется в UI)
│   ├── settings.json         # настройки (описание/префикс подписки)
│   ├── report.json           # отчёт последнего прогона
│   ├── geo_cache.json        # кеш geo-тегов
│   ├── working.txt           # рабочие конфиги (текст)
│   └── .runtime_cache/       # кеш перепроверки
└── build/                    # результат сборки (exe)
```

## Требования

| Компонент | Значение |
|---|---|
| ОС | Windows 10/11 64-bit |
| Права | Администратор |
| RAM | 16 ГБ мин., 32 ГБ реком. |
| Python (из исходников) | 3.12+ |
| Сборка | PyInstaller + Python 3.12 |

## Тесты

```bat
python scripts\test_subgen_fixes.py       :: регресс v8.1 (10/10)
python scripts\test_dpi_mobile_fix.py     :: v8.2: DPI mobile fix (51 проверка)
python scripts\test_task16.py             :: задачи конвейера
```

## Changelog

### v1.2 (2026-09-04) — возврат к чистой ПК-версии

- **Android-билд выпилен целиком**: удалены `android/` (Gradle/Chaquopy),
  `build_apk.bat`, `python/android_bridge.py`, `python/cacert.pem`,
  android-патчи `SUBGEN_ROOT`/`SUBGEN_BIN_DIR` в config.py и
  xray_runtime.py. Репозиторий снова собирается только `build_release.bat`.
- **WARP-функционал выпилен как устаревший**: удалены `subgen/warp.py`,
  `ui/pages/warp_page.py`, WARP-опции в спеках PyInstaller и зависимость
  `cryptography` (использовалась только для X25519-ключей WARP).
- `scripts/download_cores.py` переписан под ПК: качает
  `Xray-windows-64.zip` и `sing-box-*-windows-amd64.zip` в `bin/`.

### v1.0 (до объединения)

- Структура «в корне только соурс и батники»: `generate.py` +
  `build_release.bat`; остальное разложено по `python/`, `scripts/`,
  `tools/`, `assets/`, `bin/`, `data/`, `docs/`.
- `sources.txt` переехал в `data/sources.txt`; PyInstaller-спеки с
  относительными путями (сборка не зависит от машины).

Историю изменений конвейера (v8-v8.2: порядок этапов, RTT-адаптация,
DPI-инцидент на мобильных) см. в истории git-коммитов.
