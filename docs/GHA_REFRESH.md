# GHA: авто-обновление подписок на cron'е

`scripts/refresh_subs.py` + `.github/workflows/refresh-subs.yml` — лёгкая
версия sub_generator для GitHub Actions (Linux), которая делает ровно
одно: скачивает источники из `data/sources.txt` (плюс динамические URL'ы
из `data/tg_subs.txt` — см. v39 ниже), парсит их, дедуплицирует
узлы, и коммитит итоговый список в `data/preload.txt` каждые 3 часа.

Без `xray.exe` / `sing-box.exe` — только Python-стек.

## Что делает workflow

```
data/sources.txt + data/tg_subs.txt   ← v39: динамические URL'ы из Telegram + mifa.world
   ↓ scripts/fetch_tg_subs.py (парсит t.me/s/happvpn + mifa.world/)
   ↓ refresh_subs.py: --sources-file + --extra-sources-file
fetch (urllib → curl → happ-decrypt)
тела подписок (plain / base64 / JSON Xray/Hiddify / Clash-YAML)
   ↓ parse + dedup по node.key
список уникальных узлов
   ↓ TCP-ping socket'ом (опционально)
список TCP-доступных узлов
   ↓ SNI-категоризация (БС/ЧС/серый/фейк/none) + опц. TSPU-sim
   ↓ Pattern scoring (сходство с known_good.txt, замена xray-ping)
   ↓ Geo-rename (api.ip.sb/geoip → «🇩🇪 DE peppo»)
data/preload.txt (по строке на узел) + data/preload_report.json
   ↓ cat | base64 -w 0 > subs.txt
subs.txt (base64-подписка для импорта в v2rayN/Happ/Karing)
   ↓ git-auto-commit-action
коммит в main
```

## Как подключить к своему форку

1. **Форкните** репозиторий `pengvench/sub_generator` на GitHub.
2. **Заполните** `data/sources.txt` своими URL'ами (один на строку):
   ```
   happ://crypt5/...                       # Hiddify-зашифрованная подписка
   https://yax.nenadoblokirowatgnidda.ru/exec?url=http%3A%2F%2F77...   # прокси-обёртка
   https://raw.githubusercontent.com/.../subs.txt   # GitHub raw
   vless://uuid@host:port?...              # прямой конфиг (без загрузки)
   ```
3. **Push'ните** в `main` — на этом шаге workflow ещё не запустится
   автоматически (только на cron / workflow_dispatch).
4. **Проверьте вручную**: GitHub → вкладка **Actions** → **Refresh subs**
   → **Run workflow** (зелёная кнопка справа).
5. **Готово**: после первого прогона в `data/preload.txt` будет актуальный
   список узлов, обновляемый каждые 3 часа
   (UTC: 00:00, 03:00, 06:00, 09:00, 12:00, 15:00, 18:00, 21:00).

## v39: Динамические подписки из Telegram + mifa.world

Если у ваших источников подписки меняются каждый день (например
`t.me/happvpn` выкладывает свежую `happ://crypt5/...` ссылку, а
`mifa.world/<category>` меняет имя категории), вы не можете держать
их статически в `data/sources.txt`. Для этого в v39 добавлен
`scripts/fetch_tg_subs.py`, который ПЕРЕД `refresh_subs.py` парсит
динамические источники и пишет их в `data/tg_subs.txt`.

### Что парсит `fetch_tg_subs.py`

1. **`t.me/s/<channel>`** (по умолчанию `happvpn`) — Telegram web-preview
   последних 20 постов публичного канала. HTML парсится регуляркой
   `<div class="tgme_widget_message_text">...</div>`, в каждом посту
   ищется:
   - `happ://crypt5/...` (Hiddify-зашифрованная подписка, приоритет)
   - `https://.../sub/...` / `.../exec?url=...` / `.../auto`
   Берётся ПОСЛЕДНИЙ пост с совпадением (самый свежий).

2. **`mifa.world/`** — главная страница содержит таблицу со статистикой
   по категориям (`<td>NAME</td><td>COUNT</td>`). Скрипт извлекает
   все имена категорий (ursa, vless, bober, ronin, hysteria, ...)
   и формирует URL `https://mifa.world/<category>` для каждой.
   Каждый такой URL возвращает base64-encoded подписку.

   **Почему не парсим конкретный пост t.me/mifa_world/1310?**
   Пост 1310 — это «service message» (фото/видео), Telegram
   web-preview НЕ отдаёт его текст анонимным пользователям. Парсинг
   главной `mifa.world` надёжнее: не зависит от доступности конкретного
   поста и даёт все категории (а не одну).

### Где взять список категорий

Скрипт сам парсит их с `https://mifa.world/` (HTML-таблица статистики).
Если сайт недоступен или сменился layout — есть hardcoded fallback:
`ursa, vless, bober, ronin, hysteria`.

Чтобы добавить свои категории явно:
```bash
python scripts/fetch_tg_subs.py \
  --channel happvpn \
  --mifa-categories ursa bober ronin NEWCAT \
  --output data/tg_subs.txt
```

### Только Telegram или только mifa.world

```bash
# Только happ://crypt5 из Telegram (без mifa):
python scripts/fetch_tg_subs.py --no-mifa

# Только mifa.world категории (без Telegram):
python scripts/fetch_tg_subs.py --no-tg
```

### Отказоустойчивость

- Если `t.me/s/happvpn` недоступен (rate limit, приватный канал) —
  mifa.world/ всё равно отдаёт подписки.
- Если mifa.world недоступен — happ://crypt5 из Telegram есть.
- Если ОБА упали — существующий `data/tg_subs.txt` сохраняется (не
  перезаписывается при 0 URL'ах), пайплайн продолжает работу с тем
  что есть в `data/sources.txt`.

### Свой канал Telegram

Если у вас свой публичный канал (например `my_proxy_channel`) с
ежедневной подпиской:
```bash
python scripts/fetch_tg_subs.py --channel my_proxy_channel
```

Если канал приватный — web-preview `t.me/s/<channel>` вернёт пустую
страницу. В этом случае можно:
- Использовать TG Bot API + `getChat`/`forwardMessage` (нужен bot token,
  bot должен быть подписчиком канала).
- Запустить свой mtproto-bridge (сложно).
- Просто вручную обновить `data/tg_subs.txt` когда подписка поменяется.

## Настройка частоты / объёма

В `.github/workflows/refresh-subs.yml`:

```yaml
on:
  schedule:
    # v39: каждые 3 часа — t.me/happvpn и mifa.world обновляются часто.
    - cron: "0 0,3,6,9,12,15,18,21 * * *"
```

| Cron           | Что значит                       |
|----------------|----------------------------------|
| `0 0,6,12,18 * * *` | Каждые 6 часов (дефолт)         |
| `0 */3 * * *`  | Каждые 3 часа                    |
| `0 */12 * * *` | Каждые 12 часов                   |
| `0 0 * * *`    | Раз в сутки в полночь UTC         |
| `0 0 * * 1`    | Раз в неделю по понедельникам     |

Crontab-помощник: <https://crontab.guru/>.

## Лимиты GHA

- **Бесплатный тариф**: 2000 минут/месяц для приватных репозиториев;
  для **публичных — безлимитно**. Каждый прогон = ~1-3 минуты
  (с TCP-ping + 16 параллельных workers).
- **Cron джоб может задерживаться** до 15-30 минут в часы пиковой нагрузки.
- **Минимум 5 минут** между запусками (ограничение GHA).
- **Не используйте `*.txt` с приватными данными** (токенами, UUID-ами) в
  публичном форке — коммит открытый.

## Локальный прогон (без GHA)

```bash
# Linux / macOS / WSL
pip install -r requirements-gha.txt
python scripts/refresh_subs.py \
  --sources-file data/sources.txt \
  --output data/preload.txt \
  --with-ping \
  --ping-timeout 3.0 \
  --ping-workers 16
```

## CLI-аргументы

```
--sources-file PATH       Файл со списком URL'ов (по умолчанию data/sources.txt)
--sources URL...          Доп. URL'ы (добавляются к --sources-file)
--output PATH             Куда писать итог (data/preload.txt по умолчанию)
--report PATH             Куда писать JSON-отчёт (data/preload_report.json)
--with-ping               Включить TCP-ping фильтр
--ping-timeout SEC        Таймаут TCP-ping (3.0 по умолчанию)
--ping-workers N          Параллелизм TCP-ping (16 по умолчанию)
--fetch-timeout SEC       Таймаут загрузки одной подписки (20.0)
--max-servers N           Лимит итоговых узлов (0 = без лимита)
--strict                  Если ХОТЯ БЫ ОДИН источник упал — exit 2
--sort-by-sni             Сортировать узлы по SNI-категории (БС-первый)
--bs-only                 Оставить только БС-узлы (sni в белом списке РФ)
--bs-allow-grey           (с --bs-only) Включать «серые» SNI (по умолчанию ON)
--bs-allow-fake           (с --bs-only) Включать «фейк» SNI (по умолчанию OFF)
--saved-subs-dir PATH     Каталог saved_subs/ (по умолчанию data/saved_subs)
--no-saved-subs           Не мёрджить saved_subs/ в источники (по умолчанию ON)
```

## saved_subs/ — авто-мёрдж локально-сохранённых конфигов

`refresh_subs.py` автоматически мёрджит `data/saved_subs/*.txt` и `*.json`
в список источников — как локальное приложение (тумблер «Использовать
импортированные подписки» ON по умолчанию).

**Важно**: GHA работает на серверах GitHub (Ubuntu), он НЕ видит ваш локальный
путь `C:\Users\...\data\saved_subs\all-proxy-keys.txt`. Чтобы GHA его
прочитал — файл нужно положить в репозиторий:

```bash
# У вас локально:
cd path/to/sub_generator
mkdir -p data/saved_subs
cp C:\Users\peppo\Desktop\build\data\saved_subs\all-proxy-keys.txt data/saved_subs/
git add data/saved_subs/all-proxy-keys.txt
git commit -m "add saved_subs/all-proxy-keys.txt"
git push origin main
```

После push'а GHA автоматически подхватит файл при следующем запуске (крон или
ручной). Файл может содержать:
- **Прямые vless://** (по строке) — добавятся к общему списку узлов.
- **JSON-массив объектов Xray/Hiddify** — парсер `_subscription_lines` его
  понимает (v19 fix).
- **Base64-тела** — тоже парсятся.
- `#`-комментарии игнорируются.
- `README.txt` всегда пропускается (как в локальном app).

Флаг `--no-saved-subs` отключает мёрдж (если хотите тестить только URL'ы из
`sources.txt`). Путь к каталогу меняется через `--saved-subs-dir PATH`.

В логе GHA вы увидите:
```
[gha] sources: 3 (from data/sources.txt + CLI + data/saved_subs)
[gha] saved_subs merged: 2 file(s) — all-proxy-keys.txt, paste_20260930_001234.txt
[xray] reading local config file: /home/runner/work/sub_generator/data/saved_subs/all-proxy-keys.txt
[xray] dedup: 162 → 80 (...)
[gha] collected 80 unique nodes
```

## SNI-категоризация: БС / ЧС / серый / фейк / none

`checkers/sni_category.py` — статическая классификация SNI каждого узла:

| Категория | Что значит | Когда проходит на ограниченной сети РФ |
|-----------|------------|------------------------------------------|
| **white** (БС) | SNI в белом списке: `sberbank.ru`, `vk.com`, `gosuslugi.ru`, `cloudflare.com`, `github.com`, `gstatic.com` ... | Гарантированно — DPI пропускает |
| **grey** (серый) | Реальный домен (есть `.`, известная TLD), не в списках | Часто — зависит от оператора |
| **fake** | Короткая случайная строка без точки (`abc12345`) | Сейчас может работать, но ТСПУ обучается |
| **none** | SNI не задан, host — IP-адрес | Почти никогда — нет SNI = блок |
| **black** (ЧС) | SNI в чёрном списке РФ: `instagram.com`, `chatgpt.com`, `twitter.com` ... | Никогда — DPI блокирует |

**Кейс**: на мобильных операторах РФ (МТС/МегаФон/Билайн/Tele2) ЧС-узлы
не проходят DPI-блок. В подписку попадают только ЧС-узлы → на телефоне
не работает. С `--bs-only` мы отсекаем ЧС, серые и фейки (настраиваемо)
и оставляем только реальные рабочие.

**Сортировка**: с `--sort-by-sni` узлы сортируются так, что БС идут
первыми в `preload.txt`. Тогда клиент при connect'е к узлу по списку
будет выбирать БС-узел первым — гарантирует работу на ограниченной сети.

**Списки доменов** — редактируются в `python/checkers/sni_category.py`:
- `WHITE_SNI_DOMAINS` (≈80 доменов) — встроенный «must-have», работает без синка.
- `BLACK_SNI_DOMAINS` (≈30 доменов) — добавить запрещённые.
- **Dynamic whitelist** (`data/sni_whitelist.txt`, ~910 доменов): community-curated
  2026 RU mobile whitelist, обновляется сообществом. Синк скриптом:
  ```
  python scripts/sync_sni_whitelist.py
  ```
  Источник: `github.com/hxehex/russia-mobile-internet-whitelist` (люди сканируют
  IP-диапазоны во время блокировок и смотрят что живёт). Список постоянно
  обновляется сообществом — GHA workflow синкает его перед каждым запуском.
  Файл ищется по трём путям: env var `SNI_WHITELIST_FILE`, `<repo>/data/sni_whitelist.txt`,
  `cwd/data/sni_whitelist.txt`.

Суффиксное сравнение защищает от подделок: `sberbank.ru.evil.com`
НЕ считается белым (это классическая атака — подделать под whitelist).

## blocked_services + tg_media в GHA (full_test=true)

`checkers/blocked_services.py` — проверка доступа к заблокированным в РФ
сервисам (Instagram, ChatGPT, Discord, YouTube) через SOCKS-прокси узла.
Использует TLS-handshake к публичным эндпоинтам — **БЕЗ токенов**.

`checkers/tg_media.py` — проверка загрузки видео из публичной веб-версии
Telegram-канала `t.me/s/<канал>`. Страница канала и видео качаются через
прокси узла. **НЕ требует Telegram API-токена** — это публичный веб-предпросмотр.

Оба чекера требуют запущенный xray/sing-box (SOCKS-прокси). В GHA это
доступно только при `full_test=true` (см. ниже шаг "Download xray + sing-box").

В workflow добавлен step **"Full check via xray"** (только при `full_test=true`):
после `refresh_subs.py` запускает существующий `python -m ui.cli_main` на
первых 20 узлах из `preload.txt`. CLI прогоняет: alive + siberian + tcp16-20
+ blocked_services + tg_media. Узлы, прошедшие все проверки, заменяют
`preload.txt`. Без full_test этот step пропускается — preload.txt содержит
БС-узлы только после TCP-ping (дёшево, но менее строго).

**Лимиты GHA для full_test**: 20 узлов × ~30с = ~10 минут на тест.
При `--max-servers 0` (без лимита) и 80 узлах это ~40 минут —
граничит с лимитом 60 минут на job.

## Полная проверка через xray/sing-box в GHA

**Теперь доступна!** Workflow поддерживает `full_test: true` (тоггл в
workflow_dispatch) — качает **Linux binaries** `xray-linux-64.zip` и
`sing-box-linux-64.tar.gz` из апстрима и кладёт в `bin/`.

Логика `_resolve_binary` (в `runtime/procs.py`) уже кросс-платформенная:
- На Windows (`os.name == "nt"`) — ищет `xray.exe` / `sing-box.exe`.
- На Linux — ищет `xray` / `sing-box` без расширения.

То есть если в GHA поставить Linux-бинари в `bin/xray` и `bin/sing-box`,
runtime их подхватит и сможет запускать реальные проверки
(TLS-handshake, alive, siberian, tcp16-20, спид-тест).

**Что работает с full_test=true**:
- ✅ TCP/UDP-ping (бесплатно, работает всегда).
- ✅ alive (TLS-хендшейк через локальный SOCKS-прокси xray).
- ✅ siberian-проверка (залп из N параллельных TLS-хендшейков).
- ✅ tcp 16-20 (передача payload через TLS).
- ✅ CIDR-whitelist проверка.
- ✅ WHITE-SNI проверка (resilience.py:WHITE_SNI_TARGETS).
- ✅ Спид-тест (NDT7, Cloudflare, OVH).
- ⚠️ Telegram-проверка — требует API-токен (можно передать через секрет).
- ❌ DPI-suite (zapret) — требует zapret-дистрибутив, в GHA не качается.
- ❌ Гео-слепок (ИИ) — требует обращения к OpenAI (токен + IP GHA).

**Что НЕ делает GHA-скрипт без full_test**:

- **Не запускает xray.exe / sing-box.exe** — только TCP-reachability.
- **Не проверяет протокол** — узел `vless://uuid@127.0.0.1:443?...#placeholder`
  (мёртвая подписка-заглушка) пройдёт TCP-ping (443 открыт локально), но
  не заработает в реальности. Это фильтр «сервер вообще живёт», а не
  «VPN работает».
- **Не делает гео-проверку** (ИИ-слепок страны) — это требует обращения к
  OpenAI/Cloudflare trace, который GHA может блокировать по IP.

Если нужна полная проверка на регулярной основе — включайте `full_test=true`
в ручном запуске, но не ставьте на cron (долго + дорого по минутам GHA).
Для cron'а каждую 1-6 часов — только `--bs-only --sort-by-sni` без full_test.

## Безопасность / форк

- **`cryptography`** ставится из pip — открыто, без секретов.
- **`happ_keys.py`** содержит вшитые ключи (RSA-4096 PKCS#8) для
  happ://crypt5 — они публичные (извлечены из дистрибутива Happ), это
  не секрет.
- **`GITHUB_TOKEN`** в GHA используется для коммита — это автоматический
  токен workflow'а, ничего настраивать не нужно.
- **Если форкаете в private репо** — `cron` работает только если репо
  активировано (было activity за последние 60 дней, иначе GHA отключает).

## Траблшутинг

- **Workflow не запускается по cron**: проверьте вкладку Actions →
  выберите workflow → "Enable workflow" (если disabled).
- **Все источники упали**: проверьте, что URL'ы в `sources.txt` доступны
  с GitHub'овских IP (часть `*.ru` доменов могут блокироваться). Прогон
  `curl -sS -I <URL>` с локальной машины не показатель.
- **Парсер не нашёл узлов**: включите `SUBGEN_DEBUG=1` (уже выставлено в
  workflow) и смотрите DEBUG-логи runtime.
- **Коммит не пушится**: проверьте `permissions: contents: write` в
  workflow (выставлено), и что ветка `main` не защищена branch protection
  rules (или добавьте обход для `github-actions[bot]`).
