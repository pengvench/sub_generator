# GHA: авто-обновление подписок на cron'е

`scripts/refresh_subs.py` + `scripts/alive_test.py` +
`.github/workflows/refresh-subs.yml` (GitHub) — лёгкая версия sub_generator
для CI: скачивает источники из `data/sources.txt` (плюс динамические URL'ы
из `data/tg_subs.txt`), парсит, дедуплицирует, пингует, тестирует и
коммитит подписки каждые 3 часа. ПАРАЛЛЕЛЬНО отдельный репо
`sub_generator_alive` на GitVerse гоняет тот же alive-test ИЗ
РФ-датацентра по сырым пулам этого репо.

## Архитектура v9: полный пайплайн на GitHub + отдельный alive-репо на GitVerse

```
┌──────────── GitHub: sub_generator (этот репо) ────────────┐
│ refresh-subs.yml, каждые 3ч, 4 параллельных job:          │
│                                                            │
│  refresh (~20-25 мин): fetch → дедуп по серверу →          │
│  ping 2000мс → geo → split БС/ЧС → stage-pool artifact     │
│     │                                                      │
│     ├──→ alive-bs ∥ alive-chs (~10-15 мин каждый):         │
│     │    sing-box/xray SOCKS5 + HTTP-пробы (US/EU-vantage) │
│     │                                                      │
│     └──→ publish: merge + fallback'и + base64              │
│          → subs.txt / subs_chs.txt в main                  │
│          → data/pool_bs.txt / data/pool_chs.txt в main     │
│            (СЫРЫЕ пулы — вход GitVerse-стороны)            │
└────────────────────┬───────────────────────────────────────┘
                     │ публичный raw (raw.githubusercontent.com,
                     │ БЕЗ токенов; fallback cdn.jsdelivr.net)
┌────────────────────▼───── GitVerse: sub_generator_alive ──┐
│ .gitverse/workflows/alive-test.yaml (ОТДЕЛЬНЫЙ репо,       │
│ раз в сутки 10:00 МСК):                                   │
│  alive-bs ∥ alive-chs — alive-test через sing-box/xray    │
│  ИЗ РФ-ДАТАЦЕНТРА (~10-15 мин каждый, лимит 30 мин/задача) │
│         │ artifacts                                       │
│         ▼                                                 │
│  publish — merge + fallback'и + base64                    │
│  → force-push ветка `alive` (subs.txt / subs_chs.txt)     │
└───────────────────────────────────────────────────────────┘
```

Разделение труда:

- **GitHub — всё**: сборка, дедуп, пинг, geo, свой alive-test, публикация
  подписок. Минуты GitHub в публичном репо бесплатны, каденс 3 часа.
- **GitVerse — ОТДЕЛЬНЫЙ репо `sub_generator_alive`** (не зеркало!), в
  нём только alive-test: смысл — «работает ли узел ИЗ РОССИЙСКОГО
  интернета». GitHub-раннер (Azure US/EU) видит сеть не так, как юзер из
  РФ, — его вердикт «живости для России» неполный. GitVerse —
  российские датацентры, ровно тот vantage, который нужен.
- **Мост между ними — публичный raw-URL**: пулы лежат в GitHub-репо как
  обычные txt (`data/pool_bs.txt`, `data/pool_chs.txt`), GitVerse-воркфлоу
  их просто скачивает curl'ом, как любой подписчик. Никаких токенов,
  секретов и mirror-push'ей (секрет `GITVERSE_TOKEN` из v7 удалён).
- **Ветка `alive` на GitVerse, а не main**: CI там никогда не коммитит в
  main — ручные пуши кода в `sub_generator_alive` никогда не
  конфликтуют. Каждый прогон ПЕРЕЗАПИСЫВАЕТ ветку `alive` (main + 1
  коммит с результатами) — история не растёт.

Почему GitVerse-сторона тестирует СЫРОЙ пул, а не результат GitHub
alive-test: вантажи разные. Узел, живой из РФ, но мёртвый из Azure
US (и наоборот) — нормальная ситуация. Тестируя сырой пул, GitVerse
находит узлы, которые GitHub-тест потерял; тестируя GitHub-остаток —
только перепроверял бы чужой фильтр.

Два набора подписок на выходе (можно подключать оба, они не конфликтуют):

| Ссылка | Vantage | Обновление |
|---|---|---|
| `https://raw.githubusercontent.com/pengvench/sub_generator/main/subs.txt` (+ `subs_chs.txt`) | GitHub (US/EU) | каждые 3ч |
| `https://gitverse.ru/api/repos/<логин>/sub_generator_alive/raw/branch/alive/subs.txt` (+ `subs_chs.txt`) | РФ | раз в сутки |

Правила слияния в publish (обе платформы):

| Ситуация БС | Действие |
|---|---|
| alive-артефакт есть, >0 узлов | заменить preload_bs.txt |
| alive-артефакт есть, 0 узлов | пол known_good.txt |
| alive-артефакт ОТСУТСТВУЕТ (job упал) | оставить пингованный пул (fail-safe) |
| ЧС: 0 alive / артефакта нет | оставить исходный preload_chs.txt |
| оба файла-источника отсутствуют (GitVerse) | шаг падает — прошлая подписка НЕ затирается |

## Что делает pipeline

```
data/sources.txt + data/tg_subs.txt
   ↓ scripts/fetch_tg_subs.py (парсит t.me/s/happvpn + mifa.world/)
   ↓ scripts/sync_sni_whitelist.py (~910 SNI-доменов для сортировки)
   ↓ refresh_subs.py
fetch (urllib → curl → happ-decrypt) → parse → dedup по node.key
   ↓ ДЕДУП ПО СЕРВЕРУ (v7: В НАЧАЛЕ, до пинга — fp-варианты одного
     сервера живут на одном host:port, TCP-результат идентичен;
     замер: 197020 конфигов → 97313 серверов, −51% пингов)
   ↓ SNI-сортировка БС-первыми (--sort-by-sni; порядок дальше сохраняется)
   ↓ TCP-ping по УНИКАЛЬНЫМ host:port (v7: endpoint-dedup — 120
     конфигов → 97 endpoint'ов; успешные подключения ЗАХВАТЫВАЮТ IP
     через getpeername; без сортирующего эффекта — порядок входа
     сохраняется, latency только в лог)
   ↓ append known_good.txt (--known-good-mode none — только добавление)
   ↓ geo-rename «🇩🇪 DE peppo» (v7: DNS-resolve только для хостов без
     захваченного при пинге IP — known_good и прочие; замер смоука:
     82/104 хоста без DNS. Гео — цепочка ip.sb→ip-api→ipwho)
   ↓ split БС/ЧС (по секциям sources.txt + протоколу)
data/preload.txt + preload_bs.txt + preload_chs.txt + source_map.json
   ↓ [publish: cp → data/pool_bs.txt / pool_chs.txt — сырые пулы в main,
   │  вход GitVerse-стороны по raw-ссылке]
   ↓ scripts/alive_test.py (GitHub И GitVerse: sing-box/xray SOCKS5 +
   │    HTTP-пробы через прокси)
   │    проба 1: api.ipify.org — смена exit-IP + замер фаз
   │    пробы 2-4: instagram / youtube / telegram (HTTP-код + фазы)
   │    alive = exit-IP сменился И ≥1 сервис ответил 2xx/3xx
   │    --max-latency-ms применяется к TTFB пробы exit-IP
   ↓ publish: cat preload_bs.txt | base64 -w 0 > subs.txt
GitHub: subs.txt + subs_chs.txt + пулы коммитятся в main
GitVerse: subs.txt + subs_chs.txt force-push на ветку `alive`
```

**Semantics файлов в main (v9)**:
`data/preload_bs.txt` / `data/preload_chs.txt` — alive-проверенные
GitHub-вантажем списки (то же, что внутри subs-подписок GitHub);
`data/pool_bs.txt` / `data/pool_chs.txt` — СЫРЫЕ пинг-фильтрованные
пулы без alive-проверки — вход alive-test на GitVerse.

## Замеры latency в alive-test

Каждая проба измеряется через `curl -w` с разбивкой на фазы:

- `connect` — TCP-connect через прокси до целевого сервера;
- `tls` — TLS/Reality handshake;
- `ttfb` — time-to-first-byte (заголовки ответа);
- `total` — полное время ответа.

Порог `--max-latency-ms` сравнивается ТОЛЬКО с TTFB пробы exit-IP
(api.ipify.org) — одна величина для всех узлов. История порога: 2000
убивал 18 из 45 РАБОЧИХ узлов (ttfb 2061-6964ms на замеренном корпусе),
поэтому default 4000 и выносится в input workflow `max_latency_ms`.

## Порог TCP-ping в refresh (v7)

`--max-ping-ms 2000` (владелец: 1000 слишком жёстко). Замер GHA на
197694 хостах: 27980 alive, p50=173ms, p95=424ms, **max=997ms** — с
порогом 1000 в диапазоне 1000-1500ms срезалось 764 узла. `--ping-timeout`
поднят 1.5 → 2.5 сек: иначе timeout убивает connect раньше, чем сработает
порог 2000.

## Поведение alive-test на краевых случаях (v5 → v7)

- exit-код 1 при 0 alive — НЕ фейл шага workflow (`|| echo`), дальше
  publish ветвится по числу строк-узлов;
- output-файл всегда содержит header-строку → проверяется не `[ -s ]`,
  а счётчик строк-узлов (`wc -l - 1`);
- 0 alive БС → пол known_good.txt (не мусор и не пустая подписка);
  ЧС при 0 alive — оставить исходный пул;
- alive-артефакт отсутствует (job упал) → пингованный пул (fail-safe);
- `--source-map` на отсутствующем файле не падает (пустая карта).

## User-Agent политика (v6)

- Феч подписок: `v2rayNG/1.10.8` (`runtime/types.py:
  SUBSCRIPTION_USER_AGENT`) — подписочные серверы гейтят unknown-клиентов.
- HTTP-пробы alive-test: десктопный Chrome 141 (`alive_test._PROBE_UA`)
  — антиботы Instagram/Cloudflare режут `curl/8.x`, живой узел ловил
  ложный DEAD.

## Антифейк-фильтры (по умолчанию ВКЛЮЧЕНЫ)

- `--min-ping-ms 80` — CDN/PaaS-хостинги (Railway/Vercel/CF Workers)
  отвечают TCP-connect за 10-50ms — у реальных прокси 185-320ms.
  Калибровка по known_good. Opt-out: `--min-ping-ms 0`.
- `--drop-cdn-ips` — IP из диапазонов Cloudflare/Akamai/Fastly/
  CloudFront = фейк (прокси там быть не может; проверено вручную по
  ошибкам v2rayN: 403 / reality verify fail / TLS fail). DNS-IP
  блокируются всегда. Opt-out: `--no-drop-cdn-ips`.
- `--drop-geo-fallback` (default ON) — узлы «🌐 peppo»: гео неизвестно
  после цепочки ip.sb→ip-api→ipwho — владелец проверил, они не меняют
  exit-IP → бесполезны для обхода. Opt-out: `--no-drop-geo-fallback`.
- `--guess-source-type` (default ON) — классификация БС/ЧС по ключевым
  словам (wl/bl/white/black в URL и теле подписки). Opt-out:
  `--no-guess-source-type`.

## Недоказанные эвристики (по умолчанию ВЫКЛЮЧЕНЫ)

Аудит 2026-10 показал, что этот фильтр не имеет подтверждённой пользы и
может удалять рабочие конфиги. Он остался в `refresh_subs.py`, но
включается только явно:

- `--cross-dedup` — удаление из ЧС узлов с тем же (host, port, protocol),
  что уже есть в БС. Разные credential на одном сервере — это разные
  конфиги.

Удалено полностью (мёртвый код): pattern-scoring (~350 строк, магические
веса +40/+30/+25/…, в проде выключен с v49), флаг `--allow-canonical-stack`
(no-op), синка CIDR-whitelist (~30k строк в репо, нигде не использовалась).

## GitVerse: отдельный репо sub_generator_alive (v9)

GitVerse (gitverse.ru) — российский git-хостинг: его облачные CI-раннеры
стоят в РФ-датацентрах, т.е. видят сеть ровно так, как пользователь из
России. Alive-test «для РФ» выполняется ТАМ — в ОТДЕЛЬНОМ репо
`sub_generator_alive` (второй архив `sub_generator_alive.zip`), а не в
зеркале основного. Основной репо на GitHub не ломается и не зависит от
GitVerse: уберите GitVerse-репо — GitHub-подписки продолжат обновляться.

**Никаких токенов и секретов.** Мост между платформами — публичный
raw-URL GitHub-репо: GitVerse-воркфлоу скачивает пулы curl'ом, как любой
другой подписчик. Секрет `GITVERSE_TOKEN` из v7 НЕ нужен и НЕ
используется. Пуш результатов из CI — штатные учётные данные раннера
(checkout сам настраивает origin); опциональный резерв — личный токен в
секрете `GITVERSE_PAT` (нужен ТОЛЬКО если пуш раннером не заработает,
см. траблшутинг).

Лимиты GitVerse (проверены по официальным докам) учтены в дизайне:

| Лимит GitVerse | Значение | Как обходим (v9) |
|---|---|---|
| Макс. время задачи | 30 мин (kill; default 15!) | alive-bs ∥ alive-chs параллельно, `timeout-minutes: 28` задан ЯВНО |
| Квота сборок (публичные репо) | 1000 мин/мес | расписание РАЗ В СУТКИ (~15-30 мин/сутки); тяжёлая сборка осталась на GitHub |
| Артефакты | 500 МБ на всё, 30 дней | только компактные отчёты (без тел проб, ~1 КБ/узел), retention 5 дней |
| Мин. интервал cron | 15 мин | наш cron — суточный |

### Как это работает

1. GitHub `refresh-subs.yml` каждые 3 часа коммитит в main сырые пулы
   `data/pool_bs.txt`, `data/pool_chs.txt` (+ `source_map.json`).
2. GitVerse `.gitverse/workflows/alive-test.yaml` раз в сутки
   (07:00 UTC = 10:00 МСК, через час после GitHub-слота 06:00):
   - скачивает свежие пулы по raw-ссылке (fallback: cdn.jsdelivr.net);
   - параллельно тестирует БС и ЧС (sing-box/xray + HTTP-пробы);
   - merge + fallback'и + base64 → `subs.txt` / `subs_chs.txt`;
   - force-push на ветку **`alive`** (main не трогает!).

Ядра sing-box/xray (linux-amd64) уже лежат в `bin/` репо
`sub_generator_alive` — раннер берёт их локально с gitverse.ru и НЕ
зависит от GitHub Releases. Шаг загрузки в workflow сам скачает ядра
с GitHub только если файлы в `bin/` удалить (например, при обновлении
версий).

### Как залить sub_generator_alive на GitVerse (один раз)

1. **Распакуйте второй архив** `sub_generator_alive.zip` — это
   самостоятельный репо (workflow + скрипты + ядра).
2. **Создайте репозиторий** на gitverse.ru: публичный, имя
   `sub_generator_alive` (любое другое — просто поправьте ссылки).
3. **Залейте**:
   ```bash
   cd sub_generator_alive
   git init -b main
   git add -A
   git commit -m "sub_generator_alive: alive-test из РФ (v9)"
   git remote add origin https://gitverse.ru/<ваш-логин>/sub_generator_alive.git
   git push -u origin main
   ```
   Пуш с компьютера авторизуется обычным входом GitVerse — это НЕ секрет
   в CI, это обычный git.
4. **Проверьте, что CI включён** (вкладка CI/CD в настройках репо) и
   запустите workflow вручную (workflow_dispatch) — первый прогон создаст
   ветку `alive` с подписками.
5. **Обновление кода в будущем**: правите файлы → `git push origin main`.
   Данные (пулы) подтягиваются сами по raw — их в этот репо не пушим.

Основной репо на GitVerse НЕ нужен: зеркалирование main отменено (v9).

### Raw-ссылки подписок (для импорта в клиент)

```
# GitHub (каждые 3ч, US/EU-vantage):
https://raw.githubusercontent.com/pengvench/sub_generator/main/subs.txt
https://raw.githubusercontent.com/pengvench/sub_generator/main/subs_chs.txt

# GitVerse (раз в сутки, РФ-vantage):
https://gitverse.ru/api/repos/<логин>/sub_generator_alive/raw/branch/alive/subs.txt
https://gitverse.ru/api/repos/<логин>/sub_generator_alive/raw/branch/alive/subs_chs.txt
```

Формат GitVerse-ссылок тот же, что уже используется в `data/sources.txt`
для чужих GitVerse-подписок.

### Траблшутинг GitVerse

- **«Не смог скачать data/pool_*.txt»**: проверьте, что GitHub-репо
  публичный и в main есть свежий коммит «auto: refresh subs» (сначала
  должен отработать GitHub-воркфлоу; файлы pool_*.txt появляются с v9).
- **Job убили на 15-й минуте**: не выставлен `timeout-minutes` — он
  задан в alive-test.yaml (28); если правили файл — не потеряйте его
  (default облачного раннера — 15 мин).
- **`git push` в publish упал**: у раннера не хватило прав на запись.
  Резерв без правки workflow: создайте личный токен (GitVerse →
  Настройки → Управление токенами → «Репозитории») и добавьте его как
  секрет `GITVERSE_PAT` в настройках репо — publish сам подхватит его
  при повторном пуше. Результаты progona в любом случае сохранены в
  артефактах.
- **Упёрлись в квоту минут**: смените cron на `"0 7 */2 * *"` (раз в
  два дня) или реже — в файле `.gitverse/workflows/alive-test.yaml`.
- **Ядра не подходят** (новая версия нужна): удалите `bin/sing-box`
  `bin/xray` из репо и поправьте версии в шаге загрузки — workflow
  скачает их с GitHub Releases.

## Как подключить к своему форку

1. **Форкните** репозиторий `pengvench/sub_generator` на GitHub.
2. **Заполните** `data/sources.txt` своими URL'ами (один на строку):
   ```
   happ://crypt5/...                       # Hiddify-зашифрованная подписка
   https://raw.githubusercontent.com/.../subs.txt   # GitHub raw
   vless://uuid@host:port?...              # прямой конфиг (без загрузки)
   ```
   Секции `# === БС ===` / `# === ЧС ===` управляют, в какой из двух
   итоговых подписок окажутся узлы источника.
3. **Push'ните** в `main` (на cron workflow запустится сам).
4. **Проверьте вручную**: GitHub → **Actions** → **Refresh subs** →
   **Run workflow**.
5. **Готово**: подписки (`subs.txt` / `subs_chs.txt`) обновляются каждые
   3 часа (UTC: 00:00, 03:00, …, 21:00). РФ-vantage-подписки — если
   развернёте `sub_generator_alive` на GitVerse (см. раздел выше).

## Безопасность / форк

- **`cryptography`** ставится из pip — открыто, без секретов.
- **`happ_keys.py`** содержит вшитые публичные ключи (RSA-4096) для
  happ://crypt5 — извлечены из дистрибутива Happ, не секрет.
- **`GITHUB_TOKEN`** для коммита — автоматический токен workflow'а.
- **Private-форк**: cron работает, если в репо была активность за
  последние 60 дней.

## Траблшутинг

- **Workflow не запускается по cron**: Actions → выберите workflow →
  "Enable workflow".
- **Все источники упали**: проверьте, что URL'ы доступны с IP GitHub
  (часть `*.ru` доменов блокируется). Локальный `curl -sS -I <URL>` не
  показатель.
- **Парсер не нашёл узлов**: `SUBGEN_DEBUG=1` уже выставлен в workflow —
  смотрите DEBUG-логи runtime.
- **Коммит не пушится**: проверьте `permissions: contents: write` и что
  ветка `main` не защищена branch protection (или добавьте обход для
  `github-actions[bot]`).
- **0 alive после alive-test**: смотрите артефакт `alive-bs-out` /
  `alive-chs-out` (файл `alive_test_report.json`, без тел проб — только
  коды и фазы), поле `error` у dead-узлов — чаще всего это ошибки
  SOCKS5/TLS на стороне серверов, а не баг пайплайна. При этом
  preload_bs.txt не остаётся мусорным — сработает пол known_good.
- **Guard `if: github.server_url == 'https://github.com'` в refresh-subs.yml**:
  на GitHub условие ВСЕГДА истинно, job'ы не скипаются никогда. Это
  страховка на случай случайного пуша main в какой-нибудь GitVerse-репо:
  там тяжёлые job'ы скипнутся и не сожгут квоту.
