# GHA: авто-обновление подписок на cron'е

`scripts/refresh_subs.py` + `scripts/alive_test.py` +
`.github/workflows/refresh-subs.yml` — лёгкая версия sub_generator для
GitHub Actions (Linux), которая скачивает источники из `data/sources.txt`
(плюс динамические URL'ы из `data/tg_subs.txt`), парсит, дедуплицирует,
проверяет через sing-box/xray и коммитит итоговые подписки каждые 3 часа.

## Что делает workflow

```
data/sources.txt + data/tg_subs.txt
   ↓ scripts/fetch_tg_subs.py (парсит t.me/s/happvpn + mifa.world/)
   ↓ scripts/sync_sni_whitelist.py (~910 SNI-доменов для сортировки)
   ↓ refresh_subs.py
fetch (urllib → curl → happ-decrypt) → parse → dedup по node.key
   ↓ SNI-сортировка БС-первыми (--sort-by-sni; порядок дальше сохраняется)
   ↓ TCP-ping фильтр мёртвых (--with-ping; без сортирующего эффекта —
     порядок сохраняется, latency только в лог: пинг идёт с раннера
     GitHub, для юзера в РФ этот порядок — шум)
   ↓ append known_good.txt (--known-good-mode none — только добавление)
   ↓ geo-rename «🇩🇪 DE peppo» (косметика имён; гео — цепочка ip.sb→ip-api→ipwho)
   ↓ split БС/ЧС (по секциям sources.txt + протоколу) + dedup по серверу
data/preload.txt + preload_bs.txt + preload_chs.txt + source_map.json
   ↓ scripts/alive_test.py (sing-box/xray SOCKS5 + HTTP-пробы через прокси)
   │    проба 1: api.ipify.org — смена exit-IP + замер фаз
   │    пробы 2-4: instagram / youtube / telegram (HTTP-код + фазы)
   │    alive = exit-IP сменился И ≥1 сервис ответил 2xx/3xx
   │    --max-latency-ms применяется к TTFB пробы exit-IP
   ↓ cat preload_bs.txt | base64 -w 0 > subs.txt
subs.txt + subs_chs.txt → git-auto-commit в main
```

## Замеры latency в alive-test

Каждая проба измеряется через `curl -w` с разбивкой на фазы:

- `connect` — TCP-connect через прокси до целевого сервера;
- `tls` — TLS/Reality handshake;
- `ttfb` — время до первого байта ответа;
- `total` — полное время запроса.

Фильтр `--max-latency-ms` применяется к **одной** величине — TTFB пробы
exit-IP — и она же пишется в лог/отчёт как `latency_ms`. Фазы всех проб
сохраняются в `timings` внутри JSON-отчёта. Раньше порог сравнивался со
временем ipify-запроса, а в лог писалась сумма четырёх последовательных
запросов — отсюда абсурд «2006ms → DEAD, 5563ms → ALIVE».

Значение порога — вход workflow `max_latency_ms` (default 4000).
Калибровка на рабочем корпусе из TG-чата (56 конфигов, проверены
владельцем вручную, прогон через живой alive-test): у 45/56 сменился
exit-IP (прокси работает), но старый порог 2000ms отсеял 18 из них
(ttfb 2061–6964ms с дальнего вантажа). 4000 — баланс: режет
заметно-дохлые, не убивает медленные-но-рабочие.

## Поведение alive-test на краевых случаях (v5)

- Выходной код 1 при «0 alive» — это НЕ ошибка шага: workflow гасит его
  и ветвится по числу живых узлов в output-файле.
- `0 alive` в БС → preload_bs.txt = known_good.txt (пол из проверенных
  вручную конфигов): не оставляем тысячи мёртвых конфигов и не отдаём
  пустую подписку. ЧС при 0 alive сохраняет оригинальный файл.
- v4-краш `TypeError: unhashable type 'XrayNode'` (сборка alive_urls
после полного прогона) исправлен: nodes = [(XrayNode, url)],
агрегация распаковывает `( _, url )`.

Ориентиры UX (мобильный телефон, реальное использование):

| TTFB | Оценка |
|------|--------|
| 300–600 мс | отлично |
| 600–1000 мс | нормально |
| 1000–1500 мс | так себе |
| 2000+ мс | мусор |

## Антифейк-фильтры (по умолчанию ВКЛЮЧЕНЫ)

Проверены на практике (known_good + ручные проверки v2rayN) — именно они
убирают основную массу фейк-конфигов, которые проходят TCP/TLS-проверки,
но не проксируют трафик:

- `--min-ping-ms 80` — отбраковка «слишком быстрых» TCP-connect.
  Замеры на known_good: рабочие узлы 185–320ms; Railway/Vercel/CDN —
  10–50ms (TCP принимают, трафик не проксируют). Побочный эффект:
  US-хостинг рядом с раннером GHA тоже < 80ms — принятый обмен для
  РФ-подписки. `0` = выключить.
- `--drop-cdn-ips` — блэклист CDN-диапазонов (Cloudflare/Fastly/
  Akamai/CloudFront), включая 23.0.0.0/8. Проверено вручную по v2rayN:
  на CDN-узлах 403 / reality verification failed / TLS handshake failure.
  Cloudflare Spectrum (настоящий VPN за CF) платный и в бесплатных
  подписках не встречается. `--no-drop-cdn-ips` = выключить.

Классификация источников БС/ЧС (по умолчанию ВКЛЮЧЕНА):

- `--guess-source-type` — для источников без явной секции в `sources.txt`
  тип (БС/ЧС) угадывается по ключевым словам в URL (`wl`/`bl`/
  `white`/`black`/`бс`/`чс`) и в первых 5000 символах тела подписки.
  Возвращено по вердикту владельца: распределение соответствует
  реальности (e2e-прогон: BS=62 / ChS=23). Явные секции
  `# === БС ===` / `# === ЧС ===` — основной способ классификации,
  гадайка его дополняет. Переклассификация по телу подписки логируется
  (`body-analysis: N sources reclassified`).
  `--no-guess-source-type` = выключить.

Гео — метаданные, НЕ критерий жизни:

- Провайдеры гео — цепочка `api.ip.sb → ip-api.com → ipwho.is`
  (subgen/geo.py). Отказ одного провайдера (rate-limit, timeout) больше
  не «убивает» узел — запрос уходит следующему. Отказ всей цепочки →
  `geo_status: "unknown"`, узел остаётся живым в проверках.
- `--drop-geo-fallback` (default ON) — узел, у которого гео неизвестно
  ПОСЛЕ всей цепочки И в имени нет флага («🌐 peppo»), отбрасывается
  из финальной подписки: он не даёт предсказуемой страны выхода —
  бесполезен для GEO-обхода и занимает слот, который мог занять узел
  с флагом. По замерам v59 большая часть «🌐 peppo» — мёртвые.
  `--no-drop-geo-fallback` = выключить.
- В отчёте alive-test каждый узел несёт `country` + `geo_status`
  (ok/unknown) — модель `{alive, exit_ip, country, geo_status}`;
  гео никогда не влияет на вердикт alive/dead.

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
5. **Готово**: `subs.txt` (БС, base64) и `subs_chs.txt` (ЧС) обновляются
   каждые 3 часа (UTC: 00:00, 03:00, …, 21:00).

Импорт в клиент: raw-URL файла `subs.txt` в v2rayN / Happ / Karing.

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
- **0 alive после alive-test**: смотрите `data/alive_test_report.json`,
  поле `error` у dead-узлов — чаще всего это ошибки SOCKS5/TLS на стороне
  серверов, а не баг пайплайна. При этом preload_bs.txt не остаётся
  мусорным — сработает пол known_good (см. выше).
