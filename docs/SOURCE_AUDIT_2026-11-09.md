# Проверка источников подписок — 9 ноября 2026

Проверено содержимое 146 различных исходных URL: 129 из текущего sources.txt и 17 новых. Дополнительно проверены исправленный URL и альтернативный raw-адрес.

Список: 130 строк → 137 уникальных URL. Добавлено 17, удалено 9 не отдающих конфиги и 1 точный повтор. Исправлен пробел в адресе tankist939-afk.

Все различные URL зеркал сохранены, даже если их содержимое совпадает. Варианты main/refs/heads/main, GitHub/GitVerse и адреса pozor.bond не объединялись.

## Как проверялось

Загружалось тело ответа, затем использовался штатный разбор plain/base64/JSON/Clash и парсер конфигов проекта. Одного HTTP 200 недостаточно. При отказах были повторные запросы с v2rayNG/1.10.8, Happ и браузерным User-Agent, напрямую и через существующий Karing. Для удаления сетевых отказов дополнительно сверены несколько прогонов GHA.

Последний проверенный GHA: [запуск 186](https://github.com/pengvench/sub_generator/actions/runs/42481729184), 8 ноября 19:45–20:02 по Томску. Сборка успешна, но 24 источника не загрузились: 16 ответов GitVerse 429, 4 тайм-аута DuckDNS, 2 ответа 502, один 404 и URL с пробелом. Это частичные отказы источников, а не остановка всего сборщика.

User-Agent GHA уже был v2rayNG/1.10.8 и сохранён. В загрузчик добавлены повторы HTTP 429 с Retry-After и последовательная загрузка с GitVerse. HTTP 200 без конфигов теперь учитывается как отказ источника и отражается в журнале.

## Удалённые источники

- https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt
  HTTP 200, только заголовки, 0 конфигов; 3 проверки с разными User-Agent напрямую и через Karing.
- https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt
  HTTP 200, в заголовке «Количество: 0», 0 конфигов; 3 проверки.
- https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part3.txt
  HTTP 200, пустое тело (0 байт); 3 проверки.
- https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_base64_Sub.txt
  HTTP 404 с ПК напрямую и через Karing, в GHA тоже 404; альтернативный raw-адрес также 404.
- https://gitverse.ru/api/repos/Akres/VPN/raw/branch/master/all
  HTTP 400: репозиторий Akres/VPN отсутствует. Подтверждено с ПК и в нескольких прогонах GHA; ответы 429 отдельно не считались доказательством удаления.
- https://freevpnhappcluchi.duckdns.org/sub/lew1ik2xiuohs9v3
  Не отдаёт тело: TLS-сбой напрямую, тайм-аут через Karing; сетевые отказы в четырёх последовательных прогонах GHA 7–8 ноября.
- https://freevpnhappcluchi.duckdns.org/sub/o20pq89rdo9e7afo
  Не отдаёт тело: TLS-сбой напрямую, тайм-аут через Karing; сетевые отказы в четырёх последовательных прогонах GHA 7–8 ноября.
- https://freevpnhappcluchi.duckdns.org/sub/c32dw5mfut31f3ri
  Не отдаёт тело: TLS-сбой напрямую, тайм-аут через Karing; сетевые отказы в четырёх последовательных прогонах GHA 7–8 ноября.
- https://freevpnhappcluchi.duckdns.org/sub/9kaf6wcp2eok5fbe
  Не отдаёт тело: TLS-сбой напрямую, тайм-аут через Karing; сетевые отказы в четырёх последовательных прогонах GHA 7–8 ноября.

## Новые источники

- https://pozor.bond/sub/fdxvhj7zoh — 9 распознанных конфигов при проверке.
- https://pozor.bond/sub/5qsbui9cf4 — 9 распознанных конфигов при проверке.
- https://pozor.bond/sub/6i9dnv37cudz — 9 распознанных конфигов при проверке.
- https://pozor.bond/sub/vzal49dpeu1f — 9 распознанных конфигов при проверке.
- https://pozor.bond/sub/h29399r90wnq — 9 распознанных конфигов при проверке.
- https://pozor.bond/sub/utcwry9vug6k — 144 распознанных конфигов при проверке.
- https://pozor.bond/sub/2 — 9 распознанных конфигов при проверке.
- https://pozor.bond/sub/obforum — 9 распознанных конфигов при проверке.
- https://pozor.bond/sub/aic7epxbdnnc — 9 распознанных конфигов при проверке.
- https://raw.githubusercontent.com/FLAT447/v2ray-lists/refs/heads/main/BLACK_FULL.txt — 70 распознанных конфигов при проверке.
- https://raw.githubusercontent.com/FLAT447/v2ray-lists/refs/heads/main/BLACK_LTE.txt — 70 распознанных конфигов при проверке.
- https://raw.githubusercontent.com/FLAT447/v2ray-lists/refs/heads/main/WHITE_FULL.txt — 6 распознанных конфигов при проверке.
- https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/verified_configs.txt — 499 распознанных конфигов при проверке.
- https://vless.svinakraft.workers.dev/Top500.txt — 470 распознанных конфигов при проверке.
- https://vless.svinakraft.workers.dev/fastest.txt — 93 распознанных конфигов при проверке.
- https://tuftytech.github.io/ShellShift/sub_all.txt — 1288 распознанных конфигов при проверке.
- https://tuftytech.github.io/ShellShift/sub_wl.txt — 146 распознанных конфигов при проверке.

## Сохранены после сбоя

GitVerse с 429 не удалён: это ограничение запросов, доступность содержимого части URL пока не подтверждена. CP-015/017/026/030 сейчас отвечали 502 Upstream unavailable, но результаты разных прогонов GHA показывают перемежающийся характер отказов, поэтому адреса оставлены.

CP-037 отдаёт 20 конфигов с ПК, хотя в последнем GHA был 502. panel.elix.lol отдаёт 2 конфига через Karing, хотя напрямую отвечал без конфигов. Крупный sevcator/vl.txt содержит свыше 124 тысяч распознанных конфигов; локальная проверка ограничивала размер ответа, сам источник оставлен.

## Страны в домашней публикации

Подтверждена ошибка: после успешного измерения выходного IP домашний скрипт назначал флаг по адресу входного сервера/CDN. На 149 опубликованных узлах последнего успешного домашнего прогона текущая GeoIP-проверка сохранённых выходных IP выявила 100 несовпадений; ещё один узел менял страну выхода между раундами.

Исправленный домашний экспорт использует только измеренные выходные IP конкретного узла. Узлы с выходами в разных странах и без подтверждённой страны не получают фиктивный флаг и не публикуются. Перенос RU в БС опирается на фактическую страну выхода. В GHA alive_test уже переименовывал по выходному IP; найденная ошибка касается домашнего экспортёра.

Проверка источника означает получение разбираемого списка конфигов. Доступность каждого сервера проверяется отдельными существующими этапами GHA и домашней проверкой.

## Применение

Изменения списка и загрузчика опубликованы в main: d2504d7. На ПК установлены те же источники и загрузчик, а также исправленный домашний экспорт по выходным IP. Расписание подтверждено: ежедневно в 05:00 по Томску, ближайший запуск 9 ноября.

Флаги в домашней публикации облака и GitHub/alive уже исправлены: переименовано 100 узлов, один узел с выходами в разных странах исключён. Итог: 148 узлов, БС — 9, ЧС — 139. Исправление использует измерения последнего успешного домашнего прогона от 8 ноября; доступность всех серверов заново не проверялась, дата последней проверки сохранена. Новые ключи и узлы при этом не добавлялись.

Проверки кода: 4 проверки загрузчика (429/Retry-After/User-Agent/404/пустой ответ) и 2 проверки домашнего экспорта (разные выходы одного входного адреса, смена страны, отсутствие измерений, запрет старого гео-отчёта). Все пройдены.

## Подтверждение на самом GHA

[Новый запуск 187](https://github.com/pengvench/sub_generator/actions/runs/42511748469) работает на d2504d7. Этап refresh и геоэтап успешно завершены. Каждый из 18 различных адресов из сообщения пользователя (17 добавленных и один уже существовавший) отдал конфиги именно на GHA. Это подтверждено журналом штатного загрузчика с User-Agent v2rayNG/1.10.8.

Полная проверка работоспособности отдельных VPN-серверов выполняется последующими alive-bs/alive-chs; она не нужна для подтверждения того, что URL подписки отдаёт список.

HTTP 429 остался у 13 URL GitVerse после повторов; они сохранены как временно недоступные. Содержимое двух GitVerse-источников получено: TG-WLTGFF — 9 конфигов, OutlineVPN — 275. RKP_work вернул 200 с нулём конфигов в этом GHA; с ПК был 429, поэтому по одному пустому ответу он пока не удалён. panel.elix.lol также пуст на GHA, но с ПК через Karing отдаёт 2 конфига — источник сохранён.

Решение сохранить перемежающиеся 502 подтверждено: CP-015 отдал на GHA 468 конфигов, CP-017 — 168, CP-030 — 267, несмотря на повторные 502 с ПК ранее. CP-016/026 в этом прогоне ответили 502; динамические mifa/bober и mifa/ronin завершились тайм-аутами.

Подтверждённые 429 в новом GHA:

- https://gitverse.ru/api/repos/gidro/white/raw/branch/master/subscription.txt
- https://gitverse.ru/api/repos/Pizduk/Test/raw/branch/master/Test.txt
- https://gitverse.ru/api/repos/ru-wbl/wl/raw/branch/master/RosTun/utf-8_gen.txt#RosTunnel
- https://gitverse.ru/api/repos/ru-wbl/wl/raw/branch/master/Zieng2%2FZieng2_vless_lite.txt
- https://gitverse.ru/api/repos/ru-wbl/wl/raw/branch/master/Zieng2%2FZieng2_NowMeow.txt
- https://gitverse.ru/api/repos/ru-wbl/wl/raw/branch/master/RkpVPN%2FRKP_Check.txt
- https://gitverse.ru/api/repos/ru-wbl/wl/raw/branch/master/KvRuVPN%2FKvRuVPN.txt
- https://gitverse.ru/api/repos/ru-wbl/wl/raw/branch/master/EtoNeYa%2FEtoNeYa_wl.txt
- https://gitverse.ru/api/repos/bikinitw22/apelsintel/raw/branch/main/alive_bs.txt
- https://gitverse.ru/api/repos/Pizduk/PizdukVPN/raw/branch/master/WlSubPiz.txt
- https://gitverse.ru/api/repos/Pizduk/PizdukVPN/raw/branch/master/sub.txt
- https://gitverse.ru/api/repos/Pizduk/PizdukVPN/raw/branch/master/Mixer
- https://gitverse.ru/api/repos/soulcoil/Haven/raw/branch/master/Haven
