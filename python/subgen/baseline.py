"""Базовый замер скорости сети ДО запуска проверки узлов.

Зачем: пользователь на мобильной сети (пример из инцидента: download
46 Мбит/с, upload 5.3 Мбит/с — Яндекс.Интернетометр) выставляет порог
min_speed, который сама сеть физически не выдаёт. В итоге конвейер
отбраковывает ВСЕ рабочие узлы: узел не может быть быстрее канала,
через который его проверяют.

Что делаем: перед стартом тестирования (полный прогон, stress включён)
меряем ПРЯМОЙ (без прокси) download/upload только по сервисам, которые
корректно работают на мобильных сетях РФ с белыми списками:

  download (каскад, первый успешный):
    1. Яндекс.Интернетометр — CDN Яндекса (/probes/50mb, при смене
       бакета — адрес добывается со страницы yandex.ru/internet);
    2. speedtest.tele2.net (10MB.zip) — RU-ISP спидтест;
    3. speedtest.ru — QMS-движок, тот же, что у страницы «проверка
       скорости» Билайна (nearest_servers → gentoken → download.php
       на серверах российских провайдеров);
    4. proof.ovh.net (100Mb.dat) — международный fallback.
  upload (каскад):
    1. приёмник Яндекс.Интернетометра (GET uploadhost → POST 2МБ);
    2. speedtest.ru upload.php (QMS-движок, с тем же JWT).
  rtt:
    GET gstatic generate_204 — информационно.

Cloudflare speedtest (__down/__up) НЕ используется: на мобильных
сетях РФ он не входит в белые списки и регулярно режется/деградирует
(замер падал или показывал заниженную скорость, из-за чего порог
адаптировался неверно).

По замеру адаптируем пороги отбраковки ( adapt_speed_thresholds ):
  - min_download = min(порог_пользователя, 60% от базовой скорости),
    но не ниже 256 КБ/с — «лимит чуть ниже среднего от прогона», чтобы
    не отбрасывать рабочие конфиги;
  - min_upload   = min(10% от порога download, 50% от базовой upload),
    но не ниже 64 КБ/с — главный фикс асимметричных мобильных сетей;
  - tg_media_min = min(512 КБ/с, 50% от базовой download), но не ниже
    128 КБ/с — медиа-фильтр тоже не должен требовать невозможного.

КЭП БЫСТРОГО КАНАЛА (≥ 100 Мбит/с): замер игнорируется, пороги
берутся из UI. Автозамер существует ДЛЯ МОБИЛЬНЫХ СЕТЕЙ — определить,
что канал медленный/асимметричный и порог надо смягчить. Обычные
VPN-конфиги всё равно не выдают 100+ Мбит, поэтому на быстром
проводном канале адаптация по замеру неинформативна (3000 КБ/с —
нормальный пользовательский порог), и мы просто слушаем UI.

Если замер не удался (офлайн, всё порезано) — используются значения
из UI как запасные (fallback), поведение как до v1.3.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from urllib.request import Request, urlopen

from subgen.config import DATA_DIR

_logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Каскад источников замера — только белые для РФ сервисы.
# --------------------------------------------------------------------------
_UA = "Mozilla/5.0 SubGenerator/1.3"

# Яндекс.Интернетометр: CDN-проба скачивания (бакет может смениться —
# тогда адрес добывается динамически со страницы yandex.ru/internet,
# см. _yandex_page_download_url).
YANDEX_CDN_PROBE_URL = "https://cdnrphoszsa2sp7ilm7a.svc.cdn.yandex.net/probes/50mb"
# Приёмник выгрузки: GET редиректит на edge-ноду, тело ответа — URL приёмника.
YANDEX_UPLOADHOST_URL = "https://internetometr.download.cdn.yandex.net/uploadhost"
YANDEX_PAGE_URL = "https://yandex.ru/internet"

# QMS (speedtest.ru) — движок «проверки скорости» beelineru.ru:
#   GET  /api/nearest_servers  (заголовок x-api-key) -> ближайший сервер РФ;
#   POST /api/server/gentoken  (заголовок x-api-key) -> JWT;
#   GET  <server>/download.php?ckSize=N&r=<nonce>    (заголовок jwt);
#   POST <server>/upload.php?r=<nonce>               (заголовок jwt).
# Ключи публичные, взяты из сайтов-клиентов движка; пробуем по порядку.
QMS_API_BASE = "https://speedtest.ru"
QMS_API_KEYS = [
    "5f3287b55fbcd8076919114885f8f3f7",  # speedtest.ru (их собственный сайт)
    "5f271faac24c2fb06977261175815519",  # beelineru.ru (виджет того же движка)
]
QMS_DOWNLOAD_MB = 10  # ckSize: тело ровно N*1_000_000 байт
QMS_DOWNLOAD_BYTES = QMS_DOWNLOAD_MB * 1000 * 1000

# (метка, URL, макс. байт на замер) — статические цели.
# Между "tele2" и "ovh" динамически вставляется QMS-движок Билайна.
BASELINE_DOWNLOAD_TARGETS: list[tuple[str, str, int]] = [
    # Яндекс CDN — инфраструктура Интернетометра, белая везде в РФ.
    ("yandex", YANDEX_CDN_PROBE_URL, 12 * 1024 * 1024),
    # tele2 — публичный RU-спидтест, проходит даже через белые списки.
    ("tele2", "https://speedtest.tele2.net/10MB.zip", 10 * 1024 * 1024),
    # OVH proof — международный fallback (последний).
    ("ovh", "https://proof.ovh.net/files/100Mb.dat", 12 * 1024 * 1024),
]

BASELINE_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 МБ на замер выгрузки

BASELINE_RTT_URL = "https://www.gstatic.com/generate_204"

# Окно замера: читаем не дольше этого времени, скорость = байты/время.
BASELINE_SAMPLE_SEC = 8.0
# Минимальный объём, чтобы считать замер валидным (иначе это кеш/заголовок).
BASELINE_MIN_BYTES = 256 * 1024

# Коэффициенты адаптации порогов («лимиты чуть ниже среднего от прогона»).
DOWNLOAD_ADAPT_FACTOR = 0.6
UPLOAD_ADAPT_FACTOR = 0.5
TG_MEDIA_ADAPT_FACTOR = 0.5
MIN_DOWNLOAD_FLOOR_KBPS = 256.0
MIN_UPLOAD_FLOOR_KBPS = 64.0
TG_MEDIA_FLOOR_KBPS = 128.0

DEFAULT_TG_MEDIA_MIN_KBPS = 512.0  # TG_MEDIA_MIN_KBPS из runtime.types (синхронизировано)

# КЭП БЫСТРОГО КАНАЛА: если базовый download ≥ 100 Мбит/с — замер не
# слушается вовсе, пороги берутся из UI. Автозамер нужен для мобильных
# сетей (медленный/асимметричный канал); на быстрой проводной сети
# (100+ Мбит) обычные VPN-конфиги всё равно столько не выдают, и
# адаптация по замеру неинформативна — используем пользовательский
# порог (например, 3000 КБ/с — нормальный порог для классических
# VPN-конфигов).
BASELINE_CAP_MBITS = 100.0


@dataclass
class BaselineResult:
    """Результат базового замера прямой сети (без прокси)."""

    download_kbps: float | None = None
    upload_kbps: float | None = None
    rtt_ms: float | None = None
    download_source: str | None = None
    upload_source: str | None = None

    @property
    def ok(self) -> bool:
        """Замер считается успешным, если измерен download (upload факультативен)."""
        return self.download_kbps is not None and self.download_kbps > 0

    def as_dict(self) -> dict[str, object]:
        return {
            "download_kbps": round(self.download_kbps, 1) if self.download_kbps else None,
            "upload_kbps": round(self.upload_kbps, 1) if self.upload_kbps else None,
            "rtt_ms": round(self.rtt_ms, 1) if self.rtt_ms else None,
            "download_source": self.download_source,
            "upload_source": self.upload_source,
            "ok": self.ok,
        }


def _nonce_ms() -> int:
    return int(time.time() * 1000)


def _host_of(url: str) -> str:
    try:
        return url.split("://", 1)[1].split("/", 1)[0]
    except (IndexError, AttributeError):
        return url


def _is_yandex_host_url(url: str) -> bool:
    """Хост URL принадлежит Яндексу (защита от подмены приёмника выгрузки)."""
    try:
        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    except IndexError:
        return False
    return host.endswith(".yandex.net") or host.endswith(".yandex.ru")


# --------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------

def _read_download_sample(
    url: str,
    max_bytes: int,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> tuple[float, int] | None:
    """Скачать до max_bytes с окном BASELINE_SAMPLE_SEC. Возвращает (kbps, bytes) или None."""
    started = time.perf_counter()
    total = 0
    deadline = started + max(BASELINE_SAMPLE_SEC, 2.0)
    req_headers = {"User-Agent": _UA}
    if headers:
        req_headers.update(headers)
    try:
        req = Request(url, headers=req_headers)
        with urlopen(req, timeout=timeout) as resp:
            # Пропускаем заголовки: скорость меряем по телу.
            body_started: float | None = None
            while total < max_bytes and time.perf_counter() < deadline:
                chunk = resp.read(min(262144, max_bytes - total))
                if not chunk:
                    break
                if body_started is None:
                    body_started = time.perf_counter()
                total += len(chunk)
            if body_started is None or total < BASELINE_MIN_BYTES:
                return None
            elapsed = max(0.001, time.perf_counter() - body_started)
            return (total / 1024.0) / elapsed, total
    except Exception:
        return None


def _yandex_page_download_url(timeout: float) -> str | None:
    """Достать актуальный download-URL Интернетометра со страницы yandex.ru/internet.

    Бакет CDN (cdnrphoszsa2sp7ilm7a) может смениться — тогда статический
    YANDEX_CDN_PROBE_URL протухнет, а из конфига страницы возьмётся
    свежий (поле "api.download", ~290 МБ bigfile).
    """
    try:
        req = Request(YANDEX_PAGE_URL, headers={"User-Agent": _UA})
        with urlopen(req, timeout=timeout) as resp:
            html = resp.read(262144).decode("utf-8", "replace")
        m = re.search(r'"download"\s*:\s*"(https://[^"]+\.svc\.cdn\.yandex\.net/[^"]+)"', html)
        if m:
            return m.group(1)
    except Exception as exc:
        # Фетч страницы интернетометра — штатный fallback-каскад:
        # недоступность сети тут ожидаема, причину пишем только в debug.
        _logger.debug("страница интернетометра Yandex недоступна: %s", exc)
    return None


def _download_via_yandex(timeout: float, log=None) -> tuple[float, int] | None:
    """Замер download по CDN Яндекса: статическая проба -> адрес из конфига страницы."""
    sample = _read_download_sample(YANDEX_CDN_PROBE_URL, 12 * 1024 * 1024, timeout)
    if sample is not None:
        return sample
    if log:
        log("[baseline]     yandex: статическая CDN-проба недоступна, беру адрес со страницы интернетометра")
    fallback_url = _yandex_page_download_url(timeout)
    if fallback_url and fallback_url != YANDEX_CDN_PROBE_URL:
        if log:
            log(f"[baseline]     yandex: пробую {fallback_url}")
        return _read_download_sample(fallback_url, 12 * 1024 * 1024, timeout)
    return None


# --------------------------------------------------------------------------
# QMS (speedtest.ru — движок «проверки скорости» Билайна)
# --------------------------------------------------------------------------

@dataclass
class _QmsContext:
    base: str
    token: str
    server_name: str = ""


_QMS_CTX_CACHE: _QmsContext | None = None


def _qms_resolve(timeout: float = 8.0) -> _QmsContext | None:
    """Разрешить сервер и JWT спидтеста speedtest.ru (QMS-движок Билайна).

    Ключи пробуются по порядку; результат кешируется на процесс.
    Возвращает None, если API недоступен или ключи отвергнуты.
    """
    global _QMS_CTX_CACHE
    if _QMS_CTX_CACHE is not None:
        return _QMS_CTX_CACHE
    for key in QMS_API_KEYS:
        try:
            req = Request(
                f"{QMS_API_BASE}/api/nearest_servers?t={_nonce_ms()}",
                headers={"User-Agent": _UA, "x-api-key": key},
            )
            with urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            servers = data.get("data") or []
            srv = servers[0] if servers else None
            if not srv or not srv.get("src") or not srv.get("port"):
                continue
            base = f"{str(srv['src']).rstrip('/')}:{int(srv['port'])}"
            req = Request(
                f"{QMS_API_BASE}/api/server/gentoken?t={_nonce_ms()}",
                method="POST",
                headers={"User-Agent": _UA, "x-api-key": key},
            )
            with urlopen(req, timeout=timeout) as resp:
                token = json.loads(resp.read().decode("utf-8", "replace")).get("token")
            if not token:
                continue
            _QMS_CTX_CACHE = _QmsContext(
                base=base, token=token, server_name=str(srv.get("name") or "")
            )
            return _QMS_CTX_CACHE
        except Exception:
            continue
    return None


def _download_via_qms(timeout: float, log=None) -> tuple[float, int] | None:
    """Замер download через QMS: download.php с JWT, размер задаётся ckSize."""
    global _QMS_CTX_CACHE
    ctx = _qms_resolve(timeout=min(6.0, timeout))
    if ctx is None:
        return None
    if log:
        log(f"[baseline]     qms: сервер {ctx.server_name or ctx.base}")
    url = f"{ctx.base}/download.php?ckSize={QMS_DOWNLOAD_MB}&r={_nonce_ms()}"
    sample = _read_download_sample(url, QMS_DOWNLOAD_BYTES, timeout, headers={"jwt": ctx.token})
    if sample is None:
        # Токен мог протухнуть — перевыдадим при следующем заходе.
        _QMS_CTX_CACHE = None
    return sample


# --------------------------------------------------------------------------
# Измерения
# --------------------------------------------------------------------------

def measure_rtt(timeout: float = 5.0) -> float | None:
    """RTT до gstatic generate_204 (информационно)."""
    started = time.perf_counter()
    try:
        req = Request(BASELINE_RTT_URL, headers={"User-Agent": _UA})
        with urlopen(req, timeout=timeout) as resp:
            resp.read(64)
            if 200 <= resp.status < 400:
                return (time.perf_counter() - started) * 1000.0
    except Exception:
        return None
    return None


def measure_download(timeout: float = 10.0, log=None) -> tuple[float | None, str | None]:
    """Каскадный замер download по белым сервисам. Возвращает (kbps, label).

    Порядок: Яндекс.Интернетометр (CDN Яндекса) -> tele2 -> speedtest.ru
    (QMS-движок «проверки скорости» Билайна) -> OVH (международный
    fallback). Cloudflare не используется — на мобильных РФ не белый.
    """
    say = log or (lambda _msg: None)
    static = BASELINE_DOWNLOAD_TARGETS

    # 1-2) статические RU-цели (yandex, tele2).
    for label, url, max_bytes in static[:2]:
        say(f"[baseline]     download: пробую {label} ({_host_of(url)})")
        sample: tuple[float, int] | None
        if label == "yandex":
            sample = _download_via_yandex(timeout, log=say)
        else:
            sample = _read_download_sample(url, max_bytes, timeout)
        if sample is not None and sample[0] > 0:
            return sample[0], label

    # 3) QMS-движок Билайна (speedtest.ru), между RU-статикой и интернационалом.
    say("[baseline]     download: пробую qms (speedtest.ru — движок проверки скорости Билайна)")
    sample = _download_via_qms(timeout, log=say)
    if sample is not None and sample[0] > 0:
        return sample[0], "qms"

    # 4) международный fallback (ovh).
    for label, url, max_bytes in static[2:]:
        say(f"[baseline]     download: пробую {label} ({_host_of(url)})")
        sample = _read_download_sample(url, max_bytes, timeout)
        if sample is not None and sample[0] > 0:
            return sample[0], label
    return None, None


def _resolve_yandex_upload_url(timeout: float) -> str | None:
    """Разрешить приёмник выгрузки Интернетометра: GET uploadhost -> 302 -> URL.

    Тело ответа — адрес вида http://cloudcdn-<edge>.cdn.yandex.net/upload.
    Принимаем только хосты Яндекса (защита от подмены).
    """
    try:
        req = Request(YANDEX_UPLOADHOST_URL, headers={"User-Agent": _UA})
        with urlopen(req, timeout=timeout) as resp:
            if not (200 <= resp.status < 400):
                return None
            body = resp.read(512).decode("utf-8", "replace").strip()
    except Exception:
        return None
    if body.startswith(("http://", "https://")) and _is_yandex_host_url(body):
        return body
    return None


def _post_upload_sample(url: str, timeout: float, headers: dict[str, str] | None = None) -> float | None:
    """POST 2МБ нулей, вернуть КБ/с.

    urllib не умеет стримить тело — шлём одним куском и меряем полное
    время POST с телом (создание запроса + отправка + ответ).
    """
    started = time.perf_counter()
    payload = b"\x00" * min(BASELINE_UPLOAD_BYTES, 4 * 1024 * 1024)
    req_headers = {
        "User-Agent": _UA,
        "Content-Type": "application/octet-stream",
        "Connection": "close",
    }
    if headers:
        req_headers.update(headers)
    try:
        req = Request(url, data=payload, headers=req_headers)
        with urlopen(req, timeout=timeout) as resp:
            resp.read(256)
            elapsed = max(0.001, time.perf_counter() - started)
            return (len(payload) / 1024.0) / elapsed
    except Exception:
        return None


def _upload_via_yandex(timeout: float, log=None) -> float | None:
    """Замер upload: приёмник выгрузки Яндекс.Интернетометра."""
    upload_url = _resolve_yandex_upload_url(timeout)
    if upload_url is None:
        return None
    if log:
        log(f"[baseline]     yandex: приёмник выгрузки {upload_url}")
    return _post_upload_sample(upload_url, timeout)


def _upload_via_qms(timeout: float, log=None) -> float | None:
    """Замер upload через QMS: POST upload.php с JWT (speedtest.ru, движок Билайна)."""
    global _QMS_CTX_CACHE
    ctx = _qms_resolve(timeout=min(6.0, timeout))
    if ctx is None:
        return None
    if log:
        log(f"[baseline]     qms: сервер {ctx.server_name or ctx.base}")
    url = f"{ctx.base}/upload.php?r={_nonce_ms()}"
    kbps = _post_upload_sample(url, timeout, headers={"jwt": ctx.token})
    if kbps is None:
        _QMS_CTX_CACHE = None  # токен мог протухнуть
    return kbps


def measure_upload(timeout: float = 10.0, log=None) -> tuple[float | None, str | None]:
    """Каскадный замер upload по белым сервисам. Возвращает (kbps, label).

    Порядок: приёмник Яндекс.Интернетометра -> QMS (speedtest.ru, движок
    «проверки скорости» Билайна). Cloudflare /__up больше не используется:
    на мобильных сетях РФ он не белый и замер отдачи регулярно падал.
    """
    say = log or (lambda _msg: None)
    say("[baseline]     upload: пробую yandex (приёмник Интернетометра)")
    kbps = _upload_via_yandex(timeout, log=say)
    if kbps:
        return kbps, "yandex"
    say("[baseline]     upload: пробую qms (speedtest.ru — движок проверки скорости Билайна)")
    kbps = _upload_via_qms(timeout, log=say)
    if kbps:
        return kbps, "qms"
    return None, None


def measure_baseline(
    timeout: float = 10.0,
    log_sink=None,
) -> BaselineResult:
    """Полный базовый замер: rtt -> download (каскад) -> upload."""
    result = BaselineResult()
    log = log_sink or (lambda msg: None)

    result.rtt_ms = measure_rtt(timeout=min(5.0, timeout))

    log("[baseline] замер базовой скорости сети (без прокси, белые сервисы РФ)...")
    log("[baseline]   download-каскад: yandex -> tele2 -> qms(speedtest.ru/Билайн) -> ovh")
    result.download_kbps, result.download_source = measure_download(timeout=timeout, log=log)

    if result.download_kbps is not None:
        mbits = result.download_kbps * 8 / 1000.0
        log(f"[baseline]   download: {result.download_kbps:.0f} КБ/с (~{mbits:.1f} Мбит/с) via {result.download_source}")
        result.upload_kbps, result.upload_source = measure_upload(timeout=timeout, log=log)
        if result.upload_kbps is not None:
            up_mbits = result.upload_kbps * 8 / 1000.0
            log(f"[baseline]   upload:   {result.upload_kbps:.0f} КБ/с (~{up_mbits:.1f} Мбит/с) via {result.upload_source}")
        else:
            log("[baseline]   upload:   не измерился (использую стандартную долю от download)")
    else:
        log("[baseline]   download не измерился — пороги из UI используются как есть (fallback)")

    if result.rtt_ms is not None:
        log(f"[baseline]   rtt:      {result.rtt_ms:.0f} мс (gstatic generate_204)")

    return result


def adapt_speed_thresholds(
    user_min_speed_kbps: float,
    baseline: BaselineResult,
    *,
    tg_media_default_kbps: float = DEFAULT_TG_MEDIA_MIN_KBPS,
) -> tuple[float, float, float, dict[str, object]]:
    """Адаптировать пороги отбраковки под реальную скорость сети.

    Возвращает (min_download_kbps, min_upload_kbps, tg_media_min_kbps, info):
      - min_download: min(порог пользователя, 60% базовой download) — но не
        ниже 256 КБ/с. Если пользователь выставил ПОНИЖЕННЫЙ порог, его
        значение сохраняется (замер может только смягчить, не ужесточить);
      - min_upload: min(10% от итогового download, 50% базовой upload);
        если базовый upload не измерен — 10% от download (как раньше);
      - tg_media_min: min(дефолт 512, 50% базовой download) — не ниже 128.

    КЭП БЫСТРОГО КАНАЛА: если базовый download ≥ BASELINE_CAP_MBITS
    (100 Мбит/с) — замер НЕ применяется (info["ignored"] ==
    "fast_channel"), используются пороги пользователя как есть.
    Автозамер — инструмент для мобильных сетей; на быстром проводном
    канале он неинформативен (обычные VPN-конфиги столько не дают).

    При неудачном замере возвращаются исходные значения (fallback на UI).
    """
    min_dl = float(user_min_speed_kbps)
    min_up = min_dl * 0.1
    tg_min = float(tg_media_default_kbps)
    applied = False
    ignored_reason: str | None = None

    baseline_mbits = (baseline.download_kbps or 0.0) * 8 / 1000.0
    if baseline.download_kbps and baseline.download_kbps > 0:
        if baseline_mbits >= BASELINE_CAP_MBITS:
            # Быстрый канал (≥ 100 Мбит): замер не слушаем — пороги из UI.
            # Автозамер нужен для мобильных сетей, где сеть сама не выдаёт
            # порог; быструю проводную сеть VPN-конфиги всё равно не насытят.
            ignored_reason = "fast_channel"
        else:
            adapted_dl = max(
                MIN_DOWNLOAD_FLOOR_KBPS,
                baseline.download_kbps * DOWNLOAD_ADAPT_FACTOR,
            )
            # Замер может только СМЯГЧИТЬ порог: если пользователь сам поставил
            # планку ниже адаптивной — уважаем его значение.
            min_dl = min(min_dl, adapted_dl)
            tg_min = max(TG_MEDIA_FLOOR_KBPS, min(tg_min, baseline.download_kbps * TG_MEDIA_ADAPT_FACTOR))
            applied = True

    if ignored_reason is None and baseline.upload_kbps and baseline.upload_kbps > 0:
        adapted_up = max(
            MIN_UPLOAD_FLOOR_KBPS,
            baseline.upload_kbps * UPLOAD_ADAPT_FACTOR,
        )
        min_up = min(min_up, adapted_up)

    info = {
        "applied": applied,
        "ignored": ignored_reason,
        "baseline_mbits": round(baseline_mbits, 1),
        "cap_mbits": BASELINE_CAP_MBITS,
        "user_min_speed_kbps": float(user_min_speed_kbps),
        "min_download_kbps": round(min_dl, 1),
        "min_upload_kbps": round(min_up, 1),
        "tg_media_min_kbps": round(tg_min, 1),
        "factors": {
            "download": DOWNLOAD_ADAPT_FACTOR,
            "upload": UPLOAD_ADAPT_FACTOR,
            "tg_media": TG_MEDIA_ADAPT_FACTOR,
        },
    }
    return min_dl, min_up, tg_min, info


def baseline_cache_path():
    """Путь кеша последнего базового замера (для отчёта/диагностики)."""
    return DATA_DIR / "baseline_last.json"


def save_baseline_cache(baseline: BaselineResult, info: dict[str, object]) -> None:
    """Сохранить последний замер в data/baseline_last.json (перезапись)."""
    payload = {"measured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "baseline": baseline.as_dict(), "thresholds": info}
    try:
        path = baseline_cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        # Кеш не критичен для работы, но потеря последнего замера —
        # предупреждение: адаптивные пороги соберутся заново (дольше старт).
        _logger.warning("кеш baseline_last.json не сохранён: %s", exc)
