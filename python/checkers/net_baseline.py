"""Начальный замер базовой скорости сети (спидтест без прокси, белые сервисы РФ).

Запускается конвейером ДО распинговки узлов:
  - замер download/upload/RTT прямым каналом (без прокси) по белым для РФ
    сервисам: Яндекс.Интернетометр (основной), Tele2, OVH (фallback);
  - сохранение результата в data/baseline_last.json;
  - адаптация порогов скорости под медленный канал (факторы 0.6/0.5/0.5):
    на быстром канале (>= 100 Мбит/с) пороги НЕ адаптируются («fast_channel»)
    и остаётся порог пользователя.

Источники (проверено 2026-09-05):
  - Яндекс.Интернетометр: GET https://yandex.ru/internet/api/v0/get-probes
    отдаёт JSON с latency/download/upload пробами. Download — файл
    /probes/50mb на CDN (cloudcdn-XX.cdn.yandex.net), upload — POST
    приёмник /upload-http?type=upload, ping — /ping.
  - Tele2: https://speedtest.tele2.net/10MB.zip.
  - OVH: https://proof.ovh.net/files/10Mb.dat.
"""
from __future__ import annotations

import json
import random
import time
import urllib.request
from collections.abc import Callable
from typing import Any

from subgen.config import DATA_DIR

BASELINE_FILE = DATA_DIR / "baseline_last.json"
_YANDEX_PROBES_URL = "https://yandex.ru/internet/api/v0/get-probes"
_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# Порог «быстрого канала»: на каналах >= 100 Мбит/с адаптация порогов не
# выполняется (порог пользователя и так адекватен каналу).
FAST_CHANNEL_MBITS = 100.0

# Факторы адаптации порогов от базовой скорости (медленный канал).
FACTOR_DOWNLOAD = 0.6
FACTOR_UPLOAD = 0.5
FACTOR_TG_MEDIA = 0.5

# Полы (минимальные пороги при адаптации), КБ/с.
MIN_DOWNLOAD_FLOOR_KBPS = 500.0
MIN_UPLOAD_FLOOR_KBPS = 100.0
TG_MEDIA_FLOOR_KBPS = 256.0

# Окна замера, сек.
_DOWNLOAD_WINDOW_SEC = 6.0
_UPLOAD_BYTES = 4 * 1024 * 1024
_RTT_TRIES = 3

LogSink = Callable[[str], None]


def _kbps_mbits(kbps: float) -> float:
    return kbps * 8.0 / 1000.0


def _http_get_json(url: str, timeout: float) -> dict[str, Any] | None:
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _measure_download(url: str, window_sec: float = _DOWNLOAD_WINDOW_SEC) -> float | None:
    """Скорость скачивания (КБ/с) по streaming-замеру на окне window_sec."""
    started = time.monotonic()
    total = 0
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=window_sec + 15.0) as resp:
            while time.monotonic() - started < window_sec:
                chunk = resp.read(262144)
                if not chunk:
                    break
                total += len(chunk)
    except Exception:
        return None
    elapsed = time.monotonic() - started
    if total < 256 * 1024 or elapsed <= 0.3:
        return None
    return total / 1024.0 / elapsed


def _measure_upload(url: str, size: int = _UPLOAD_BYTES) -> float | None:
    """Скорость выгрузки (КБ/с): POST size случайных байт в приёмник."""
    payload = random.randbytes(size)
    started = time.monotonic()
    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={**_UA, "Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(req, timeout=60.0) as resp:
            resp.read(256)
    except Exception:
        return None
    elapsed = time.monotonic() - started
    if elapsed <= 0.3:
        return None
    return size / 1024.0 / elapsed


def _measure_rtt(url: str, tries: int = _RTT_TRIES) -> float | None:
    """RTT (мс) — лучший из tries запросов к ping-пробе."""
    best: float | None = None
    for _ in range(tries):
        started = time.monotonic()
        try:
            req = urllib.request.Request(url, headers=_UA)
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                resp.read(256)
        except Exception:
            continue
        rtt = (time.monotonic() - started) * 1000.0
        if best is None or rtt < best:
            best = rtt
    return best


def _gstatic_rtt() -> float | None:
    started = time.monotonic()
    try:
        req = urllib.request.Request("https://www.gstatic.com/generate_204", headers=_UA)
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            resp.read(64)
        return (time.monotonic() - started) * 1000.0
    except Exception:
        return None


def _download_via_yandex(log: LogSink) -> tuple[float | None, str]:
    """Download через Яндекс.Интернетометр: get-probes -> файл 50mb на CDN."""
    probes = _http_get_json(_YANDEX_PROBES_URL, timeout=10.0)
    if not probes:
        return None, "yandex"
    dl_probes = (probes.get("download") or {}).get("probes") or []
    url = ""
    for probe in dl_probes:
        candidate = str(probe.get("url") or "")
        if "50mb" in candidate:
            url = candidate
            break
    if not url and dl_probes:
        # fallback: первый probe без timeout-параметра (100kb — маленький)
        for probe in dl_probes:
            candidate = str(probe.get("url") or "")
            if "timeout" not in candidate:
                url = candidate
                break
    if not url:
        return None, "yandex"
    host = url.split("/")[2] if "/" in url else "cdn.yandex.net"
    log(f"[baseline]     download: пробую yandex ({host})")
    kbps = _measure_download(url)
    return kbps, "yandex"


def _upload_via_yandex(log: LogSink) -> tuple[float | None, str]:
    """Upload через приёмник Интернетометра (POST /upload-http)."""
    probes = _http_get_json(_YANDEX_PROBES_URL, timeout=10.0)
    if not probes:
        return None, "yandex"
    up_probes = (probes.get("upload") or {}).get("probes") or []
    post_url = ""
    for probe in up_probes:
        candidate = str(probe.get("postUrl") or "")
        if candidate:
            post_url = candidate
            break
    if not post_url:
        return None, "yandex"
    log("[baseline]     upload: пробую yandex (приёмник Интернетометра)")
    log(f"[baseline]     yandex: приёмник выгрузки {post_url.split('?')[0]}")
    kbps = _measure_upload(post_url)
    return kbps, "yandex"


def _download_cascade(log: LogSink) -> tuple[float | None, str]:
    """Каскад download: yandex -> tele2 -> ovh (первая успешная проба)."""
    log("[baseline]   download-каскад: yandex -> tele2 -> ovh")
    kbps, source = _download_via_yandex(log)
    if kbps is not None:
        return kbps, source
    log("[baseline]     download: yandex недоступен, пробую tele2")
    kbps = _measure_download("https://speedtest.tele2.net/10MB.zip")
    if kbps is not None:
        return kbps, "tele2"
    log("[baseline]     download: tele2 недоступен, пробую ovh")
    kbps = _measure_download("https://proof.ovh.net/files/10Mb.dat")
    if kbps is not None:
        return kbps, "ovh"
    return None, ""


def compute_thresholds(
    download_kbps: float | None,
    upload_kbps: float | None,
    user_min_speed_kbps: float,
    *,
    tg_media_user_kbps: float = 512.0,
) -> dict[str, Any]:
    """Пороги скорости под фактический канал.

    Быстрый канал (>= 100 Мбит/с): адаптация НЕ нужна — «fast_channel»,
    порог пользователя остаётся как есть.
    Медленный: min_download = clamp(baseline*0.6, floor, user_min) — ниже
    порога пользователя, но не абсурдно низкий; аналогично upload/tg_media.
    """
    baseline_mbits = _kbps_mbits(download_kbps) if download_kbps else 0.0
    if not download_kbps or baseline_mbits >= FAST_CHANNEL_MBITS:
        return {
            "applied": False,
            "ignored": "fast_channel" if download_kbps else "no_baseline",
            "baseline_mbits": round(baseline_mbits, 1),
            "cap_mbits": FAST_CHANNEL_MBITS,
            "user_min_speed_kbps": float(user_min_speed_kbps),
            "min_download_kbps": float(user_min_speed_kbps),
            "min_upload_kbps": 150.0,
            "tg_media_min_kbps": float(tg_media_user_kbps),
            "factors": {
                "download": FACTOR_DOWNLOAD,
                "upload": FACTOR_UPLOAD,
                "tg_media": FACTOR_TG_MEDIA,
            },
        }
    min_download = max(
        MIN_DOWNLOAD_FLOOR_KBPS,
        min(float(user_min_speed_kbps), download_kbps * FACTOR_DOWNLOAD),
    )
    min_upload = max(
        MIN_UPLOAD_FLOOR_KBPS,
        (upload_kbps or download_kbps / 4.0) * FACTOR_UPLOAD,
    )
    tg_media = max(TG_MEDIA_FLOOR_KBPS, download_kbps * FACTOR_TG_MEDIA)
    return {
        "applied": True,
        "ignored": None,
        "baseline_mbits": round(baseline_mbits, 1),
        "cap_mbits": FAST_CHANNEL_MBITS,
        "user_min_speed_kbps": float(user_min_speed_kbps),
        "min_download_kbps": round(min_download, 1),
        "min_upload_kbps": round(min_upload, 1),
        "tg_media_min_kbps": round(tg_media, 1),
        "factors": {
            "download": FACTOR_DOWNLOAD,
            "upload": FACTOR_UPLOAD,
            "tg_media": FACTOR_TG_MEDIA,
        },
    }


def measure_baseline(
    log_sink: LogSink | None = None,
    *,
    user_min_speed_kbps: float = 3000.0,
    save: bool = True,
) -> dict[str, Any]:
    """Замерить базовую скорость сети (без прокси) + посчитать пороги.

    Возвращает словарь для отчёта:
      {"baseline": {...}, "thresholds": {...}, "measured_at_utc": ...}
    """
    log = log_sink or (lambda _msg: None)

    log("[baseline] замер базовой скорости сети (без прокси, белые сервисы РФ)...")
    download_kbps, download_source = _download_cascade(log)
    if download_kbps is not None:
        log(
            f"[baseline]   download: {download_kbps:.0f} КБ/с "
            f"(~{_kbps_mbits(download_kbps):.1f} Мбит/с) via {download_source}"
        )
    else:
        log("[baseline]   download: замер НЕ удался (все источники недоступны)")

    upload_kbps: float | None = None
    upload_source = ""
    if download_source == "yandex":
        upload_kbps, upload_source = _upload_via_yandex(log)
    else:
        # Приёмник выгрузки есть только у Интернетометра; если download шёл
        # мимо яндекса — пробуем его отдельно.
        upload_kbps, upload_source = _upload_via_yandex(log)
    if upload_kbps is not None:
        log(
            f"[baseline]   upload:  {upload_kbps:.0f} КБ/с "
            f"(~{_kbps_mbits(upload_kbps):.1f} Мбит/с) via {upload_source}"
        )
    else:
        log("[baseline]   upload: замер НЕ удался (приёмник недоступен)")

    rtt = _gstatic_rtt()
    if rtt is None:
        probes = _http_get_json(_YANDEX_PROBES_URL, timeout=10.0)
        ping_probes = (probes or {}).get("latency", {}).get("probes") or []
        if ping_probes:
            rtt = _measure_rtt(str(ping_probes[0].get("url") or ""))
    if rtt is not None:
        log(f"[baseline]   rtt:      {rtt:.0f} мс (gstatic generate_204)")
    else:
        log("[baseline]   rtt:      замер НЕ удался")

    thresholds = compute_thresholds(download_kbps, upload_kbps, user_min_speed_kbps)
    ok = download_kbps is not None
    report: dict[str, Any] = {
        "measured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "baseline": {
            "download_kbps": round(download_kbps, 1) if download_kbps else None,
            "upload_kbps": round(upload_kbps, 1) if upload_kbps else None,
            "rtt_ms": round(rtt, 1) if rtt else None,
            "download_source": download_source,
            "upload_source": upload_source,
            "ok": ok,
        },
        "thresholds": thresholds,
    }
    if thresholds.get("applied"):
        log(
            f"[baseline] канал медленный (~{thresholds['baseline_mbits']:.0f} Мбит/с): "
            f"порог скорости адаптирован {user_min_speed_kbps:.0f} -> "
            f"{thresholds['min_download_kbps']:.0f} КБ/с"
        )
    else:
        log(
            f"[baseline] канал быстрый (~{thresholds['baseline_mbits']:.0f} Мбит/с): "
            f"порог скорости пользователя {user_min_speed_kbps:.0f} КБ/с без изменений"
        )
    if save:
        try:
            BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
            BASELINE_FILE.write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass
    return report


def effective_min_speed(baseline_report: dict[str, Any] | None, user_min_speed: float) -> float:
    """Итоговый порог скорости с учётом baseline (для стресс-теста и recheck)."""
    if not baseline_report:
        return float(user_min_speed)
    thresholds = baseline_report.get("thresholds") or {}
    if thresholds.get("applied"):
        value = thresholds.get("min_download_kbps")
        if isinstance(value, (int, float)) and value > 0:
            return float(value)
    return float(user_min_speed)
