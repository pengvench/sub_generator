"""Константы и типы данных рантайма (узлы, результаты проб, конфиг).

Раньше жили в xray_runtime.py; вынесены сюда, чтобы «основной» файл
ядра не тащил за собой определения констант."""
from __future__ import annotations


import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

# NODE_SCHEMES определён в uritools и реэкспортируется здесь.
from .uritools import NODE_SCHEMES, _node_dedup_text  # noqa: F401


TELEGRAM_PROBE_TARGETS = [
    ("api.telegram.org", 443, "api.telegram.org"),
    ("telegram.org", 443, "telegram.org"),
]
TELEGRAM_DCS = [
    ("149.154.167.50", 443),
    ("149.154.167.51", 443),
    ("149.154.167.91", 443),
    ("149.154.167.220", 443),  # клиентский MTProto DC (медиа-проверка)
]
TELEGRAM_XRAY_PROBE_TOTAL = 1 + len(TELEGRAM_DCS)
XRAY_SPEED_TEST_HOST = "speed.cloudflare.com"
XRAY_SPEED_TEST_PATH = "/__down?bytes=262144"
XRAY_SPEED_UPLOAD_PATH = "/__up"
XRAY_PROBE_SPEED_TEST_BYTES = 512 * 1024
XRAY_PROBE_SPEED_TEST_SECONDS = 2.5
XRAY_ACTIVE_SPEED_TEST_BYTES = 128 * 1024 * 1024
XRAY_ACTIVE_SPEED_TEST_SECONDS = 8.0

# Быстрые HTTPS-цели для проверки пинга (лёгкие, без больших тел ответа).
GSTATIC_GENERATE_204 = ("www.gstatic.com", 443, "www.gstatic.com", "/generate_204")
IP_SB_IP = ("api.ip.sb", 443, "api.ip.sb", "/ip")

# M-Lab Locate API: возвращает ближайшие NDT7-серверы с wss:// URL.
M_LAB_LOCATE_URL = "https://locate.measurementlab.net/v2/nearest/ndt/ndt7"
M_LAB_NDT7_TIMEOUT_SEC = 12.0
M_LAB_NDT7_SAMPLE_SEC = 2.5
# Медиа-проверка Telegram Bot API: ожидаем HTTP/2 200 или 302 через HEAD.
TELEGRAM_API_HEAD_TARGET = ("api.telegram.org", 443, "api.telegram.org")
# Клиентский MTProto сервер Telegram (DC), используемый при медиа-проверке.
TELEGRAM_MEDIA_DC = ("149.154.167.220", 443)

# --- Telegram-медиа фильтр (t.me/s/peppe_poppo) — ОБЯЗАТЕЛЬНЫЙ для всех ---
# Скачиваем РЕАЛЬНОЕ видео из веб-превью канала через прокси узла и меряем
# скорость: каждый узел, прошедший раунды стресс-теста, ОБЯЗАН качать
# медиа из Telegram. Узел, не набирающий порога, отбраковывается
# (reason="tg_media_failed") независимо от результатов спид-теста —
# медиа-фильтр самостоятельный и равнозначный, а не «спасение».
# Порог 512 КБ/с — достаточно для воспроизведения 480p/720p.
TG_MEDIA_PAGE_HOST = "t.me"
TG_MEDIA_PAGE_PATH = "/s/peppe_poppo"
TG_MEDIA_MIN_KBPS = 512.0
TG_MEDIA_WINDOW_BYTES = 2 * 1024 * 1024  # окно замера (Range)
TG_MEDIA_RANGE_SPAN = 8 * 1024 * 1024  # случайный старт Range в этих пределах
TG_MEDIA_MIN_BODY_BYTES = 128 * 1024  # меньше — считаем Range-окно неудачным
# <video ...> тег целиком: атрибуты парсим ВНУТРИ одного тега, чтобы
# класс blured соседнего видео (за пределами тега) не давал ложных срабатываний.
TG_MEDIA_VIDEO_TAG_RE = re.compile(rb"<video\b([^>]*)>")
TG_MEDIA_VIDEO_SRC_RE = re.compile(
    rb'src="(https://cdn[0-9a-z]*\.(?:telesco\.pe|telegram\.org)/file/[^"]+)"'
)


# Дополнительные запрещённые в РФ цели: ChatGPT и Instagram.
# Проверка не является обязательной для принятия узла (Telegram и спид-тест
# остаются основным критерием), но позволяет отличить «живой, но частично
# заблокированный» узел от полностью пригодного.
CHATGPT_PROBE_TARGETS = [
    ("chatgpt.com", 443, "chatgpt.com"),
    ("chat.openai.com", 443, "chat.openai.com"),
]
INSTAGRAM_PROBE_TARGETS = [
    ("instagram.com", 443, "instagram.com"),
    ("www.instagram.com", 443, "www.instagram.com"),
    ("i.instagram.com", 443, "i.instagram.com"),
]
BLOCKED_MEDIA_TARGETS = CHATGPT_PROBE_TARGETS + INSTAGRAM_PROBE_TARGETS

# Дополнительные HTTPS-цели для пинга (Karing-стиль). Раньше проверяли
# только GSTATIC + IP-SB — если оба заблокированы/недоступны, узел
# отбраковывался. Теперь перебираем все цели: GSTATIC → IP-SB → Cloudflare
# → Google → Microsoft. Успешный ответ ЛЮБОЙ из них = узел жив.
# HTTPS-цели для пинга через SOCKS. Используем IP-адреса (не домены!).
# _socks_open_connection с ATYP=1 (IPv4) — ядро подключается к IP напрямую,
# БЕЗ DNS-резолвинга. На заблокированных сетях DNS через DoH таймаутится,
# но с IP это не проблема. SNI для TLS-handshake передаётся отдельно.
PING_HTTPS_TARGETS = [
    ("1.1.1.1", 443, "speed.cloudflare.com", "/generate_204"),
    ("1.0.0.1", 443, "speed.cloudflare.com", "/generate_204"),
    ("8.8.8.8", 443, "www.google.com", "/generate_204"),
    ("8.8.4.4", 443, "www.google.com", "/generate_204"),
    ("20.190.128.0", 443, "www.microsoft.com", "/generate_204"),
    ("23.55.32.17", 443, "www.apple.com", "/generate_204"),
]

# Фильтр «мёртвых» подписок: после N последовательных неудач источник
# исключается из повторных попыток на cooldown, чтобы refresh не тратил
# время (и не входил в бесконечный цикл) на гарантированно недоступные URL.
XRAY_DEAD_SOURCE_FAILURES = 3
XRAY_DEAD_SOURCE_COOLDOWN_SEC = 3600.0


XRAY_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}

SING_BOX_PROTOCOLS = {"hysteria", "hysteria2", "hy2"}
XRAY_GOOD_DOWNLOAD_KBPS = 512.0
# Минимальная скорость загрузки/выгрузки для принятия конфига при полной проверке
# (2 МБ/с). Измерения download_kbps/upload_kbps ведутся в КБ/с.
XRAY_MIN_MEDIA_KBPS = 2048.0
NODE_LINK_RE = re.compile(
    r"(?:vless|vmess|trojan|ss|hysteria2|hy2|hysteria)://[^\s\"'<>]+",
    re.IGNORECASE,
)
SUBSCRIPTION_USER_AGENT = "v2rayN/6.23 MTProxyAutoSwitch/1.0"
@dataclass
class XrayRuntimeConfig:
    subscription_urls: list[str] = field(default_factory=list)
    socks_host: str = "127.0.0.1"
    socks_port: int = 10808
    probe_workers: int = 4
    probe_timeout_sec: float = 8.0
    max_servers: int = 0
    # Единый порог скорости загрузки (КБ/с), применяемый и в стресс-тесте
    # (Фаза 2), и в финальном recheck. Раньше стресс-тест жёстко использовал
    # XRAY_MIN_MEDIA_KBPS (2 МБ/с), а sub_generator — --min-speed (5 МБ/с),
    # из-за чего узлы проходили начальную проверку, но отсеивались на финале.
    min_speed_kbps: float = XRAY_MIN_MEDIA_KBPS
    # Адаптивный порог выгрузки (КБ/с). None = старое поведение (10% от
    # min_speed_kbps). Устанавливается конвейером по базовому замеру сети
    # (subgen/baseline.py): на мобильных сетях с низкой отдачей (например,
    # 46 Мбит/46 -> 5 Мбит/down) фиксированные 10% от порога download
    # заваливают все узлы по slow_upload, хотя сеть сама столько не даёт.
    upload_min_kbps: float | None = None
    # Порог медиа-фильтра t.me/s/ (КБ/с). По умолчанию TG_MEDIA_MIN_KBPS;
    # конвейер может опустить его по базовому замеру (слабая сеть).
    tg_media_min_kbps: float = TG_MEDIA_MIN_KBPS
    # Медиа-проверка Telegram (загрузка/выгрузка: HEAD api.telegram.org +
    # MTProto DC + спид-тест) выполняется в стресс-тесте. Флаг позволяет
    # отключить её и принимать узлы только по спид-тесту.
    telegram_media_check: bool = True

    xray_binary_path: str = ""
    sing_box_binary_path: str = ""
    selection_strategy: str = "sticky_session"
    manual_upstream_url: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.socks_host}:{int(self.socks_port)}"


@dataclass
class XrayNode:
    protocol: str
    raw_url: str
    name: str
    host: str
    port: int
    credential: str
    query: dict[str, str] = field(default_factory=dict)
    source_url: str = ""
    runtime: str = "xray"
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, int, str]:
        dedup = _node_dedup_text(self.raw_url) or str(self.credential or "")
        digest = hashlib.sha256(dedup.encode("utf-8", errors="ignore")).hexdigest()[:16]
        return (self.protocol, self.host.lower(), int(self.port), digest)

    def title(self) -> str:
        return self.name or f"{self.protocol}://{self.host}:{self.port}"


@dataclass
class XrayProbeResult:
    node: XrayNode
    accepted: bool
    reason: str
    latency_ms: float | None
    successes: int
    attempts: int
    runtime: str
    api_latency_ms: float | None = None
    dc_latency_ms: float | None = None
    chatgpt_latency_ms: float | None = None
    instagram_latency_ms: float | None = None
    chatgpt_blocked: bool = False
    instagram_blocked: bool = False
    download_kbps: float | None = None
    upload_kbps: float | None = None
    # Telegram-медиа фильтр (t.me/s/peppe_poppo, ОБЯЗАТЕЛЬНЫЙ для всех узлов):
    # скорость скачивания видео из веб-превью канала. None — проба провалена
    # (узел отбракровывается с reason="tg_media_failed") или Telegram-проверки
    # отключены (--no-telegram). Метки в имени подписки больше нет — фильтр
    # универсальный, категорий не заводим.
    tg_media_kbps: float | None = None
    # v8: ISO-код страны из ИИ-гео слепка (CF trace loc=, как видит OpenAI).
    # Источник флага страны в подписке (subgen.geo.serialize_working).
    # Пусто = слепок не получен -> флаг по обычной цепочке pyip/egress/geoip.
    ai_geo_country: str = ""
    # True — нода прошла ПОЛНУЮ проверку (спидтест + доступность Telegram).
    # False — только быстрый пинг (кандидат, не гарантированно рабочий).
    fully_checked: bool = False

    def row(self) -> dict[str, Any]:
        return {
            "url": self.node.raw_url,
            "protocol": self.node.protocol,
            "runtime": self.runtime,
            "name": self.node.title(),
            "host": self.node.host,
            "port": self.node.port,
            "accepted": self.accepted,
            "reason": self.reason,
            "latency_ms": self.latency_ms,
            "api_latency_ms": self.api_latency_ms,
            "dc_latency_ms": self.dc_latency_ms,
            "chatgpt_latency_ms": self.chatgpt_latency_ms,
            "instagram_latency_ms": self.instagram_latency_ms,
            "chatgpt_blocked": self.chatgpt_blocked,
            "instagram_blocked": self.instagram_blocked,
            "download_kbps": self.download_kbps,
            "upload_kbps": self.upload_kbps,
            "tg_media_kbps": self.tg_media_kbps,
            "ai_geo_country": self.ai_geo_country,
            "fully_checked": self.fully_checked,
            "successes": self.successes,
            "attempts": self.attempts,
            "source": self.node.source_url,
        }


def _truthy(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}
# Лояльные для ТСПУ TLS-фингерпринты uTLS (статья «dpi-tls-june-2026», схема
# «Siberian»). Самый популярный браузер (chrome) оказался самым палевным;
# firefox/edge/360/qq считаются «безопасными». random = реальный пресет (ок),
# randomized = синтетика uTLS (палевная, тоже не используем). Если в подписке
# явно указан палевный/синтетический fp — заменяем на лояльный, чтобы пробный
# клиент не провоцировал заморозку ТСПУ сам по себе.
_LOYAAL_FINGERPRINTS = {"firefox", "edge", "360", "qq", "random", "chrome"}
_SAFE_DEFAULT_FINGERPRINT = "firefox"


def _safe_fingerprint(value: object) -> str:
    fp = str(value or "").strip().lower()
    if not fp:
        return _SAFE_DEFAULT_FINGERPRINT
    if fp in _LOYAAL_FINGERPRINTS:
        # v15: fp из ссылки узла используется КАК ЕСТЬ — в т.ч. chrome.
        # Раньше chrome молча подменялся на firefox («самый палевный сигнал»
        # по статье) — но подмена меняет TLS-отпечаток, который ожидают
        # CDN-фронтинг конфиги (Happ/Fastly: fp=chrome в ссылке неспроста),
        # и сервер видел не того клиента, под которого маскировался конфиг.
        # Анти-DPI-подмена не должна ломать честные ссылки провайдеров.
        return fp
    # Неизвестный/синтетический пресет (randomized, ios, safari и т.п.) —
    # подменяем лояльным, чтобы не детектиться.
    return _SAFE_DEFAULT_FINGERPRINT
