from __future__ import annotations

import atexit
import base64
import contextlib
import ctypes
import gzip
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import ssl
import struct
import sys
import tempfile
import threading
import urllib.parse
import time
from ctypes import wintypes
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, quote, unquote, urlparse, urlsplit, urlunsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_XRAY_SUBSCRIPTIONS = [
    "https://raw.githubusercontent.com/misha12333211-ctrl/proxy-subs/refs/heads/main/2.txt",
    "https://raw.githubusercontent.com/misha12333211-ctrl/proxy-subs/refs/heads/main/4.txt",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt",
    "https://yax.nenadoblokirowatgnidda.ru/exec?url=http%3A%2F%2F77.110.104.181%3A5002%2Fsub%2FVGdSdSwxNzg2MDE1NDU56hnfxM-O2I",
]

# Старые подписки, вытесненные новым списком (для миграции пользовательских конфигов)
LEGACY_XRAY_SUBSCRIPTION_PATTERNS = (
    "charity.invisibleshrimp.su/",
    "s3.toostep.top/",
    "github.com/zieng2/wl",
    "github.com/whoahaow/rjsxrd",
    "github.com/igareck/vpn-configs-for-russia",
)


def is_legacy_xray_subscription(url: str) -> bool:
    """True, если URL относится к удалённому списку подписок."""
    return any(pattern in url for pattern in LEGACY_XRAY_SUBSCRIPTION_PATTERNS)


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

# ---------------------------------------------------------------------------
# Режим «только sing-box» (тумблер UI / флаг --sing-box-only).
# Глобальный форс ядра: когда установлен, ВСЕ узлы (включая vless/vmess/
# trojan/ss) тестируются через sing-box, а не через xray. Отдельный
# пер-протокольный «автовыбор» удалён: по умолчанию всё идёт через xray,
# hy2/hysteria — всегда через sing-box (протокол физически только там),
# а этот форс покрывает ручной режим «погонять всё на sing-box».
# Глобальность нужна потому, что checkers.base.run_with_node создаёт СВОЙ
# XrayCoreRuntime на каждый вызов — передавать флаг через каждый чекер
# не нужно, достаточно один раз выставить форс на старте конвейера.
# ---------------------------------------------------------------------------
_FORCED_RUNTIME: str | None = None


def set_forced_runtime(runtime: str | None) -> None:
    """Установить принудительное ядро для всех узлов (или снять форс)."""
    global _FORCED_RUNTIME
    value = str(runtime or "").strip().lower() or None
    if value not in (None, "xray", "sing-box"):
        value = None
    _FORCED_RUNTIME = value


def get_forced_runtime() -> str | None:
    """Текущий форс ядра (None = выбор по протоколу узла)."""
    return _FORCED_RUNTIME


# ---------------------------------------------------------------------------
# v11: алиасы для обратной совместимости со старым API и test_singbox_mode.py.
# Старый API использовал "auto"/"xray"/"sing-box" вместо None/"xray"/"sing-box".
# ---------------------------------------------------------------------------

# Список uTLS-фингерпринтов, разрешённых для sing-box (он же _LOYAAL_FINGERPRINTS).
SING_BOX_UTLS_FINGERPRINTS = frozenset({
    "chrome", "firefox", "edge", "360", "qq", "random",
})


class SingBoxUnsupported(Exception):
    """Узел не может быть представлен в sing-box (kcp/quic/xhttp/legacy-scy).

    v11: заглушка для обратной совместимости со старым test_singbox_mode.py.
    Реальный raise в _sing_box_outbound не делаем (это потребует глубокой
    переработки конфигуратора) — но исключение определено, чтобы импорт работал.
    """
    pass


def set_default_core_mode(mode: str | None) -> None:
    """Алиас для set_forced_runtime. Принимает 'auto' = снять форс."""
    if mode is None or str(mode).strip().lower() in ("", "auto"):
        set_forced_runtime(None)
    else:
        set_forced_runtime(str(mode).strip().lower())


def get_default_core_mode() -> str:
    """Алиас для get_forced_runtime. Возвращает 'auto' вместо None."""
    return get_forced_runtime() or "auto"


def _normalize_core_mode(raw: str) -> str:
    """Нормализовать строку режима ядра.

    Аналог старого API: 'sing_box_only'/'sb' → 'sing-box', 'hybrid'/мусор → 'auto'.
    """
    if not raw:
        return ""
    value = str(raw).strip().lower()
    if value in ("sing-box", "singbox", "sing_box_only", "sb"):
        return "sing-box"
    if value == "xray":
        return "xray"
    if value in ("auto", "hybrid"):
        return "auto"
    # Неизвестное значение → auto (не форсируем).
    return "auto"


def _resolved_core_mode(config: Any) -> str:
    """Определить итоговый режим ядра для конфига.

    Если у config есть явное поле core_mode (не 'auto') — оно приоритетнее.
    Иначе — get_default_core_mode().
    """
    core_mode = getattr(config, "core_mode", None) or "auto"
    if core_mode and str(core_mode).strip().lower() not in ("auto", ""):
        return _normalize_core_mode(str(core_mode))
    return get_default_core_mode()


def _sing_box_supports(node: Any) -> tuple[bool, str]:
    """Проверить, поддерживает ли sing-box данный узел.

    Возвращает (supported, reason). reason пустой если supported=True.
    Аналог старого API для test_singbox_mode.py.
    """
    # Импорт здесь — чтобы избежать циклического импорта.
    from singbox_convert import sing_box_unsupported_reason
    reason = sing_box_unsupported_reason(node)
    if reason:
        return (False, reason)
    return (True, "")


XRAY_GOOD_DOWNLOAD_KBPS = 512.0
# Минимальная скорость загрузки/выгрузки для принятия конфига при полной проверке
# (2 МБ/с). Измерения download_kbps/upload_kbps ведутся в КБ/с.
XRAY_MIN_MEDIA_KBPS = 2048.0
NODE_LINK_RE = re.compile(
    r"(?:vless|vmess|trojan|ss|hysteria2|hy2|hysteria)://[^\s\"'<>]+",
    re.IGNORECASE,
)
NODE_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "hysteria://")
SUBSCRIPTION_USER_AGENT = "v2rayN/6.23 MTProxyAutoSwitch/1.0"


@dataclass
class XrayRuntimeConfig:
    subscription_urls: list[str] = field(default_factory=lambda: list(DEFAULT_XRAY_SUBSCRIPTIONS))
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


def _wait_if_paused(
    pause_event: threading.Event | None,
    cancel_event: threading.Event | None = None,
) -> None:
    """Блокирующий ожидатель паузы (вызывается из главного потока).

    Пока pause_event установлен — спим короткими интервалами, реагируя при
    этом на cancel_event (остановка должна работать даже во время паузы).
    """
    if pause_event is None or not pause_event.is_set():
        return
    while pause_event.is_set():
        if cancel_event and cancel_event.is_set():
            raise RuntimeError("refresh_cancelled")
        time.sleep(0.2)


class XrayCoreRuntime:
    def __init__(
        self,
        config: XrayRuntimeConfig,
        *,
        root_dir: Path,
        out_dir: Path,
        log_sink: Callable[[str], None] | None = None,
        event_sink: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.config = config
        self.root_dir = root_dir
        self.out_dir = out_dir
        self.log_sink = log_sink
        self.event_sink = event_sink
        self._lock = threading.RLock()
        self._process: subprocess.Popen | None = None
        self._running_node: XrayNode | None = None
        self._config_path: str = ""
        self._pid_path = self.out_dir / "xray_runtime.pid"
        self._shutdown_requested = False
        self._job_handle: int | None = _create_kill_on_close_job()
        self._cleanup_stale_processes()
        atexit.register(self.stop)
        self.active_result: XrayProbeResult | None = None
        self.last_working: list[XrayProbeResult] = []
        self.last_rejected: list[XrayProbeResult] = []
        self.discovered_nodes: list[XrayNode] = []
        # Кандидаты, прошедшие быстрый пинг (Фаза 1), но ещё не прошедшие
        # стресс-тест/полную проверку (Фаза 2). last_working содержит ТОЛЬКО
        # полностью проверенные (fully_checked=True) узлы.
        self.ping_candidates: list[XrayProbeResult] = []
        self.last_error = ""
        self.last_refresh_finished_at = 0.0
        self.active_download_kbps: float | None = None
        self.active_download_measured_at: float = 0.0
        self._round_robin_cursor = 0
        self._sticky_key: tuple[str, str, int, str] | None = None
        # Защита от реентерабельного refresh: если refresh уже выполняется
        # (например из фонового health-цикла), повторный вызов не должен
        # запускать параллельный полный пересбор подписок.
        self._refresh_running = threading.Event()
        # Счётчики последовательных неудач источника и время до «размораживания»
        # мёртвых подписок (источник не опрашивается в cooldown).
        self._source_failures: dict[str, int] = {}
        self._source_dead_until: dict[str, float] = {}
        self._load_cached_results()


    def is_running(self) -> bool:
        proc = self._process
        return bool(proc and proc.poll() is None)

    @property
    def local_tg_url(self) -> str:
        return f"tg://socks?server={self.config.socks_host}&port={int(self.config.socks_port)}"

    @property
    def local_proxy_url(self) -> str:
        return self.local_tg_url

    def start(self) -> bool:
        with self._lock:
            if self._shutdown_requested:
                return False
            if self.is_running():
                return True
            # Если есть кеш рабочих узлов — стартуем сразу, без полной перепроверки.
            if self.active_result is None and self.last_working:
                self._select_active_result(advance_round_robin=True)
            # Кеша полностью проверенных нет — пробуем лучшего кандидата по пингу,
            # чтобы стартовать как можно раньше (стресс-тест идёт фоном).
            if self.active_result is None and self.ping_candidates:
                self.active_result = self.ping_candidates[0]
                self._log(f"[xray] start from best ping candidate {self.active_result.node.title()}")
            if self.active_result is None:
                # Кеша нет — единственный случай, когда блокируем на полной проверке.
                # refresh() сам запустит лучший по пингу узел сразу после Фазы 1.
                self.refresh()
            if self.is_running():
                return True
            if self.active_result is None:
                self.last_error = "No accepted xray/sing-box nodes"
                self._log(f"[xray] start skipped: {self.last_error}")
                return False
            try:
                self._start_node(self.active_result.node, int(self.config.socks_port))
                self._emit("xray_state", running=True, endpoint=self.config.endpoint)
                return True
            except Exception as exc:
                self.last_error = str(exc)
                self._log(f"[xray] start failed: {exc}")
                self._emit("xray_state", running=False, error=str(exc))
                return False

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            proc = self._process
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=timeout)
            elif proc is None:
                stale_pid = self._read_pid_file()
                if stale_pid:
                    _terminate_pid_tree(stale_pid, timeout=timeout)
            self._process = None
            self._running_node = None
            self._unlink_pid_file()
            self._reset_process_job()
            if self._config_path:
                with contextlib.suppress(Exception):
                    Path(self._config_path).unlink(missing_ok=True)
                self._config_path = ""
            self._emit("xray_state", running=False)

    def shutdown(self, timeout: float = 5.0) -> None:
        self._shutdown_requested = True
        self.stop(timeout=timeout)

    def _read_pid_file(self) -> int | None:
        try:
            payload = json.loads(self._pid_path.read_text(encoding="utf-8"))
            pid = int(payload.get("pid") or 0)
            return pid if pid > 0 else None
        except Exception:
            return None

    def _write_pid_file(self, proc: subprocess.Popen, config_path: str, binary: str) -> None:
        with contextlib.suppress(Exception):
            self.out_dir.mkdir(parents=True, exist_ok=True)
            self._pid_path.write_text(
                json.dumps(
                    {
                        "pid": int(proc.pid),
                        "binary": str(binary),
                        "config": str(config_path),
                        "started_at": time.time(),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

    def _unlink_pid_file(self) -> None:
        with contextlib.suppress(Exception):
            self._pid_path.unlink(missing_ok=True)

    def _cleanup_stale_processes(self) -> None:
        stale_pid = self._read_pid_file()
        if stale_pid:
            _terminate_pid_tree(stale_pid, timeout=2.0)
            self._unlink_pid_file()
        _cleanup_stale_bundle_cores(self.root_dir, self.out_dir)

    def _assign_to_process_job(self, proc: subprocess.Popen) -> None:
        if self._shutdown_requested:
            _terminate_process_tree(proc, timeout=1.0)
            return
        if self._job_handle is None:
            self._job_handle = _create_kill_on_close_job()
        _assign_process_to_job(self._job_handle, proc)

    def _reset_process_job(self) -> None:
        if self._job_handle is not None:
            _close_windows_handle(self._job_handle)
        self._job_handle = _create_kill_on_close_job()

    def restart(self) -> bool:
        self.stop()
        return self.start()

    def probe_active_latency(self, timeout: float | None = None) -> float | None:
        if not self.is_running():
            return None
        probe_timeout = float(timeout if timeout is not None else self.config.probe_timeout_sec or 8.0)
        for host, target_port in TELEGRAM_DCS:
            latency = _socks_mtproto_latency(
                self.config.socks_host,
                int(self.config.socks_port),
                host,
                target_port,
                min(5.0, max(2.0, probe_timeout)),
            )
            if latency is not None:
                return latency
        return None

    def probe_active_download_speed(self, timeout: float | None = None) -> float | None:
        if not self.is_running():
            return None
        probe_timeout = float(timeout if timeout is not None else self.config.probe_timeout_sec or 8.0)
        speed = _xray_download_speed(
            self.config.socks_host,
            int(self.config.socks_port),
            min(15.0, max(8.0, probe_timeout)),
            max_bytes=XRAY_ACTIVE_SPEED_TEST_BYTES,
            sample_seconds=XRAY_ACTIVE_SPEED_TEST_SECONDS,
        )
        if speed is not None and speed > 0:
            self.active_download_kbps = float(speed)
            self.active_download_measured_at = time.time()
            if self.active_result is not None:
                self.active_result.download_kbps = max(float(self.active_result.download_kbps or 0.0), float(speed))
            return float(speed)
        return None

    def refresh(
        self,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
    ) -> None:
        """Полная проверка в две фазы.

        Фаза 1 — быстрый параллельный пинг всех найденных нод (_probe_node_ping):
        глобальный пинг + доступность серверов Telegram (HEAD api.telegram.org
        + MTProto DC). Прошедшие попадают в ping_candidates (отсортированы по
        пингу). Сразу после Фазы 1 лучший по пингу кандидат включается в работу,
        не дожидаясь стресс-теста.

        Фаза 2 — стресс-тест (_stress_probe_node) только по пропинговавшимся
        кандидатам: спид-тест (download/upload) + доступность Telegram в 3 раунда.
        Прошедшие попадают в last_working (fully_checked=True). Отклонённые —
        в last_rejected.
        """
        if self._shutdown_requested:
            raise RuntimeError("runtime_shutdown")
        if self._refresh_running.is_set():
            self._log("[xray] refresh already in progress, skipping duplicate")
            return
        self._refresh_running.set()
        self._log("[xray] fetching subscriptions")
        try:
            previous_working = list(self.last_working)
            previous_active = self.active_result
            nodes = collect_subscription_nodes(
                self._live_subscription_urls(self.config.subscription_urls),
                timeout=float(self.config.probe_timeout_sec or 8.0),
                max_servers=int(self.config.max_servers or 0),
                log_sink=self._log,
                on_source_result=self._note_source_result,
                on_progress=lambda index, total, url: self._emit(
                    "xray_subscription_progress",
                    index=index,
                    total=total,
                    url=str(url or ""),
                ),
                cancel_event=cancel_event,
                pause_event=pause_event,
            )
            _wait_if_paused(pause_event, cancel_event)
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            # Если подписки недоступны (нет сети / все источники упали) —
            # используем кеш пропингованных узлов pinged_subs.txt.
            if not nodes:
                cached = self.load_pinged_subs()
                if cached:
                    self._log(
                        f"[xray] subscriptions unreachable, fallback to {len(cached)} cached pinged nodes"
                    )
                    nodes = cached
                else:
                    self._log("[xray] subscriptions unreachable and no cached pinged nodes")
            self.discovered_nodes = list(nodes)
            if not self.last_working:
                self.last_rejected = [
                    XrayProbeResult(node, False, "pending", None, 0, TELEGRAM_XRAY_PROBE_TOTAL, node.runtime)
                    for node in nodes
                ]
            self.last_error = ""
            self._log(f"[xray] parsed {len(nodes)} nodes")
            if not nodes:
                self.last_working = previous_working
                self.active_result = previous_active
                self.last_refresh_finished_at = time.time()
                self._emit(
                    "xray_refresh_complete",
                    working=len(self.last_working),
                    rejected=len(self.last_rejected),
                    total=0,
                    phase="ping",
                    candidates=0,
                    reason_counts=_reason_counts(self.last_rejected),
                )
                return

            # ---------- Фаза 1: быстрый параллельный пинг всех нод ----------
            # ---------------------------------------------------------------
            # Предварительный TCP-ping: отсеивает мёртвые узлы (закрытые порты,
            # недоступные IP) за секунды, без поднятия ядра. Только узлы с
            # открытым портом идут в дорогой _probe_node_ping ниже.
            # На 10000 узлов: TCP-ping ~30 сек, xray-ping был бы ~5-8 часов.
            # ---------------------------------------------------------------
            # TCP-ping таймаут: 5 сек (а не 2) — это компромисс.
            # 2 сек слишком мало для мобильных сетей с потерями и спутников
            # (RTT 600-1500ms), а также для дальних серверов (Австралия/
            # Сингапур). 5 сек покрывает большинство реальных сценариев
            # и всё ещё в 3 раза быстрее, чем 15-секундный SOCKS-ping.
            # Берём min(5.0, probe_timeout_sec) — если пользователь явно
            # поставил короткий --timeout, уважаем его.
            tcp_timeout_phase1 = min(5.0, float(self.config.probe_timeout_sec or 8.0))
            # TCP/UDP-ping — дешёвый I/O (просто сокеты, без subprocess).
            # Не зависит от RAM/CPU так, как SOCKS-ping с xray.exe.
            # Ставим минимум 256 потоков — это безопасно даже на слабом CPU,
            # т.к. потоки в основном ждут сети (timeout), а не крутят CPU.
            # При workers >= 32 масштабируем до 512 — это ускорит TCP-ping
            # на больших списках без ущерба для системы.
            tcp_workers_phase1 = max(256, int(self.config.probe_workers or 1) * 8)
            self._log(
                f"[xray] TCP/UDP-ping prefilter: {len(nodes)} nodes, "
                f"timeout={tcp_timeout_phase1}s, workers={tcp_workers_phase1} "
                f"(TCP for vless/vmess/trojan/ss, UDP for hysteria/hy2)"
            )
            alive_nodes_phase1: list[XrayNode] = []
            tcp_dead_phase1 = 0
            tcp_started_phase1 = time.monotonic()
            with ThreadPoolExecutor(max_workers=tcp_workers_phase1, thread_name_prefix="tcp-ping") as tcp_exec:
                # Используем _tcp_udp_ping_node: для vless/vmess/trojan/ss
                # это TCP-ping, для hysteria/hy2 — UDP-ping (QUIC-like probe).
                tcp_futures = {tcp_exec.submit(_tcp_udp_ping_node, n, tcp_timeout_phase1): n for n in nodes}
                for tcp_f in as_completed(tcp_futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    n = tcp_futures[tcp_f]
                    if tcp_f.result() is not None:
                        alive_nodes_phase1.append(n)
                    else:
                        tcp_dead_phase1 += 1
            self._log(
                f"[xray] TCP/UDP-ping done in {time.monotonic() - tcp_started_phase1:.1f}s: "
                f"{len(alive_nodes_phase1)} alive, {tcp_dead_phase1} dead (filtered out before xray-ping)"
            )

            # Все TCP-мёртвые узлы сразу попадают в rejected с причиной
            # tcp_ping_failed — они не пойдут в дорогой xray-ping.
            # Используем node.key (хешируемый tuple) для membership-проверки,
            # т.к. XrayNode не реализует __hash__ по умолчанию.
            alive_keys_phase1 = {n.key for n in alive_nodes_phase1}
            tcp_rejected = [
                XrayProbeResult(n, False, "tcp_ping_failed", None, 0, 1, n.runtime)
                for n in nodes if n.key not in alive_keys_phase1
            ]
            # Заменяем nodes на TCP-живые — дальше пингуем только их.
            nodes_for_ping = alive_nodes_phase1

            ping_outcomes: list[XrayProbeResult] = []
            completed = 0
            workers = max(8, int(self.config.probe_workers or 1) * 2)
            if not nodes_for_ping:
                self._log("[xray] WARNING: после TCP-ping не осталось живых узлов для xray-ping")
                with self._lock:
                    self.ping_candidates = []
                    self.last_rejected = list(tcp_rejected)
                    self.last_refresh_finished_at = time.time()
                self._emit(
                    "xray_refresh_complete",
                    working=0,
                    rejected=len(tcp_rejected),
                    total=len(nodes),
                    phase="ping",
                    candidates=0,
                    reason_counts={"tcp_ping_failed": len(tcp_rejected)},
                )
                return
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xray-ping") as executor:
                futures = {executor.submit(self._probe_node_ping, node): node for node in nodes_for_ping}
                for future in as_completed(futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    node = futures[future]
                    completed += 1
                    self._emit("xray_probe_progress", index=completed, total=len(nodes_for_ping), node=node.title(), phase="ping")
                    outcome = future.result()
                    ping_outcomes.append(outcome)
                    status = "ok" if outcome.accepted else outcome.reason
                    latency = f"{outcome.latency_ms:.0f}ms" if outcome.latency_ms is not None else "-"
                    self._log(f"[xray] ping {node.protocol} {node.host}:{node.port} -> {status} {latency}")

            # Объединяем: TCP-мёртвые + xray-ping rejected.
            ping_outcomes.extend(tcp_rejected)
            ping_accepted = sorted(
                (item for item in ping_outcomes if item.accepted),
                key=lambda item: (float("inf") if item.latency_ms is None else float(item.latency_ms)),
            )
            with self._lock:
                self.ping_candidates = ping_accepted
                self.last_rejected = [item for item in ping_outcomes if not item.accepted]

            self._log(f"[xray] phase 1 done: {len(self.ping_candidates)}/{len(nodes)} passed ping (TCP-ping filtered {len(tcp_rejected)} dead)")

            # Сразу включаем конфигурацию с лучшим пингом, пока идёт стресс-тест.
            if self.ping_candidates and not self.is_running():
                best_ping = self.ping_candidates[0]
                self.active_result = best_ping
                self.last_error = ""
                try:
                    self._start_node(best_ping.node, int(self.config.socks_port))
                    self._emit("xray_state", running=True, endpoint=self.config.endpoint)
                    self._log(f"[xray] started best-ping node {best_ping.node.title()} ({best_ping.latency_ms:.0f}ms)")
                except Exception as exc:
                    self.last_error = str(exc)
                    self._log(f"[xray] start failed for best-ping node: {exc}")
                    self._emit("xray_state", running=False, error=str(exc))

            self._emit(
                "xray_refresh_complete",
                working=len(self.ping_candidates),
                rejected=len(self.last_rejected),
                total=len(nodes),
                phase="ping",
                candidates=len(self.ping_candidates),
                reason_counts=_reason_counts(self.last_rejected),
            )

            if not self.ping_candidates:
                self.last_working = previous_working
                self.active_result = previous_active
                self.last_refresh_finished_at = time.time()
                if self.active_result is None:
                    self.last_error = _reason_summary(self.last_rejected) or "No accepted xray/sing-box nodes"
                else:
                    self.last_error = ""
                self._export_results()
                return

            # ---------- Фаза 2: стресс-тест только пропинговавшихся ----------
            stress_outcomes: list[XrayProbeResult] = []
            completed = 0
            stress_nodes = [item.node for item in self.ping_candidates]
            workers = max(1, int(self.config.probe_workers or 1))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xray-stress") as executor:
                futures = {executor.submit(self._stress_probe_node, node): node for node in stress_nodes}
                for future in as_completed(futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    node = futures[future]
                    completed += 1
                    self._emit(
                        "xray_stress_progress",
                        index=completed,
                        total=len(stress_nodes),
                        node=node.title(),
                        accepted=False,
                        reason="stress",
                        latency_ms=None,
                        download_kbps=None,
                        phase="stress",
                    )
                    outcome = future.result()
                    stress_outcomes.append(outcome)
                    status = "ok" if outcome.accepted else outcome.reason
                    latency = f"{outcome.latency_ms:.0f}ms" if outcome.latency_ms is not None else "-"
                    speed = f"{outcome.download_kbps:.0f}K" if outcome.download_kbps is not None else "-"
                    self._log(f"[xray] stress {node.protocol} {node.host}:{node.port} -> {status} {latency} {speed}")

            new_working = sorted(
                (item for item in stress_outcomes if item.accepted),
                key=_xray_result_sort_key,
            )
            stress_rejected = [item for item in stress_outcomes if not item.accepted]
            ping_rejected = [item for item in ping_outcomes if not item.accepted]
            new_rejected = ping_rejected + stress_rejected
            with self._lock:
                if new_working:
                    self.last_working = new_working
                    self.last_rejected = new_rejected
                    self._select_active_result(advance_round_robin=True)
                else:
                    self.last_working = previous_working
                    self.last_rejected = new_rejected
                    # Не выключаем уже запущенную ноду (например, включённую
                    # сразу после Фазы 1 по лучшему пингу), даже если стресс-тест
                    # её отклонил. previous_active сохраняется только если нода
                    # не была выбрана из ping-кандидатов.
                    if self.is_running() and self.active_result is not None:
                        self._log(
                            f"[xray] stress rejected all; keeping running node "
                            f"{self.active_result.node.title()} ({self.active_result.reason})"
                        )
                    else:
                        self.active_result = previous_active
                if not new_working and self.active_result is None:
                    self.last_error = _reason_summary(self.last_rejected) or "No accepted xray/sing-box nodes"
                else:
                    self.last_error = ""
                self.last_refresh_finished_at = time.time()
                self._export_results()
            self._emit(
                "xray_refresh_complete",
                working=len(self.last_working),
                rejected=len(self.last_rejected),
                total=len(nodes),
                phase="stress",
                candidates=len(self.ping_candidates),
                reason_counts=_reason_counts(self.last_rejected),
            )
            # Если после стресса выбранный fully-checked узел отличается от того,
            # что уже запущен (например, был включён ping-кандидат по Фазе 1) —
            # переключаемся на него.
            if new_working and self.active_result is not None:
                if self._shutdown_requested or (cancel_event and cancel_event.is_set()):
                    return
                if self.is_running():
                    running_key = getattr(self._running_node, "key", None)
                    if self.active_result.node.key != running_key:
                        self._log(
                            f"[xray] switching to fully-checked node "
                            f"{self.active_result.node.title()} (latency "
                            f"{self.active_result.latency_ms:.0f}ms)"
                        )
                        self.stop()
                try:
                    self._start_node(self.active_result.node, int(self.config.socks_port))
                    self._emit("xray_state", running=True, endpoint=self.config.endpoint)
                except Exception as exc:
                    self.last_error = str(exc)
                    self._log(f"[xray] start failed after stress: {exc}")
                    self._emit("xray_state", running=False, error=str(exc))
        finally:
            self._refresh_running.clear()

    def quick_sort_by_ping(
        self,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
    ) -> int:
        if self._shutdown_requested:
            return len(self.last_working)
        if self._refresh_running.is_set():
            self._log("[xray] refresh already in progress, skipping quick sort")
            return len(self.last_working)
        self._refresh_running.set()
        try:
            with self._lock:
                # Проверяем весь найденный пул (discovered_nodes), а не только принятые ноды.
                nodes = list(self.discovered_nodes)
                if not nodes:
                    nodes = [item.node for item in self.last_working]
                    if not nodes:
                        nodes = [item.node for item in self.ping_candidates]
            if not nodes:
                # Пула нет — запускаем полный refresh (guard временно снимаем, чтобы
                # не заблокировать собственный вызов refresh()).
                self._refresh_running.clear()
                try:
                    self.refresh(cancel_event=cancel_event, pause_event=pause_event)
                finally:
                    return len(self.last_working)

            self._log(f"[xray] quick ping sort for {len(nodes)} nodes")
            # ---------------------------------------------------------------
            # Предварительный TCP-ping: быстрый connect к (host, port) без
            # поднятия ядра. Отсеивает 60-70% мёртвых узлов (закрытые порты,
            # таймауты, недоступные IP) за ~30 сек вместо часов xray-ping.
            # Только узлы с открытым портом идут в дорогой xray-ping ниже.
            # ---------------------------------------------------------------
            # v11: увеличили workers с 64 до 128 — xray.exe лёгкий (~50MB RAM),
            # 128 параллельных инстансов = ~6GB RAM, на 16GB машине норм.
            # Это даёт ~2× ускорение xray-ping.
            workers = max(16, int(self.config.probe_workers or 1) * 4)
            # TCP-ping таймаут: 3 сек (было 5) — мёртвые порты отваливаются быстрее.
            tcp_timeout = min(3.0, float(self.config.probe_timeout_sec or 8.0))
            # TCP/UDP-ping — дешёвый I/O, минимум 256 потоков.
            tcp_workers = max(256, int(self.config.probe_workers or 1) * 8)
            self._log(f"[xray] TCP/UDP-ping prefilter: {len(nodes)} nodes, timeout={tcp_timeout}s, workers={tcp_workers} (TCP+UDP)")
            alive_nodes: list[XrayNode] = []
            tcp_dead = 0
            tcp_started = time.monotonic()
            # v11: сохраняем TCP latency для ранней отбраковки медленных нод.
            tcp_latencies: dict = {}  # node.key -> latency_ms
            with ThreadPoolExecutor(max_workers=tcp_workers, thread_name_prefix="tcp-ping") as tcp_executor:
                tcp_futures = {tcp_executor.submit(_tcp_udp_ping_node, node, tcp_timeout): node for node in nodes}
                for tcp_future in as_completed(tcp_futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    node = tcp_futures[tcp_future]
                    latency = tcp_future.result()
                    if latency is not None:
                        # v11: ранняя отбраковка — если TCP-ping > 3000мс, нода
                        # слишком медленная для туннеля. Пропускаем xray-ping.
                        if latency > 3000.0:
                            tcp_dead += 1
                            continue
                        alive_nodes.append(node)
                        tcp_latencies[node.key] = latency
                    else:
                        tcp_dead += 1
            tcp_elapsed = time.monotonic() - tcp_started
            self._log(
                f"[xray] TCP/UDP-ping done in {tcp_elapsed:.1f}s: "
                f"{len(alive_nodes)} alive, {tcp_dead} dead (filtered out before xray-ping)"
            )

            # Если после TCP-ping ничего не осталось — выходим без xray-ping.
            if not alive_nodes:
                self._log("[xray] WARNING: после TCP-ping не осталось живых узлов")
                with self._lock:
                    self.ping_candidates = []
                    self.last_rejected = [
                        XrayProbeResult(node, False, "tcp_ping_failed", None, 0, 1, node.runtime)
                        for node in nodes
                    ]
                    self.last_refresh_finished_at = time.time()
                self._emit(
                    "xray_refresh_complete",
                    working=0,
                    rejected=len(nodes),
                    total=len(nodes),
                    phase="ping",
                    candidates=0,
                    reason_counts={"tcp_ping_failed": len(nodes)},
                )
                return 0

            # Заменяем nodes на TCP-живые — дальше пингуем только их.
            nodes = alive_nodes

            previous_working = list(self.last_working)
            previous_active = self.active_result
            outcomes: list[XrayProbeResult] = []
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xray-ping") as executor:

                futures = {executor.submit(self._probe_node_ping, node): node for node in nodes}
                completed = 0
                for future in as_completed(futures):
                    _wait_if_paused(pause_event, cancel_event)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("refresh_cancelled")
                    node = futures[future]
                    completed += 1
                    self._emit("xray_probe_progress", index=completed, total=len(nodes), node=node.title(), phase="ping")
                    outcome = future.result()
                    outcomes.append(outcome)
                    status = "ok" if outcome.accepted else outcome.reason
                    latency = f"{outcome.latency_ms:.0f}ms" if outcome.latency_ms is not None else "-"
                    self._log(f"[xray] quick {node.protocol} {node.host}:{node.port} -> {status} {latency}")

            with self._lock:
                # Быстрая ping-сортировка НЕ трогает last_working (там только
                # полностью проверенные). Она обновляет ping_candidates и при
                # необходимости переключает активную ноду на лучший пинг.
                old_rejected = [item for item in self.last_rejected if item.reason != "quick_ping_failed"]
                new_candidates = sorted(
                    (item for item in outcomes if item.accepted),
                    key=lambda item: (float("inf") if item.latency_ms is None else float(item.latency_ms)),
                )
                self.ping_candidates = new_candidates
                self.last_rejected = old_rejected + [item for item in outcomes if not item.accepted]
                if new_candidates:
                    best = new_candidates[0]
                    if self.active_result is None or (
                        best.latency_ms is not None
                        and (self.active_result.latency_ms is None or best.latency_ms < float(self.active_result.latency_ms))
                        and best.node.key != self.active_result.node.key
                    ):
                        self.active_result = best
                        if self.is_running():
                            if self._shutdown_requested or (cancel_event and cancel_event.is_set()):
                                return len(self.last_working)
                            self.stop()
                            self._start_node(best.node, int(self.config.socks_port))
                            self._emit("xray_state", running=True, endpoint=self.config.endpoint)
                            self._log(f"[xray] switched to best-ping node {best.node.title()} ({best.latency_ms:.0f}ms)")
                else:
                    self.active_result = previous_active
                    self.last_error = _reason_summary([item for item in outcomes if not item.accepted]) or self.last_error
                self.last_refresh_finished_at = time.time()
            self._emit(
                "xray_refresh_complete",
                working=len(self.last_working),
                rejected=len(self.last_rejected),
                total=len(nodes),
                phase="ping",
                candidates=len(self.ping_candidates),
                reason_counts=_reason_counts(self.last_rejected),
            )
            return len(self.last_working)
        finally:
            self._refresh_running.clear()

    def stress_test(
        self,
        *,
        limit: int = 24,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Стресс-тест vless/vmess/trojan/ss узлов (xray/sing-box).

        Для каждого кандидата поднимает временный локальный core на свободном
        порту и прогоняет несколько раундов проверки: доступность Telegram
        (HEAD api.telegram.org + MTProto DC) и спид-тест (M-Lab NDT7 с fallback
        на speed.cloudflare.com). Узел считается стабильным, если минимум
        (rounds - 1) раундов успешны. Медиа-проверка (загрузка/выгрузка в
        Telegram) выполняется на уровне AppRuntime через with_node_process.

        Эмитит события xray_stress_started / xray_stress_progress; финальное
        xray_stress_finished эмитит AppRuntime (добавляет счётчик media_probed).
        """
        if self._shutdown_requested:
            raise RuntimeError("runtime_shutdown")
        if self._refresh_running.is_set():
            self._log("[xray] refresh in progress, skipping stress test")
            return {"total": 0, "stable": [], "rejected": 0, "error": "refresh_in_progress"}
        with self._lock:
            nodes = list(self.discovered_nodes)
            if not nodes:
                nodes = [item.node for item in self.last_working]
        if not nodes:
            return {"total": 0, "stable": [], "rejected": 0}

        nodes = nodes[: max(1, min(int(limit or 24), len(nodes)))]
        self._emit("xray_stress_started", total=len(nodes))
        self._log(f"[xray] stress test for {len(nodes)} nodes")
        outcomes: list[XrayProbeResult] = []
        completed = 0
        workers = max(1, int(self.config.probe_workers or 1))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xray-stress") as executor:
            futures = {executor.submit(self._stress_probe_node, node): node for node in nodes}
            for future in as_completed(futures):
                _wait_if_paused(pause_event, cancel_event)
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                node = futures[future]
                outcome = future.result()
                outcomes.append(outcome)
                completed += 1
                self._emit(
                    "xray_stress_progress",
                    index=completed,
                    total=len(nodes),
                    node=node.title(),
                    accepted=outcome.accepted,
                    reason=outcome.reason,
                    latency_ms=outcome.latency_ms,
                    download_kbps=outcome.download_kbps,
                )
                status = "ok" if outcome.accepted else outcome.reason
                latency = f"{outcome.latency_ms:.0f}ms" if outcome.latency_ms is not None else "-"
                self._log(f"[xray-stress] {node.protocol} {node.host}:{node.port} -> {status} {latency}")

        with self._lock:
            stable = sorted((item for item in outcomes if item.accepted), key=_xray_result_sort_key)
            rejected = [item for item in outcomes if not item.accepted]
            if stable:
                self.last_working = stable
                self.last_rejected = rejected
                self._select_active_result(advance_round_robin=True)
            else:
                self.last_rejected = rejected
                self.last_error = _reason_summary(rejected) or self.last_error
            self._export_results()
        return {"total": len(nodes), "stable": stable, "rejected": len(rejected)}

    def _stress_probe_node(self, node: XrayNode) -> XrayProbeResult:
        if self._shutdown_requested:
            return XrayProbeResult(node, False, "runtime_shutdown", None, 0, 0, node.runtime)
        binary = self._binary_for_node(node)
        if not binary:
            return XrayProbeResult(node, False, f"{node.runtime} binary not found", None, 0, 0, node.runtime)
        port = _find_free_port()
        config_path = ""
        proc: subprocess.Popen | None = None
        started_at = time.monotonic()
        rounds = 3
        try:
            config_path = _write_temp_config(self._build_config(node, port))
            proc = subprocess.Popen(
                [binary, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_subprocess_no_window(),
            )
            self._assign_to_process_job(proc)
            time.sleep(0.8)
            if proc.poll() is not None:
                return XrayProbeResult(node, False, "core exited", None, 0, rounds, node.runtime)
            timeout = float(self.config.probe_timeout_sec or 8.0)
            # Медиа-проверка Telegram (загрузка/выгрузка: HEAD api.telegram.org +
            # MTProto DC) — обязательная часть стресс-теста, если включена.
            # При telegram_media_check=False узлы принимаются только по
            # спид-тесту (download/upload), без требования доступности Telegram.
            telegram_check = bool(getattr(self.config, "telegram_media_check", True))
            round_ok = 0
            latencies: list[float] = []
            speeds: list[float] = []
            upload_speeds: list[float] = []
            for _ in range(rounds):
                if telegram_check:
                    head_result = _socks_https_head_status("127.0.0.1", port, *TELEGRAM_API_HEAD_TARGET, timeout)
                    if head_result is None or head_result[0] not in (200, 302):
                        continue
                    dc_latency: float | None = None
                    for host, target_port in TELEGRAM_DCS:
                        latency = _socks_mtproto_latency("127.0.0.1", port, host, target_port, timeout)
                        if latency is not None:
                            dc_latency = latency
                            break
                    if dc_latency is None:
                        continue
                else:
                    dc_latency = None
                speed = _download_speed_probe("127.0.0.1", port, timeout)
                if speed is not None and speed > 0:
                    speeds.append(speed)

                up = _xray_upload_speed("127.0.0.1", port, timeout)
                if up is not None and up > 0:
                    upload_speeds.append(up)
                if telegram_check:
                    latencies.append(dc_latency)
                round_ok += 1
                time.sleep(0.2)
            accepted = round_ok >= (rounds - 1)
            download_kbps = sorted(speeds)[len(speeds) // 2] if speeds else None
            upload_kbps = sorted(upload_speeds)[len(upload_speeds) // 2] if upload_speeds else None
            min_latency = min(latencies) if latencies else None
            # Проверка скорости: download — главный критерий, upload — второстепенный.
            # Раньше оба проверялись по одному порогу min_speed — узел с хорошим
            # download (3 МБ/с) и плохим upload (500 КБ/с) отбраковывался как
            # slow_upload, хотя для просмотра видео/серфинга он нормально работает.
            # Теперь: download >= min_speed (главный), upload >= min_speed * 0.1
            # (10% от порога — достаточно для базовых задач).
            min_speed = float(getattr(self.config, "min_speed_kbps", XRAY_MIN_MEDIA_KBPS) or XRAY_MIN_MEDIA_KBPS)
            min_upload_speed = min_speed * 0.1  # 10% от порога download
            if accepted and download_kbps is not None and download_kbps < min_speed:
                accepted = False
                reason = f"slow_download ({download_kbps:.0f} < {min_speed:.0f})"
            elif accepted and upload_kbps is not None and upload_kbps < min_upload_speed:
                accepted = False
                reason = f"slow_upload ({upload_kbps:.0f} < {min_upload_speed:.0f})"
            else:
                reason = "ready" if accepted else ("stress_unstable" if round_ok > 0 else "stress_failed")

            # --- Telegram-медиа фильтр ПЕРЕСЁЛ в этап telegram_pro ---
            # (checkers/telegram_pro.py): загрузка видео из t.me/s/ — часть
            # Telegram-этапа, а НЕ стресс-теста. Стресс-тест теперь измеряет
            # ТОЛЬКО скорость (download/upload), как требует архитектура
            # «главный критерий — заблокированные сервисы, скорость — в конце».
            return XrayProbeResult(
                node,
                accepted,
                reason,
                min_latency,
                round_ok,
                rounds,
                node.runtime,
                dc_latency_ms=min_latency,
                download_kbps=download_kbps,
                upload_kbps=upload_kbps,
                tg_media_kbps=None,
                fully_checked=True,
            )
        except Exception as exc:
            return XrayProbeResult(node, False, str(exc), None, 0, rounds, node.runtime)
        finally:
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=max(0.2, 2.0 - (time.monotonic() - started_at)))
            if config_path:
                with contextlib.suppress(Exception):
                    Path(config_path).unlink(missing_ok=True)

    def with_node_process(
        self,
        node: XrayNode,
        fn: Callable[[str, int], Any],
        *,
        fp: str | None = None,
    ) -> Any:
        """Поднимает временный core-процесс ноды на свободном порту, вызывает
        fn(host, port), затем убивает процесс. Используется для медиа-проверки
        (upload/download в Telegram) через локальный SOCKS5 во время стресс-теста.

        ``fp`` — принудительный TLS-фингерпринт uTLS ("chrome"/"firefox"/"random",
        "none" = без uTLS/system TLS). None = использовать fp из ссылки узла.

        v11: ретрай при сбросе процесса (xray.exe иногда падает при старте под
        высокой нагрузкой — 32 параллельных инстанса исчерпывают ресурсы).
       sleep уменьшен с 0.8 до 0.4 сек (SOCKS поднимается за 200-400мс).
        """
        binary = self._binary_for_node(node)
        if not binary:
            raise RuntimeError(f"{node.runtime} binary not found")
        last_error: Exception | None = None
        # v11: 2 попытки. Первая часто падает при высокой нагрузке (32 параллельных
        # xray.exe), вторая обычно проходит — ресурсы освобождаются.
        for attempt in range(2):
            port = _find_free_port()
            config_path = ""
            proc: subprocess.Popen | None = None
            started_at = time.monotonic()
            try:
                config_path = _write_temp_config(self._build_config(node, port, fp=fp))
                proc = subprocess.Popen(
                    [binary, "run", "-c", config_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=_subprocess_no_window(),
                )
                self._assign_to_process_job(proc)
                # v11: sleep 0.4 вместо 0.8 — SOCKS поднимается за 200-400мс.
                # Раньше 0.8 сек × 174 ноды × 9 чекеров = 21 минута чистого sleep.
                time.sleep(0.4)
                if proc.poll() is not None:
                    # Ядро упало при старте. На первой попытке — ретрай (возможно,
                    # ресурсов не хватило). На второй — кидаем исключение.
                    last_error = RuntimeError(f"{node.runtime} exited during startup (attempt {attempt+1})")
                    continue
                return fn("127.0.0.1", port)
            except Exception as exc:
                last_error = exc
                continue
            finally:
                if proc is not None and proc.poll() is None:
                    _terminate_process_tree(proc, timeout=max(0.2, 2.0 - (time.monotonic() - started_at)))
                if config_path:
                    with contextlib.suppress(Exception):
                        Path(config_path).unlink(missing_ok=True)
        # Обе попытки провалились.
        raise last_error if last_error else RuntimeError(f"{node.runtime} failed to start after 2 attempts")

    def snapshot(self) -> dict[str, Any]:
        rows = [item.row() for item in self.last_working]
        rejected_rows = [item.row() for item in self.last_rejected]
        pool_rows = rows + rejected_rows
        active = self.active_result.row() if self.active_result else None
        running = self.is_running()
        if active:
            latency_value = active.get("latency_ms")
            latency = ""
            if latency_value is not None:
                latency_number = float(latency_value)
                latency = f" · {'<1' if latency_number < 1 else str(int(round(latency_number)))} ms"
            active_text = (
                f"{active.get('protocol')} via {active.get('runtime')} · "
                f"{active.get('host')}:{active.get('port')} · {active.get('name')}{latency}"
            )
        else:
            active_text = ""
        return {
            "mode": "xray_core",
            "running": running,
            "local_running": running,
            "local_tg_url": self.local_tg_url,
            "local_url": self.local_proxy_url,
            "endpoint": self.config.endpoint,
            "status_text": "sing-box активен" if running else (self.last_error or ("sing-box ожидает перезапуск" if self.active_result else "sing-box остановлен")),
            "best_proxy": active_text,

            "active_node": active,
            "pool_rows": pool_rows,
            "xray_rejected_rows": rejected_rows,
            "ping_candidate_rows": [item.row() for item in self.ping_candidates],
            "working_count": len(rows),
            "ping_candidate_count": len(self.ping_candidates),
            "discovered_count": len(self.discovered_nodes),
            "rejected_count": len(rejected_rows),
            "unique_count": len(pool_rows),
            "balancer_strategy": _normalize_selection_strategy(self.config.selection_strategy),
            "manual_upstream_url": self.config.manual_upstream_url,
            "last_refresh_finished_at": self.last_refresh_finished_at,
            "active_download_kbps": self.active_download_kbps,
            "active_download_measured_at": self.active_download_measured_at,
            "reason_counts": _reason_counts(self.last_rejected),
            "xray_binary_found": bool(_resolve_binary(self.config.xray_binary_path, self.root_dir, "xray")),
            "sing_box_binary_found": bool(_resolve_binary(self.config.sing_box_binary_path, self.root_dir, "sing-box")),
        }

    def update_selection(self, selection_strategy: str, manual_upstream_url: str = "", *, restart: bool = True) -> None:
        with self._lock:
            self.config.selection_strategy = _normalize_selection_strategy(selection_strategy)
            self.config.manual_upstream_url = str(manual_upstream_url or "").strip()
            if self.config.manual_upstream_url and self.last_working and self._find_working_by_url(self.config.manual_upstream_url) is None:
                raise ValueError("xray node not found in accepted list")
            previous = self.active_result.node.key if self.active_result else None
            self._select_active_result(advance_round_robin=True)
            current = self.active_result.node.key if self.active_result else None
            if restart and previous != current and self.is_running():
                self.stop()
                if self.active_result is not None:
                    self._start_node(self.active_result.node, int(self.config.socks_port))
                    self._emit("xray_state", running=True, endpoint=self.config.endpoint)

    def _find_working_by_url(self, raw_url: str) -> XrayProbeResult | None:
        raw_url = str(raw_url or "").strip()
        return next((item for item in self.last_working if item.node.raw_url == raw_url), None)

    def _best_working_result(self) -> XrayProbeResult | None:
        return min(self.last_working, key=_xray_result_sort_key) if self.last_working else None

    def _select_active_result(self, *, advance_round_robin: bool) -> XrayProbeResult | None:
        ordered = sorted(self.last_working, key=_xray_result_sort_key)
        if not ordered:
            self.active_result = None
            return None

        manual = self._find_working_by_url(self.config.manual_upstream_url)
        if manual is not None:
            self.active_result = manual
            return manual

        strategy = _normalize_selection_strategy(self.config.selection_strategy)
        if strategy == "round_robin":
            index = self._round_robin_cursor % len(ordered)
            chosen = ordered[index]
            if advance_round_robin:
                self._round_robin_cursor = (self._round_robin_cursor + 1) % max(1, len(ordered))
        elif strategy == "consistent_hash":
            session_key = f"{self.config.socks_host}:{int(self.config.socks_port)}"
            digest = hashlib.blake2b(session_key.encode("utf-8", errors="ignore"), digest_size=8).digest()
            chosen = ordered[int.from_bytes(digest, "big") % len(ordered)]
        else:
            chosen = next((item for item in ordered if item.node.key == self._sticky_key), None)
            if chosen is None:
                chosen = ordered[0]
                self._sticky_key = chosen.node.key
        self.active_result = chosen
        return chosen

    def _probe_node(self, node: XrayNode) -> XrayProbeResult:
        if self._shutdown_requested:
            return XrayProbeResult(node, False, "runtime_shutdown", None, 0, 0, node.runtime)
        binary = self._binary_for_node(node)
        if not binary:
            return XrayProbeResult(node, False, f"{node.runtime} binary not found", None, 0, 0, node.runtime)
        port = _find_free_port()
        config_path = ""
        proc: subprocess.Popen | None = None
        started_at = time.monotonic()
        try:
            config_path = _write_temp_config(self._build_config(node, port))
            proc = subprocess.Popen(
                [binary, "run", "-c", config_path] if node.runtime == "xray" else [binary, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_subprocess_no_window(),
            )
            self._assign_to_process_job(proc)
            time.sleep(0.8)
            if proc.poll() is not None:
                return XrayProbeResult(node, False, "core exited", None, 0, TELEGRAM_XRAY_PROBE_TOTAL, node.runtime)
            api_latencies: list[float] = []
            api_status_ok = False
            for host, target_port, server_name in TELEGRAM_PROBE_TARGETS[:1]:
                latency = _socks_https_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    server_name,
                    float(self.config.probe_timeout_sec or 8.0),
                )
                if latency is not None:
                    api_latencies.append(latency)
                    api_status_ok = True
            total_probes = TELEGRAM_XRAY_PROBE_TOTAL
            if not api_latencies:
                return XrayProbeResult(node, False, "telegram_api_unreachable", None, 0, total_probes, node.runtime)

            # Медиа-проверка Bot API: HEAD https://api.telegram.org, ожидаем HTTP/2 200/302.
            head_result = _socks_https_head_status(
                "127.0.0.1",
                port,
                *TELEGRAM_API_HEAD_TARGET,
                float(self.config.probe_timeout_sec or 8.0),
            )
            if head_result is None or head_result[0] not in (200, 302):
                return XrayProbeResult(node, False, "telegram_api_bad_status", None, len(api_latencies), total_probes, node.runtime)

            dc_latencies: list[float] = []
            dc_ok = False
            for host, target_port in TELEGRAM_DCS:
                latency = _socks_mtproto_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    float(self.config.probe_timeout_sec or 8.0),
                )
                if latency is not None:
                    dc_latencies.append(latency)
                    dc_ok = True
                    break
            if not dc_latencies:
                return XrayProbeResult(node, False, "telegram_dc_unreachable", None, len(api_latencies), total_probes, node.runtime)
            if not dc_ok:
                return XrayProbeResult(node, False, "telegram_data_unreachable", None, len(api_latencies), total_probes, node.runtime)
            api_latency = min(api_latencies)
            dc_latency = min(dc_latencies)
            accepted = dc_latency < 5000

            # Дополнительные запрещённые в РФ цели: ChatGPT и Instagram.
            # Эти проверки не влияют на accepted — узел считается рабочим, если
            # Telegram и спид-тест прошли. Но мы фиксируем доступность, чтобы
            # отличать полностью пригодный узел от частично заблокированного.
            chatgpt_latencies: list[float] = []
            for host, target_port, server_name in CHATGPT_PROBE_TARGETS:
                latency = _socks_https_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    server_name,
                    min(float(self.config.probe_timeout_sec or 8.0), 3.0),
                )
                if latency is not None:
                    chatgpt_latencies.append(latency)
            chatgpt_latency = min(chatgpt_latencies) if chatgpt_latencies else None
            chatgpt_blocked = chatgpt_latency is None

            instagram_latencies: list[float] = []
            for host, target_port, server_name in INSTAGRAM_PROBE_TARGETS:
                latency = _socks_https_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    server_name,
                    min(float(self.config.probe_timeout_sec or 8.0), 3.0),
                )
                if latency is not None:
                    instagram_latencies.append(latency)
            instagram_latency = min(instagram_latencies) if instagram_latencies else None
            instagram_blocked = instagram_latency is None

            download_kbps = None
            upload_kbps = None
            if accepted:
                # Единый спид-тест (NDT7 → CF → proof.ovh.net → tele2, 16MB/8s).
                download_kbps = _download_speed_probe("127.0.0.1", port, float(self.config.probe_timeout_sec or 8.0))
                # Upload-тест для отбрасывания конфигов с медленной выгрузкой.
                upload_kbps = _xray_upload_speed("127.0.0.1", port, float(self.config.probe_timeout_sec or 8.0))
                # Отбрасываем конфиги, у которых скорость загрузки ИЛИ выгрузки
                # ниже единого минимального порога (min_speed_kbps из конфига).
                min_speed = float(getattr(self.config, "min_speed_kbps", XRAY_MIN_MEDIA_KBPS) or XRAY_MIN_MEDIA_KBPS)
                if download_kbps is not None and download_kbps < min_speed:
                    accepted = False
                    reason = "slow_download"
                elif upload_kbps is not None and upload_kbps < min_speed:
                    accepted = False
                    reason = "slow_upload"
                else:
                    reason = "ready" if accepted else "slow"
            return XrayProbeResult(
                node,
                accepted,
                reason,
                dc_latency,
                len(api_latencies) + len(dc_latencies),
                total_probes,
                node.runtime,
                api_latency_ms=api_latency,
                dc_latency_ms=dc_latency,
                chatgpt_latency_ms=chatgpt_latency,
                instagram_latency_ms=instagram_latency,
                chatgpt_blocked=chatgpt_blocked,
                instagram_blocked=instagram_blocked,
                download_kbps=download_kbps,
                upload_kbps=upload_kbps,
                fully_checked=True,
            )
        except Exception as exc:
            return XrayProbeResult(node, False, str(exc), None, 0, TELEGRAM_XRAY_PROBE_TOTAL, node.runtime)
        finally:
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=max(0.2, 2.0 - (time.monotonic() - started_at)))
            if config_path:
                with contextlib.suppress(Exception):
                    Path(config_path).unlink(missing_ok=True)

    def _probe_node_ping(self, node: XrayNode) -> XrayProbeResult:
        """Быстрый пинг узла через SOCKS-прокси.

        Ключевое отличие от старой версии: пинг НЕ отбраковывает узел, если
        Telegram недоступен. Раньше узел, который работает, но не пингует
        api.telegram.org, отбраковывался целиком (`telegram_api_bad_status`).
        В Karing-стиле: узел остаётся в списке с пометкой telegram_blocked=True,
        Telegram-проверка выполняется отдельно на этапе stress/telegram_pro.

        Перебор HTTPS-целей: GSTATIC → IP-SB → Cloudflare → Google → Microsoft
        → Apple. Успешный ответ ЛЮБОЙ из них = узел жив. Это критично для
        заблокированных сетей, где часть CDN недоступна.

        time.sleep(0.5) после старта ядра — даём xray/sing-box время поднять
        SOCKS-сервер (раньше было 0.2 — слишком мало, первый запрос падал).
        """
        if self._shutdown_requested:
            return XrayProbeResult(node, False, "runtime_shutdown", None, 0, 0, node.runtime)
        binary = self._binary_for_node(node)
        if not binary:
            return XrayProbeResult(node, False, f"{node.runtime} binary not found", None, 0, 0, node.runtime)
        port = _find_free_port()
        config_path = ""
        proc: subprocess.Popen | None = None
        started_at = time.monotonic()
        try:
            config_path = _write_temp_config(self._build_config(node, port))
            # stderr=PIPE: при core exited читаем последние строки, чтобы
            # понять причину (битый конфиг, неподдерживаемый шифр, кривой
            # Reality pbk и т.д.). Без этого мы видели только «core exited»
            # без объяснения, и не могли понять, почему 7-10% узлов падают.
            proc = subprocess.Popen(
                [binary, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                creationflags=_subprocess_no_window(),
            )
            self._assign_to_process_job(proc)
            # v11: sleep 0.2 вместо 0.3 — SOCKS поднимается за 150-250мс.
            # На 17479 нод × 0.1с экономия = 1750с / 128 потоков = ~14с.
            time.sleep(0.2)
            if proc.poll() is not None:
                # Ядро упало при старте — читаем stderr и логируем.
                stderr_tail = ""
                try:
                    stderr_bytes, _ = proc.communicate(timeout=2.0)
                    stderr_text = (stderr_bytes or b"").decode("utf-8", errors="replace").strip()
                    if stderr_text:
                        stderr_tail = "\n".join(stderr_text.splitlines()[-3:])
                except Exception:
                    pass
                if stderr_tail:
                    self._log(f"[xray] {node.protocol} {node.host}:{node.port} core exited — {stderr_tail}")
                return XrayProbeResult(node, False, "core exited", None, 0, len(PING_HTTPS_TARGETS), node.runtime)

            # Перебор HTTPS-целей: берём первую успешную, остальные не ждём.
            # v11: таймаут 2 сек (было 4) — мёртвые ноды отваливаются быстрее.
            # Живые ноды ответят за <2 сек (ya.ru/vk.com — белые SNI, быстрые).
            per_target_timeout = min(2.0, float(self.config.probe_timeout_sec or 8.0))
            ping_latencies: list[float] = []
            for host, target_port, server_name, path in PING_HTTPS_TARGETS:
                latency = _socks_https_latency(
                    "127.0.0.1",
                    port,
                    host,
                    target_port,
                    server_name,
                    per_target_timeout,
                    path=path,
                )
                if latency is not None:
                    ping_latencies.append(latency)
                    # Первой успешной достаточно — узел жив.
                    break
            if not ping_latencies:
                return XrayProbeResult(node, False, "quick_ping_failed", None, 0, len(PING_HTTPS_TARGETS), node.runtime)
            ping_latency = min(ping_latencies)
            accepted = ping_latency < 5000

            # Telegram-проверка — НЕ блокирующая. Если недоступен, помечаем
            # telegram_blocked=True, но узел остаётся в ping_candidates.
            # Полная Telegram-проверка (MTProto DC + upload) выполняется
            # отдельно на этапе telegram_pro.
            head_result = _socks_https_head_status(
                "127.0.0.1",
                port,
                *TELEGRAM_API_HEAD_TARGET,
                per_target_timeout,
            )
            telegram_ok = head_result is not None and head_result[0] in (200, 302)
            dc_latency: float | None = None
            if telegram_ok:
                for tg_host, tg_port in TELEGRAM_DCS:
                    latency = _socks_mtproto_latency(
                        "127.0.0.1",
                        port,
                        tg_host,
                        tg_port,
                        per_target_timeout,
                    )
                    if latency is not None:
                        dc_latency = latency
                        break

            return XrayProbeResult(
                node,
                accepted,
                "ready" if accepted else "slow",
                ping_latency,
                len(ping_latencies) + (1 if telegram_ok else 0) + (1 if dc_latency is not None else 0),
                len(PING_HTTPS_TARGETS) + 1 + len(TELEGRAM_DCS),
                node.runtime,
                dc_latency_ms=dc_latency,
                download_kbps=None,
            )
        except Exception as exc:
            return XrayProbeResult(node, False, str(exc), None, 0, len(PING_HTTPS_TARGETS), node.runtime)

        finally:
            if proc is not None and proc.poll() is None:
                _terminate_process_tree(proc, timeout=max(0.2, 2.0 - (time.monotonic() - started_at)))
            # Закрываем stderr-PIPE, чтобы не оставлять открытый файловый
            # дескриптор. communicate() уже вызван выше в случае падения,
            # здесь — для нормального пути (когда proc.poll() is None).
            if proc is not None and proc.stderr is not None:
                with contextlib.suppress(Exception):
                    proc.stderr.close()
            if config_path:
                with contextlib.suppress(Exception):
                    Path(config_path).unlink(missing_ok=True)

    def _effective_runtime(self, node: XrayNode) -> str:
        """Ядро для узла с учётом глобального форса («только sing-box»)."""
        forced = get_forced_runtime()
        if forced:
            return forced
        return node.runtime

    def _build_config(
        self,
        node: XrayNode,
        port: int,
        *,
        fp: str | None = None,
    ) -> dict[str, Any]:
        if self._effective_runtime(node) == "sing-box":
            return _sing_box_config(node, "127.0.0.1", port, fp=fp)
        return _xray_config(node, "127.0.0.1", port, fp=fp)

    def _binary_for_node(self, node: XrayNode) -> str:
        if self._effective_runtime(node) == "sing-box":
            return _resolve_binary(self.config.sing_box_binary_path, self.root_dir, "sing-box")
        return _resolve_binary(self.config.xray_binary_path, self.root_dir, "xray")

    def _export_results(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "xray_working.json").write_text(
            json.dumps([item.row() for item in self.last_working], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (self.out_dir / "xray_rejected.json").write_text(
            json.dumps([item.row() for item in self.last_rejected], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        # Кеш пропингованных подписок в txt (для тестов на заблокированной сети,
        # где подписки не импортируются). Содержит raw_url всех узлов, прошедших
        # быстрый пинг (ping_candidates) и полностью проверенных (last_working),
        # отсортированных по пингу.
        pinged = list(self.ping_candidates)
        for item in self.last_working:
            if not any(p.node.raw_url == item.node.raw_url for p in pinged):
                pinged.append(item)
        pinged_sorted = sorted(
            pinged,
            key=lambda r: (float("inf") if r.latency_ms is None else float(r.latency_ms)),
        )
        (self.out_dir / "pinged_subs.txt").write_text(
            "\n".join(item.node.raw_url for item in pinged_sorted) + ("\n" if pinged_sorted else ""),
            encoding="utf-8",
        )

    def load_pinged_subs(self) -> list[XrayNode]:
        """Загрузить пропингованные узлы из txt-кеша (pinged_subs.txt).

        Используется на заблокированной сети, где подписки не импортируются:
        берём сохранённые ранее пропингованные узлы и прогоняем по ним проверки.
        """
        path = self.out_dir / "pinged_subs.txt"
        if not path.exists():
            return []
        nodes: list[XrayNode] = []
        seen: set[str] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = str(line).strip()
            if not raw or raw in seen:
                continue
            seen.add(raw)
            node = parse_node_link(raw, source_url="pinged_cache")
            if node is not None:
                nodes.append(node)
        return nodes


    def _load_cached_results(self) -> None:
        working_path = self.out_dir / "xray_working.json"
        rejected_path = self.out_dir / "xray_rejected.json"
        # Старые кеши (созданные до введения двухфазной проверки) в
        # xray_working.json содержат все принятые записи без поля fully_checked.
        # Такие записи — только «пропингованные» кандидаты, а не полностью
        # проверенные рабочие. Раскладываем их по соответствующим спискам, иначе
        # GUI после обновления поверх покажет всех старых «рабочих».
        loaded = self._load_result_file(working_path, accepted=True)
        self.last_working = [item for item in loaded if item.fully_checked]
        self.ping_candidates = [item for item in loaded if not item.fully_checked]
        self.last_rejected = self._load_result_file(rejected_path, accepted=False)
        if self.last_working:
            self.last_refresh_finished_at = working_path.stat().st_mtime
            self._select_active_result(advance_round_robin=False)
            self._log(
                f"[xray] loaded {len(self.last_working)} cached fully-checked nodes, "
                f"{len(self.ping_candidates)} ping candidates"
            )

    def _load_result_file(self, path: Path, *, accepted: bool) -> list[XrayProbeResult]:
        if not path.exists():
            return []
        try:
            rows = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        results: list[XrayProbeResult] = []
        if not isinstance(rows, list):
            return results
        for row in rows:
            if not isinstance(row, dict):
                continue
            # Пропускаем заведомо мусорные записи: падение NDT7 (UnboundLocalError
            # в _mlab_fetch_target, исправлено) ловилось except и писало reason с
            # текстом исключения, а не причину отклонения узла.
            reason = str(row.get("reason") or "")
            if reason.startswith("cannot access local variable") or "is not associated with a value" in reason:
                continue
            result = _result_from_row(row, accepted=accepted)
            if result is not None:
                results.append(result)
        return sorted(results, key=_xray_result_sort_key)

    def _log(self, message: str) -> None:
        if self.log_sink is not None:
            self.log_sink(str(message))

    def _emit(self, event_name: str, **payload: Any) -> None:
        if self.event_sink is not None:
            self.event_sink(event_name, payload)

    def _live_subscription_urls(self, urls: list[str]) -> list[str]:
        """Возвращает подписки без тех, что сейчас в cooldown как «мёртвые»."""
        now = time.time()
        live: list[str] = []
        for url in urls:
            clean = str(url or "").strip()
            if not clean:
                continue
            dead_until = self._source_dead_until.get(clean, 0.0)
            if dead_until > now:
                self._log(
                    f"[xray] subscription {clean} marked dead, skipped "
                    f"({max(0.0, dead_until - now):.0f}s remaining)"
                )
                continue
            live.append(clean)
        return live

    def _note_source_result(self, source_url: str, *, ok: bool) -> None:
        """Ведёт счёт последовательных неудач источника; после N подряд — cooldown."""
        clean = str(source_url or "").strip()
        if not clean:
            return
        now = time.time()
        if ok:
            if clean in self._source_failures:
                del self._source_failures[clean]
            if clean in self._source_dead_until:
                del self._source_dead_until[clean]
            return
        failures = self._source_failures.get(clean, 0) + 1
        self._source_failures[clean] = failures
        if failures >= XRAY_DEAD_SOURCE_FAILURES:
            self._source_dead_until[clean] = now + XRAY_DEAD_SOURCE_COOLDOWN_SEC
            self._log(
                f"[xray] subscription {clean} marked dead after {failures} consecutive failures, "
                f"cooldown {XRAY_DEAD_SOURCE_COOLDOWN_SEC:.0f}s"
            )


# Максимум потоков для параллельной загрузки подписок. Fetch источника —
# сетевой (3 таймаута × 2 SSL-контекста × до 5 зеркал), поэтому узкое место
# не CPU; 8 потоков дают многократное ускорение при нескольких источниках.
XRAY_SUBSCRIPTION_FETCH_WORKERS = 8


def _collect_from_source(
    source_url: str,
    *,
    timeout: float,
    per_source_limit: int,
    log_sink: Callable[[str], None] | None,
    on_source_result: Callable[[str, bool], None] | None,
) -> list[XrayNode]:
    try:
        text = _fetch_text(source_url, timeout=timeout, log_sink=log_sink)
    except Exception as exc:
        if log_sink is not None:
            log_sink(f"[xray] subscription {source_url} failed: {type(exc).__name__}: {exc}")
        if on_source_result is not None:
            on_source_result(source_url, ok=False)
        return []

    source_nodes: list[XrayNode] = []
    source_added = 0

    # _subscription_lines выполняет сложный разбор тела (base64/JSON/URL-декод)
    # и на битом теле одной подписки может бросить исключение. В многопоточном
    # режиме collect_subscription_nodes такое исключение упадёт через
    # future.result() и оборвёт ВЕСЬ конвейер. Логируем и пропускаем источник.
    try:
        lines = _subscription_lines(text)
    except Exception as exc:
        if log_sink is not None:
            log_sink(f"[xray] bad subscription body from {source_url}: {type(exc).__name__}: {exc}")
        if on_source_result is not None:
            on_source_result(source_url, ok=False)
        return []

    for raw in lines:
        try:
            node = parse_node_link(raw, source_url=source_url)

        except Exception as exc:
            if log_sink is not None:
                log_sink(
                    f"[xray] bad node skipped from {source_url}: "
                    f"{type(exc).__name__}: {exc}"
                )
            continue

        if node is None:
            continue

        source_nodes.append(node)
        source_added += 1

        if per_source_limit > 0 and source_added >= per_source_limit:
            break

    if on_source_result is not None:
        on_source_result(source_url, ok=True)

    return source_nodes

def collect_subscription_nodes(
    urls: list[str],
    *,
    timeout: float,
    max_servers: int,
    log_sink: Callable[[str], None] | None = None,
    on_source_result: Callable[[str, bool], None] | None = None,
    on_progress: Callable[[int, int, str], None] | None = None,
    cancel_event: threading.Event | None = None,
    pause_event: threading.Event | None = None,
) -> list[XrayNode]:
    """Скачать все подписки и собрать уникальные узлы.

    on_progress(index, total, url) вызывается после завершения каждого
    источника (из главного потока), чтобы сквозной прогресс «загрузка
    подписок» двигался: 1/24, 2/24, ... 24/24.
    """
    nodes: dict[tuple[str, str, int, str], XrayNode] = {}
    source_urls = [str(url).strip() for url in urls if str(url).strip()]
    if not source_urls:
        return []
    per_source_limit = 0
    if max_servers > 0:
        # Не режем жёстко по источнику: при обновлении важно получить ВСЕ
        # актуальные ноды из подписок. Лимит нужен только как страховка от
        # одного гигантского источника.
        per_source_limit = max(1, int(max_servers) * 4)
    workers = max(1, min(XRAY_SUBSCRIPTION_FETCH_WORKERS, len(source_urls)))
    fetched: list[list[XrayNode]] = []
    completed = 0
    total = len(source_urls)
    if workers <= 1:
        for source_url in source_urls:
            _wait_if_paused(pause_event, cancel_event)
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("refresh_cancelled")
            fetched.append(
                _collect_from_source(
                    source_url,
                    timeout=timeout,
                    per_source_limit=per_source_limit,
                    log_sink=log_sink,
                    on_source_result=on_source_result,
                )
            )
            completed += 1
            if on_progress is not None:
                on_progress(completed, total, source_url)
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sub-fetch") as executor:
            futures = {
                executor.submit(
                    _collect_from_source,
                    source_url,
                    timeout=timeout,
                    per_source_limit=per_source_limit,
                    log_sink=log_sink,
                    on_source_result=on_source_result,
                ): source_url
                for source_url in source_urls
            }
            for future in as_completed(futures):
                _wait_if_paused(pause_event, cancel_event)
                if cancel_event and cancel_event.is_set():
                    raise RuntimeError("refresh_cancelled")
                url = futures[future]
                try:
                    source_nodes = future.result()
                except Exception as exc:
                    # Одна битая подписка НЕ должна ронять весь refresh:
                    # исключение из потока иначе пробрасывается сюда и
                    # обрывает конвейер на первой строке traceback.
                    if log_sink is not None:
                        log_sink(
                            f"[xray] subscription {url} crashed: "
                            f"{type(exc).__name__}: {exc}"
                        )
                    if on_source_result is not None:
                        on_source_result(url, ok=False)
                    source_nodes = []
                fetched.append(source_nodes)
                completed += 1
                if on_progress is not None:
                    on_progress(completed, total, url)

    # Дедупликация: собираем все узлы из всех подписок в dict по node.key.
    # Первый выигрывает (если два узла имеют одинаковый key — protocol/host/port/
    # sha256(normalized-url) — остаётся тот, что из более ранней подписки).
    # Логируем количество дубликатов, чтобы было видно эффективность дедупликации.
    total_before_dedup = sum(len(source_nodes) for source_nodes in fetched)
    duplicates_removed = 0
    for source_nodes in fetched:
        for node in source_nodes:
            if node.key in nodes:
                duplicates_removed += 1
            else:
                nodes[node.key] = node
    result = list(nodes.values())
    total_after_dedup = len(result)
    if log_sink is not None and duplicates_removed > 0:
        log_sink(
            f"[xray] dedup: {total_before_dedup} → {total_after_dedup} "
            f"({duplicates_removed} duplicates removed)"
        )
    return result[:max_servers] if max_servers > 0 else result


def _reason_counts(results: list[XrayProbeResult]) -> dict[str, int]:
    return dict(Counter(str(item.reason or "unknown") for item in results))


def _xray_result_sort_key(item: XrayProbeResult) -> tuple[int, float, float, float, str]:
    latency = item.dc_latency_ms if item.dc_latency_ms is not None else item.latency_ms
    speed = float(item.download_kbps or 0.0)
    upload = float(item.upload_kbps or 0.0)
    speed_bucket = 0 if speed >= XRAY_GOOD_DOWNLOAD_KBPS else 1 if speed > 0 else 2
    return (
        speed_bucket,
        latency if latency is not None else 10_000_000.0,
        -speed,
        -upload,
        item.node.raw_url,
    )


def _normalize_selection_strategy(strategy: str) -> str:
    normalized = str(strategy or "").strip()
    if normalized not in {"round_robin", "consistent_hash", "sticky_session"}:
        return "sticky_session"
    return normalized


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
        # chrome сам по себе лоялен по факту (реальный пресет), но статья прямо
        # называет его самым палевным сигналом — заменяем на firefox.
        if fp == "chrome":
            return "firefox"
        return fp
    # Неизвестный/синтетический пресет (randomized, ios, safari и т.п.) —
    # подменяем лояльным, чтобы не детектиться.
    return _SAFE_DEFAULT_FINGERPRINT


def _reason_summary(results: list[XrayProbeResult], *, limit: int = 3) -> str:
    counts = Counter(str(item.reason or "unknown") for item in results)
    if not counts:
        return ""
    parts = [f"{reason}: {count}" for reason, count in counts.most_common(limit)]
    return "No accepted nodes. " + ", ".join(parts)


def _result_from_row(row: dict[str, Any], *, accepted: bool) -> XrayProbeResult | None:
    node = parse_node_link(str(row.get("url") or ""), source_url=str(row.get("source") or "cache"))
    if node is None:
        return None
    try:
        latency = row.get("latency_ms")
        api_latency = row.get("api_latency_ms")
        dc_latency = row.get("dc_latency_ms")
        download = row.get("download_kbps")
        upload = row.get("upload_kbps")
        tg_media = row.get("tg_media_kbps")
        ai_country = str(row.get("ai_geo_country") or "").strip().upper()
        # Обратная совместимость: старые xray_working.json (созданные до введения
        # двухфазной проверки) не содержали поля fully_checked. Считать их
        # полностью проверенными НЕЛЬЗЯ — они прошли только быструю проверку,
        # а не полный стресс-тест. Поэтому без явного ключа fully_checked=True
        # запись считается лишь «пропингованной» (accepted, not fully_checked).
        fully_checked = bool(row.get("fully_checked", False))
        return XrayProbeResult(
            node=node,
            accepted=bool(row.get("accepted", accepted)),
            reason=str(row.get("reason") or ("ready" if accepted else "cached")),
            latency_ms=float(latency) if latency is not None else None,
            successes=int(row.get("successes") or (TELEGRAM_XRAY_PROBE_TOTAL if accepted else 0)),
            attempts=int(row.get("attempts") or TELEGRAM_XRAY_PROBE_TOTAL),
            runtime=str(row.get("runtime") or node.runtime),
            api_latency_ms=float(api_latency) if api_latency is not None else None,
            dc_latency_ms=float(dc_latency) if dc_latency is not None else None,
            download_kbps=float(download) if download is not None else None,
            upload_kbps=float(upload) if upload is not None else None,
            tg_media_kbps=float(tg_media) if tg_media is not None else None,
            ai_geo_country=ai_country if len(ai_country) == 2 else "",
            fully_checked=fully_checked,
        )
    except (TypeError, ValueError):
        return None


def parse_node_link(raw_url: str, *, source_url: str = "") -> XrayNode | None:
    raw_url = _sanitize_node_uri(raw_url)
    if not raw_url:
        return None
    scheme = raw_url.split(":", 1)[0].lower()
    if scheme == "vmess":
        return _parse_vmess(raw_url, source_url)
    if scheme == "ss":
        return _parse_shadowsocks(raw_url, source_url)
    if scheme in {"vless", "trojan", "hysteria", "hysteria2", "hy2"}:
        return _parse_uri_node(raw_url, source_url)
    return None


def _parse_vmess(raw_url: str, source_url: str) -> XrayNode | None:
    payload = raw_url.split("://", 1)[1]
    decoded = _decode_base64(payload)
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        return None
    host = str(data.get("add") or data.get("host") or "").strip()
    port = int(data.get("port") or 0)
    uuid = str(data.get("id") or "").strip()
    if not host or not port or not uuid:
        return None
    query = {
        "security": str(data.get("tls") or data.get("security") or ""),
        "network": str(data.get("net") or "tcp"),
        "path": str(data.get("path") or ""),
        "host": str(data.get("host") or data.get("sni") or ""),
        "sni": str(data.get("sni") or ""),
        "alpn": str(data.get("alpn") or ""),
        "fp": str(data.get("fp") or ""),
    }
    return XrayNode(
        protocol="vmess",
        raw_url=raw_url,
        name=str(data.get("ps") or host),
        host=host,
        port=port,
        credential=uuid,
        query=query,
        source_url=source_url,
        runtime="xray",
        extra=data,
    )


def _parse_uri_node(raw_url: str, source_url: str) -> XrayNode | None:
    try:
        parsed = urlparse(raw_url)
    except ValueError:
        return None

    protocol = parsed.scheme.lower()

    try:
        host = parsed.hostname or ""
        port = int(parsed.port or 0)
    except (ValueError, TypeError):
        return None

    credential = unquote(parsed.username or "")
    if not host or not port or not credential:
        return None

    query = {
        key: values[-1]
        for key, values in parse_qs(
            parsed.query,
            keep_blank_values=True,
        ).items()
    }

    name = unquote(parsed.fragment or "") or f"{protocol}://{host}:{port}"
    runtime = "sing-box" if protocol in SING_BOX_PROTOCOLS else "xray"

    if protocol == "hy2":
        protocol = "hysteria2"

    return XrayNode(
        protocol=protocol,
        raw_url=raw_url,
        name=name,
        host=host,
        port=port,
        credential=credential,
        query=query,
        source_url=source_url,
        runtime=runtime,
    )


def _parse_shadowsocks(raw_url: str, source_url: str) -> XrayNode | None:
    try:
        parsed = urlparse(raw_url)
    except ValueError:
        # Python 3.12: urlparse кидает ValueError на битые bracketed-netloc
        # (например, спам-маскировка GitHub "[email protected]"). Мусор.
        return None
    fragment = unquote(parsed.fragment or "")
    main = raw_url.split("://", 1)[1].split("#", 1)[0]
    main = main.split("?", 1)[0]

    method = ""
    password = ""
    host = parsed.hostname or ""
    port = int(parsed.port or 0)

    if "@" in main:
        userinfo = main.rsplit("@", 1)[0]
        decoded_userinfo = _decode_base64_plain(userinfo) if ":" not in userinfo else unquote(userinfo)
        if ":" not in decoded_userinfo:
            decoded_userinfo = unquote(userinfo)
        if ":" in decoded_userinfo:
            method, password = decoded_userinfo.split(":", 1)
    else:
        decoded = _decode_base64_plain(main)
        if "@" in decoded:
            userinfo, hostport = decoded.rsplit("@", 1)
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            host, port = _split_host_port(hostport, default_port=8388)

    if not host or not port or not method or not password:
        return None
    return XrayNode(
        protocol="shadowsocks",
        raw_url=raw_url,
        name=fragment or f"ss://{host}:{port}",
        host=host,
        port=port,
        credential=password,
        query={"method": method},
        source_url=source_url,
        runtime="xray",
    )


def _split_host_port(hostport: str, *, default_port: int) -> tuple[str, int]:
    value = str(hostport or "").strip()
    if value.startswith("[") and "]" in value:
        host, _, rest = value[1:].partition("]")
        port_text = rest[1:] if rest.startswith(":") else ""
        try:
            return host, int(port_text or default_port)
        except ValueError:
            return host, default_port
    host, sep, port_text = value.rpartition(":")
    if sep:
        try:
            return host, int(port_text or default_port)
        except ValueError:
            return host, default_port
    return value, default_port


def _subscription_lines(text: str) -> list[str]:
    """Извлечь список node-ссылок из тела подписки.

    Пробует несколько интерпретаций тела:
      1. текст как есть;
      2. URL-декодированный текст;
      3. base64 (однократно);
      4. URL-декодированный base64;
      5. многоуровневый base64 (base64 внутри base64, до 3 уровней).

    Для каждой интерпретации извлекаются узлы, и выбирается вариант с
    максимальным числом распознанных node-ссылок (приоритет у протоколов
    из NODE_SCHEMES, а не просто у наибольшего числа строк).
    """
    text = str(text or "").strip()
    if not text:
        return []

    candidates: list[str] = []
    seen_text: set[str] = set()

    def add_candidate(value: str) -> None:
        value = str(value or "").strip()
        if value and value not in seen_text:
            seen_text.add(value)
            candidates.append(value)

    add_candidate(text)
    # URL-декодированный вариант.
    unquoted = text
    with contextlib.suppress(Exception):
        decoded_unquoted = unquote(text)
        if decoded_unquoted != text:
            unquoted = decoded_unquoted
            add_candidate(unquoted)
    # base64-варианты (в т.ч. URL-safe) и многоуровневые — и для исходного
    # текста, и для URL-декодированного (например %3D в url-encoded base64).
    for decoded in _decode_base64_multi(text):
        add_candidate(decoded)
    if unquoted != text:
        for decoded in _decode_base64_multi(unquoted):
            add_candidate(decoded)


    best: list[str] = []
    best_score = -1
    for candidate in candidates:
        lines = _node_lines_from_candidate(candidate)
        score = _candidate_score(lines)
        if score > best_score:
            best_score = score
            best = lines
    return best


def _candidate_score(lines: list[str]) -> int:
    """Оценка кандидата: доминирует число строк с известными протоколами."""
    recognized = 0
    for line in lines:
        lowered = line.lower()
        if any(lowered.startswith(scheme) for scheme in NODE_SCHEMES):
            recognized += 1
    return recognized * 10000 + len(lines)


def _looks_like_readable_text(value: str) -> bool:
    """Отбросить бинарный мусор после декодирования base64.

    Читаемый текст не содержит управляющих символов (кроме \r \n \t)
    и включает хотя бы одну букву/цифру.
    """
    if not value:
        return False
    if any(ord(ch) < 32 and ch not in "\r\n\t" for ch in value):
        return False
    return any(ch.isalnum() for ch in value)


def _node_lines_from_candidate(candidate: str) -> list[str]:
    """Извлечь node-ссылки из одной интерпретации тела подписки."""
    extracted: list[str] = []
    seen: set[str] = set()

    def remember(value: str) -> None:
        clean = _sanitize_node_uri(value)
        if clean and clean not in seen:
            seen.add(clean)
            extracted.append(clean)

    for value in _node_links_from_text(candidate):
        remember(value)
    if extracted:
        return extracted
    for value in _node_links_from_json(candidate):
        remember(value)
    if extracted:
        return extracted
    for value in _node_links_from_clash_yaml(candidate):
        remember(value)
    if extracted:
        return extracted
    lines: list[str] = []
    for line in candidate.replace("\r", "\n").split("\n"):
        value = _sanitize_node_uri(line)
        if value:
            lines.append(value)
    return lines


def _decode_base64_multi(value: str, *, max_depth: int = 3) -> list[str]:
    """Декодировать base64, включая URL-encoded и многоуровневый.

    Возвращает список всех уникальных результатов декодирования
    (не более max_depth уровней вложенности).
    """
    results: list[str] = []
    seen: set[str] = set()

    def walk(current: str, depth: int) -> None:
        current = str(current or "").strip()
        if not current or depth > max_depth:
            return
        # Строгий вариант: декодированная строка содержит node-ссылки
        # (://), переносы строк или JSON.
        decoded = _decode_base64(current)
        if decoded and decoded != current and decoded not in seen:
            seen.add(decoded)
            results.append(decoded)
            walk(decoded, depth + 1)
            return
        # «Сырой» вариант: промежуточный уровень многоуровневого base64
        # не обязан содержать :// и \n, но обязан дать читаемый текст.
        plain = _decode_base64_plain(current)
        if (
            plain
            and plain != current
            and plain not in seen
            and _looks_like_readable_text(plain)
        ):
            seen.add(plain)
            results.append(plain)
            walk(plain, depth + 1)

    walk(value, 1)
    return results


def _fetch_text(
    url: str,
    *,
    timeout: float,
    log_sink: Callable[[str], None] | None = None,
) -> str:
    clean_url = str(url or "").strip()

    # Локальный файл (кастомный кеш конфигов, выбранный пользователем):
    # читаем как есть, а декодирование base64 / извлечение только ссылок
    # выполняет _subscription_lines ниже по конвейеру.
    if clean_url.startswith("file://"):
        local_path = Path(clean_url[len("file://"):])
    else:
        local_path = Path(clean_url)
    if clean_url and local_path.exists() and local_path.is_file():
        try:
            data = local_path.read_bytes()
            if log_sink is not None:
                log_sink(f"[xray] reading local config file: {local_path}")
            return _decode_subscription_body(data)
        except OSError as exc:
            if log_sink is not None:
                log_sink(f"[xray] cannot read local config file {local_path}: {exc}")
            raise RuntimeError("local config file read failed") from exc

    errors: list[str] = []
    for candidate_url in _subscription_candidate_urls(clean_url):

        headers = _subscription_headers(candidate_url)
        for current_timeout in _subscription_timeouts(timeout):
            for context in _subscription_ssl_contexts():
                try:
                    req = Request(candidate_url, headers=headers)
                    with urlopen(req, timeout=current_timeout, context=context) as resp:
                        encoding = str(resp.headers.get("Content-Encoding", "") or "")
                        return _decode_subscription_body(resp.read(), encoding=encoding)
                except HTTPError as exc:
                    # HTTP 4xx/5xx — подписка недоступна/заблокирована.
                    # Нет смысла перебирать все таймауты и SSL-контексты.
                    marker = f"{urlparse(candidate_url).netloc or '?'}:HTTP_{exc.code}"
                    if marker not in errors:
                        errors.append(marker)
                    break
                except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
                    marker = f"{urlparse(candidate_url).netloc or '?'}:{type(exc).__name__}"
                    if marker not in errors:
                        errors.append(marker)
                except Exception as exc:
                    marker = f"{urlparse(candidate_url).netloc or '?'}:{type(exc).__name__}"
                    if marker not in errors:
                        errors.append(marker)
    if log_sink is not None and errors:
        log_sink(f"[xray] source fetch attempts failed {clean_url}: {' | '.join(errors[:5])}")
    raise RuntimeError("subscription fetch failed")


def _subscription_headers(url: str) -> dict[str, str]:
    # ВАЖНО: не задаём Host вручную. urllib сам выставляет корректный Host для
    # каждого запроса, включая редиректы (github.com -> raw.githubusercontent.com).
    # Ручной Host не обновляется при 302 и ломает редирект: GitHub отвечает 500.
    return {
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
        "Connection": "close",
        "User-Agent": SUBSCRIPTION_USER_AGENT,
        "X-Device-Locale": "en",
        "X-Device-OS": "Windows",
    }


def _subscription_timeouts(timeout: float) -> list[float]:
    base = max(3.0, float(timeout or 8.0))
    values = [base, max(base, 15.0), max(base, 30.0)]
    out: list[float] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def _subscription_ssl_contexts() -> list[ssl.SSLContext | None]:
    contexts: list[ssl.SSLContext | None] = [None]
    with contextlib.suppress(Exception):
        contexts.append(ssl._create_unverified_context())
    return contexts


def _subscription_candidate_urls(url: str) -> list[str]:
    target = str(url or "").strip()
    if not target:
        return []
    urls = [target]
    with contextlib.suppress(Exception):
        parsed = urlparse(target)
        host = str(parsed.netloc or "").strip().lower()
        parts = [part for part in str(parsed.path or "").split("/") if part]
        if host == "raw.githubusercontent.com" and len(parts) >= 5 and parts[2] == "refs" and parts[3] == "heads":
            owner = parts[0]
            repo = parts[1]
            branch = parts[4]
            tail = parts[5:]
            canonical_path = "/" + "/".join([owner, repo, branch] + tail)
            canonical = urlunsplit((parsed.scheme or "https", parsed.netloc, canonical_path, parsed.query or "", ""))
            if canonical not in urls:
                urls.append(canonical)
            jsd_path = "/gh/" + "/".join([owner, repo + "@" + branch] + tail)
            for cdn_host in ("cdn.jsdelivr.net", "gcore.jsdelivr.net", "fastly.jsdelivr.net"):
                cdn_url = urlunsplit(("https", cdn_host, jsd_path, parsed.query or "", ""))
                if cdn_url not in urls:
                    urls.append(cdn_url)
    return urls


def _decode_subscription_body(raw: bytes, *, encoding: str = "") -> str:
    data = bytes(raw or b"")
    if data[:2] == b"\x1f\x8b" or "gzip" in str(encoding or "").lower():
        with contextlib.suppress(Exception):
            data = gzip.decompress(data)
    return data.decode("utf-8", errors="replace")


def _node_links_from_text(text: str) -> list[str]:
    values: list[str] = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.lower().startswith(scheme) for scheme in NODE_SCHEMES):
            values.append(stripped)
            continue
        values.extend(match.group(0) for match in NODE_LINK_RE.finditer(stripped))
    if not values:
        values.extend(match.group(0) for match in NODE_LINK_RE.finditer(str(text or "")))
    return values


def _node_links_from_json(text: str) -> list[str]:
    raw = str(text or "").strip()
    if not raw or raw[0] not in "{[":
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    links: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            links.extend(_node_links_from_text(value))
            return
        if isinstance(value, list):
            for item in value:
                walk(item)
            return
        if not isinstance(value, dict):
            return
        converted = _node_link_from_json_object(value)
        if converted:
            links.append(converted)
        for item in value.values():
            walk(item)

    walk(payload)
    return links


def _node_link_from_json_object(item: dict[str, Any]) -> str:
    protocol = str(item.get("protocol") or item.get("type") or "").strip().lower()
    if not protocol:
        return ""
    if protocol == "shadowsocks":
        return _shadowsocks_link_from_json(item)
    if protocol in {"vless", "trojan"}:
        return _standard_link_from_json(item, protocol)
    return ""


def _standard_link_from_json(item: dict[str, Any], protocol: str) -> str:
    try:
        credential = ""
        server = str(item.get("server") or item.get("address") or "").strip()
        port = int(item.get("server_port") or item.get("port") or 0)
        if protocol == "trojan":
            credential = str(item.get("password") or "").strip()
        else:
            credential = str(item.get("uuid") or item.get("id") or item.get("user") or "").strip()
        settings = item.get("settings") if isinstance(item.get("settings"), dict) else {}
        if protocol == "vless" and (not server or not port or not credential):
            for vnext in settings.get("vnext") or []:
                if not isinstance(vnext, dict):
                    continue
                server = str(vnext.get("address") or vnext.get("server") or server or "").strip()
                port = int(vnext.get("port") or port or 0)
                users = vnext.get("users") or []
                if users and isinstance(users[0], dict):
                    credential = str(users[0].get("id") or users[0].get("uuid") or credential or "").strip()
                break
        if not server or not port or not credential:
            return ""
        query = _query_from_json_transport(item)
        tag = quote(str(item.get("tag") or item.get("name") or ""), safe="")
        url = f"{protocol}://{quote(credential, safe='')}@{server}:{port}"
        if query:
            url += "?" + query
        if tag:
            url += "#" + tag
        return url
    except Exception:
        return ""


def _query_from_json_transport(item: dict[str, Any]) -> str:
    params: dict[str, str] = {}
    stream = item.get("streamSettings") if isinstance(item.get("streamSettings"), dict) else {}
    if stream:
        if stream.get("network"):
            params["type"] = str(stream.get("network") or "")
        if stream.get("security"):
            params["security"] = str(stream.get("security") or "")
        tls = stream.get("tlsSettings") if isinstance(stream.get("tlsSettings"), dict) else {}
        if tls:
            if tls.get("serverName"):
                params["sni"] = str(tls.get("serverName") or "")
            if tls.get("fingerprint"):
                params["fp"] = str(tls.get("fingerprint") or "")
            if tls.get("alpn"):
                alpn = tls.get("alpn")
                params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
            if tls.get("allowInsecure") is True:
                params["allowInsecure"] = "1"
        reality = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}
        if reality:
            params["security"] = "reality"
            for source, target in [
                ("serverName", "sni"),
                ("fingerprint", "fp"),
                ("publicKey", "pbk"),
                ("shortId", "sid"),
                ("spiderX", "spx"),
            ]:
                if reality.get(source):
                    params[target] = str(reality.get(source) or "")
        ws = stream.get("wsSettings") if isinstance(stream.get("wsSettings"), dict) else {}
        if ws:
            if ws.get("path"):
                params["path"] = str(ws.get("path") or "")
            headers = ws.get("headers") if isinstance(ws.get("headers"), dict) else {}
            if headers.get("Host") or headers.get("host"):
                params["host"] = str(headers.get("Host") or headers.get("host") or "")
        grpc = stream.get("grpcSettings") if isinstance(stream.get("grpcSettings"), dict) else {}
        if grpc:
            if grpc.get("serviceName"):
                params["serviceName"] = str(grpc.get("serviceName") or "")
            if grpc.get("authority"):
                params["authority"] = str(grpc.get("authority") or "")
            if grpc.get("multiMode") is True:
                params["mode"] = "multi"
        for settings_key in ("xhttpSettings", "splithttpSettings", "httpupgradeSettings"):
            transport_settings = stream.get(settings_key) if isinstance(stream.get(settings_key), dict) else {}
            if transport_settings:
                if transport_settings.get("path"):
                    params["path"] = str(transport_settings.get("path") or "")
                if transport_settings.get("host"):
                    params["host"] = str(transport_settings.get("host") or "")
                if transport_settings.get("mode"):
                    params["mode"] = str(transport_settings.get("mode") or "")
    tls = item.get("tls") if isinstance(item.get("tls"), dict) else {}
    if tls:
        if tls.get("enabled") is True or str(tls.get("enabled") or "").lower() == "true":
            params["security"] = "tls"
        if tls.get("server_name") or tls.get("sni"):
            params["sni"] = str(tls.get("server_name") or tls.get("sni") or "")
        if tls.get("alpn"):
            alpn = tls.get("alpn")
            params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    transport = item.get("transport") if isinstance(item.get("transport"), dict) else {}
    if transport:
        if transport.get("type") or transport.get("network"):
            params["type"] = str(transport.get("type") or transport.get("network") or "")
        if transport.get("path"):
            params["path"] = str(transport.get("path") or "")
        headers = transport.get("headers") if isinstance(transport.get("headers"), dict) else {}
        if headers.get("Host") or headers.get("host"):
            params["host"] = str(headers.get("Host") or headers.get("host") or "")
    return "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='/@:')}" for k, v in params.items() if v)


def _shadowsocks_link_from_json(item: dict[str, Any]) -> str:
    try:
        server = str(item.get("server") or item.get("address") or "").strip()
        port = int(item.get("server_port") or item.get("port") or 0)
        method = str(item.get("method") or "").strip()
        password = str(item.get("password") or "").strip()
        if not server or not port or not method or not password:
            return ""
        userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
        tag = quote(str(item.get("tag") or item.get("name") or ""), safe="")
        url = f"ss://{userinfo}@{server}:{port}"
        if tag:
            url += "#" + tag
        return url
    except Exception:
        return ""


def _node_links_from_clash_yaml(text: str) -> list[str]:
    """Извлечь node-ссылки из Clash-формата YAML (секция ``proxies``)."""
    raw = str(text or "")
    if "proxies:" not in raw:
        return []
    try:
        import yaml  # отложенный импорт: зависимость опциональна
    except Exception:
        return []
    try:
        payload = yaml.safe_load(raw)
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    proxies = payload.get("proxies")
    if not isinstance(proxies, list):
        return []
    links: list[str] = []
    for item in proxies:
        if not isinstance(item, dict):
            continue
        link = _node_link_from_clash_proxy(item)
        if link:
            links.append(link)
    return links


def _node_link_from_clash_proxy(item: dict[str, Any]) -> str:
    """Собрать node-ссылку из одного Clash-прокси."""
    try:
        proxy_type = str(item.get("type") or "").strip().lower()
        server = str(item.get("server") or item.get("host") or "").strip()
        port = int(item.get("port") or 0)
        name = str(item.get("name") or item.get("tag") or "").strip()
        if not proxy_type or not server or not port:
            return ""
        tag = quote(name, safe="")
        query = _clash_query(item)

        if proxy_type in ("vless",):
            uuid = str(item.get("uuid") or "").strip()
            if not uuid:
                return ""
            url = f"vless://{quote(uuid, safe='')}@{server}:{port}"
            if query:
                url += "?" + query
            if tag:
                url += "#" + tag
            return url

        if proxy_type in ("trojan",):
            password = str(item.get("password") or "").strip()
            if not password:
                return ""
            url = f"trojan://{quote(password, safe='')}@{server}:{port}"
            if query:
                url += "?" + query
            if tag:
                url += "#" + tag
            return url

        if proxy_type in ("ss", "shadowsocks"):
            method = str(item.get("cipher") or item.get("method") or "").strip()
            password = str(item.get("password") or "").strip()
            if not method or not password:
                return ""
            userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
            url = f"ss://{userinfo}@{server}:{port}"
            if tag:
                url += "#" + tag
            return url

        if proxy_type == "vmess":
            payload: dict[str, Any] = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": str(port),
                "id": str(item.get("uuid") or ""),
                "aid": str(item.get("alterId") or item.get("aid") or "0"),
                "scy": str(item.get("cipher") or item.get("security") or "auto"),
                "net": str(item.get("network") or "tcp"),
                "type": "none",
                "tls": "" if not item.get("tls") else "tls",
            }
            host = ""
            ws_opts = item.get("ws-opts")
            if isinstance(ws_opts, dict):
                if ws_opts.get("path"):
                    payload["path"] = str(ws_opts.get("path"))
                headers = ws_opts.get("headers")
                if isinstance(headers, dict) and (headers.get("Host") or headers.get("host")):
                    host = str(headers.get("Host") or headers.get("host"))
            else:
                if item.get("ws-path"):
                    payload["path"] = str(item.get("ws-path"))
            headers = item.get("headers")
            if not host and isinstance(headers, dict):
                host = str(headers.get("Host") or headers.get("host") or "")
            if host:
                payload["host"] = host
            sni = str(item.get("servername") or item.get("sni") or "").strip()
            if sni:
                payload["sni"] = sni
            encoded = base64.urlsafe_b64encode(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            url = f"vmess://{encoded}"
            if tag:
                url += "#" + tag
            return url

        return ""
    except Exception:
        return ""


def _clash_query(item: dict[str, Any]) -> str:
    """Собрать query-строку из транспортных полей Clash-прокси."""
    params: dict[str, str] = {}
    network = str(item.get("network") or "").strip().lower()
    if network and network != "tcp":
        params["type"] = network
    tls = item.get("tls")
    tls_enabled = False
    if isinstance(tls, bool):
        tls_enabled = tls
    elif tls is not None:
        tls_enabled = str(tls).strip().lower() in {"true", "1", "yes", "on"}
    if tls_enabled:
        params["security"] = "tls"
    sni = str(item.get("servername") or item.get("sni") or "").strip()
    if sni:
        params["sni"] = sni
    alpn = item.get("alpn")
    if alpn:
        params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    fp = str(item.get("client-fingerprint") or "").strip()
    if fp:
        params["fp"] = fp
    if item.get("skip-cert-verify") is True:
        params["allowInsecure"] = "1"
    ws_opts = item.get("ws-opts")
    if isinstance(ws_opts, dict):
        if ws_opts.get("path"):
            params["path"] = str(ws_opts.get("path"))
        headers = ws_opts.get("headers")
        if isinstance(headers, dict) and (headers.get("Host") or headers.get("host")):
            params["host"] = str(headers.get("Host") or headers.get("host"))
    else:
        if item.get("ws-path"):
            params["path"] = str(item.get("ws-path"))
        ws_headers = item.get("ws-headers")
        if isinstance(ws_headers, dict) and (ws_headers.get("Host") or ws_headers.get("host")):
            params["host"] = str(ws_headers.get("Host") or ws_headers.get("host"))
    grpc_opts = item.get("grpc-opts")
    if isinstance(grpc_opts, dict):
        if grpc_opts.get("grpc-service-name"):
            params["serviceName"] = str(grpc_opts.get("grpc-service-name"))
        if grpc_opts.get("grpc-mode"):
            params["mode"] = str(grpc_opts.get("grpc-mode"))
    h2_opts = item.get("h2-opts")
    if isinstance(h2_opts, dict):
        if h2_opts.get("path"):
            params["path"] = str(h2_opts.get("path"))
        if h2_opts.get("host"):
            params["host"] = str(h2_opts.get("host"))
    return "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='/@:')}" for k, v in params.items() if v)


def _sanitize_node_uri(raw_uri: object) -> str:
    try:
        value = html.unescape(str(raw_uri or ""))
    except Exception:
        return ""
    value = value.replace("\r", "").replace("\n", "").strip()
    if not value:
        return ""
    lowered = value.lower()
    indices = [lowered.find(scheme) for scheme in NODE_SCHEMES if lowered.find(scheme) >= 0]
    if indices:
        value = value[min(indices):]
    value = re.sub(r"[\s\)\]>,\.;]+$", "", value)
    if "#" in value and not value.lower().startswith("vmess://"):
        base, fragment = value.split("#", 1)
        with contextlib.suppress(Exception):
            fragment = quote(unquote(fragment), safe="")
        value = base + "#" + fragment
    return value


def _normalize_base64_padding(value: str) -> str:
    """Привести base64-строку к каноническому виду с правильным padding.

    Некоторые подписки отдают pbk/sid без '=' в конце (URL-safe без padding),
    другие — с '='. Например:
      pbk=abc123      (без padding)
      pbk=abc123=     (с padding)

    Это ОДИН И ТОТ ЖЕ ключ, но без нормализации они считаются разными
    конфигами. Добавляем padding по длине (base64 должен быть кратен 4).
    """
    if not value:
        return value
    # Убираем существующий padding для пересчёта.
    stripped = value.rstrip("=")
    # Добавляем правильный padding.
    pad_len = (-len(stripped)) % 4
    return stripped + ("=" * pad_len)


# Query-параметры, которые содержат base64-данные и нуждаются в
# нормализации padding. Без этого один и тот же Reality-узел с
# pbk=abc123 (без =) и pbk=abc123= (с =) считаются разными.
_BASE64_QUERY_PARAMS = frozenset({
    "pbk", "sid", "publickey", "public-key",
    "privatekey", "private-key",
    "spxfingerprint", "spx",
})


def _normalize_ss_userinfo(userinfo: str) -> str:
    """Нормализовать userinfo из ss:// URL.

    ss://userinfo@host:port — userinfo может быть:
      1. base64("method:password") — стандартный v2ray-формат
      2. "method:password" — plaintext (v2rayN/happ могут так отдавать)

    Декодируем base64 в "method:password", если это возможно — так оба
    варианта считаются одинаковыми при дедупликации.
    """
    if not userinfo:
        return userinfo
    # Если уже содержит ':' — это plaintext "method:password".
    if ":" in userinfo:
        return userinfo
    # Пробуем декодировать base64 → "method:password".
    try:
        # URL-safe base64 decode (c padding коррекцией).
        padded = _normalize_base64_padding(userinfo)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            with contextlib.suppress(Exception):
                decoded = decoder(padded).decode("utf-8", errors="replace")
                if ":" in decoded:
                    return decoded
    except Exception:
        pass
    return userinfo


def _node_dedup_text(raw_uri: str, *, mode: str | None = None) -> str:
    """Делегирует в runtime.uritools._node_dedup_text.

    Легаси-копия оставлена как thin-wrapper, чтобы все импорты ``from
    xray_runtime import _node_dedup_text`` продолжали работать, но
    канонизация единственная (в runtime.uritools), а не расходящиеся
    две копии. Поддержка режимов дедупликации (strict/normal/aggressive)
    реализована в runtime.uritools.
    """
    # Импорт здесь (а не на уровне модуля) — чтобы избежать циклического
    # импорта: runtime.uritools не зависит от xray_runtime, а xray_runtime
    # может зависеть от runtime.
    from runtime.uritools import _node_dedup_text as _impl
    return _impl(raw_uri, mode=mode)


def _decode_base64(value: str) -> str:
    compact = "".join(str(value or "").strip().split())
    if not compact:
        return ""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        with contextlib.suppress(Exception):
            padded = compact + "=" * (-len(compact) % 4)
            decoded = decoder(padded.encode("ascii"))
            text = decoded.decode("utf-8", errors="replace")
            stripped = text.lstrip()
            if "://" in text or "\n" in text or stripped.startswith(("{", "[")):
                return text
    return value


def _decode_base64_plain(value: str) -> str:
    compact = "".join(str(value or "").strip().split())
    if not compact:
        return ""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        with contextlib.suppress(Exception):
            padded = compact + "=" * (-len(compact) % 4)
            return decoder(padded.encode("ascii")).decode("utf-8", errors="replace")
    return value


def _xray_config(
    node: XrayNode,
    listen_host: str,
    listen_port: int,
    *,
    fp: str | None = None,
) -> dict[str, Any]:
    """Собрать конфиг Xray-core с SOCKS-inbound.

    DNS — ЛОКАЛЬНЫЙ системный ("localhost" = системный резолвер) с fallback
    на обычный UDP DNS (1.1.1.1/8.8.8.8 — НЕ DoH): DoH-эндпоинты могут
    блокироваться/не работать (требование пользователя), а системный DNS
    доступен всегда — он же обслуживает все остальные приложения машины.
    """
    outbound = _xray_outbound(node, fp=fp)
    inbounds: list[dict[str, Any]] = [
        {
            "listen": listen_host,
            "port": listen_port,
            "protocol": "socks",
            "tag": "socks-in",
            "settings": {"udp": True, "auth": "noauth"},
            # sniffing: routeOnly=False (НЕ маршрутизировать по sniffed-домену).
            # Раньше было routeOnly=True + fakedns в destOverride — это требует
            # FakeIP-объект в dns-секции, без него xray-core v26 падает при
            # старте («core exited» на каждом узле). В SOCKS-режиме FakeIP
            # вообще неработоспособен (клиент уже резолвит IP локально и
            # прокси не может сопоставить IP→домен для SNI).
            # Теперь: только http/tls/quic sniffing для корректного SNI,
            # без fakedns, без routeOnly — конфиг валиден на чистом xray v26.
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": False,
            },
        }
    ]
    outbounds: list[dict[str, Any]] = [
        outbound,
        {
            "protocol": "blackhole",
            "tag": "block",
            "settings": {"response": {"type": "none"}},
        },
    ]
    routing_rules: list[dict[str, Any]] = [
        # Локальный трафик — в block, чтобы не уходил через прокси.
        {
            "type": "field",
            "outboundTag": "block",
            "ip": ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        }
    ]
    # DNS — ЛОКАЛЬНЫЙ системный резолвер (первый) + обычный UDP DNS как
    # fallback. DoH убран: может блокироваться (требование пользователя).
    # Домены целей уходят в туннель как домены — резолвит их удалённый
    # сервер, локальный DNS нужен только для адреса самого узла.
    dns_servers = ["localhost", "1.1.1.1", "8.8.8.8"]

    return {
        "log": {"loglevel": "warning", "access": "", "error": ""},
        "dns": {
            "servers": dns_servers,
            "queryStrategy": "UseIPv4",
            "disableFallback": False,
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": routing_rules,
        },
    }


def _xray_outbound(node: XrayNode, *, fp: str | None = None) -> dict[str, Any]:
    q = node.query
    stream = _xray_stream_settings(q, fp=fp)
    flow = (q.get("flow") or "").strip()
    security = (q.get("security") or q.get("tls") or "").strip().lower()
    # flow (xtls-rprx-vision и т.п.) поддерживается ТОЛЬКО на Reality.
    # На TLS-узлах xray-core падает на старте — узел ложно «мёртв» (core
    # exited). Выкидываем flow на не-Reality узлах.
    if flow and security != "reality":
        flow = ""
    if node.protocol == "vless":
        user = {"id": node.credential, "encryption": q.get("encryption") or "none"}
        if flow:
            user["flow"] = flow
        outbound = {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {"vnext": [{"address": node.host, "port": node.port, "users": [user]}]},
            "streamSettings": stream,
        }
    elif node.protocol == "vmess":
        user = {"id": node.credential, "alterId": int(node.extra.get("aid") or 0), "security": node.extra.get("scy") or "auto"}
        outbound = {
            "protocol": "vmess",
            "tag": "proxy",
            "settings": {"vnext": [{"address": node.host, "port": node.port, "users": [user]}]},
            "streamSettings": stream,
        }
    elif node.protocol == "trojan":
        outbound = {
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {"servers": [{"address": node.host, "port": node.port, "password": node.credential}]},
            "streamSettings": stream,
        }
    elif node.protocol == "shadowsocks":
        outbound = {
            "protocol": "shadowsocks",
            "tag": "proxy",
            "settings": {
                "servers": [
                    {
                        "address": node.host,
                        "port": node.port,
                        "method": q.get("method") or "aes-256-gcm",
                        "password": node.credential,
                    }
                ]
            },
        }
    else:
        raise ValueError(f"Unsupported xray protocol: {node.protocol}")
    # Анти-детект ТСПУ: mux консолидирует параллельные TLS-соединения к одному
    # SNI в одно (Сигнал 3 «заморозки»). XTLS Vision несовместим с TCP-mux
    # («MUX is not compatible with XTLS raw connections») — только XUDP.
    if node.protocol in ("vless", "vmess", "trojan"):
        if flow == "xtls-rprx-vision":
            outbound["mux"] = {"enabled": True, "concurrency": -1, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}
        else:
            outbound["mux"] = {"enabled": True, "concurrency": 8, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}
    return outbound


def _resolve_stream_fingerprint(query: dict[str, str], fp: str | None) -> str | None:
    """Выбрать TLS-фингерпринт uTLS для stream-конфига.

    Приоритет:
      1. fp_override (fp) из fingerprint-матрицы/активного теста — используется
         КАК ЕСТЬ, без _safe_fingerprint (нужен настоящий chrome/random, чтобы
         проверить устойчивость к DPI).
      2. fp из query-ссылки узла — через _safe_fingerprint (безопасный режим).
      3. Неизвестный/пустой — _SAFE_DEFAULT_FINGERPRINT (как раньше).

    Возвращает None только если fp == "none" (системный TLS, без uTLS).
    """
    if fp is not None:
        value = str(fp or "").strip().lower()
        if not value or value == "none":
            return None
        return value
    return _safe_fingerprint(query.get("fp") or query.get("fingerprint"))


def _normalize_reality_pbk(value: str) -> str:
    """Нормализовать Reality publicKey (pbk) до base64URL БЕЗ padding.

    xray-core v26+ парсит publicKey через base64.RawURLEncoding: принимает
    ТОЛЬКО URL-safe алфавит ('-'/'_') без '='. Старая нормализация
    («+»/«/» + padding) валидна для StdEncoding, но xray v26 её отвергает —
    каждый Reality-узел падал с «core exited» ( reproducing: xray -test
    возвращает «Failed to build REALITY config: invalid "password"»).
    Подписи дают pbk в URL-safe виде — пропускаем как есть; standard-вариант
    конвертируем в URL-safe и срезаем padding.
    Ничего не делает с пустым/не-base64 значением (передаём как есть —
    ядро само выдаст внятную ошибку в stderr).
    """
    text = str(value or "").strip()
    if not text:
        return text
    cleaned = text.replace("+", "-").replace("/", "_").rstrip("=")
    if not cleaned or not all(c.isalnum() or c in "-_" for c in cleaned):
        return text
    return cleaned


def _xray_stream_settings(query: dict[str, str], *, fp: str | None = None) -> dict[str, Any]:
    network = (query.get("type") or query.get("network") or query.get("net") or "tcp").strip()
    if network == "h2":
        network = "http"
    security = query.get("security") or query.get("tls") or ""
    stream: dict[str, Any] = {"network": network}
    if query.get("packetEncoding"):
        stream["packetEncoding"] = query["packetEncoding"]
    if security and security != "none":
        stream["security"] = security
    sni = query.get("sni") or query.get("serverName") or query.get("host") or ""
    resolved_fp = _resolve_stream_fingerprint(query, fp)
    if security == "tls":
        tls: dict[str, Any] = {}
        if sni:
            tls["serverName"] = sni
        if _truthy(query.get("allowInsecure") or query.get("allow_insecure") or query.get("insecure")):
            tls["allowInsecure"] = True
        if resolved_fp is not None:
            tls["fingerprint"] = resolved_fp
        if query.get("alpn"):
            tls["alpn"] = [item.strip() for item in str(query.get("alpn") or "").split(",") if item.strip()]
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality: dict[str, Any] = {}
        if sni:
            reality["serverName"] = sni
        for source, target in [("pbk", "publicKey"), ("publicKey", "publicKey"), ("sid", "shortId"), ("spx", "spiderX")]:
            if query.get(source):
                value = query[source]
                # pbk/publicKey приходит URL-safe и без padding — нормализуем,
                # иначе ядро падает на старте и узел ложно «мёртв».
                if target == "publicKey":
                    value = _normalize_reality_pbk(value)
                reality[target] = value
        if resolved_fp is not None:
            reality["fingerprint"] = resolved_fp
        stream["realitySettings"] = reality
    if network == "ws":
        ws: dict[str, Any] = {}
        if query.get("path"):
            ws["path"] = query["path"]
        if query.get("host"):
            ws["headers"] = {"Host": query["host"]}
        stream["wsSettings"] = ws
    elif network == "tcp":
        header_type = query.get("headerType") or query.get("header") or ""
        if header_type and header_type != "none":
            tcp: dict[str, Any] = {"header": {"type": header_type}}
            if header_type == "http":
                request: dict[str, Any] = {}
                if query.get("host"):
                    request["headers"] = {"Host": [item.strip() for item in query["host"].split(",") if item.strip()]}
                if query.get("path"):
                    request["path"] = [item.strip() for item in query["path"].split(",") if item.strip()]
                if request:
                    tcp["header"]["request"] = request
            stream["tcpSettings"] = tcp
    elif network == "http":
        http: dict[str, Any] = {}
        if query.get("host"):
            http["host"] = [item.strip() for item in query["host"].split(",") if item.strip()]
        if query.get("path"):
            http["path"] = query["path"]
        stream["httpSettings"] = http
    elif network == "grpc":
        service = query.get("serviceName") or query.get("service") or ""
        stream["grpcSettings"] = {"serviceName": service}
        if (query.get("mode") or "").lower() == "multi":
            stream["grpcSettings"]["multiMode"] = True
        if query.get("authority"):
            stream["grpcSettings"]["authority"] = query["authority"]
    elif network == "httpupgrade":
        httpupgrade: dict[str, Any] = {}
        if query.get("path"):
            httpupgrade["path"] = query["path"]
        if query.get("host"):
            httpupgrade["host"] = query["host"]
        stream["httpupgradeSettings"] = httpupgrade
    elif network == "xhttp":
        xhttp: dict[str, Any] = {}
        if query.get("path"):
            xhttp["path"] = query["path"]
        if query.get("host"):
            xhttp["host"] = query["host"]
        if query.get("mode"):
            xhttp["mode"] = query["mode"]
        stream["xhttpSettings"] = xhttp
    elif network == "splithttp":
        xhttp: dict[str, Any] = {}
        if query.get("path"):
            xhttp["path"] = query["path"]
        if query.get("host"):
            xhttp["host"] = query["host"]
        if query.get("mode"):
            xhttp["mode"] = query["mode"]
        stream["splithttpSettings"] = xhttp
    elif network == "kcp":
        kcp: dict[str, Any] = {
            "mtu": int(query.get("mtu") or 1350),
            "tti": int(query.get("tti") or 50),
            "uplinkCapacity": int(query.get("uplinkCapacity") or query.get("up") or 12),
            "downlinkCapacity": int(query.get("downlinkCapacity") or query.get("down") or 100),
            "congestion": _truthy(query.get("congestion")),
            "readBufferSize": int(query.get("readBufferSize") or 2),
            "writeBufferSize": int(query.get("writeBufferSize") or 2),
            "header": {"type": query.get("headerType") or query.get("header") or "none"},
        }
        if query.get("seed"):
            kcp["seed"] = query["seed"]
        stream["kcpSettings"] = kcp
    elif network == "quic":
        stream["quicSettings"] = {
            "security": query.get("quicSecurity") or query.get("securityType") or query.get("host") or "none",
            "key": query.get("key") or query.get("path") or "",
            "header": {"type": query.get("headerType") or query.get("header") or "none"},
        }
    return stream


def _sing_box_transport(query: dict[str, str]) -> dict[str, Any] | None:
    """Транспорт для sing-box outbound из query-параметров ссылки узла.

    Возвращает None для чистого TCP (транспорта нет), dict — для ws/grpc/http.
    Неподдерживаемые sing-box транспорты (xhttp/splithttp) дают ValueError —
    узел честно отбраковывается, а не тестируется молча неправильно.
    """
    network = (query.get("type") or query.get("network") or query.get("net") or "tcp").strip().lower()
    if network in ("", "tcp", "raw"):
        header_type = (query.get("headerType") or query.get("header") or "").strip().lower()
        if header_type and header_type != "none":
            # headerType=http поверх TCP sing-box не поддерживает в outbound.
            return None
        return None
    if network == "ws":
        transport: dict[str, Any] = {"type": "ws"}
        if query.get("path"):
            transport["path"] = query["path"]
        if query.get("host"):
            transport["headers"] = {"Host": query["host"]}
        if query.get("ed") or query.get("eh") or (query.get("path") or "").find("ed=2048") >= 0:
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return transport
    if network in ("grpc",):
        transport = {"type": "grpc"}
        service = query.get("serviceName") or query.get("service") or ""
        if service:
            transport["service_name"] = service
        return transport
    if network in ("http", "h2"):
        transport = {"type": "http"}
        if query.get("host"):
            transport["host"] = [item.strip() for item in query["host"].split(",") if item.strip()]
        if query.get("path"):
            transport["path"] = query["path"]
        return transport
    if network == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if query.get("path"):
            transport["path"] = query["path"]
        if query.get("host"):
            transport["host"] = query["host"]
        return transport
    # v11: SingBoxUnsupported вместо ValueError — для совместимости с
    # _sing_box_supports() и test_singbox_mode.py.
    raise SingBoxUnsupported(f"sing-box does not support transport: {network}")


def _sing_box_tls(node: XrayNode, query: dict[str, str], fp: str | None) -> dict[str, Any] | None:
    """TLS-блок sing-box outbound (tls/reality) из query-параметров.

    Возвращает None, если узел без TLS. Для Reality обязательно включается
    uTLS (требование sing-box).
    """
    security = (query.get("security") or query.get("tls") or "").strip().lower()
    if not security or security == "none":
        return None
    sni = query.get("sni") or query.get("peer") or query.get("serverName") or query.get("host") or ""
    tls: dict[str, Any] = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    if _truthy(query.get("insecure") or query.get("allowInsecure") or query.get("allow_insecure")):
        tls["insecure"] = True
    if query.get("alpn"):
        tls["alpn"] = [item.strip() for item in query["alpn"].split(",") if item.strip()]
    resolved_fp = _resolve_stream_fingerprint(query, fp)
    if security == "reality":
        reality: dict[str, Any] = {"enabled": True}
        pbk = query.get("pbk") or query.get("publicKey") or ""
        if pbk:
            reality["public_key"] = _normalize_reality_pbk(pbk)
        if query.get("sid"):
            reality["short_id"] = query["sid"]
        # Reality в sing-box ТРЕБУЕТ uTLS — без фингерпринта ядро падает.
        reality_fp = resolved_fp or _SAFE_DEFAULT_FINGERPRINT
        tls["utls"] = {"enabled": True, "fingerprint": reality_fp}
        tls["reality"] = reality
    else:
        if resolved_fp is not None:
            tls["utls"] = {"enabled": True, "fingerprint": resolved_fp}
    return tls


def _sing_box_outbound(node: XrayNode, *, fp: str | None = None) -> dict[str, Any]:
    """Собрать sing-box outbound для ЛЮБОГО протокола ссылки узла.

    Требуется для режима «только sing-box»: vless/vmess/trojan/ss тоже
    должны собираться в корректный sing-box-конфиг (раньше builder умел
    только hysteria/hy2 и ставил password всем подряд).

    v11: бросает SingBoxUnsupported для неподдерживаемых транспортов/протоколов
    (kcp/quic/xhttp/legacy-scy). Это позволяет _sing_box_supports() и тестам
    ловить unsupported-случай как исключение, а не как ValueError.
    """
    # v11: пред-проверка поддержки через sing_box_unsupported_reason.
    # Если узел не поддерживается — кидаем SingBoxUnsupported (не ValueError).
    try:
        from singbox_convert import sing_box_unsupported_reason
        reason = sing_box_unsupported_reason(node, fp=fp)
        if reason:
            raise SingBoxUnsupported(reason)
    except SingBoxUnsupported:
        raise
    except Exception:
        pass  # если singbox_convert недоступен — продолжаем по старому пути
    q = node.query
    protocol = node.protocol
    outbound: dict[str, Any] = {
        "tag": "proxy",
        "server": node.host,
        "server_port": node.port,
    }
    if protocol == "vless":
        outbound["type"] = "vless"
        outbound["uuid"] = node.credential
        flow = (q.get("flow") or "").strip()
        security = (q.get("security") or q.get("tls") or "").strip().lower()
        # flow (xtls-rprx-vision) валиден только на Reality — как в xray-builder.
        if flow and security == "reality":
            outbound["flow"] = flow
    elif protocol == "vmess":
        outbound["type"] = "vmess"
        outbound["uuid"] = node.credential
        outbound["security"] = node.extra.get("scy") or "auto"
        outbound["alter_id"] = int(node.extra.get("aid") or 0)
    elif protocol == "trojan":
        outbound["type"] = "trojan"
        outbound["password"] = node.credential
    elif protocol == "shadowsocks":
        outbound["type"] = "shadowsocks"
        outbound["method"] = q.get("method") or "aes-256-gcm"
        outbound["password"] = node.credential
    elif protocol in ("hysteria", "hysteria2", "hy2"):
        outbound["type"] = "hysteria2" if protocol in ("hysteria2", "hy2") else "hysteria"
        if protocol in ("hysteria2", "hy2"):
            outbound["password"] = node.credential
            if q.get("obfs"):
                obfs_type = q.get("obfs")
                if obfs_type == "1":
                    obfs_type = "salamander"
                outbound["obfs"] = {
                    "type": obfs_type,
                    "password": q.get("obfs-password") or q.get("obfsPassword") or q.get("obfs_password") or "",
                }
        else:
            outbound["auth_str"] = node.credential
            outbound["up_mbps"] = int(q.get("upmbps") or q.get("up_mbps") or q.get("up") or 100)
            outbound["down_mbps"] = int(q.get("downmbps") or q.get("down_mbps") or q.get("down") or 100)
            if q.get("obfs"):
                outbound["obfs"] = {"type": "salamander", "password": q.get("obfs-password") or ""}
    else:
        raise SingBoxUnsupported(f"Unsupported sing-box protocol: {protocol}")

    # TLS: hysteria/hy2 всегда с TLS (протокол TLS-based). Остальные — по security.
    if protocol in ("hysteria", "hysteria2", "hy2"):
        tls = _sing_box_tls(node, {**q, "security": q.get("security") or "tls"}, fp)
        if tls is None:
            tls = {"enabled": True}
        if "server_name" not in tls:
            sni = q.get("sni") or q.get("peer") or node.host
            if sni:
                tls["server_name"] = sni
        outbound["tls"] = tls
    else:
        tls = _sing_box_tls(node, q, fp)
        if tls is not None:
            outbound["tls"] = tls
    # Транспорт (ws/grpc/http) — только для не-hysteria протоколов.
    if protocol not in ("hysteria", "hysteria2", "hy2"):
        transport = _sing_box_transport(q)
        if transport is not None:
            outbound["transport"] = transport
    return outbound


def _sing_box_config(
    node: XrayNode,
    listen_host: str,
    listen_port: int,
    *,
    fp: str | None = None,
) -> dict[str, Any]:
    """Собрать конфиг sing-box с SOCKS-inbound (ЛЮБОЙ протокол узла).

    DNS-резолвинг выполняет САМ прокси-сервер (через outbound proxy): все
    DNS-серверы в секции `dns.servers` имеют `"detour": "proxy"`, поэтому
    DoH/UDP DNS-запросы идут через прокси-сервер узла, а не через локальный
    резолвер. Это критично для заблокированных сетей, где локальный DNS
    режется провайдером.
    """
    outbound = _sing_box_outbound(node, fp=fp)

    inbounds: list[dict[str, Any]] = [
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": listen_host,
            "listen_port": listen_port,
        }
    ]
    outbounds: list[dict[str, Any]] = [outbound]
    route: dict[str, Any] = {"final": "proxy", "auto_detect_interface": True}

    # DNS — ЛОКАЛЬНЫЙ системный резолвер (type: local). DoH через прокси
    # убран: DoH-эндпоинты могут блокироваться/не работать (требование
    # пользователя). Домены целей уходят в туннель как домены — их
    # резолвит удалённый сервер; локальный DNS нужен только для адреса
    # самого узла, а он всегда доступен (обслуживает всю систему).
    dns_block: dict[str, Any] = {
        "servers": [
            {
                "tag": "local",
                "type": "local",
            },
        ],
        "final": "local",
        "strategy": "ipv4_only",
    }

    result: dict[str, Any] = {
        "log": {"level": "warn", "disabled": False},
        "dns": dns_block,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
    }
    return result


def _write_temp_config(config: dict[str, Any]) -> str:
    handle = tempfile.NamedTemporaryFile("w", prefix="mtproxy-autoswitch-core-", suffix=".json", delete=False, encoding="utf-8")
    with handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
    return handle.name


if os.name == "nt":
    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]


def _create_kill_on_close_job() -> int | None:
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return None
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = kernel32.SetInformationJobObject(
            handle,
            9,  # JobObjectExtendedLimitInformation
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            kernel32.CloseHandle(handle)
            return None
        return int(handle)
    except Exception:
        return None


def _assign_process_to_job(job_handle: int | None, proc: subprocess.Popen) -> None:
    if os.name != "nt" or not job_handle:
        return
    process_handle = int(getattr(proc, "_handle", 0) or 0)
    if process_handle <= 0:
        return
    with contextlib.suppress(Exception):
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject(wintypes.HANDLE(job_handle), wintypes.HANDLE(process_handle))


def _close_windows_handle(handle: int | None) -> None:
    if os.name != "nt" or not handle:
        return
    with contextlib.suppress(Exception):
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def _terminate_process_tree(proc: subprocess.Popen, *, timeout: float = 5.0) -> None:
    if proc.poll() is not None:
        return
    with contextlib.suppress(Exception):
        proc.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=max(0.1, timeout))
    if proc.poll() is None:
        _terminate_pid_tree(int(proc.pid), timeout=max(1.0, timeout))
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=1.0)


def _terminate_pid_tree(pid: int, *, timeout: float = 5.0) -> None:
    """Убить процесс и всех его детей БЕЗ subprocess (taskkill).

    Старая версия вызывала subprocess.run(["taskkill", ...]) — это
    spawn нового процесса на каждый terminate, что сериализовало 32
    потока-работника через Windows kernel. На 5070 узлов × ~3 вызова
    = 15000+ subprocess spawn-ов = минуты потерянного времени.

    Новая версия: proc.kill() + прямые WinAPI вызовы через ctypes.
    OpenProcess + TerminateProcess — без spawn subprocess, в 50-100x
    быстрее. Дерево процессов убираем через итеративный snapshot, но
    для нашего случая (xray/sing-box) обычно достаточно убить корень.
    """
    if pid <= 0:
        return
    if os.name == "nt":
        _windows_terminate_pid_tree(pid)
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, 15)
    deadline = time.monotonic() + max(0.1, timeout)
    while time.monotonic() < deadline:
        if not _pid_exists(pid):
            return
        time.sleep(0.05)
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, 9)


def _windows_terminate_pid_tree(root_pid: int) -> None:
    """Убить дерево процессов через WinAPI (без subprocess).

    Использует CreateToolhelp32Snapshot для обхода дерева процессов,
    OpenProcess + TerminateProcess для убийства каждого. Это в 50-100x
    быстрее, чем spawn subprocess на taskkill.
    """
    if root_pid <= 0:
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # TH32CS_SNAPPROCESS = 0x00000002
        TH32CS_SNAPPROCESS = 0x00000002
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        # PROCESSENTRY32W структура.
        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        # Сначала собираем всех детей рекурсивно (BFS), потом убиваем.
        # Сначала корень, потом детей — это безопаснее, чем наоборот.
        pids_to_kill: list[int] = [root_pid]
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            # Snapshot не создался — хотя бы корень убьём.
            _windows_terminate_process(root_pid)
            return
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            # Process32FirstW / Process32NextW
            if not kernel32.Process32FirstW(ctypes.wintypes.HANDLE(snapshot), ctypes.byref(entry)):
                _windows_terminate_process(root_pid)
                return
            # Строим map: parent_pid -> [child_pids].
            parent_to_children: dict[int, list[int]] = {}
            while True:
                parent = int(entry.th32ParentProcessID)
                child = int(entry.th32ProcessID)
                parent_to_children.setdefault(parent, []).append(child)
                if not kernel32.Process32NextW(ctypes.wintypes.HANDLE(snapshot), ctypes.byref(entry)):
                    break
            # BFS от root_pid — собираем всех потомков.
            queue = [root_pid]
            visited: set[int] = set()
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                pids_to_kill.append(current)
                for child in parent_to_children.get(current, []):
                    if child not in visited:
                        queue.append(child)
        finally:
            kernel32.CloseHandle(ctypes.wintypes.HANDLE(snapshot))

        # Убиваем от листьев к корню — так чище (дети не успевают создать
        # новых детей-сирот, пока корень ещё жив). Но на практике xray
        # не spawn-ит дочерние процессы, так что порядок не критичен.
        for pid in reversed(pids_to_kill):
            _windows_terminate_process(pid)
    except Exception:
        # Fallback на os.kill — хоть что-то.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(root_pid, 9)


def _windows_terminate_process(pid: int) -> None:
    """Убить один процесс по PID через TerminateProcess (без subprocess).

    PROCESS_TERMINATE = 0x0001.
    """
    if pid <= 0:
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        PROCESS_TERMINATE = 0x0001
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not handle:
            return  # процесс уже мёртв или нет прав
        try:
            kernel32.TerminateProcess(handle, 1)
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        pass


def _pid_exists(pid: int) -> bool:
    """Проверить, жив ли процесс, БЕЗ subprocess (tasklist).

    Старая версия вызывала subprocess.run(["tasklist", ...]) — это spawn
    нового процесса на каждую проверку. На 32 потоках × 5070 узлов это
    десятки тысяч лишних subprocess spawn-ов.

    Новая версия: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) — прямой
    WinAPI вызов через ctypes, без subprocess. В 100x быстрее.
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                # OpenProcess возвращает 0 если процесса нет или нет прав.
                # Различаем: ERROR_INVALID_PARAMETER (87) = нет такого PID.
                last_error = kernel32.GetLastError()
                return last_error != 87
            kernel32.CloseHandle(handle)
            return True
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _cleanup_stale_bundle_cores(root_dir: Path, out_dir: Path) -> None:
    if os.name != "nt":
        return
    roots = [root_dir.resolve()]
    bundle_root = Path(str(getattr(sys, "_MEIPASS", "") or ""))
    if bundle_root:
        with contextlib.suppress(Exception):
            roots.append(bundle_root.resolve())
    module_root = Path(__file__).resolve().parent
    with contextlib.suppress(Exception):
        roots.append(module_root.resolve())
    root_literals = []
    for root in roots:
        text = str(root)
        if text and text not in root_literals:
            root_literals.append(text)
    if not root_literals:
        return
    ps_roots = "@(" + ",".join("'" + item.replace("'", "''") + "'" for item in root_literals) + ")"
    script = f"""
$roots = {ps_roots}
Get-CimInstance Win32_Process |
  Where-Object {{
    $exe = $_.ExecutablePath
    ($_.Name -in @('xray.exe','sing-box.exe')) -and
    ($_.CommandLine -match ' run -c ') -and
    ($_.CommandLine -match 'mtproxy-autoswitch-core-|tmp[a-z0-9]+\\.json') -and
    ($roots | Where-Object {{ $exe -like ($_.TrimEnd('\\') + '\\*') }})
  }} |
  ForEach-Object {{ taskkill /PID $_.ProcessId /T /F | Out-Null }}
"""
    with contextlib.suppress(Exception):
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=4.0,
            creationflags=_subprocess_no_window(),
            check=False,
        )


def _resolve_binary(override_path: str, root_dir: Path, name: str) -> str:
    candidates: list[Path] = []
    if override_path:
        candidates.append(Path(override_path))
    exe = f"{name}.exe" if os.name == "nt" else name
    bundle_root = Path(str(getattr(sys, "_MEIPASS", "") or ""))
    if bundle_root:
        candidates.extend([bundle_root / "bin" / exe, bundle_root / exe])
    # Модуль лежит в python/, ядра — в <корень>/bin,
    # поэтому проверяем и каталог модуля, и его родителя (корень репо).
    module_root = Path(__file__).resolve().parent
    candidates.extend(
        [
            root_dir / "bin" / exe,
            root_dir / exe,
            module_root / "bin" / exe,
            module_root / exe,
            module_root.parent / "bin" / exe,
            module_root.parent / exe,
            Path(exe),
        ]
    )
    for path in candidates:
        if path.exists():
            return str(path.resolve())
    found = shutil.which(exe)
    if found:
        return found
    return ""


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _tcp_ping_node(node: "XrayNode", timeout: float = 2.0) -> float | None:
    """Быстрый TCP-ping: connect к (host, port) без поднятия ядра.

    Возвращает latency в мс или None, если connect не удался за timeout.
    Намного дешевле, чем поднимать xray.exe/sing-box.exe на каждый узел:
    на 10000 узлов TCP-ping занимает ~30 сек (32 потока × 2 сек timeout),
    тогда как xray-ping — 10000 старт-стопов ~ 5-8 часов.

    Не проверяет протокол — только доступность порта. Этого достаточно для
    отсеивания 60-70% мёртвых узлов до дорогих проверок.
    """
    host = node.host
    port = int(node.port)
    started = time.perf_counter()
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        latency_ms = (time.perf_counter() - started) * 1000.0
        return latency_ms
    except Exception:
        return None
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()


# Протоколы, которые работают по UDP (hysteria/hy2). Для них TCP-ping
# бесполезен — сервер слушает UDP, и TCP-порт может быть закрыт, хотя узел
# жив. Для них используем UDP-ping: отправляем QUIC-like Initial-пакет
# и ждём любого ответа. Это не полноценный QUIC-handshake (это сложно),
# но достаточный для проверки «жив ли UDP-порт и отвечает ли сервер».
UDP_PROTOCOLS = frozenset({"hysteria", "hysteria2", "hy2"})


def _udp_ping_node(node: "XrayNode", timeout: float = 2.0) -> float | None:
    """UDP-ping для hysteria/hy2 узлов.

    Отправляет упрощённый QUIC Initial-пакет и ждёт ответа. Если сервер
    ответил хоть чем-то за timeout — узел жив. Если нет — мёртв.

    Полноценный QUIC-handshake требует реализации crypto frames, TLS 1.3
    ClientHello и обработки retry-пакетов — это слишком сложно для
    предфильтра. Мы используем эвристику:

    1. Отправляем несколько «проб» — пустой UDP-пакет, QUIC Initial-заголовок
       с фейковым DCID и random payload. Hysteria-сервер (на базе quic-go)
       обычно отвечает одним из:
         - Retry-пакетом (если требует token)
         - Initial-пакетом (если принимает соединение)
         - ICMP Port Unreachable (если порт закрыт — но это не приходит
           обратно как UDP-ответ, мы этого не увидим)
    2. Если за timeout получен ЛЮБОЙ UDP-пакет от сервера — узел жив.
    3. Если ничего не пришло — узел мёртв (или за NAT, или порт закрыт).

    Ложноположительные срабатывания: сервер мог ответить на наш мусорный
    пакет, но реальный handshake потом упадёт (например, неверный auth_str).
    Это нормально — отсеет следующая SOCKS/UDP-проверка через ядро.

    Ложноотрицательные: сервер мог быть жив, но не ответить за timeout
    (большой RTT, потеря пакетов). Поэтому timeout = 3 сек (больше, чем
    у TCP, т.к. UDP может потеряться и сервер делает retransmit).
    """
    host = node.host
    port = int(node.port)
    started = time.perf_counter()
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Несколько пробных пакетов разной формы — повышает шанс, что
        # хотя бы на один сервер ответит. Hysteria слушает QUIC, поэтому
        # делаем QUIC-like пакеты:
        probes = [
            # 1. Минимальный QUIC Initial (Long Header, type=0xC0, DCID=8 байт).
            #    Это не валидный QUIC, но quic-go часто отвечает на «похожее»
            #    retry-пакетом или сразу сбрасывает соединение.
            bytes([0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x40, 0x00])
            + b"\x01\x02\x03\x04\x05\x06\x07\x08"  # DCID (8 байт)
            + b"\x00" * 20,  #(payload)
            # 2. Пустой UDP-пакет — некоторые серверы отвечают ICMP/RESET.
            #    Мы не увидим ICMP, но если сервер использует raw-socket, может
            #    прислать ошибку в UDP-домене.
            b"",
            # 3. Случайные байты — для серверов с нестандартной обработкой.
            os.urandom(32),
        ]

        for probe in probes:
            try:
                sock.sendto(probe, (host, port))
            except Exception:
                # sendto может упасть на недоступном хосте — пробуем следующий.
                continue
            try:
                # Ждём ответ. Если получен любой пакет — узел жив.
                data, _ = sock.recvfrom(2048)
                if data:
                    return (time.perf_counter() - started) * 1000.0
            except socket.timeout:
                # Эта проба не дала ответа — пробуем следующую.
                continue
            except Exception:
                continue
        return None
    except Exception:
        return None
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()


def _tcp_udp_ping_node(node: "XrayNode", timeout: float = 2.0) -> float | None:
    """Универсальный предфильтр: TCP для TCP-протоколов, UDP для UDP-протоколов.

    Для vless/vmess/trojan/ss — TCP-ping (узел работает по TCP).
    Для hysteria/hy2 — UDP-ping (узел работает по UDP/QUIC).

    Возвращает latency_ms или None (узел мёртв).
    """
    if node.protocol in UDP_PROTOCOLS:
        # Для UDP-протоколов даём чуть больше времени (потеря пакетов).
        return _udp_ping_node(node, timeout=max(timeout, 3.0))
    return _tcp_ping_node(node, timeout=timeout)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _socks_open_connection(socks_host: str, socks_port: int, target_host: str, target_port: int, timeout: float) -> socket.socket | None:
    """Открыть соединение через SOCKS5 к target_host:target_port.

    ATYP выбирается автоматически:
      * IPv4-строка (1.1.1.1) → ATYP=1 (4 байта). Ядро подключается к IP напрямую,
        БЕЗ DNS-резолвинга. На заблокированных сетях DNS через DoH таймаутится,
        но с IP это не проблема.
      * Домен (www.google.com) → ATYP=3 (домен-строка, ядро само резолвит).
    """
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
        sock.settimeout(timeout)
        # Greeting: VER=5, NMETHODS=1, METHOD=0x00 (no auth).
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            sock.close()
            return None
        # CONNECT request. ATYP=1 для IP-адреса (4 сырых байта),
        # ATYP=3 для домена (длина+строка).
        try:
            # socket.inet_aton бросает OSError для невалидных IPv4 —
            # значит это домен, используем ATYP=3.
            ip_bytes = socket.inet_aton(target_host)
            request = b"\x05\x01\x00\x01" + ip_bytes + int(target_port).to_bytes(2, "big")
        except OSError:
            # Домен: ATYP=3 + длина-байт + домен в ASCII (idna не нужен,
            # SOCKS5 RFC 1928 требует ASCII/UTF-8 байты, не punycode).
            host_bytes = target_host.encode("utf-8")
            if len(host_bytes) > 255:
                sock.close()
                return None
            request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + int(target_port).to_bytes(2, "big")
        sock.sendall(request)
        header = _recv_exact(sock, 4)
        if len(header) < 4 or header[1] != 0:
            sock.close()
            return None
        atyp = header[3]
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 3:
            length = _recv_exact(sock, 1)
            if not length:
                sock.close()
                return None
            _recv_exact(sock, length[0])
        elif atyp == 4:
            _recv_exact(sock, 16)
        _recv_exact(sock, 2)
        return sock
    except Exception:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()
        return None


def _socks_https_head_status(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    timeout: float,
    path: str = "/",
) -> tuple[int, float] | None:
    """HEAD-запрос через SOCKS+SSL. Возвращает (http_status, latency_ms) или None.

    Ожидаем HTTP/2 200 или 302 (стандартный ответ api.telegram.org на HEAD /).
    """
    started = time.perf_counter()
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"HEAD {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            response = b""
            while b"\r\n" not in response:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            if not response.startswith(b"HTTP/"):
                return None
            line = response.split(b"\r\n", 1)[0]
            parts = line.split(b" ", 2)
            try:
                status = int(parts[1])
            except (IndexError, ValueError):
                return None
            return status, (time.perf_counter() - started) * 1000.0
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def _socks_https_get_body(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    timeout: float,
    max_bytes: int = 512 * 1024,
    extra_headers: dict[str, str] | None = None,
) -> tuple[bool, bytes, int]:
    """GET через SOCKS+SSL с телом ответа. Возвращает (ok, body, status).

    Нужен для Telegram-медиа фильтра: скачать HTML страницы t.me/s/<канал>
    (домен передаётся в SOCKS ATYP=0x03 — резолвит выход узла, hosts не
    участвует) и вытащить ссылки на видео.
    """
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return False, b"", 0
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            header_lines = [
                f"GET {path} HTTP/1.1\r\n",
                f"Host: {server_name}\r\n",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n",
                "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n",
                "Accept-Language: ru-RU,ru;q=0.9,en;q=0.6\r\n",
                "Connection: close\r\n",
            ]
            for key, value in (extra_headers or {}).items():
                header_lines.append(f"{key}: {value}\r\n")
            header_lines.append("\r\n")
            tls_sock.sendall("".join(header_lines).encode("ascii"))

            # Заголовки.
            buf = b""
            deadline = time.perf_counter() + timeout
            while b"\r\n\r\n" not in buf and time.perf_counter() < deadline:
                piece = tls_sock.recv(4096)
                if not piece:
                    break
                buf += piece
                if len(buf) > 128 * 1024:
                    break
            header_end = buf.find(b"\r\n\r\n")
            if header_end < 0 or not buf.startswith(b"HTTP/"):
                return False, b"", 0
            try:
                status = int(buf.split(b" ", 2)[1])
            except (IndexError, ValueError):
                return False, b"", 0
            headers_text = buf[:header_end].decode("latin-1", errors="replace").lower()
            is_chunked = "transfer-encoding: chunked" in headers_text

            initial = buf[header_end + 4 :]
            if is_chunked:
                # t.me отдаёт страницу с фиксированным Content-Length, но на
                # всякий случай поддерживаем chunked (best-effort).
                body = b""
                rest = initial
                while len(body) < max_bytes and time.perf_counter() < deadline:
                    while b"\r\n" not in rest:
                        piece = tls_sock.recv(8192)
                        if not piece:
                            return True, body[:max_bytes], status
                        rest += piece
                    size_line, rest = rest.split(b"\r\n", 1)
                    try:
                        size = int(size_line.split(b";")[0].strip(), 16)
                    except ValueError:
                        return True, body[:max_bytes], status
                    if size <= 0:
                        return True, body[:max_bytes], status
                    while len(rest) < size + 2:
                        piece = tls_sock.recv(min(65536, size + 2 - len(rest)))
                        if not piece:
                            return True, body[:max_bytes], status
                        rest += piece
                    body += rest[:size]
                    rest = rest[size + 2 :]
                return True, body[:max_bytes], status
            # Content-Length или connection-close.
            body = initial
            while len(body) < max_bytes and time.perf_counter() < deadline:
                piece = tls_sock.recv(min(65536, max_bytes - len(body)))
                if not piece:
                    break
                body += piece
            return True, body[:max_bytes], status
    except Exception:
        return False, b"", 0
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def _tg_media_video_urls(html: bytes) -> list[str]:
    """Вытащить URL видео из HTML t.me/s/<канал>.

    Веб-превью Telegram рендерит видео постов как
    ``<video src="https://cdn4.telesco.pe/file/<id>.mp4?token=<signed>" class=...>``.
    Тег парсится ЦЕЛИКОМ (``<video ...>``): класс ``blured`` ищется только
    среди атрибутов ЭТОГО тега — хвост после src мог дотянуться до класса
    соседнего видео и ложно отправить полноразмерное видео в конец списка.
    Токен в URL подписан, поэтому менять query нельзя — анти-кеш делаем
    случайным Range-стартом, а не подменой параметров.
    Порядок: сначала «чистые» (не blured) видео — они полноразмерные.
    """
    urls: list[str] = []
    blured: list[str] = []
    for tag_match in TG_MEDIA_VIDEO_TAG_RE.finditer(html):
        attrs = tag_match.group(1)
        src_match = TG_MEDIA_VIDEO_SRC_RE.search(attrs)
        if src_match is None:
            continue
        url = src_match.group(1).decode("ascii", errors="replace")
        if url in urls or url in blured:
            continue
        if b"blured" in attrs:
            blured.append(url)
        else:
            urls.append(url)
    return urls + blured


def _tg_media_ranged_download(
    socks_host: str,
    socks_port: int,
    video_url: str,
    timeout: float,
    *,
    range_start: int | None = None,
) -> tuple[float | None, int, int]:
    """Скачать окно видео по Range через прокси и измерить скорость.

    Анти-кеш (хардкор): старт окна — СЛУЧАЙНЫЙ байт в первых 8 МБ файла.
    Edge-кеш CDN держит выровненные сегменты с нуля (0-2MB кешированы у всех),
    а случайное окно (например, bytes=5242880-7340031) с высокой вероятностью
    идёт до origin — это честная скорость узла, а не кеш соседа.

    Возвращает (kbps, status, downloaded_bytes); kbps=None при неудаче.
    """
    parsed = urllib.parse.urlsplit(video_url)
    host = (parsed.hostname or "").strip()
    if not host:
        return None, 0, 0
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    if range_start is None:
        range_start = secrets.randbelow(max(1, TG_MEDIA_RANGE_SPAN))
    range_end = range_start + TG_MEDIA_WINDOW_BYTES - 1
    range_header = f"bytes={range_start}-{range_end}"

    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, host, port, timeout)
        if raw_sock is None:
            return None, 0, 0
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            raw_sock = None
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n"
                "Accept: video/mp4,video/*;q=0.9,*/*;q=0.8\r\n"
                f"Range: {range_header}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)

            buf = b""
            deadline = time.perf_counter() + timeout
            while b"\r\n\r\n" not in buf and time.perf_counter() < deadline:
                piece = tls_sock.recv(4096)
                if not piece:
                    break
                buf += piece
                if len(buf) > 65536:
                    break
            header_end = buf.find(b"\r\n\r\n")
            if header_end < 0 or not buf.startswith(b"HTTP/"):
                return None, 0, 0
            try:
                status = int(buf.split(b" ", 2)[1])
            except (IndexError, ValueError):
                return None, 0, 0
            if status not in (200, 206):
                return None, status, 0

            # Тело: Content-Length известна (206 partial) — читаем окно.
            body = buf[header_end + 4 :]
            body_started = time.perf_counter()
            while len(body) < TG_MEDIA_WINDOW_BYTES and time.perf_counter() < deadline:
                piece = tls_sock.recv(min(262144, TG_MEDIA_WINDOW_BYTES - len(body)))
                if not piece:
                    break
                body += piece
            elapsed = max(0.001, time.perf_counter() - body_started)
            if len(body) < TG_MEDIA_MIN_BODY_BYTES:
                # Окно за пределами файла (416-подобный случай) — сигнал
                # вызывающему попробовать другой старт/кандидата.
                return None, status, len(body)
            kbps = (len(body) / 1024.0) / elapsed
            return kbps, status, len(body)
    except Exception:
        return None, 0, 0
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def _tg_media_probe(socks_host: str, socks_port: int, timeout: float) -> float | None:
    """Полный цикл Telegram-медиа фильтра: страница -> видео -> скорость.

    1. Скачиваем HTML https://t.me/s/peppe_poppo через прокси узла.
    2. Извлекаем ссылки на видео постов канала (cdn4.telesco.pe, signed).
    3. Скачиваем СЛУЧАЙНОЕ окно (анти-кеш) первого подходящего видео.
       При неудаче (окно за EOF/короткое) — второй кандидат или другой старт.

    Возвращает скорость в КБ/с или None. Порог применения — TG_MEDIA_MIN_KBPS:
    вызывается для КАЖДОГО узла в стресс-тесте (обязательный фильтр).
    """
    page_timeout = min(12.0, max(6.0, timeout))
    ok, body, status = _socks_https_get_body(
        socks_host,
        socks_port,
        TG_MEDIA_PAGE_HOST,
        443,
        TG_MEDIA_PAGE_HOST,
        TG_MEDIA_PAGE_PATH,
        page_timeout,
        max_bytes=512 * 1024,
    )
    if not ok or status != 200 or not body:
        return None
    urls = _tg_media_video_urls(body)
    if not urls:
        return None

    dl_timeout = min(25.0, max(10.0, timeout * 1.5))
    attempts: list[tuple[str, int | None]] = [(urls[0], None)]
    if len(urls) > 1:
        attempts.append((urls[1], None))
    attempts.append((urls[0], 0))  # контроль с нулевого байта (макс. кеш-скорость)

    for url, forced_start in attempts:
        kbps, _status, _bytes = _tg_media_ranged_download(
            socks_host,
            socks_port,
            url,
            dl_timeout,
            range_start=forced_start,
        )
        if kbps is not None and kbps > 0:
            return kbps
    return None


def _socks_https_latency(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    timeout: float,
    path: str = "/",
) -> float | None:
    started = time.perf_counter()
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            response = tls_sock.recv(32)
            if not response.startswith(b"HTTP/"):
                return None
            return (time.perf_counter() - started) * 1000.0
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


# ---------------------------------------------------------------------------
# M-Lab NDT7: WebSocket-клиент на чистом socket (без внешних зависимостей).
# ---------------------------------------------------------------------------

def _ws_build_frame(opcode: int, payload: bytes) -> bytes:
    """Собрать клиентский WebSocket-кадр (RFC 6455, маскированный)."""
    mask_key = secrets.token_bytes(4)
    length = len(payload)
    header = bytearray([0x80 | opcode])
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack(">H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack(">Q", length))
    header.extend(mask_key)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return bytes(header) + masked


def _ws_read_frame(sock: socket.socket) -> tuple[int, bytes]:
    """Прочитать один серверный WebSocket-кадр (без маски)."""
    head = _recv_exact(sock, 2)
    if len(head) < 2:
        return 0x8, b""
    fin_op = head[0]
    opcode = fin_op & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _recv_exact(sock, 8))[0]
    mask_key = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length)
    if masked and mask_key and len(mask_key) == 4:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return opcode, payload


_mlab_cached_url: str | None = None
_mlab_cache_until: float = 0.0


def _mlab_fetch_target(timeout: float = 8.0) -> str | None:
    """Запросить M-Lab Locate API и вернуть wss:// URL ближайшего NDT7-сервера.

    Результат кешируется на 10 минут — не дёргаем locate API при каждой ноде.
    """
    global _mlab_cached_url, _mlab_cache_until
    now = time.monotonic()
    if _mlab_cache_until > now:
        return _mlab_cached_url
    try:
        req = Request(
            M_LAB_LOCATE_URL,
            headers={"User-Agent": "MTProxyAutoSwitch/1.0", "Accept": "application/json"},
        )
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if not isinstance(data, dict):
            _mlab_cache_until = now + 60.0
            return None
        results = data.get("results") or []
        for item in results:
            if not isinstance(item, dict):
                continue
            urls = item.get("urls") or []
            for u in urls:
                text = str(u or "")
                if text.startswith("wss://") and ("/ndt/v7" in text or "ndt" in text):
                    _mlab_cached_url = text
                    _mlab_cache_until = now + 600.0
                    return text
        _mlab_cache_until = now + 60.0
        return None
    except Exception:
        # Любая ошибка (сеть, парсинг, UnboundLocalError) — не должна валить
        # стресс-тест. Fallback на speed.cloudflare.com сработает.
        _mlab_cache_until = now + 60.0
        return None


def _ws_url_to_target(ws_url: str) -> tuple[str, int, str] | None:
    """Разобрать wss://host:port/path на (host, port, path)."""
    try:
        parts = urlparse(ws_url)
        host = parts.hostname or ""
        port = parts.port or 443
        path = parts.path or "/ndt/v7/download"
        if not host:
            return None
        return host, int(port), path
    except Exception:
        return None


def _mlab_ndt7_download_kbps(
    socks_host: str,
    socks_port: int,
    timeout: float = M_LAB_NDT7_TIMEOUT_SEC,
    sample_seconds: float = M_LAB_NDT7_SAMPLE_SEC,
) -> float | None:
    """Прогнать NDT7 download-тест через SOCKS-прокси и вернуть скорость в кбит/с.

    Если locate не вернул URL или канал недоступен — возвращаем None (без фатала).
    """
    ws_url = _mlab_fetch_target(timeout=min(8.0, timeout))
    if not ws_url:
        return None
    target = _ws_url_to_target(ws_url)
    if target is None:
        return None
    host, port, path = target
    raw: socket.socket | None = None
    tls: socket.socket | None = None
    try:
        raw = _socks_open_connection(socks_host, socks_port, host, port, timeout)
        if raw is None:
            return None
        raw.settimeout(timeout)
        context = ssl.create_default_context()
        tls = context.wrap_socket(raw, server_hostname=host)
        raw = None
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: net.measurementlab.ndt.v7\r\n"
            f"\r\n"
        ).encode("ascii")
        tls.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = tls.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 65536:
                break
        if not response.startswith(b"HTTP/1.1 101"):
            return None

        # NDT7: клиент отправляет текстовое сообщение {"msg":"hello"} на download-канал,
        # сервер затем шлёт тестовый поток бинарных кадров.
        hello = b'{"msg":"hello"}'
        tls.sendall(_ws_build_frame(0x1, hello))
        total = 0
        started: float | None = None
        deadline = time.perf_counter() + timeout
        sample_deadline: float | None = None
        while time.perf_counter() < deadline:
            opcode, payload = _ws_read_frame(tls)
            if opcode in (0x8, 0xA):
                break
            if opcode == 0x9:
                try:
                    tls.sendall(_ws_build_frame(0xA, payload))
                except Exception:
                    pass
                continue
            if opcode in (0x1, 0x2):
                if started is None:
                    started = time.perf_counter()
                    sample_deadline = started + max(0.5, float(sample_seconds))
                total += len(payload)
                if sample_deadline is not None and time.perf_counter() >= sample_deadline:
                    break
        if started is None or total <= 0:
            return None
        elapsed = max(0.001, time.perf_counter() - started)
        return (total * 8.0 / 1000.0) / elapsed
    except Exception:
        return None
    finally:
        if tls is not None:
            with contextlib.suppress(Exception):
                tls.close()
        if raw is not None:
            with contextlib.suppress(Exception):
                raw.close()


def _xray_download_speed(
    socks_host: str,
    socks_port: int,
    timeout: float,
    *,
    max_bytes: int = XRAY_PROBE_SPEED_TEST_BYTES,
    sample_seconds: float = XRAY_PROBE_SPEED_TEST_SECONDS,
) -> float | None:
    return _socks_https_download_kbps(
        socks_host,
        socks_port,
        XRAY_SPEED_TEST_HOST,
        443,
        XRAY_SPEED_TEST_HOST,
        XRAY_SPEED_TEST_PATH,
        max_bytes,
        min(max(2.0, timeout), max(2.0, float(sample_seconds) + 4.0)),
        sample_seconds=sample_seconds,
    )


# Скорость загрузки — единый надёжный замер, используемый и в стресс-тесте,
# и в финальном recheck. speed.cloudflare.com не работает через Cloudflare
# Worker-прокси (даёт None/0), поэтому после него идут внешние fallback-хосты.
# Большой объём (16MB) и длинный sample-период (8s) сглаживают ramp-up
# у worker-узлов, замер становится стабильным (проверено: 1.8→7.6 MB/s).
XRAY_SPEED_TEST_BIG_BYTES = 16 * 1024 * 1024
XRAY_SPEED_TEST_BIG_SECONDS = 8.0


def _download_speed_probe(
    socks_host: str,
    socks_port: int,
    timeout: float,
) -> float | None:
    """Надёжный замер скорости загрузки (КБ/с).

    Пробуем по порядку, берём первый успешный результат:
      1) NDT7 (M-Lab) — объективный замер до ближайшего сервера;
      2) speed.cloudflare.com — стандартный короткий замер;
      3) proof.ovh.net /files/100Mb.dat (16MB, 8s) — fallback для worker-узлов;
      4) speedtest.tele2.net /100MB.zip (16MB, 8s) — последний fallback.
    Возвращает None, если ни один источник не сработал.
    """
    big_timeout = max(8.0, float(timeout))
    ndt7 = _mlab_ndt7_download_kbps(socks_host, socks_port, timeout=big_timeout)
    if ndt7 is not None and ndt7 > 0:
        return ndt7
    cf = _xray_download_speed(socks_host, socks_port, timeout=big_timeout)
    if cf is not None and cf > 0:
        return cf
    ovh = _socks_https_download_kbps(
        socks_host,
        socks_port,
        "proof.ovh.net",
        443,
        "proof.ovh.net",
        "/files/100Mb.dat",
        XRAY_SPEED_TEST_BIG_BYTES,
        big_timeout,
        sample_seconds=XRAY_SPEED_TEST_BIG_SECONDS,
    )
    if ovh is not None and ovh > 0:
        return ovh
    tele2 = _socks_https_download_kbps(
        socks_host,
        socks_port,
        "speedtest.tele2.net",
        443,
        "speedtest.tele2.net",
        "/100MB.zip",
        XRAY_SPEED_TEST_BIG_BYTES,
        big_timeout,
        sample_seconds=XRAY_SPEED_TEST_BIG_SECONDS,
    )
    if tele2 is not None and tele2 > 0:
        return tele2
    return None


def _xray_upload_speed(

    socks_host: str,
    socks_port: int,
    timeout: float,
    *,
    max_bytes: int = XRAY_PROBE_SPEED_TEST_BYTES,
    sample_seconds: float = XRAY_PROBE_SPEED_TEST_SECONDS,
) -> float | None:
    """Прогнать upload-тест через speed.cloudflare.com (POST /__up) через SOCKS-прокси."""
    return _socks_https_upload_kbps(
        socks_host,
        socks_port,
        XRAY_SPEED_TEST_HOST,
        443,
        XRAY_SPEED_TEST_HOST,
        XRAY_SPEED_UPLOAD_PATH,
        max_bytes,
        min(max(2.0, timeout), max(2.0, float(sample_seconds) + 4.0)),
        sample_seconds=sample_seconds,
    )


def _socks_https_upload_kbps(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    max_bytes: int,
    timeout: float,
    *,
    sample_seconds: float,
) -> float | None:
    """POST-загрузка через SOCKS+SSL. Шлём max_bytes байт, меряем скорость.

    Cloudflare /__up принимает произвольное тело и отвечает 200. Возвращает КБ/с.
    """
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {max_bytes}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            started = time.perf_counter()
            chunk = b"\x00" * 65536
            sent = 0
            sample_deadline = started + max(0.5, float(sample_seconds))
            while sent < max_bytes and time.perf_counter() < sample_deadline:
                tls_sock.sendall(chunk)
                sent += len(chunk)
            elapsed = max(0.001, time.perf_counter() - started)
            # Ждём ответ (не обязательно), сбрасываем в 0.
            with contextlib.suppress(Exception):
                tls_sock.settimeout(1.0)
                tls_sock.recv(4096)
            return (sent / 1024.0) / elapsed
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def _socks_https_download_kbps(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    path: str,
    max_bytes: int,
    timeout: float,
    *,
    sample_seconds: float,
) -> float | None:
    raw_sock: socket.socket | None = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                f"User-Agent: MTProxyAutoSwitch/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            buffer = b""
            body_bytes = 0
            started: float | None = None
            deadline = time.perf_counter() + timeout
            sample_deadline: float | None = None
            while body_bytes < max_bytes and time.perf_counter() < deadline:
                chunk = tls_sock.recv(min(65536, max_bytes - body_bytes + 4096))
                if not chunk:
                    break
                if started is None:
                    buffer += chunk
                    header_end = buffer.find(b"\r\n\r\n")
                    if header_end < 0:
                        continue
                    headers = buffer[:header_end]
                    if not headers.startswith(b"HTTP/"):
                        return None
                    status = headers.split(b" ", 2)[1:2]
                    if not status or not status[0].startswith(b"2"):
                        return None
                    body = buffer[header_end + 4 :]
                    body_bytes += len(body)
                    started = time.perf_counter()
                    sample_deadline = started + max(0.5, float(sample_seconds))
                    buffer = b""
                else:
                    body_bytes += len(chunk)
                if sample_deadline is not None and time.perf_counter() >= sample_deadline:
                    break
            if started is None or body_bytes <= 0:
                return None
            elapsed = max(0.001, time.perf_counter() - started)
            return (body_bytes / 1024.0) / elapsed
    except Exception:
        return None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def _encode_abridged_packet(data: bytes) -> bytes:
    length = len(data) >> 2
    if length < 127:
        return struct.pack("B", length) + data
    return b"\x7f" + int(length).to_bytes(3, "little") + data


def _read_abridged_packet(sock: socket.socket) -> bytes:
    first = _recv_exact(sock, 1)
    if not first:
        return b""
    length = first[0]
    if length >= 127:
        extra = _recv_exact(sock, 3)
        if len(extra) < 3:
            return b""
        length = int.from_bytes(extra + b"\0", "little")
    return _recv_exact(sock, length << 2)


def _socks_mtproto_latency(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float,
) -> float | None:
    started = time.perf_counter()
    sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
    if sock is None:
        return None
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\xef")
        nonce = secrets.randbits(127)
        nonce_bytes = nonce.to_bytes(16, "little", signed=True)
        body = struct.pack("<I", 0xBE7E8EF1) + nonce_bytes
        message_id = int(time.time() * (2**32)) & ~3
        payload = struct.pack("<q", 0) + struct.pack("<q", message_id) + struct.pack("<i", len(body)) + body
        sock.sendall(_encode_abridged_packet(payload))
        response = _read_abridged_packet(sock)
        if len(response) < 40 or response[:8] != b"\0" * 8:
            return None
        body_len = struct.unpack("<i", response[16:20])[0]
        if body_len <= 0 or 20 + body_len > len(response):
            return None
        response_body = response[20 : 20 + body_len]
        if nonce_bytes not in response_body:
            return None
        return (time.perf_counter() - started) * 1000.0
    except Exception:
        return None
    finally:
        with contextlib.suppress(Exception):
            sock.close()


def _subprocess_no_window() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)
