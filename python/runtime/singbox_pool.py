"""SingBoxBatchPool: один sing-box процесс с N outbounds + Clash API.

Замена «старт-стоп xray.exe/sing-box.exe на каждый узел» для массовых этапов
(ping, initial_check). Вместо 14000 × 1.5с старта ядра = 5.8 часов оверхеда,
один sing-box с selector-outbound переключается за ~50мс через Clash API.

Архитектура:
  - Один sing-box процесс на батч из N узлов (по умолчанию 200).
  - Конфиг: SOCKS inbound + N outbound'ов (proxy-1..N) + selector "active"
    + direct + block. route.final = "active".
  - experimental.clash_api.external_controller = "127.0.0.1:<port>".
  - Для проверки узла: PUT /proxies/active {"name": "proxy-K"} → ждём 50мс →
    запрос через SOCKS. Переключение selector'а в sing-box мгновенное
    (это in-memory, без рестарта outbounds).

Применяется ТОЛЬКО для этапов ping и initial_check. Чекеры (telegram_pro,
services, dpi и т.д.) остаются на run_with_node — там узлов уже мало
(100-500 после initial_check), и каждый чекер использует свой набор целей.

Ограничения:
  -sing-box не поддерживает xhttp/splithttp/kcp/quic (см. singbox_convert.py).
    Такие узлы пропускаются через старый путь (with_node_process).
  - Clash API в sing-box включается через experimental.clash_api (есть с 1.0).
  - Размер батча: 200 узлов. Больше — sing-box долго стартует (парсит конфиг).
    Меньше — больше оверхеда на старт-стоп батчей.
"""
from __future__ import annotations

import contextlib
import json
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from .procs import (
    _assign_process_to_job,
    _create_kill_on_close_job,
    _find_free_port,
    _resolve_binary,
    _subprocess_no_window,
    _terminate_process_tree,
)


# Размер батча по умолчанию. На 200 узлов sing-box стартует за 1.5-2 сек,
# конфиг ~500KB. Больше — медленнее старт, но меньше оверхеда.
# Меньше — чаще рестарты. 200 — эмпирический оптимум на Intel i5-12400.
DEFAULT_BATCH_SIZE = 200

# Сколько ждать после старта sing-box до первой пробы (мс). SOCKS+Clash API
# поднимаются за 200-500мс, даём запас.
STARTUP_DELAY_SEC = 1.0

# Сколько ждать после переключения selector перед пробой (мс). В sing-box
# selector switch — in-memory, мгновенно, но даём 50мс на применение.
SELECTOR_SWITCH_DELAY_SEC = 0.05

# Таймаут Clash API HTTP-запроса (сек).
CLASH_API_TIMEOUT = 3.0


class SingBoxBatchPool:
    """Один sing-box процесс с N outbounds + Clash API для переключения.

    Использование::

        pool = SingBoxBatchPool(nodes, root_dir=Path(...))
        pool.start()
        try:
            for node in nodes:
                if pool.select(node):
                    latency = probe_via_socks(pool.socks_host, pool.socks_port)
                    ...
        finally:
            pool.stop()

    Несовместимые узлы (xhttp/splithttp/kcp/quic, или неподдерживаемые
    протоколы) автоматически пропускаются — `select()` вернёт False для них,
    их надо тестировать через старый путь (with_node_process).
    """

    def __init__(
        self,
        nodes: list[Any],
        *,
        root_dir: Path,
        sing_box_binary_path: str = "",
        listen_host: str = "127.0.0.1",
        socks_port: int | None = None,
        clash_api_port: int | None = None,
        batch_id: int = 0,
        log_sink: Callable[[str], None] | None = None,
    ) -> None:
        self.nodes = list(nodes)
        self.root_dir = Path(root_dir)
        self.listen_host = listen_host
        self.socks_port = int(socks_port) if socks_port else _find_free_port()
        self.clash_api_port = int(clash_api_port) if clash_api_port else _find_free_port()
        self.batch_id = int(batch_id)
        self._log = log_sink or (lambda msg: None)

        # Резолвим бинарник sing-box.
        self.binary = _resolve_binary(sing_box_binary_path, self.root_dir, "sing-box")
        if not self.binary:
            raise RuntimeError("sing-box binary not found")

        # Строим конфиг: N outbounds + selector + direct + block.
        # selector "active" — переключаемый Python'ом через Clash API.
        self._config: dict[str, Any] | None = None
        self._tag_to_node_key: dict[str, tuple] = {}      # tag -> node.key
        self._node_key_to_tag: dict[tuple, str] = {}       # node.key -> tag
        self._unsupported_keys: set[tuple] = set()          # node.key, несовместимые с sing-box
        self._build_config()

        # Процесс и Job Object.
        self._proc: subprocess.Popen | None = None
        self._config_path: str = ""
        self._job_handle: int | None = None
        self._started_at: float = 0.0
        self._lock = threading.Lock()  # serializes select() across threads

    def _build_config(self) -> None:
        """Построить конфиг sing-box с N outbounds + selector + Clash API."""
        # Импорт здесь — чтобы избежать циклического импорта.
        from singbox_convert import sing_box_outbound

        outbounds: list[dict[str, Any]] = []
        tags: list[str] = []
        for index, node in enumerate(self.nodes, 1):
            tag = f"proxy-{index}"
            outbound, reason = sing_box_outbound(node, tag=tag)
            if outbound is None:
                self._unsupported_keys.add(node.key)
                continue
            # v11: дополнительная валидация reality — sing-box падает ВСЕГО
            # батча если хоть один outbound имеет reality без public_key.
            # sing_box_outbound уже возвращает (None, reason) для таких, но
            # проверим ещё раз на всякий случай (защита от регрессий).
            tls = outbound.get("tls", {}) or {}
            reality = tls.get("reality", {}) or {}
            if reality and not reality.get("public_key"):
                self._unsupported_keys.add(node.key)
                continue
            outbounds.append(outbound)
            tags.append(tag)
            self._tag_to_node_key[tag] = node.key
            self._node_key_to_tag[node.key] = tag

        if not outbounds:
            self._config = None
            return

        # selector "active" — переключаемый Python'ом. default — первый outbound.
        selector = {
            "type": "selector",
            "tag": "active",
            "outbounds": tags,
            "default": tags[0],
        }

        self._config = {
            "log": {"level": "warn", "disabled": False},
            # v11: DNS sing-box 1.13+ — НОВЫЙ формат серверов (старый address/detour
            # в 1.13 запрещён — «ENABLE_DEPRECATED_LEGACY_DNS_SERVERS»).
            # Используем тот же формат что singbox_convert._dns_block:
            #   1) udp 8.8.8.8 — bootstrap, резолв адреса самого узла (через direct)
            #   2) https 1.1.1.1 через active — резолв целей на стороне туннеля
            # Это работает на всех сетях (мобильных с белыми списками тоже):
            # UDP DNS не режется ТСПУ, DoH через прокси идёт через туннель.
            "dns": {
                "servers": [
                    {"type": "udp", "tag": "dns-bootstrap", "server": "8.8.8.8"},
                    {"type": "https", "tag": "dns-proxy", "server": "1.1.1.1", "detour": "active"},
                ],
                "final": "dns-proxy",
                "strategy": "ipv4_only",
            },
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": self.listen_host,
                    "listen_port": self.socks_port,
                    "udp_timeout": "300s",
                }
            ],
            "outbounds": outbounds + [
                selector,
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
            ],
            "route": {
                "final": "active",
                "auto_detect_interface": True,
                "default_domain_resolver": "dns-bootstrap",
                "rules": [{"ip_is_private": True, "outbound": "block"}],
            },
            "experimental": {
                "clash_api": {
                    "external_controller": f"{self.listen_host}:{self.clash_api_port}",
                },
                "cache_file": {"enabled": False},
            },
        }

    @property
    def supported_count(self) -> int:
        """Сколько узлов из батча поддерживаются sing-box (попали в конфиг)."""
        return len(self._node_key_to_tag)

    @property
    def unsupported_keys(self) -> set[tuple]:
        """Ключи узлов, которые sing-box не поддерживает — проверять через xray."""
        return set(self._unsupported_keys)

    def is_started(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> bool:
        """Запустить sing-box процесс. Возвращает True при успехе."""
        if self._config is None:
            self._log(f"[sb-pool#{self.batch_id}] конфиг пуст (нет поддерживаемых узлов)")
            return False
        if self.is_started():
            return True

        # Пишем конфиг во временный файл.
        fd, path = tempfile.mkstemp(prefix=f"sb-batch-{self.batch_id}-", suffix=".json", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._config, f, ensure_ascii=False, separators=(",", ":"))
            self._config_path = path
        except Exception as exc:
            with contextlib.suppress(Exception):
                Path(path).unlink(missing_ok=True)
            self._config_path = ""
            self._log(f"[sb-pool#{self.batch_id}] не удалось записать конфиг: {exc}")
            return False

        # v11: валидация конфига ДО запуска через `sing-box check -c <path>`.
        # Если конфиг невалиден — sing-box run всё равно упадёт через 1с, но
        # мы потеряем время. check мгновенно возвращает ошибку с указанием строки.
        try:
            check = subprocess.run(
                [self.binary, "check", "-c", self._config_path],
                capture_output=True, text=True, timeout=5.0,
            )
            if check.returncode != 0:
                stderr = (check.stderr or "").strip()
                tail = "\n".join(stderr.splitlines()[-3:]) if stderr else "unknown"
                self._log(f"[sb-pool#{self.batch_id}] конфиг невалиден: {tail}")
                # v11: dump конфига в data/.runtime_cache для диагностики.
                self._dump_config_for_debug()
                self.stop()
                return False
        except Exception as exc:
            self._log(f"[sb-pool#{self.batch_id}] sing-box check не удался: {exc}")

        # Job Object — kill-on-close, чтобы при падении Python процесс не осел.
        self._job_handle = _create_kill_on_close_job()

        try:
            # v11: stderr=PIPE чтобы при падении sing-box прочитать причину.
            self._proc = subprocess.Popen(
                [self.binary, "run", "-c", self._config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                creationflags=_subprocess_no_window(),
            )
        except Exception as exc:
            self._log(f"[sb-pool#{self.batch_id}] не удалось запустить sing-box: {exc}")
            return False

        if self._job_handle is not None:
            with contextlib.suppress(Exception):
                _assign_process_to_job(self._job_handle, self._proc)

        self._started_at = time.monotonic()
        time.sleep(STARTUP_DELAY_SEC)

        if self._proc.poll() is not None:
            # sing-box упал — читаем stderr для диагностики.
            stderr_tail = ""
            try:
                stderr_bytes, _ = self._proc.communicate(timeout=2.0)
                stderr_text = (stderr_bytes or b"").decode("utf-8", errors="replace").strip()
                if stderr_text:
                    stderr_tail = "\n".join(stderr_text.splitlines()[-5:])
            except Exception:
                pass
            if stderr_tail:
                self._log(f"[sb-pool#{self.batch_id}] sing-box упал при старте: {stderr_tail}")
            else:
                self._log(f"[sb-pool#{self.batch_id}] sing-box упал при старте (stderr пуст)")
            # v11: dump конфига в data/.runtime_cache для диагностики.
            self._dump_config_for_debug()
            self.stop()
            return False

        # Проверяем, что Clash API отвечает.
        if not self._wait_clash_api(timeout=3.0):
            self._log(f"[sb-pool#{self.batch_id}] Clash API не отвечает")
            self._dump_config_for_debug()
            self.stop()
            return False

        return True

    def _dump_config_for_debug(self) -> None:
        """Сохранить конфиг в data/.runtime_cache/sb-pool-<id>-failed.json.

        Это позволяет пользователю прислать конфиг, на котором sing-box падает,
        чтобы мы могли воспроизвести проблему локально через `sing-box check`.
        """
        try:
            from subgen.config import DATA_DIR
            debug_dir = DATA_DIR / ".runtime_cache"
            debug_dir.mkdir(parents=True, exist_ok=True)
            debug_path = debug_dir / f"sb-pool-{self.batch_id}-failed.json"
            if self._config is not None:
                debug_path.write_text(
                    json.dumps(self._config, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                self._log(f"[sb-pool#{self.batch_id}] конфиг сохранён для диагностики: {debug_path}")
        except Exception:
            pass

    def _wait_clash_api(self, *, timeout: float = 3.0) -> bool:
        """Подождать, пока Clash API начнёт отвечать."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://{self.listen_host}:{self.clash_api_port}/version",
                    timeout=0.5,
                ) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                pass
            time.sleep(0.1)
        return False

    def stop(self) -> None:
        """Остановить sing-box процесс."""
        if self._proc is not None:
            with contextlib.suppress(Exception):
                _terminate_process_tree(self._proc, timeout=2.0)
            self._proc = None
        if self._config_path:
            with contextlib.suppress(Exception):
                Path(self._config_path).unlink(missing_ok=True)
            self._config_path = ""

    def select(self, node: Any) -> bool:
        """Переключить selector на outbound узла. Возвращает True при успехе.

        False означает: узел несовместим с sing-box (проверять через xray),
        или sing-box не запущен, или Clash API не ответил.
        """
        if not self.is_started():
            return False
        tag = self._node_key_to_tag.get(node.key)
        if tag is None:
            return False  # unsupported, проверять через xray
        return self._select_tag(tag)

    def _select_tag(self, tag: str) -> bool:
        """Переключить selector "active" на tag через Clash API."""
        with self._lock:  # serialize — selector один, потоков может быть много
            url = f"http://{self.listen_host}:{self.clash_api_port}/proxies/active"
            body = json.dumps({"name": tag}).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=body,
                method="PUT",
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=CLASH_API_TIMEOUT) as resp:
                    if resp.status != 204 and resp.status != 200:
                        return False
            except urllib.error.HTTPError as exc:
                # 204 No Content — норма. Другие — ошибка.
                if exc.code not in (204, 200):
                    return False
            except Exception:
                return False
            # Даём sing-box 50мс на применение selector'а.
            time.sleep(SELECTOR_SWITCH_DELAY_SEC)
            return True

    @property
    def endpoint(self) -> tuple[str, int]:
        """SOCKS5 endpoint для проб (host, port)."""
        return (self.listen_host, self.socks_port)

    def __enter__(self) -> "SingBoxBatchPool":
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()


# Импорт os нужен для fdopen/mkstemp — размещаем внизу, чтобы не загромождать.
import os  # noqa: E402


def iter_batches(
    nodes: list[Any],
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> list[tuple[int, list[Any]]]:
    """Разбить список узлов на батчи. Возвращает [(batch_id, [nodes]), ...]."""
    if batch_size <= 0:
        batch_size = DEFAULT_BATCH_SIZE
    return [
        (i, nodes[i : i + batch_size])
        for i in range(0, len(nodes), batch_size)
    ]


def probe_node_via_pool(
    pool: SingBoxBatchPool,
    node: Any,
    probe_fn: Callable[[str, int], Any],
) -> Any:
    """Переключить pool на узел, выполнить probe_fn(socks_host, socks_port).

    Если узел несовместим с sing-box или pool не запущен — возвращает None,
    вызывать должен проверить и протестировать узел через старый путь.
    """
    if not pool.select(node):
        return None
    host, port = pool.endpoint
    try:
        return probe_fn(host, port)
    except Exception:
        return None
