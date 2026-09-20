"""XrayBatchPool: ОДИН xray-процесс с N SOCKS-inbound'ами и N outbound'ами.

Зачем (запрос юзера 2026-09-20): «сам sing-box может отваливать reality
конфиги? может сделаем тогда xray pool? групповой тест». Sing-box pool
реality поддерживает, но его реализация reality/uTLS — СВОЯ, отличная от
xray-core, которым пользуются конечные клиенты (Happ/v2rayN): узел может
вести себя в sing-box иначе, чем поведёт себя в xray у юзера. Тест через
ТО ЖЕ ядро, что и у юзера, — честнее. Плюс sing-box не умеет
xhttp/splithttp/kcp/quic (те уходили в медленный per-node fallback).

Архитектура (без переключений и гонок):
  - Один xray-процесс на батч из N узлов (по умолчанию 200).
  - Конфиг: N SOCKS-inbound'ов (socks-in-1..N, каждый на СВОЁМ порту),
    N outbound'ов (proxy-1..N, собирается ТЕМ ЖЕ _xray_outbound, что и в
    одиночном with_node_process — 100% идентичная настройка узла),
    routing-правило на каждый: inboundTag socks-in-K -> outboundTag proxy-K.
  - Проверка узла: probe через его ЛИЧНЫЙ порт. Никакого selector'а
    и задержек на переключение (в отличие от sing-box pool) — пробы разных
    узлов можно гонять параллельно, не мешая друг другу.
  - Локальные IP (127/8, RFC1918) — в blackhole, как в одиночном конфиге.

Совместимость узлов: vless/vmess/trojan/shadowsocks (всё, что умеет
_xray_outbound). hysteria/hysteria2/hy2 (runtime sing-box) и узлы с
битыми параметрами — unsupported: их пайплайн проверяет через прежний
путь (with_node_process / sing-box pool), т.е. НИЧЕГО не теряется.

Интерфейс — дроп-ин замена SingBoxBatchPool:
  start() / stop() / select(node) / endpoint / supported_count /
  unsupported_keys / is_started().
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from .procs import (
    _assign_process_to_job,
    _close_windows_handle,
    _create_kill_on_close_job,
    _find_free_port,
    _resolve_binary,
    _subprocess_no_window,
    _terminate_process_tree,
)

_logger = logging.getLogger(__name__)


# Размер батча по умолчанию — как у sing-box pool (200): один xray с 200
# inbound'ами стартует за ~1с, конфиг ~600KB. N порт ограничений не имеет
# (ephemeral-диапазон 16-28к портов хватает с запасом на любой батч).
DEFAULT_BATCH_SIZE = 200

# Сколько ждать готовности ПЕРВОГО SOCKS-порта после старта xray (сек).
# Остальные порты поднимаются тем же листенером почти мгновенно; для
# надёжности _wait_socks_port вызывается и на пробах (lazy-проверка).
STARTUP_TIMEOUT_SEC = 6.0

# Таймаут `xray run -test` (валидация конфига до старта, сек).
CONFIG_TEST_TIMEOUT_SEC = 8.0


def _tag_index(tag: str) -> int:
    """Номер узла из тега proxy-N (для сортировки выбрасывания)."""
    m = re.search(r"(\d+)", tag or "")
    return int(m.group(1)) if m else 0


class XrayBatchPool:
    """Один xray-процесс: N SOCKS-портов, по одному на каждый узел батча.

    Использование (совместимо с SingBoxBatchPool)::

        pool = XrayBatchPool(nodes, root_dir=Path(...))
        pool.start()
        try:
            for node in nodes:
                if pool.select(node):
                    host, port = pool.endpoint
                    latency = probe_via_socks(host, port)
        finally:
            pool.stop()

    Несовместимые узлы (hysteria2 и др.) автоматически пропускаются —
    `select()` вернёт False, их надо проверять через старый путь.
    """

    def __init__(
        self,
        nodes: list[Any],
        *,
        root_dir: Path,
        xray_binary_path: str = "",
        listen_host: str = "127.0.0.1",
        base_port: int | None = None,
        batch_id: int = 0,
        log_sink: Callable[[str], None] | None = None,
    ) -> None:
        self.nodes = list(nodes)
        self.root_dir = Path(root_dir)
        self.listen_host = listen_host
        self.base_port = int(base_port) if base_port else _find_free_port()
        self.batch_id = int(batch_id)
        self._log = log_sink or (lambda msg: None)
        self._xray_binary_path = xray_binary_path
        # Бинарник резолвится лениво в start(): конструктор нужен и для
        # инспекции конфига (тесты) — без установленного ядра.
        self.binary = ""

        self._config: dict[str, Any] | None = None
        # node.key -> порт SOCKS-inbound'а этого узла; tag -> node.key.
        self._node_key_to_port: dict[tuple, int] = {}
        self._tag_to_node_key: dict[str, tuple] = {}
        self._unsupported_keys: set[tuple] = set()
        self._build_config()

        self._proc: subprocess.Popen | None = None
        self._config_path: str = ""
        self._stderr_path: str = ""
        self._job_handle: int | None = None
        self._endpoint: tuple[str, int] = (listen_host, self.base_port)

    # ------------------------------------------------------------ конфиг

    def _build_config(self) -> None:
        """Собрать конфиг xray: N inbound + N outbound + routing-правила.

        Outbound каждого узла строится ТЕМ ЖЕ _xray_outbound(), что и в
        одиночном тесте (with_node_process) — mux, reality, uTLS,
        fingerprint-матрица — всё идентично. Отличие только в тегах.
        """
        # Импорт здесь — чтобы избежать циклических импортов.
        from runtime.configs import _xray_outbound

        inbounds: list[dict[str, Any]] = []
        outbounds: list[dict[str, Any]] = []
        rules: list[dict[str, Any]] = [
            # Локальный трафик — в blackhole (как в одиночном конфиге):
            # проба локального IP не должна уходить в туннель.
            {
                "type": "field",
                "outboundTag": "block",
                "ip": [
                    "127.0.0.0/8", "::1/128",
                    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                ],
            }
        ]

        port = self.base_port
        for index, node in enumerate(self.nodes, 1):
            try:
                outbound = _xray_outbound(node)
            except Exception as exc:
                # Неподдерживаемый протокол/битые параметры — узел уйдёт
                # через прежний путь (with_node_process / sing-box).
                _logger.debug(
                    "xray-pool: узел %s не собран в outbound: %s",
                    getattr(node, "title", lambda: "?")(), exc,
                )
                self._unsupported_keys.add(node.key)
                continue
            # Гонять через пул sing-box-узлы (hysteria/hy2) нельзя — xray их
            # не умеет; их тестирует прежний путь со своим бинарником.
            if str(getattr(node, "runtime", "xray") or "xray") == "sing-box":
                self._unsupported_keys.add(node.key)
                continue

            tag_in = f"socks-in-{index}"
            tag_out = f"proxy-{index}"
            outbound["tag"] = tag_out

            inbounds.append({
                "listen": self.listen_host,
                "port": port,
                "protocol": "socks",
                "tag": tag_in,
                "settings": {"udp": True, "auth": "noauth"},
                # Тот же sniffing, что в одиночном конфиге: корректный SNI
                # без fakedns/routeOnly (валидно на xray v26).
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": False,
                },
            })
            outbounds.append(outbound)
            # Правило: трафик ЭТОГО inbound'а — в outbound ЭТОГО узла.
            rules.append({
                "type": "field",
                "inboundTag": [tag_in],
                "outboundTag": tag_out,
            })
            self._node_key_to_port[node.key] = port
            self._tag_to_node_key[tag_out] = node.key
            port += 1

        if not outbounds:
            self._config = None
            return

        outbounds.append({
            "protocol": "blackhole",
            "tag": "block",
            "settings": {"response": {"type": "none"}},
        })

        self._config = {
            "log": {"loglevel": "warning", "access": "", "error": ""},
            # DNS — как в одиночном конфиге: системный + обычный UDP DNS
            # (DoH может блокироваться — требование пользователя).
            "dns": {
                "servers": ["localhost", "1.1.1.1", "8.8.8.8"],
                "queryStrategy": "UseIPv4",
                "disableFallback": False,
            },
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": rules,
            },
        }

    @property
    def supported_count(self) -> int:
        """Сколько узлов из батча попали в конфиг xray."""
        return len(self._node_key_to_port)

    @property
    def unsupported_keys(self) -> set[tuple]:
        """Ключи узлов, которые xray не поддерживает — проверить через fallback."""
        return set(self._unsupported_keys)

    def is_started(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _proxy_outbound_count(self) -> int:
        """Сколько прокси-outbound'ов (не blackhole) осталось в конфиге."""
        if self._config is None:
            return 0
        return sum(
            1
            for ob in (self._config.get("outbounds") or [])
            if isinstance(ob, dict) and str(ob.get("tag") or "").startswith("proxy-")
        )

    def _drop_outbound_by_tag(self, tag: str) -> bool:
        """Исключить битый outbound (и его inbound + routing-правило).

        xray в stderr называет тег упавшего outbound («failed to build
        outbound config with tag proxy-7») — выбрасываем только ЭТОТ узел
        (его key уходит в unsupported — пайплайн проверит его через
        per-node fallback), а не весь батч из 200 узлов. Возвращает True,
        если узел реально был в конфиге.
        """
        if self._config is None or not tag:
            return False
        node_key = self._tag_to_node_key.pop(tag, None)
        if node_key is None:
            return False
        port = self._node_key_to_port.pop(node_key, None)
        self._unsupported_keys.add(node_key)
        # outbound
        self._config["outbounds"] = [
            ob for ob in (self._config.get("outbounds") or [])
            if not (isinstance(ob, dict) and ob.get("tag") == tag)
        ]
        # inbound этого узла — ищем по сохранённому порту.
        if port is not None:
            self._config["inbounds"] = [
                ib for ib in (self._config.get("inbounds") or [])
                if not (isinstance(ib, dict) and ib.get("port") == port)
            ]
        # routing-правило этого узла (inboundTag → outboundTag).
        routing = self._config.setdefault("routing", {})
        routing["rules"] = [
            r for r in (routing.get("rules") or [])
            if not (isinstance(r, dict) and r.get("outboundTag") == tag)
        ]
        return True

    # ------------------------------------------------------------ lifecycle

    def start(self) -> bool:
        """Запустить xray-процесс. Возвращает True при успехе."""
        if self._config is None:
            self._log(f"[xray-pool#{self.batch_id}] конфиг пуст (нет поддерживаемых узлов)")
            return False
        if self.is_started():
            return True

        self.binary = _resolve_binary(self._xray_binary_path, self.root_dir, "xray")
        if not self.binary:
            self._log(f"[xray-pool#{self.batch_id}] xray binary not found")
            return False

        # Пишем конфиг во временный файл.
        fd, path = tempfile.mkstemp(prefix=f"xray-batch-{self.batch_id}-", suffix=".json", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._config, f, ensure_ascii=False, separators=(",", ":"))
            self._config_path = path
        except Exception as exc:
            with contextlib.suppress(Exception):
                Path(path).unlink(missing_ok=True)
            self._config_path = ""
            self._log(f"[xray-pool#{self.batch_id}] не удалось записать конфиг: {exc}")
            return False

        # Валидация ДО старта: `xray run -test` парсит конфиг без запуска.
        # Битый outbound (например, reality pbk, который не декодируется)
        # валит ВЕСЬ конфиг — но xray называет в stderr ТЕГ битого outbound
        # («failed to build outbound config with tag proxy-7»): выбрасываем
        # этот узел (уйдёт через per-node fallback), переписываем конфиг и
        # проверяем снова — до 8 битых узлов на батч (как в sing-box pool).
        for _check_attempt in range(9):
            try:
                check = subprocess.run(
                    [self.binary, "run", "-test", "-c", self._config_path],
                    capture_output=True, text=True, timeout=CONFIG_TEST_TIMEOUT_SEC,
                )
            except Exception as exc:
                # -test не выполнился — пробуем стартовать как есть: run сам
                # выдаст вердикт (может, это старый xray без флага -test).
                self._log(f"[xray-pool#{self.batch_id}] xray -test не удался: {exc}")
                break
            if check.returncode == 0:
                break
            stderr = (check.stderr or check.stdout or "").strip()
            tail = "\n".join(stderr.splitlines()[-3:]) or "unknown"
            bad_tags = set(re.findall(r"outbound config with tag (proxy-\d+)", stderr))
            dropped = False
            for tag in sorted(bad_tags, key=_tag_index):
                if self._drop_outbound_by_tag(tag):
                    dropped = True
                    self._log(
                        f"[xray-pool#{self.batch_id}] битый outbound {tag} исключён "
                        "(узел уйдёт через per-node fallback) — повторная проверка"
                    )
            if not dropped or not self._proxy_outbound_count():
                self._log(
                    f"[xray-pool#{self.batch_id}] конфиг не прошёл валидацию "
                    f"(весь батч — через fallback): {tail}"
                )
                self._dump_config_for_debug()
                self.stop()
                return False
            try:
                with open(self._config_path, "w", encoding="utf-8") as f:
                    json.dump(self._config, f, ensure_ascii=False, separators=(",", ":"))
            except Exception as exc:
                self._log(f"[xray-pool#{self.batch_id}] не удалось переписать конфиг: {exc}")
                self.stop()
                return False
        else:
            self._log(
                f"[xray-pool#{self.batch_id}] конфиг всё ещё невалиден после "
                "исключения 8 битых outbound'ов — fallback"
            )
            self._dump_config_for_debug()
            self.stop()
            return False

        # Job Object — kill-on-close, чтобы при падении Python процесс не осел.
        self._job_handle = _create_kill_on_close_job()

        # stderr — в ФАЙЛ, не в PIPE (как в sing-box pool): xray пишет
        # warnings на каждую неудачную пробу, PIPE-буфер ОС переполняется и
        # ядро виснет на write.
        stderr_fd: int | None = None
        try:
            stderr_fd, self._stderr_path = tempfile.mkstemp(
                prefix=f"xray-batch-{self.batch_id}-", suffix=".stderr.log", text=True
            )
        except Exception as exc:
            _logger.debug("stderr-файл xray-пула #%s не создан: %s", self.batch_id, exc)
            self._stderr_path = ""

        try:
            self._proc = subprocess.Popen(
                [self.binary, "run", "-c", self._config_path],
                stdout=subprocess.DEVNULL,
                stderr=stderr_fd if stderr_fd is not None else subprocess.DEVNULL,
                creationflags=_subprocess_no_window(),
            )
        except Exception as exc:
            self._log(f"[xray-pool#{self.batch_id}] не удалось запустить xray: {exc}")
            if stderr_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(stderr_fd)
            self.stop()
            return False
        # Popen дублирует дескриптор в дочерний процесс — свою копию закрываем.
        if stderr_fd is not None:
            with contextlib.suppress(OSError):
                os.close(stderr_fd)

        if self._job_handle is not None:
            with contextlib.suppress(Exception):
                _assign_process_to_job(self._job_handle, self._proc)

        # Ждём готовности первого ОСТАВШЕГОСЯ порта (после выбрасывания
        # битых outbound'ов их inbound'ы удалены — базовый порт мог уйти;
        # берём минимальный порт живых узлов).
        from .probing import _wait_socks_port

        live_ports = [p for p in self._node_key_to_port.values()]
        probe_port = min(live_ports) if live_ports else self.base_port
        if not _wait_socks_port(self._proc, probe_port, STARTUP_TIMEOUT_SEC):
            if self._proc.poll() is not None:
                self._log(
                    f"[xray-pool#{self.batch_id}] xray упал при старте: "
                    f"{self._stderr_tail()}"
                )
            else:
                self._log(
                    f"[xray-pool#{self.batch_id}] SOCKS-порты не поднялись за "
                    f"{STARTUP_TIMEOUT_SEC}с"
                )
            self._dump_config_for_debug()
            self.stop()
            return False
        return True

    def stop(self) -> None:
        """Остановить xray-процесс и освободить все ресурсы."""
        if self._proc is not None:
            with contextlib.suppress(Exception):
                _terminate_process_tree(self._proc, timeout=2.0)
            self._proc = None
        if self._config_path:
            with contextlib.suppress(Exception):
                Path(self._config_path).unlink(missing_ok=True)
            self._config_path = ""
        if self._job_handle is not None:
            _close_windows_handle(self._job_handle)
            self._job_handle = None
        if self._stderr_path:
            with contextlib.suppress(Exception):
                Path(self._stderr_path).unlink(missing_ok=True)
            self._stderr_path = ""

    def _stderr_tail(self) -> str:
        """Хвост stderr-лога xray (последние строки) — для диагностики."""
        try:
            if not self._stderr_path:
                return "stderr пуст"
            with open(self._stderr_path, "rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - 16384))
                text = fh.read().decode("utf-8", errors="replace").strip()
            return "\n".join(text.splitlines()[-5:]) or "stderr пуст"
        except Exception:
            return "stderr не прочитан"

    def _dump_config_for_debug(self) -> None:
        """Сохранить копию конфига в data/.runtime_cache для разбора полётов."""
        try:
            dump_dir = self.root_dir / "data" / ".runtime_cache"
            dump_dir.mkdir(parents=True, exist_ok=True)
            dump = dump_dir / f"xray-pool-{self.batch_id}-failed.json"
            dump.write_text(
                json.dumps(self._config, ensure_ascii=False, indent=1),
                encoding="utf-8",
            )
        except Exception as exc:
            _logger.debug("dump конфига xray-пула #%s не записан: %s", self.batch_id, exc)

    # ------------------------------------------------------------ пробы

    def select(self, node: Any) -> bool:
        """Выбрать узел: его endpoint станет текущим. True при успехе.

        В отличие от sing-box pool здесь НЕТ переключения selector'а —
        каждый узел слушает на своём порту, «переключение» мгновенно и
        не требует задержек/блокировок.
        """
        port = self._node_key_to_port.get(node.key)
        if port is None:
            return False  # unsupported — проверять через fallback
        self._endpoint = (self.listen_host, port)
        return True

    @property
    def endpoint(self) -> tuple[str, int]:
        """SOCKS5 endpoint выбранного узла (host, port)."""
        return self._endpoint

    def __enter__(self) -> "XrayBatchPool":
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()
