"""Пробы узлов через временное ядро (перенесено из runtime/core.py).

ProbingMixin входит в XrayCoreRuntime и содержит:
  _probe_node      — полная проверка (Telegram API/DC + ChatGPT/Instagram + спид);
  _probe_node_ping — быстрый пинг (Фаза 1): перебор HTTPS-целей, Telegram
                     не блокирующий (узел остаётся с пометкой telegram_blocked);
  probe_active_*   — латентность/скорость уже запущенного активного узла.
"""
from __future__ import annotations

import contextlib
import logging
import socket
import subprocess
import time
from pathlib import Path

from .configs import _write_temp_config
from .netsocks import _socks_https_head_status, _socks_https_latency
from .probes_speed import _download_speed_probe, _xray_download_speed, _xray_upload_speed
from .probes_telegram import _socks_mtproto_latency
from .procs import _find_free_port, _subprocess_no_window, _terminate_process_tree
from .types import (
    CHATGPT_PROBE_TARGETS,
    INSTAGRAM_PROBE_TARGETS,
    PING_HTTPS_TARGETS,
    TELEGRAM_API_HEAD_TARGET,
    TELEGRAM_DCS,
    TELEGRAM_PROBE_TARGETS,
    TELEGRAM_XRAY_PROBE_TOTAL,
    XRAY_ACTIVE_SPEED_TEST_BYTES,
    XRAY_ACTIVE_SPEED_TEST_SECONDS,
    XRAY_MIN_MEDIA_KBPS,
    XrayNode,
    XrayProbeResult,
)

__all__ = ["ProbingMixin", "_wait_socks_port", "_SOCKS_PORT_WAIT_SEC"]

# stdlib-логгер: мост в stdout + data/run.log ставит subgen.logging.
_logger = logging.getLogger(__name__)

# v15: сколько ждать готовности SOCKS-порта ядра после старта процесса
# (было: слепой time.sleep(0.2) — на Windows с 128 параллельными ядрами
# и AV-сканом спавнов порт запаздывал на секунды; пробы ловили
# «connection refused» и живые узлы ложно отбраковывались).
_SOCKS_PORT_WAIT_SEC = 2.5


def _wait_socks_port(
    proc: subprocess.Popen,
    port: int,
    timeout: float = _SOCKS_PORT_WAIT_SEC,
) -> bool:
    """Дождаться, пока ядро начнёт слушать SOCKS-порт.

    Мелкие connect-пробы каждые ~50мс до потолка ``timeout``. Возвращает
    True, если порт принял соединение (сразу закрываем — это только
    проверка listen, не SOCKS-хендшейк). False — порт так и не поднялся
    (ядро живо, но слушает слишком долго — причина будет в core_not_listening).
    Процессы, упавшие при старте, отслеживает вызывающий код (proc.poll()).
    """
    deadline = time.monotonic() + max(0.2, float(timeout))
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        probe_sock: socket.socket | None = None
        try:
            probe_sock = socket.create_connection(("127.0.0.1", int(port)), timeout=0.25)
            return True
        except OSError:
            pass
        finally:
            if probe_sock is not None:
                with contextlib.suppress(Exception):
                    probe_sock.close()
        time.sleep(0.05)
    return False


class ProbingMixin:
    """Проверки узлов через локальный SOCKS5 временного core-процесса."""

    # Атрибуты экземпляра (config/_lock/_process/...) создаются в
    # XrayCoreRuntime.__init__ (runtime/core.py) — примесь не имеет __init__.

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
            # v15 (инцидент 2026-09-19, лог юзера: 50/50 живых узлов BlancVPN
            # помечены quick_ping_failed за 7 секунд пачкой): слепой sleep(0.2)
            # не гарантирует, что SOCKS-порт уже слушает. На Windows при 128
            # параллельных xray.exe (AV-скан каждого спавна, 35МБ PE) старт
            # ядра легко занимает 1-3с — проба ловит «connection refused»,
            # мгновенно проваливает все 6 целей и узел ложно отбраковывается.
            # Теперь ЖДЁМ готовности порта (мелкие connect-пробы, потолок 2.5с).
            _socks_ready = _wait_socks_port(proc, port, _SOCKS_PORT_WAIT_SEC)
            if proc.poll() is not None:
                # Ядро упало при старте — читаем stderr и логируем.
                stderr_tail = ""
                try:
                    stderr_bytes, _ = proc.communicate(timeout=2.0)
                    stderr_text = (stderr_bytes or b"").decode("utf-8", errors="replace").strip()
                    if stderr_text:
                        stderr_tail = "\n".join(stderr_text.splitlines()[-3:])
                except Exception as exc:
                    # Диагностика причины падения ядра не критична для вердикта.
                    _logger.debug("stderr ядра %s:%s не прочитан: %s", node.host, node.port, exc)
                if stderr_tail:
                    self._log(f"[xray] {node.protocol} {node.host}:{node.port} core exited — {stderr_tail}")
                return XrayProbeResult(node, False, "core exited", None, 0, len(PING_HTTPS_TARGETS), node.runtime)
            if not _socks_ready:
                return XrayProbeResult(node, False, "core_not_listening", None, 0, len(PING_HTTPS_TARGETS), node.runtime)

            # Перебор HTTPS-целей: берём первую успешную, остальные не ждём.
            # v15: таймаут 2.5с (было 2.0): на канале с RTT ~300мс (Сквозная
            # латентность initial p50 ~800мс у юзера) хендшейк reality/vless
            # + TLS до цели = 4-6 RTT ≈ 1.2-2.0с — старый потолок 2.0с
            # срезал живые узлы на грани. Мёртвые всё равно отваливаются
            # быстрее — по refusal на SOCKS CONNECT, а не по таймауту.
            per_target_timeout = min(2.5, float(self.config.probe_timeout_sec or 8.0))
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
