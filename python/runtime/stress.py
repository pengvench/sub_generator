"""Стресс-тест узлов (перенесено из runtime/core.py).

StressMixin входит в XrayCoreRuntime и содержит:
  stress_test        — параллельный стресс ограниченного пула (rounds раундов);
  _stress_probe_node — один узел: 3 раунда Telegram+спид, адаптивные пороги
                       upload/tg_media (v1.3), обязательный медиа-фильтр t.me/s/;
  with_node_process  — контекст «поднять ядро -> fn(host, port) -> убить»,
                       v11-ретраи при падении xray.exe под нагрузкой.
"""
from __future__ import annotations

import contextlib
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from .collect import _wait_if_paused
from .configs import _write_temp_config
from .netsocks import _socks_https_head_status
from .probes_speed import _download_speed_probe, _xray_upload_speed
from .probes_telegram import _socks_mtproto_latency, _tg_media_probe
from .procs import _find_free_port, _subprocess_no_window, _terminate_process_tree
from .sorting import _reason_summary, _xray_result_sort_key
from .types import (
    TELEGRAM_API_HEAD_TARGET,
    TELEGRAM_DCS,
    TG_MEDIA_MIN_KBPS,
    XRAY_MIN_MEDIA_KBPS,
    XrayNode,
    XrayProbeResult,
)

__all__ = ["StressMixin"]


class StressMixin:
    """Стресс-тесты узлов через временные core-процессы."""

    # Атрибуты экземпляра (config/_lock/_process/...) создаются в
    # XrayCoreRuntime.__init__ (runtime/core.py) — примесь не имеет __init__.

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
            # v1.3: оба порога могут быть адаптированы под реальную сеть
            # (config.upload_min_kbps/tg_media_min_kbps от базового замера
            # subgen/baseline.py) — мобильная сеть 46/5 Мбит не должна
            # браковать узлы по порогу, который сама не выдаёт.
            min_speed = float(getattr(self.config, "min_speed_kbps", XRAY_MIN_MEDIA_KBPS) or XRAY_MIN_MEDIA_KBPS)
            upload_min_cfg = getattr(self.config, "upload_min_kbps", None)
            min_upload_speed = float(upload_min_cfg) if upload_min_cfg else min_speed * 0.1
            tg_media_min_kbps = float(getattr(self.config, "tg_media_min_kbps", 0.0) or TG_MEDIA_MIN_KBPS) or TG_MEDIA_MIN_KBPS
            if accepted and download_kbps is not None and download_kbps < min_speed:
                accepted = False
                reason = f"slow_download ({download_kbps:.0f} < {min_speed:.0f})"
            elif accepted and upload_kbps is not None and upload_kbps < min_upload_speed:
                accepted = False
                reason = f"slow_upload ({upload_kbps:.0f} < {min_upload_speed:.0f})"
            else:
                reason = "ready" if accepted else ("stress_unstable" if round_ok > 0 else "stress_failed")

            # --- Telegram-медиа фильтр (t.me/s/peppe_poppo) — ОБЯЗАТЕЛЬНЫЙ ---
            # Раньше это было «спасение»: проба запускалась только для узлов,
            # проваливших спид-тест, и прошедшие 512 КБ/с принимались с особым
            # reason и обходили фильтр min-speed и финальный recheck. Теперь
            # проба выполняется для КАЖДОГО узла, прошедшего
            # раунды (прокси жив): не качает видео из Telegram — отбраковка
            # (reason="tg_media_failed"), даже если спид-тест пройден.
            # Обратного перекрытия нет: slow_download/slow_upload медиа-пробой
            # НЕ «спасается» — узел должен проходить оба фильтра.
            # Метка в имени подписки не ставится: категорий больше нет.
            tg_media_kbps: float | None = None
            if telegram_check and round_ok > 0:
                try:
                    tg_media_kbps = _tg_media_probe("127.0.0.1", port, timeout)
                except Exception:
                    tg_media_kbps = None
                if tg_media_kbps is None or tg_media_kbps < tg_media_min_kbps:
                    failed_detail = (
                        f"{tg_media_kbps:.0f} < {tg_media_min_kbps:.0f} Kbps"
                        if tg_media_kbps is not None
                        else f"видео из t.me не скачалось (порог {tg_media_min_kbps:.0f} Kbps)"
                    )
                    tg_media_kbps = None
                    if accepted:
                        accepted = False
                        reason = f"tg_media_failed ({failed_detail})"
                # Иначе: tg_media_kbps зафиксирован как данные строки (row/кеш);
                # вердикт спид-теста не меняется.
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
                tg_media_kbps=tg_media_kbps,
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
        v15: слепой sleep(0.4) заменён на ожидание готовности SOCKS-порта
        (_wait_socks_port из probing): под нагрузкой порт запаздывает и все
        пробы чекера ловили «connection refused» — узел ложно браковался;
        на разгруженной машине ожидание завершается раньше sleep (порт
        поднимается за ~150-250мс).
        """
        from .probing import _wait_socks_port

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
                # v15: ждём готовности SOCKS-порта вместо слепого sleep(0.4) —
                # надёжно под нагрузкой и быстрее на разгруженной машине.
                if not _wait_socks_port(proc, port, 2.5):
                    if proc.poll() is not None:
                        # Ядро упало при старте. На первой попытке — ретрай (возможно,
                        # ресурсов не хватило). На второй — кидаем исключение.
                        last_error = RuntimeError(f"{node.runtime} exited during startup (attempt {attempt+1})")
                        continue
                    last_error = RuntimeError(f"{node.runtime} SOCKS port not listening (attempt {attempt+1})")
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
