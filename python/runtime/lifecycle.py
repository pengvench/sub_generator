"""Жизненный цикл core-процесса (перенесено из runtime/core.py).

LifecycleMixin входит в XrayCoreRuntime и отвечает за:
  старт/стоп/рестарт долгоживущего процесса ядра (xray/sing-box);
  pid-файл (восстановление после падения приложения);
  Windows Job Object (kill-on-close — ядра не переживают приложение);
  _start_node — запуск активного узла на socks-порту (багфикс P0: метод
  вызывался 10 раз, но не был определён — AttributeError при перезапуске).
"""
from __future__ import annotations

import contextlib
import json
import subprocess
import time
from pathlib import Path

from .configs import _write_temp_config
from .procs import (
    _assign_process_to_job,
    _cleanup_stale_bundle_cores,
    _close_windows_handle,
    _create_kill_on_close_job,
    _subprocess_no_window,
    _terminate_pid_tree,
    _terminate_process_tree,
)
from .types import XrayNode

__all__ = ["LifecycleMixin"]


class LifecycleMixin:
    """Управление долгоживущим core-процессом активного узла."""

    # Атрибуты экземпляра (config/_lock/_process/...) создаются в
    # XrayCoreRuntime.__init__ (runtime/core.py) — примесь не имеет __init__.

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
            elif proc is None and not self._lightweight:
                # pid-файл и xray_runtime.pid — ОБЩЕЕ состояние долгоживущих
                # runtime'ов (один out_dir). Одноразовый (lightweight) runtime
                # НЕ имеет права убивать чужой активный узел: при реюзе PID
                # _terminate_pid_tree убивает невинный процесс (в худшем
                # случае — наш собственный, инцидент 2026-09-16).
                stale_pid = self._read_pid_file()
                if stale_pid:
                    _terminate_pid_tree(stale_pid, timeout=timeout)
            self._process = None
            self._running_node = None
            if not self._lightweight:
                # Общий pid-файл принадлежит долгоживущему runtime —
                # одноразовый его не трогает (иначе удалит живой PID-маркер).
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
        # Одноразовый (lightweight) runtime после stop() больше не нужен:
        # новый Job Object не создаём — объект умрёт без atexit-ссылки, и
        # закрывать этот хендл будет некому (утечка kernel-handle).
        self._job_handle = (
            None if self._lightweight else _create_kill_on_close_job()
        )

    def restart(self) -> bool:
        self.stop()
        return self.start()

    def _start_node(self, node: XrayNode, port: int) -> None:
        """Запустить ДОЛГОЖИВУЩИЙ core-процесс активного узла на socks-порту.

        Багфикс (P0): метод вызывался из start()/refresh()/update_selection()
        пять раз, но не был определён — AttributeError при каждом перезапуске
        активного узла (пауза/резюм, смена стратегии, фоновый refresh).

        Паттерн — как в _stress_probe_node/with_node_process, но процесс НЕ
        убивается: он становится self._process / self._running_node и живёт
        до следующего stop()/switch-узла. Вызывать ТОЛЬКО под self._lock
        после stop() предыдущего процесса.
        """
        binary = self._binary_for_node(node)
        if not binary:
            raise RuntimeError(f"{node.runtime} binary not found")
        config_path = ""
        try:
            config_path = _write_temp_config(self._build_config(node, port))
            proc = subprocess.Popen(
                [binary, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_subprocess_no_window(),
            )
            self._assign_to_process_job(proc)
            # SOCKS поднимается за 200-400 мс; 0.8 с — с запасом под нагрузку.
            time.sleep(0.8)
            if proc.poll() is not None:
                raise RuntimeError(f"{node.runtime} exited during startup")
            self._process = proc
            self._running_node = node
            self._config_path = config_path
            self._write_pid_file(proc, config_path, binary)
            self.last_error = ""
            self._log(f"[xray] node started: {node.title()} on port {port} ({self._effective_runtime(node)})")
        except Exception:
            if config_path:
                with contextlib.suppress(Exception):
                    Path(config_path).unlink(missing_ok=True)
            raise
