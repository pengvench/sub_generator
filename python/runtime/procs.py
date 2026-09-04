"""Управление процессами ядер на Windows: Job Objects (kill-on-close),
терминация дерева PID, поиск бинарников (bin/, PyInstaller-бандл),
свободные порты, CREATE_NO_WINDOW."""
from __future__ import annotations


import contextlib
import ctypes
import os
import shutil
import socket
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path


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

def _subprocess_no_window() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)
