"""Временный скрипт: список python-процессов."""
import subprocess

ps = (
    "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
    "ForEach-Object { Write-Output ($_.ProcessId.ToString() + ' || ' + $_.CommandLine) }"
)
r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
print(r.stdout or "(no python processes)")
