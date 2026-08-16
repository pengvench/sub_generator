# run_sub_generator.ps1 - запуск конвейера SubGenerator с прогресс-баром.
# Перехватывает маркеры прогресса из stdout:
#   [POWERPROGRESS]|pct|stage|current|total|message
# и рисует нативный прогресс-бар (Write-Progress) в шапке окна.
# Обычные строки лога печатаются как есть и дублируются в data\run.log.
#
# ВАЖНО: в конце скрипта НЕ используется команда `exit`. При запуске через
# -Command "& 'script.ps1' @args" команда exit завершает ВЕСЬ процесс PowerShell,
# из-за чего последующая пауза (Read-Host) не выполняется и окно мгновенно
# закрывается. Вместо exit код возврата сохраняется в $global:SubGenExitCode.
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PyArgs
)

# 'Continue' вместо 'Stop': вывод stderr от python (2>&1) превращается в
# ErrorRecord, и при 'Stop' конвейер обрывается на ПЕРВОЙ строке traceback,
# из-за чего в окне видно только "Error: Traceback (most recent call last):",
# а сам traceback не печатается и не пишется в run.log. С 'Continue' строки
# stderr проходят через конвейер как обычные строки.
$ErrorActionPreference = 'Continue'

# Аргументы конвейера передаются через переменную окружения SUB_GEN_ARGS
# (JSON-массив строк). Это надёжнее, чем аргументы командной строки:
# PowerShell 5.1 НЕ поддерживает "--" как разделитель аргументов после
# -Command, поэтому передача флагов через командную строку приводила к
# мгновенному падению парсера и закрытию окна.
# Значения из командной строки ($PyArgs) добавляются следом (для обратной
# совместимости с run_sub_generator.bat, где используется -Command с "--").
$envArgs = @()
if ($env:SUB_GEN_ARGS) {
    try {
        $envArgs = $env:SUB_GEN_ARGS | ConvertFrom-Json
    } catch {
        Write-Host "WARNING: не удалось прочитать SUB_GEN_ARGS: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}
$PyArgs = @($envArgs) + @($PyArgs)


# Use UTF-8 everywhere so Russian messages from Python render correctly.
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = 'utf-8'

# Enable progress markers in generate.py.
$env:SUB_GEN_PS_WRAPPER = '1'

$Marker = '[POWERPROGRESS]'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
# Корень приложения — каталог, где лежит generate.py или SubGenerator-CLI.exe.
# В исходниках это корень проекта (ps1 в scripts/), в собранной сборке — рядом с exe.
$hasGen = Test-Path (Join-Path $scriptDir 'generate.py')
$hasCli = Test-Path (Join-Path $scriptDir 'SubGenerator-CLI.exe')
$rootDir = $scriptDir
if ($hasGen -or $hasCli) {
    $rootDir = $scriptDir
} elseif (Test-Path (Join-Path (Split-Path -Parent $scriptDir) 'generate.py')) {
    $rootDir = Split-Path -Parent $scriptDir
}
Set-Location $rootDir


Write-Progress -Activity 'Sub Generator' -Status 'starting' -PercentComplete 0 -CurrentOperation 'init'

$exitCode = 0
try {
    # Исполнитель: в собранной сборке рядом с ps1 лежит SubGenerator-CLI.exe —
    # билд полностью независим от Python (python используется только в исходниках).
    $runner = 'python'
    $runnerArgs = @('generate.py')
    if (Test-Path (Join-Path $rootDir 'SubGenerator-CLI.exe')) {
        $runner = Join-Path $rootDir 'SubGenerator-CLI.exe'
        $runnerArgs = @()
    }

    # Дублируем весь вывод в data\run.log, чтобы ошибки можно было посмотреть
    # даже после закрытия окна.
    $logDir = Join-Path $rootDir 'data'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $logPath = Join-Path $logDir 'run.log'
    Add-Content -Path $logPath -Value ("===== {0} =====" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

    Write-Host "Runner: $runner $($runnerArgs -join ' ')" -ForegroundColor DarkGray
    Add-Content -Path $logPath -Value "Runner: $runner $($runnerArgs -join ' ')"

    # Run the generator and process its output line by line.
    & $runner @runnerArgs @PyArgs 2>&1 | ForEach-Object {
        $line = $_
        if ($line -is [System.Management.Automation.ErrorRecord]) {
            $line = $line.ToString()
        }
        $text = [string]$line
        # Дублируем строку в лог-файл (маркеры прогресса не пишем).
        if (-not $text.StartsWith($Marker)) {
            Add-Content -Path $logPath -Value $text
        }

        if ($text.StartsWith($Marker)) {

            $body = $text.Substring($Marker.Length).TrimStart('|')
            if ($body -eq '_END') {
                Write-Progress -Activity 'Sub Generator' -Completed
            } else {
                $parts = $body.Split('|')
                $pct = 0; $cur = 0; $total = 0
                $stage = ''; $msg = ''
                try {
                    $pct = [int]$parts[0]
                    $stage = if ($parts.Length -gt 1) { $parts[1] } else { '' }
                    $cur = if ($parts.Length -gt 2) { [int]$parts[2] } else { 0 }
                    $total = if ($parts.Length -gt 3) { [int]$parts[3] } else { 0 }
                    $msg = if ($parts.Length -gt 4) { $parts[4] } else { '' }
                } catch {
                    # Malformed marker - skip it.
                    return
                }
                $pct = [Math]::Max(0, [Math]::Min(100, $pct))
                Write-Progress -Activity 'Sub Generator' `
                    -Status ("{0} - {1}/{2}" -f $stage, $cur, $total) `
                    -PercentComplete $pct `
                    -CurrentOperation $msg
            }
        } else {
            # Regular log line: print as-is.
            Write-Output $text
        }
    }
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 0 }
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
} finally {
    Write-Progress -Activity 'Sub Generator' -Completed
}

# Сохраняем код возврата в глобальной переменной и НЕ вызываем exit:
# при запуске через -Command "& 'script.ps1' @args; ...; Read-Host" команда exit
# завершает весь процесс PowerShell, и последующая пауза не выполняется.
$global:SubGenExitCode = $exitCode

