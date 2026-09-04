@echo off
setlocal

cd /d "%~dp0"

set "PYTHON_EXE=%LocalAppData%\Programs\Python\Python312\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=python"

echo ============================================
echo   Sub Generator - build (folder build)
echo ============================================
echo.

if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [1/3] Building GUI (windowed) ...
"%PYTHON_EXE%" -m PyInstaller --noconfirm --clean --workpath "build\_work\gui" --distpath "build\dist" "%~dp0scripts\SubGenerator.spec"
if errorlevel 1 exit /b 1

echo [2/3] Building CLI (console) ...
"%PYTHON_EXE%" -m PyInstaller --noconfirm --clean --workpath "build\_work\cli" --distpath "build\dist" "%~dp0scripts\SubGenerator-cli.spec"
if errorlevel 1 exit /b 1

echo [3/3] Assembling build\ ...
mkdir build\
copy /Y build\dist\SubGenerator.exe build\SubGenerator.exe >nul
copy /Y build\dist\SubGenerator-CLI.exe build\SubGenerator-CLI.exe >nul
copy /Y data\sources.txt build\sources.txt >nul
mkdir build\data >nul 2>nul
copy /Y data\sources.txt build\data\sources.txt >nul
copy /Y "%~dp0scripts\run_sub_generator.ps1" build\run_sub_generator.ps1 >nul
copy /Y "%~dp0scripts\run_sub_generator.bat" build\run_sub_generator.bat >nul
copy /Y "%~dp0assets\icon.ico" build\icon.ico >nul

rem Собранная сборка должна быть полностью независима от Python:
rem при запуске run_sub_generator.ps1 рядом с exe используется
rem SubGenerator-CLI.exe, а не системный python.
if not exist build\SubGenerator-CLI.exe (
    echo ERROR: SubGenerator-CLI.exe not found in build\ - build failed.
    exit /b 1
)

if exist build\_work rmdir /s /q build\_work
if exist build\dist rmdir /s /q build\dist
if exist __pycache__ rmdir /s /q __pycache__
if exist python\__pycache__ rmdir /s /q python\__pycache__

echo.
echo Build complete:
echo   build\SubGenerator.exe      (GUI)
echo   build\SubGenerator-CLI.exe  (console)
echo   build\sources.txt           (subscriptions, editable)
echo   build\data\sources.txt      (то же, в data/ — куда смотрит приложение)
echo   build\run_sub_generator.ps1 (PowerShell progress wrapper)
echo   build\run_sub_generator.bat (one-click PowerShell run)
echo   build\icon.ico              (app icon)

echo.
echo On first run next to exe will appear:
echo   data\  (logs, cache, working.txt, report.json, settings.json)
echo   subs.txt  (resulting subscription, next to exe)
endlocal
