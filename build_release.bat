@echo off
setlocal

cd /d "%~dp0"

set "PYTHON_EXE=%LocalAppData%\Programs\Python\Python312\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=python"

echo ============================================
echo   Sub Generator - build (folder build)
echo ============================================
echo.

rem [0/4] Check Python and PyInstaller
echo [0/4] Checking Python + PyInstaller ...
"%PYTHON_EXE%" --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ from https://python.org
    echo        Or check PYTHON_EXE path: %PYTHON_EXE%
    pause
    exit /b 1
)
"%PYTHON_EXE%" -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not installed. Installing via pip...
    "%PYTHON_EXE%" -m pip install --upgrade pip pyinstaller
    if errorlevel 1 (
        echo ERROR: PyInstaller install failed.
        pause
        exit /b 1
    )
)
echo   OK: Python + PyInstaller ready

rem Check customtkinter (GUI dependency)
"%PYTHON_EXE%" -c "import customtkinter" >nul 2>&1
if errorlevel 1 (
    echo customtkinter not installed. Installing via pip...
    "%PYTHON_EXE%" -m pip install customtkinter darkdetect
    if errorlevel 1 (
        echo ERROR: customtkinter install failed.
        pause
        exit /b 1
    )
)
echo   OK: customtkinter ready

if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo.
echo [1/4] Building GUI (windowed) ...
"%PYTHON_EXE%" -m PyInstaller --noconfirm --clean --workpath "build\_work\gui" --distpath "build\dist" "%~dp0scripts\SubGenerator.spec"
if errorlevel 1 (
    echo ERROR: GUI build failed.
    pause
    exit /b 1
)

echo.
echo [2/4] Building CLI (console) ...
"%PYTHON_EXE%" -m PyInstaller --noconfirm --clean --workpath "build\_work\cli" --distpath "build\dist" "%~dp0scripts\SubGenerator-cli.spec"
if errorlevel 1 (
    echo ERROR: CLI build failed.
    pause
    exit /b 1
)

echo.
echo [3/4] Assembling build\ ...
mkdir build\
copy /Y build\dist\SubGenerator.exe build\SubGenerator.exe >nul
copy /Y build\dist\SubGenerator-CLI.exe build\SubGenerator-CLI.exe >nul
copy /Y data\sources.txt build\sources.txt >nul
mkdir build\data >nul 2>nul
copy /Y data\sources.txt build\data\sources.txt >nul
copy /Y "%~dp0scripts\run_sub_generator.ps1" build\run_sub_generator.ps1 >nul
copy /Y "%~dp0scripts\run_sub_generator.bat" build\run_sub_generator.bat >nul
copy /Y "%~dp0assets\icon.ico" build\icon.ico >nul

rem [4/4] Copy saved_subs folder (imported configs)
echo.
echo [4/4] Copying saved_subs\ folder ...
mkdir build\data\saved_subs >nul 2>nul
if exist data\saved_subs (
    xcopy /Y /E /I data\saved_subs build\data\saved_subs >nul
    echo   Copied saved_subs files to build\data\saved_subs\
) else (
    echo   data\saved_subs\ is empty (will be created on first run)
)

rem Собранная сборка должна быть полностью независима от Python:
rem при запуске run_sub_generator.ps1 рядом с exe используется
rem SubGenerator-CLI.exe, а не системный python.
if not exist build\SubGenerator-CLI.exe (
    echo ERROR: SubGenerator-CLI.exe not found in build\ - build failed.
    pause
    exit /b 1
)

if exist build\_work rmdir /s /q build\_work
if exist build\dist rmdir /s /q build\dist
if exist __pycache__ rmdir /s /q __pycache__
if exist python\__pycache__ rmdir /s /q python\__pycache__

echo.
echo ============================================
echo   Build complete!
echo ============================================
echo   build\SubGenerator.exe      (GUI)
echo   build\SubGenerator-CLI.exe  (console)
echo   build\sources.txt           (subscriptions, editable)
echo   build\data\sources.txt      (то же, в data/)
echo   build\data\saved_subs\       (imported configs from "Импорт" tab)
echo   build\run_sub_generator.ps1 (PowerShell progress wrapper)
echo   build\run_sub_generator.bat (one-click PowerShell run)
echo   build\icon.ico              (app icon)
echo.
echo On first run next to exe will appear:
echo   data\  (logs, cache, working.txt, report.json, settings.json)
echo   subs.txt  (resulting subscription, next to exe)
echo.
pause
endlocal
