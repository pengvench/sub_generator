@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0.."

echo ============================================
echo  Фильтрация sources.txt (мусорные подписки)
echo ============================================
echo.

python "%~dp0..\tools\_filter_sources.py" --sources sources.txt --working data\.runtime_cache\xray_working.json --rejected data\.runtime_cache\xray_rejected.json

echo.
echo Готово. sources.txt обновлён.
pause
