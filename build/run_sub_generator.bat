@echo off
chcp 65001 >nul
title Sub Generator
cd /d "%~dp0"


echo ============================================
echo   Sub Generator - build subscription
echo ============================================
echo.
echo Running: powershell -Command "& run_sub_generator.ps1 @args" -- --workers 32 --dpi-check --dpi-siberian --max-ping 1500 --min-speed 3000 --timeout 15 %*
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%~dp0run_sub_generator.ps1' @args" -- --workers 32 --dpi-check --dpi-siberian --max-ping 1500 --min-speed 3000 --timeout 15 %*

echo.
echo ============================================
echo   Done. Results: data\subs.txt / data\working.txt / data\report.json
echo ============================================
pause >nul
