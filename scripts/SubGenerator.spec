# -*- mode: python ; coding: utf-8 -*-
# Спецификация PyInstaller: GUI-версия SubGenerator.
# Пути относительные (от scripts/), сборка запускается build_release.bat
# из корня репозитория — работает на любой машине.
from PyInstaller.utils.hooks import collect_all
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))
PYTHON = os.path.join(ROOT, 'python')

datas = [
    (os.path.join(ROOT, 'bin'), 'bin'),
    (os.path.join(ROOT, 'data', 'sources.txt'), 'data'),
    (os.path.join(ROOT, 'assets', 'icon.ico'), '.'),
]

binaries = []
hiddenimports = [
    'xray_runtime', 'subgen.pipeline', 'subgen.refresh', 'subgen.geo',
    'subgen.output', 'subgen.logging', 'subgen.progress', 'subgen.config',
    'subgen.checker_thresholds', 'subgen.checker_cache',
    'subgen.settings',
    'checkers.dpi', 'checkers.cidr', 'checkers.zapret', 'checkers.base',
    'checkers.initial_check', 'checkers.telegram_pro', 'checkers.route',
    'checkers.blocked_services', 'checkers.dpi_active', 'checkers.hostres',
    'checkers.net_baseline', 'checkers.net_diagnostic', 'checkers.resilience',
    'checkers.tg_media', 'checkers.ai_geo',
    'ui.app', 'ui.runner', 'ui.paths', 'ui.tooltip', 'ui.theme', 'ui.main',
    'ui.pages.start_page', 'ui.pages.sources_page', 'ui.pages.log_page',
    'ui.pages.settings_page', 'ui.pages.recheck_page',
    'ui.pages.diag_page', 'ui.pages.import_page',
]
tmp_ret = collect_all('customtkinter')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('darkdetect')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

a = Analysis(
    [os.path.join(PYTHON, 'ui', 'main.py')],
    pathex=[ROOT, PYTHON],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SubGenerator',
    icon=os.path.join(ROOT, 'assets', 'icon.ico'),
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # UAC-манифест: при запуске exe Windows автоматически показывает
    # диалог «Запустить от имени администратора?». Нужны права админа
    # для управления процессами xray.exe/sing-box.exe (terminate tree
    # через WinAPI, kill-on-close job objects) и корректной очистки
    # временных файлов в data/.runtime_cache.
    uac_admin=True,
)
