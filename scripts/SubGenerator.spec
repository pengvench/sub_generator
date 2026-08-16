# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

ROOT = 'c:\\Users\\peppo\\Desktop\\sub_generator'

datas = [(ROOT + '\\bin', 'bin'), (ROOT + '\\sources.txt', '.'), (ROOT + '\\icon.ico', '.')]

binaries = []
hiddenimports = [
    'xray_runtime', 'subgen.pipeline', 'subgen.refresh', 'subgen.geo',
    'subgen.output', 'subgen.logging', 'subgen.progress', 'subgen.config',
    'checkers.dpi', 'checkers.cidr', 'checkers.zapret', 'checkers.base',
    'ui.app', 'ui.runner', 'ui.paths', 'ui.tooltip', 'ui.theme', 'ui.main',
    'ui.pages.start_page', 'ui.pages.sources_page', 'ui.pages.log_page',
    'ui.pages.settings_page',

]
tmp_ret = collect_all('customtkinter')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('darkdetect')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

a = Analysis(
    [ROOT + '\\ui\\main.py'],
    pathex=[ROOT],
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
    icon=ROOT + '\\icon.ico',
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
)
