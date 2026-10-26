# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.utils.hooks import copy_metadata

datas = [('C:/Users/krmah/OneDrive - University of Huddersfield/Documents/linkshield-siem/dashboard/dist', 'dashboard/dist'), ('C:/Users/krmah/OneDrive - University of Huddersfield/Documents/linkshield-siem/backend/geoip/GeoLite2-Country.mmdb', 'backend/geoip')]
hiddenimports = []
datas += copy_metadata('geoip2')
datas += copy_metadata('maxminddb')
hiddenimports += collect_submodules('uvicorn')
hiddenimports += collect_submodules('pydantic')
hiddenimports += collect_submodules('starlette')
hiddenimports += collect_submodules('geoip2')


a = Analysis(
    ['C:/Users/krmah/OneDrive - University of Huddersfield/Documents/linkshield-siem/backend/portable_app.py'],
    pathex=['C:/Users/krmah/OneDrive - University of Huddersfield/Documents/linkshield-siem/backend'],
    binaries=[],
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
    [],
    exclude_binaries=True,
    name='LinkShield',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='LinkShield',
)
