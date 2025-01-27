# encryptor_gui.spec

# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['encryptor_gui.py'],
    pathex=['/home/barren/Documents/INSA/anonymizator'],
    binaries=[
        ('/usr/lib/x86_64-linux-gnu/libpython3.9.so.1.0', '.'),
        ('/usr/lib/x86_64-linux-gnu/libpython3.9.so', '.')
    ],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='encryptor_encrypt',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False
)
