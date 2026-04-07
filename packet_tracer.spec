# packet_tracer.spec — PyInstaller build specification.
#
# Build with:
#   pyinstaller packet_tracer.spec
#
# Output: dist/PacketTracer.exe  (single file, ~150-200 MB)
#
# Notes:
#   - Scapy needs its data files (protocols, manuf DB) collected explicitly.
#   - PyQt6 plugins (platform, styles) are collected automatically by PyInstaller
#     but we add them explicitly to be safe on all Windows versions.
#   - The build embeds everything except Npcap, which the end user must install
#     separately from https://npcap.com for live capture to work.

import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect scapy's data files (protocol definitions, OUI/manuf database, etc.)
scapy_datas = collect_data_files("scapy")

# Collect all scapy submodules so protocol layers are available at runtime.
scapy_hiddenimports = collect_submodules("scapy")

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=scapy_datas,
    hiddenimports=scapy_hiddenimports + [
        # PyQt6 modules that may not be auto-detected by static analysis.
        "PyQt6.QtCore",
        "PyQt6.QtGui",
        "PyQt6.QtWidgets",
        # Scapy Windows-specific modules needed for Npcap integration.
        "scapy.arch.windows",
        "scapy.arch.windows.native",
        "scapy.layers.all",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude unused heavy packages to keep the exe smaller.
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "IPython",
        "jupyter",
        "notebook",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="PacketTracer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,          # UPX compression reduces file size if UPX is installed
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,     # False = no console window behind the GUI
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon="assets/icon.ico",  # uncomment and add an .ico file to set an icon
)
