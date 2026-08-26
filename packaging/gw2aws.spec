from __future__ import annotations

from pathlib import Path

from PyInstaller.utils.hooks import collect_all, copy_metadata

SPEC_DIR = Path(SPECPATH)  # noqa: F821
ROOT = SPEC_DIR.parent

# `gw2aws --version` reads the distribution metadata, which is not package
# content and so would otherwise be left behind.
datas = copy_metadata("gw2aws")
binaries = []
hiddenimports = []

# Playwright ships no PyInstaller hook, and its Node driver (`playwright/driver`,
# ~130MB) is what actually talks to the browser: without it the frozen binary
# cannot log in at all. boto3/botocore are covered by pyinstaller-hooks-contrib.
playwright_datas, playwright_binaries, playwright_hiddenimports = collect_all("playwright")
for entry in playwright_datas:
    # The driver is exec'd, so it has to keep its executable bit -- and on
    # macOS get code-signed. Only BINARIES entries are treated that way.
    if Path(entry[0]).name in {"node", "node.exe"}:
        binaries.append(entry)
    else:
        datas.append(entry)
binaries += playwright_binaries
hiddenimports += playwright_hiddenimports

a = Analysis(  # noqa: F821
    [str(SPEC_DIR / "entrypoint.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["pytest", "tkinter"],
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="gw2aws",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
