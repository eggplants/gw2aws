"""Entry point frozen into the standalone binary by `packaging/gw2aws.spec`.

The console script declared in `pyproject.toml` is not usable here: PyInstaller
analyses a source file, not an installed entry point, and the project itself is
imported from the repo tree rather than pip-installed during the build.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from playwright._impl._driver import compute_driver_executable

from gw2aws.cli import main

EXEC_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def _default_browsers_path() -> Path:
    """Where a pip-installed Playwright keeps its browsers, per platform."""
    if sys.platform == "darwin":
        cache = Path.home() / "Library" / "Caches"
    elif sys.platform == "win32":
        cache = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return cache / "ms-playwright"


def _persist_browsers_outside_the_bundle() -> None:
    """Keep the downloaded Chromium out of PyInstaller's temporary unpack dir.

    Playwright forces `PLAYWRIGHT_BROWSERS_PATH=0` for frozen apps, which puts
    browsers next to the bundled driver -- i.e. inside `_MEIxxxx`, wiped when
    the process exits, so every single login would re-download Chromium.
    Pointing it at the usual per-user cache also shares the download with a
    pip-installed Playwright.
    """
    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        return
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(_default_browsers_path())


def _ensure_driver_executable() -> None:
    """Restore the +x bit on the bundled Node driver, which Playwright exec's.

    The spec file ships `driver/node` as a PyInstaller *binary* so the bit
    survives unpacking, but nothing about that is guaranteed across platforms
    and versions -- and without it every login dies inside Playwright with a
    permission error rather than anything actionable.
    """
    if os.name == "nt":
        return
    node = Path(compute_driver_executable()[0])
    if node.is_file() and not os.access(node, os.X_OK):
        node.chmod(node.stat().st_mode | EXEC_BITS)


if __name__ == "__main__":
    if getattr(sys, "frozen", False):
        _persist_browsers_outside_the_bundle()
        _ensure_driver_executable()
    sys.exit(main())
