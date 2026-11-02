"""Resolve `op://` secret references via the 1Password CLI (`op read`).

Any profile field that starts with ``op://`` is treated as a 1Password secret
reference and expanded at login time by shelling out to ``op read <ref>``.
Plain values (and empty strings) are returned unchanged, so existing profiles
keep working.

A reference wrapped in quotes (``"op://..."``) -- the form 1Password desktop's
"Copy Secret Reference" produces -- is accepted as the bare reference.
"""

from __future__ import annotations

import shutil
import subprocess

OP_PREFIX = "op://"
_QUOTES = ('"', "'")


def normalize_op_reference(value: str) -> str:
    """Strip whitespace and one pair of matching quotes around an op:// reference.

    Anything that is not a (possibly quoted) op:// reference is returned unchanged,
    so a password that merely happens to be quoted is never altered.
    """
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] in _QUOTES and stripped[-1] == stripped[0]:  # noqa: PLR2004
        stripped = stripped[1:-1].strip()
    return stripped if stripped.startswith(OP_PREFIX) else value


def is_op_reference(value: str) -> bool:
    return normalize_op_reference(value).startswith(OP_PREFIX)


def resolve_secret(value: str) -> str:
    """Return ``value`` verbatim, or expand it via ``op read`` if it is an op:// ref."""
    if not is_op_reference(value):
        return value
    value = normalize_op_reference(value)

    if shutil.which("op") is None:
        msg = (
            f"'{value}' is a 1Password reference but the `op` CLI is not installed. "
            "Install the 1Password CLI: https://developer.1password.com/docs/cli/"
        )
        raise ValueError(msg)

    try:
        result = subprocess.run(  # noqa: S603
            ["op", "read", value],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        msg = f"Failed to resolve 1Password reference '{value}': {detail}"
        raise ValueError(msg) from exc

    return result.stdout.strip()
