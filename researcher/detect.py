from __future__ import annotations

from pathlib import Path


LINUX_MARKERS = (
    "etc/passwd",
    "var/log",
    "bin",
    "usr/bin",
    "boot",
)

WINDOWS_MARKERS = (
    "Windows/System32",
    "Windows/SysWOW64",
    "Program Files",
    "Users",
    "ProgramData",
)


def detect_backup_os(root: Path) -> str:
    linux_score = sum(1 for marker in LINUX_MARKERS if (root / marker).exists())
    windows_score = sum(1 for marker in WINDOWS_MARKERS if (root / marker).exists())

    if windows_score > linux_score:
        return "windows"
    if linux_score > windows_score:
        return "linux"
    if (root / "Windows" / "System32").exists():
        return "windows"
    if (root / "var" / "log").exists() or (root / "etc" / "passwd").exists():
        return "linux"
    return "unknown"
