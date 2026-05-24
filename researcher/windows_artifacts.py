from __future__ import annotations

from pathlib import Path

from .artifacts import (
    ArtifactScan,
    SUSPICIOUS_COMMAND_RE,
    WEBSHELL_RE,
    add_finding,
    add_file_finding,
    collect_matching_lines,
    limited_files,
    safe_rglob,
    scan_threat_artifacts,
    scan_yara,
)
from .threats import classify_command_threat


def scan_windows_artifacts(
    root: Path,
    max_files_per_area: int = 20000,
    yara_rules: list[Path] | None = None,
    builtin_yara: bool = True,
) -> ArtifactScan:
    scan = ArtifactScan()
    scan_user_profiles(root, scan)
    scan_scheduled_tasks(root, scan)
    scan_powershell_history(root, scan)
    scan_inetpub(root, scan, max_files_per_area)
    scan_windows_triage(root, scan, max_files_per_area)
    scan_threat_artifacts(root, scan, max_files_per_area)
    if builtin_yara or yara_rules:
        scan_yara(
            root,
            scan,
            yara_rules or [],
            max_files_per_area,
            builtin_yara,
            targets=[
                root / "inetpub",
                root / "Users",
                root / "ProgramData",
                root / "Windows" / "Temp",
            ],
        )
    return scan


def scan_user_profiles(root: Path, scan: ArtifactScan) -> None:
    users_root = root / "Users"
    if not users_root.exists():
        return
    try:
        profiles = list(users_root.iterdir())
    except OSError:
        return
    for profile in profiles:
        if not profile.is_dir():
            continue
        name = profile.name
        if name in {"Default", "Default User", "Public", "All Users"}:
            continue
        severity = "medium" if name.lower() in {"administrator", "admin"} else "info"
        add_finding(
            scan,
            "user_profile",
            "accounts",
            profile,
            root,
            severity,
            detail=f"profile={name}",
            value=name,
        )


def scan_scheduled_tasks(root: Path, scan: ArtifactScan) -> None:
    tasks_root = root / "Windows" / "System32" / "Tasks"
    if not tasks_root.exists():
        return
    for path in safe_rglob(tasks_root, "*"):
        if not path.is_file():
            continue
        add_file_finding(scan, root, path, "scheduled_task", "persistence", "medium")
        collect_matching_lines(scan, root, path, "scheduled_task_command", "persistence", SUSPICIOUS_COMMAND_RE, "high")


def scan_powershell_history(root: Path, scan: ArtifactScan) -> None:
    users_root = root / "Users"
    if not users_root.exists():
        return
    try:
        profiles = list(users_root.iterdir())
    except OSError:
        return
    for profile in profiles:
        if not profile.is_dir():
            continue
        history = (
            profile
            / "AppData"
            / "Roaming"
            / "Microsoft"
            / "Windows"
            / "PowerShell"
            / "PSReadLine"
            / "ConsoleHost_history.txt"
        )
        for line_number, line in _iter_lines(history):
            if not line:
                continue
            severity = "high" if SUSPICIOUS_COMMAND_RE.search(line) else "info"
            add_finding(scan, "powershell_history", "commands", history, root, severity, line_number, value=line[:300])
            threat = classify_command_threat(line)
            if threat:
                add_finding(scan, threat, "threats", history, root, "high", line_number, value=line[:300])


def scan_inetpub(root: Path, scan: ArtifactScan, max_files: int) -> None:
    base = root / "inetpub" / "wwwroot"
    if not base.exists():
        return
    for path in limited_files(base, max_files):
        if path.suffix.lower() in (".php", ".phtml", ".phar", ".js", ".jsp", ".asp", ".aspx", ".ashx"):
            add_file_finding(scan, root, path, "web_file", "web_compromise", "medium")
            collect_matching_lines(scan, root, path, "webshell_pattern", "web_compromise", WEBSHELL_RE, "high")
        if "upload" in path.as_posix().lower():
            add_file_finding(scan, root, path, "upload_area_file", "web_compromise", "medium")


def scan_windows_triage(root: Path, scan: ArtifactScan, max_files: int) -> None:
    areas = [
        root / "Windows" / "Temp",
        root / "ProgramData",
        root / "Users",
    ]
    for area in areas:
        files = list(limited_files(area, max_files))
        for path in sorted(files, key=lambda item: _safe_mtime(item), reverse=True)[:200]:
            add_file_finding(scan, root, path, "recent_file", "filesystem", "info")


def _iter_lines(path: Path):
    from .artifacts import iter_text_lines

    yield from iter_text_lines(path)


def _safe_mtime(path: Path) -> float:
    from .artifacts import safe_mtime

    return safe_mtime(path)
