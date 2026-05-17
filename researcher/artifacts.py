from __future__ import annotations

import hashlib
import importlib.util
import importlib.resources as resources
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator


URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

SUSPICIOUS_COMMAND_RE = re.compile(
    r"\b("
    r"wget|curl|nc|ncat|netcat|socat|bash\s+-i|sh\s+-i|python\d?\s+-c|perl\s+-e|"
    r"base64\s+-d|chmod\s+\+x|chattr|nohup|setsid|mkfifo|/dev/tcp|"
    r"iptables|ufw|sshpass|scp|rsync|tar|zip|7z"
    r")\b",
    re.IGNORECASE,
)
WEBSHELL_RE = re.compile(
    r"(eval\s*\(|assert\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|"
    r"proc_open\s*\(|popen\s*\(|base64_decode\s*\(|gzinflate\s*\(|"
    r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[)",
    re.IGNORECASE,
)
SECRET_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"aws_access_key_id|aws_secret_access_key|database_url|db_password)",
    re.IGNORECASE,
)

TEXT_SUFFIXES = {
    "",
    ".conf",
    ".config",
    ".env",
    ".history",
    ".ini",
    ".js",
    ".json",
    ".log",
    ".php",
    ".profile",
    ".py",
    ".rb",
    ".service",
    ".sh",
    ".timer",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
ARCHIVE_SUFFIXES = {
    ".zip",
    ".7z",
    ".rar",
    ".gz",
    ".bz2",
    ".xz",
    ".tgz",
    ".sql",
    ".dump",
    ".bak",
    ".backup",
}


@dataclass
class ArtifactFinding:
    kind: str
    category: str
    path: str
    severity: str = "info"
    line_number: int = 0
    detail: str = ""
    value: str = ""
    mtime: str = ""
    size: int = 0
    sha256: str = ""


@dataclass
class ArtifactScan:
    findings: list[ArtifactFinding] = field(default_factory=list)
    ips: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)


def scan_artifacts(
    root: Path,
    max_files_per_area: int = 20000,
    yara_rules: list[Path] | None = None,
    builtin_yara: bool = True,
) -> ArtifactScan:
    scan = ArtifactScan()
    scan_accounts(root, scan)
    scan_persistence(root, scan)
    scan_histories(root, scan)
    scan_web(root, scan, max_files_per_area)
    scan_filesystem_triage(root, scan, max_files_per_area)
    scan_secret_and_archive_hints(root, scan, max_files_per_area)
    if builtin_yara or yara_rules:
        scan_yara(root, scan, yara_rules or [], max_files_per_area, builtin_yara)
    return scan


def scan_yara(root: Path, scan: ArtifactScan, rule_inputs: list[Path], max_files: int, builtin_yara: bool) -> None:
    if importlib.util.find_spec("yara") is None:
        add_finding(
            scan,
            "yara_unavailable",
            "yara",
            root,
            root,
            "low",
            detail="yara-python is not installed; reinstall researcher so package dependencies are installed",
        )
        return

    import yara  # type: ignore[import-not-found]

    rule_files = discover_yara_rule_files(rule_inputs)
    compiled_rules = []

    if builtin_yara:
        try:
            builtin_source = resources.files("researcher.rules").joinpath("builtin.yar").read_text(encoding="utf-8")
            compiled_rules.append(yara.compile(source=builtin_source))
        except Exception as error:
            add_finding(scan, "yara_builtin_compile_error", "yara", root, root, "medium", detail=str(error))

    if rule_files:
        try:
            compiled_rules.append(yara.compile(filepaths={safe_rule_namespace(path): str(path) for path in rule_files}))
        except Exception as error:
            add_finding(scan, "yara_compile_error", "yara", rule_files[0], root, "medium", detail=str(error))
    elif rule_inputs:
        for path in rule_inputs:
            add_finding(scan, "yara_rules_not_found", "yara", path, root, "low", detail="no .yar/.yara files found")

    if not compiled_rules:
        return

    targets = [
        root / "var" / "www",
        root / "srv" / "www",
        root / "tmp",
        root / "dev" / "shm",
        root / "usr" / "local" / "bin",
        root / "opt",
    ]
    for base in targets:
        for path in limited_files(base, max_files):
            for rules in compiled_rules:
                try:
                    matches = rules.match(str(path), timeout=10)
                except Exception as error:
                    add_finding(scan, "yara_scan_error", "yara", path, root, "low", detail=str(error))
                    continue
                for match in matches:
                    strings = []
                    for string_match in getattr(match, "strings", []):
                        identifier = getattr(string_match, "identifier", "")
                        if identifier:
                            strings.append(identifier)
                    detail = f"rule={match.rule} namespace={match.namespace}"
                    if strings:
                        detail += f" strings={','.join(sorted(set(strings))[:10])}"
                    add_file_finding(scan, root, path, "yara_match", "yara", "high")
                    scan.findings[-1].detail = detail


def discover_yara_rule_files(paths: list[Path]) -> list[Path]:
    rule_files: list[Path] = []
    for path in paths:
        expanded = path.expanduser()
        if expanded.is_file() and expanded.suffix.lower() in (".yar", ".yara"):
            rule_files.append(expanded)
        elif expanded.is_dir():
            for child in safe_rglob(expanded, "*"):
                if child.is_file() and child.suffix.lower() in (".yar", ".yara"):
                    rule_files.append(child)
    return rule_files


def safe_rule_namespace(path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", path.stem) or "rule"


def scan_accounts(root: Path, scan: ArtifactScan) -> None:
    passwd = root / "etc" / "passwd"
    for line_number, line in iter_text_lines(passwd):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, _, uid, gid, comment, home, shell = parts[:7]
        severity = "info"
        detail = f"uid={uid} gid={gid} home={home} shell={shell}"
        if uid == "0" and user != "root":
            severity = "high"
            detail += " uid0_non_root"
        elif shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""):
            severity = "medium"
        add_finding(scan, "user_account", "accounts", passwd, root, severity, line_number, detail, user)

    shadow = root / "etc" / "shadow"
    if shadow.exists():
        try:
            st = shadow.stat()
            detail = f"mode={oct(stat.S_IMODE(st.st_mode))} mtime={format_mtime(st.st_mtime)}"
            add_finding(scan, "shadow_metadata", "accounts", shadow, root, "info", detail=detail)
        except OSError as error:
            add_finding(scan, "shadow_metadata", "accounts", shadow, root, "low", detail=str(error))

    collect_config_lines(scan, root, root / "etc" / "sudoers", "sudoers_entry", "accounts")
    sudoers_d = root / "etc" / "sudoers.d"
    if sudoers_d.exists():
        for path in safe_rglob(sudoers_d, "*"):
            if path.is_file():
                collect_config_lines(scan, root, path, "sudoers_entry", "accounts")

    for home in iter_home_dirs(root):
        auth_keys = home / ".ssh" / "authorized_keys"
        for line_number, line in iter_text_lines(auth_keys):
            if line and not line.startswith("#"):
                severity = "medium"
                detail = "authorized SSH key"
                if "command=" in line or "from=" in line:
                    detail += " with options"
                add_finding(scan, "authorized_key", "accounts", auth_keys, root, severity, line_number, detail, line[:160])


def scan_persistence(root: Path, scan: ArtifactScan) -> None:
    cron_paths = [
        root / "etc" / "crontab",
        root / "var" / "spool" / "cron",
        root / "var" / "spool" / "cron" / "crontabs",
    ]
    cron_dirs = [root / "etc" / name for name in ("cron.d", "cron.hourly", "cron.daily", "cron.weekly", "cron.monthly")]
    for path in cron_paths:
        if path.is_file():
            collect_config_lines(scan, root, path, "cron_entry", "persistence")
        elif path.is_dir():
            for child in safe_rglob(path, "*"):
                if child.is_file():
                    collect_config_lines(scan, root, child, "cron_entry", "persistence")
    for directory in cron_dirs:
        if directory.exists():
            for child in safe_rglob(directory, "*"):
                if child.is_file():
                    collect_config_lines(scan, root, child, "cron_entry", "persistence")

    systemd_dirs = [
        root / "etc" / "systemd" / "system",
        root / "usr" / "local" / "lib" / "systemd" / "system",
    ]
    for directory in systemd_dirs:
        if directory.exists():
            for unit in safe_rglob(directory, "*"):
                if unit.is_file() and unit.suffix in (".service", ".timer", ".socket", ".path"):
                    severity = "medium" if unit.suffix in (".service", ".timer") else "low"
                    add_file_finding(scan, root, unit, "systemd_unit", "persistence", severity)
                    collect_matching_lines(scan, root, unit, "systemd_exec", "persistence", SUSPICIOUS_COMMAND_RE, "high")

    for path in (root / "etc" / "rc.local", root / "etc" / "profile", root / "etc" / "bash.bashrc"):
        collect_config_lines(scan, root, path, "startup_script_entry", "persistence")

    profile_d = root / "etc" / "profile.d"
    if profile_d.exists():
        for path in safe_rglob(profile_d, "*"):
            if path.is_file():
                collect_config_lines(scan, root, path, "startup_script_entry", "persistence")


def scan_histories(root: Path, scan: ArtifactScan) -> None:
    for home in iter_home_dirs(root):
        for name in (".bash_history", ".zsh_history", ".ash_history", ".mysql_history", ".psql_history", ".python_history"):
            path = home / name
            for line_number, line in iter_text_lines(path):
                if not line:
                    continue
                severity = "high" if SUSPICIOUS_COMMAND_RE.search(line) else "info"
                add_finding(scan, "shell_history", "commands", path, root, severity, line_number, value=line[:300])
                collect_iocs(scan, line)


def scan_web(root: Path, scan: ArtifactScan, max_files: int) -> None:
    for base in (root / "var" / "www", root / "srv" / "www"):
        for path in limited_files(base, max_files):
            if path.suffix.lower() in (".php", ".phtml", ".phar", ".js", ".jsp", ".asp", ".aspx"):
                add_recent_or_suspicious_web_file(root, scan, path)
                collect_matching_lines(scan, root, path, "webshell_pattern", "web_compromise", WEBSHELL_RE, "high")
            if "upload" in path.as_posix().lower() or "uploads" in path.as_posix().lower():
                add_file_finding(scan, root, path, "upload_area_file", "web_compromise", "medium")


def scan_filesystem_triage(root: Path, scan: ArtifactScan, max_files: int) -> None:
    areas = [
        root / "etc",
        root / "var" / "www",
        root / "tmp",
        root / "dev" / "shm",
        root / "usr" / "local" / "bin",
    ]
    for area in areas:
        files = list(limited_files(area, max_files))
        for path in sorted(files, key=lambda item: safe_mtime(item), reverse=True)[:300]:
            add_file_finding(scan, root, path, "recent_file", "filesystem", "info")
            if is_executable(path) and area.name in ("tmp", "shm", "bin"):
                add_file_finding(scan, root, path, "executable_file", "filesystem", "medium")


def scan_secret_and_archive_hints(root: Path, scan: ArtifactScan, max_files: int) -> None:
    areas = [root / "etc", root / "home", root / "root", root / "var" / "www", root / "opt"]
    for area in areas:
        for path in limited_files(area, max_files):
            lower = path.name.lower()
            suffixes = [suffix.lower() for suffix in path.suffixes]
            if lower == ".env" or SECRET_RE.search(lower):
                add_file_finding(scan, root, path, "secret_hint_file", "secrets", "medium")
                collect_matching_lines(scan, root, path, "secret_hint_line", "secrets", SECRET_RE, "medium")
            if any(suffix in ARCHIVE_SUFFIXES for suffix in suffixes) or lower.endswith((".tar.gz", ".tar.xz", ".tar.bz2")):
                add_file_finding(scan, root, path, "archive_or_dump", "archives", "low")


def collect_config_lines(scan: ArtifactScan, root: Path, path: Path, kind: str, category: str) -> None:
    for line_number, line in iter_text_lines(path):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            severity = "high" if SUSPICIOUS_COMMAND_RE.search(stripped) else "medium"
            add_finding(scan, kind, category, path, root, severity, line_number, value=stripped[:300])
            collect_iocs(scan, stripped)


def collect_matching_lines(
    scan: ArtifactScan,
    root: Path,
    path: Path,
    kind: str,
    category: str,
    pattern: re.Pattern[str],
    severity: str,
) -> None:
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return
    for line_number, line in iter_text_lines(path):
        if pattern.search(line):
            add_finding(scan, kind, category, path, root, severity, line_number, value=line.strip()[:300])
            collect_iocs(scan, line)


def add_recent_or_suspicious_web_file(root: Path, scan: ArtifactScan, path: Path) -> None:
    severity = "medium" if path.suffix.lower() in (".php", ".phtml", ".phar") else "info"
    add_file_finding(scan, root, path, "web_file", "web_compromise", severity)


def add_file_finding(
    scan: ArtifactScan,
    root: Path,
    path: Path,
    kind: str,
    category: str,
    severity: str,
) -> None:
    try:
        st = path.stat()
    except OSError:
        return
    add_finding(
        scan,
        kind,
        category,
        path,
        root,
        severity,
        detail=f"mode={oct(stat.S_IMODE(st.st_mode))}",
        mtime=format_mtime(st.st_mtime),
        size=st.st_size,
        sha256=sha256_file(path) if st.st_size <= 10 * 1024 * 1024 else "",
    )


def add_finding(
    scan: ArtifactScan,
    kind: str,
    category: str,
    path: Path,
    root: Path,
    severity: str = "info",
    line_number: int = 0,
    detail: str = "",
    value: str = "",
    mtime: str = "",
    size: int = 0,
    sha256: str = "",
) -> None:
    scan.findings.append(
        ArtifactFinding(
            kind=kind,
            category=category,
            path=relative(root, path),
            severity=severity,
            line_number=line_number,
            detail=detail,
            value=value,
            mtime=mtime,
            size=size,
            sha256=sha256,
        )
    )
    collect_iocs(scan, " ".join(part for part in (detail, value, sha256) if part))


def collect_iocs(scan: ArtifactScan, text: str) -> None:
    scan.urls.update(URL_RE.findall(text))
    scan.hashes.update(HASH_RE.findall(text))
    scan.emails.update(EMAIL_RE.findall(text))
    for domain in DOMAIN_RE.findall(text):
        if not domain.lower().endswith((".log", ".service", ".local", ".socket", ".target")):
            scan.domains.add(domain.lower())


def iter_home_dirs(root: Path) -> Iterator[Path]:
    root_home = root / "root"
    if root_home.exists():
        yield root_home
    home_root = root / "home"
    if home_root.exists():
        for child in safe_iterdir(home_root):
            if child.is_dir():
                yield child


def iter_text_lines(path: Path, max_line_bytes: int = 1024 * 1024) -> Iterator[tuple[int, str]]:
    if not path.exists() or not path.is_file():
        return
    try:
        with path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if len(raw_line) > max_line_bytes:
                    continue
                yield line_number, raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
    except OSError:
        return


def limited_files(base: Path, limit: int) -> Iterator[Path]:
    count = 0
    for path in safe_rglob(base, "*"):
        if path.is_file():
            yield path
            count += 1
            if count >= limit:
                return


def safe_iterdir(path: Path) -> Iterator[Path]:
    try:
        yield from path.iterdir()
    except OSError:
        return


def safe_rglob(path: Path, pattern: str) -> Iterator[Path]:
    if not path.exists():
        return
    try:
        yield from path.rglob(pattern)
    except OSError:
        return


def safe_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0


def is_executable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def format_mtime(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
