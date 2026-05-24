from __future__ import annotations

import bz2
import gzip
import io
import ipaddress
import lzma
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

import zstandard

from .artifacts import ArtifactScan, scan_artifacts
from .threats import INJECTION_KINDS, classify_command_threat, classify_url_threat


IP_RE = re.compile(
    r"(?<![A-Za-z0-9_.:-])"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4})"
    r"(?![A-Za-z0-9_.:-])"
)
WEB_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)
FAILED_AUTH_RE = re.compile(
    r"(?:Failed password|Invalid user|authentication failure|Connection closed by invalid user).*?"
    r"(?:from|rhost=)\s+(?P<ip>[^\s]+)",
    re.IGNORECASE,
)
ACCEPTED_AUTH_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[^\s]+)",
    re.IGNORECASE,
)
SUDO_RE = re.compile(r"\bsudo\b.*?\bUSER=(?P<user>\S+)", re.IGNORECASE)

LOG_NAME_RE = re.compile(
    r"("
    r"access|error|auth|secure|syslog|messages|audit|kern|daemon|mail|ufw|"
    r"firewall|fail2ban|cron|sudo|ssh|nginx|apache|apache2|httpd"
    r")",
    re.IGNORECASE,
)
ROTATED_LOG_RE = re.compile(r"\.log(?:\.\d+)?(?:\.(?:gz|bz2|xz|zst))?$", re.IGNORECASE)
SKIP_LOG_SUFFIXES = {".journal", ".idx", ".db", ".sqlite", ".sock"}


@dataclass(frozen=True)
class ScanOptions:
    root: Path
    include_private: bool = True
    max_line_bytes: int = 1024 * 1024
    yara_rules: list[Path] = field(default_factory=list)
    builtin_yara: bool = True


@dataclass
class Event:
    ip: str
    kind: str
    source: str
    line_number: int
    timestamp: str = ""
    method: str = ""
    url: str = ""
    status: str = ""
    user: str = ""
    referrer: str = ""
    user_agent: str = ""
    category: str = "other"
    raw: str = ""


@dataclass
class IpStats:
    ip: str
    total_events: int = 0
    web_requests: int = 0
    suspicious_web_requests: int = 0
    failed_logins: int = 0
    successful_logins: int = 0
    other_hits: int = 0
    sources: Counter[str] = field(default_factory=Counter)
    statuses: Counter[str] = field(default_factory=Counter)
    users: Counter[str] = field(default_factory=Counter)
    urls: Counter[str] = field(default_factory=Counter)
    user_agents: Counter[str] = field(default_factory=Counter)
    referrers: Counter[str] = field(default_factory=Counter)

    @property
    def attack_score(self) -> int:
        return (
            self.web_requests
            + self.failed_logins
            + (self.suspicious_web_requests * 5)
            + (self.successful_logins * 3)
        )


@dataclass
class ScanResult:
    root: Path
    os_type: str
    files_scanned: int
    scanned_files: list[str]
    skipped_files: list[str]
    events: list[Event]
    ip_stats: dict[str, IpStats]
    artifacts: ArtifactScan


def scan_backup(options: ScanOptions) -> ScanResult:
    from .detect import detect_backup_os

    root = options.root.resolve()
    os_type = detect_backup_os(root)

    if os_type == "windows":
        from .windows_scanner import scan_windows_backup

        return scan_windows_backup(options)
    if os_type == "linux":
        return scan_linux_backup(options)

    return ScanResult(
        root=root,
        os_type="unknown",
        files_scanned=0,
        scanned_files=[],
        skipped_files=["Could not detect Linux or Windows backup layout under --root"],
        events=[],
        ip_stats={},
        artifacts=ArtifactScan(),
    )


def scan_linux_backup(options: ScanOptions) -> ScanResult:
    root = options.root.resolve()
    events: list[Event] = []
    scanned_files: list[str] = []
    skipped_files: list[str] = []

    for log_path in discover_log_files(root):
        scanned_files.append(relative_source(root, log_path))
        for event in scan_log_file(root, log_path, options):
            events.append(event)

    journal_dir = root / "var" / "log" / "journal"
    if journal_dir.exists():
        if shutil.which("journalctl"):
            scanned_files.append("var/log/journal")
            events.extend(scan_journal(root, journal_dir, options))
        else:
            skipped_files.append("var/log/journal - journalctl not found")

    artifacts = scan_artifacts(root, yara_rules=options.yara_rules, builtin_yara=options.builtin_yara)

    return ScanResult(
        root=root,
        os_type="linux",
        files_scanned=len(scanned_files),
        scanned_files=scanned_files,
        skipped_files=skipped_files,
        events=events,
        ip_stats=build_ip_stats(events),
        artifacts=artifacts,
    )


def discover_log_files(root: Path) -> Iterator[Path]:
    search_root = root / "var" / "log"
    if not search_root.exists():
        search_root = root

    for path in search_root.rglob("*"):
        if path.is_file() and is_probable_log(path, search_root):
            yield path


def is_probable_log(path: Path, search_root: Path) -> bool:
    name = path.name.lower()
    if path.suffix.lower() in SKIP_LOG_SUFFIXES:
        return False
    if ROTATED_LOG_RE.search(name):
        return True
    if LOG_NAME_RE.search(name):
        return True
    try:
        path.relative_to(search_root)
    except ValueError:
        return False
    return name.endswith((".gz", ".bz2", ".xz", ".zst")) or "." not in name


def scan_log_file(root: Path, path: Path, options: ScanOptions) -> Iterator[Event]:
    try:
        stream = open_log_binary(path)
    except OSError:
        return

    with stream:
        for line_number, raw_line in enumerate(stream, start=1):
            if len(raw_line) > options.max_line_bytes:
                continue
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            for event in parse_line(root, path, line_number, line, options):
                yield event


def scan_journal(root: Path, journal_dir: Path, options: ScanOptions) -> list[Event]:
    source = relative_source(root, journal_dir)
    command = [
        "journalctl",
        f"--directory={journal_dir}",
        "--no-pager",
        "--output=short-iso",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return []

    events: list[Event] = []
    if completed.returncode != 0:
        return events

    for line_number, line in enumerate(completed.stdout.splitlines(), start=1):
        for event in parse_journal_line(source, line_number, line, options):
            events.append(event)
    return events


def parse_journal_line(
    source: str,
    line_number: int,
    line: str,
    options: ScanOptions,
) -> Iterable[Event]:
    failed = FAILED_AUTH_RE.search(line)
    if failed:
        ip = normalize_ip(failed.group("ip"), options.include_private)
        if ip:
            yield Event(
                ip=ip,
                kind="failed_login",
                source=source,
                line_number=line_number,
                timestamp=line[:25].strip(),
                category="auth",
                raw=line,
            )
        return

    accepted = ACCEPTED_AUTH_RE.search(line)
    if accepted:
        ip = normalize_ip(accepted.group("ip"), options.include_private)
        if ip:
            yield Event(
                ip=ip,
                kind="successful_login",
                source=source,
                line_number=line_number,
                timestamp=line[:25].strip(),
                user=accepted.group("user"),
                category="auth",
                raw=line,
            )
        return

    for ip in extract_ips(line, options.include_private):
        yield Event(
            ip=ip,
            kind="ip_observed",
            source=source,
            line_number=line_number,
            timestamp=line[:25].strip(),
            category="system",
            raw=line,
        )


def open_log_binary(path: Path) -> BinaryIO:
    suffix = path.suffix.lower()
    if suffix == ".gz":
        return gzip.open(path, "rb")
    if suffix == ".bz2":
        return bz2.open(path, "rb")
    if suffix == ".xz":
        return lzma.open(path, "rb")
    if suffix == ".zst":
        handle = path.open("rb")
        reader = zstandard.ZstdDecompressor().stream_reader(handle, closefd=True)
        return io.BufferedReader(reader)  # type: ignore[arg-type]
    return path.open("rb")


def relative_source(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def parse_line(
    root: Path,
    path: Path,
    line_number: int,
    line: str,
    options: ScanOptions,
) -> Iterable[Event]:
    source = relative_source(root, path)
    category = categorize_log(path)

    web_event = parse_web_line(source, line_number, line, options, category)
    if web_event is not None:
        yield web_event
        return

    failed = FAILED_AUTH_RE.search(line)
    if failed:
        ip = normalize_ip(failed.group("ip"), options.include_private)
        if ip:
            yield Event(
                ip=ip,
                kind="failed_login",
                source=source,
                line_number=line_number,
                timestamp=extract_syslog_timestamp(line),
                category=category,
                raw=line,
            )
        return

    accepted = ACCEPTED_AUTH_RE.search(line)
    if accepted:
        ip = normalize_ip(accepted.group("ip"), options.include_private)
        if ip:
            yield Event(
                ip=ip,
                kind="successful_login",
                source=source,
                line_number=line_number,
                timestamp=extract_syslog_timestamp(line),
                user=accepted.group("user"),
                category=category,
                raw=line,
            )
        return

    if SUDO_RE.search(line):
        for ip in extract_ips(line, options.include_private):
            yield Event(
                ip=ip,
                kind="sudo_context",
                source=source,
                line_number=line_number,
                timestamp=extract_syslog_timestamp(line),
                category=category,
                raw=line,
            )
        return

    command_threat = classify_command_threat(line)
    if command_threat:
        ips = list(extract_ips(line, options.include_private))
        if ips:
            for ip in ips:
                yield Event(
                    ip=ip,
                    kind=command_threat,
                    source=source,
                    line_number=line_number,
                    timestamp=extract_syslog_timestamp(line),
                    category="threats",
                    raw=line,
                )
            return

    for ip in extract_ips(line, options.include_private):
        yield Event(
            ip=ip,
            kind="ip_observed",
            source=source,
            line_number=line_number,
            timestamp=extract_syslog_timestamp(line),
            category=category,
            raw=line,
        )


def parse_web_line(
    source: str,
    line_number: int,
    line: str,
    options: ScanOptions,
    category: str,
) -> Event | None:
    match = WEB_RE.match(line)
    if not match:
        return None

    ip = normalize_ip(match.group("ip"), options.include_private)
    if not ip:
        return None

    request = match.group("request")
    method = ""
    url = request
    request_parts = request.split()
    if len(request_parts) >= 2:
        method = request_parts[0]
        url = request_parts[1]

    threat_kind = classify_url_threat(url)
    kind = threat_kind or "web_request"
    return Event(
        ip=ip,
        kind=kind,
        source=source,
        line_number=line_number,
        timestamp=match.group("timestamp"),
        method=method,
        url=url,
        status=match.group("status"),
        referrer=match.group("referrer") or "",
        user_agent=match.group("user_agent") or "",
        category="web" if category == "other" else category,
        raw=line,
    )


def categorize_log(path: Path) -> str:
    normalized = str(path).replace("\\", "/").lower()
    name = path.name.lower()
    if any(part in normalized for part in ("/nginx/", "/apache2/", "/apache/", "/httpd/")):
        return "web"
    if "access" in name or "error" in name:
        return "web"
    if any(part in name for part in ("auth", "secure", "ssh", "sudo", "fail2ban")):
        return "auth"
    if any(part in name for part in ("ufw", "firewall", "iptables", "audit")):
        return "security"
    if any(part in name for part in ("syslog", "messages", "kern", "daemon", "cron", "mail")):
        return "system"
    return "other"


def normalize_ip(value: str, include_private: bool) -> str | None:
    cleaned = value.strip("[],:;\"'")
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return None
    if not include_private and not ip.is_global:
        return None
    return str(ip)


def extract_ips(line: str, include_private: bool) -> Iterator[str]:
    seen: set[str] = set()
    for match in IP_RE.finditer(line):
        ip = normalize_ip(match.group("ip"), include_private)
        if ip and ip not in seen:
            seen.add(ip)
            yield ip


def extract_syslog_timestamp(line: str) -> str:
    # Syslog often starts with "May 17 10:20:30"; keep it as evidence text.
    return line[:15].strip() if len(line) >= 15 and line[3:4] == " " else ""


def is_suspicious_url(url: str) -> bool:
    return classify_url_threat(url) is not None


def build_ip_stats(events: Iterable[Event]) -> dict[str, IpStats]:
    stats: dict[str, IpStats] = defaultdict(lambda: IpStats(ip=""))
    for event in events:
        item = stats[event.ip]
        item.ip = event.ip
        item.total_events += 1
        item.sources[event.source] += 1

        if event.kind == "web_request":
            item.web_requests += 1
        elif event.kind in INJECTION_KINDS:
            item.web_requests += 1
            item.suspicious_web_requests += 1
        elif event.kind == "failed_login":
            item.failed_logins += 1
        elif event.kind == "successful_login":
            item.successful_logins += 1
        else:
            item.other_hits += 1

        if event.status:
            item.statuses[event.status] += 1
        if event.user:
            item.users[event.user] += 1
        if event.url:
            item.urls[event.url] += 1
        if event.user_agent:
            item.user_agents[event.user_agent] += 1
        if event.referrer:
            item.referrers[event.referrer] += 1

    return dict(stats)
