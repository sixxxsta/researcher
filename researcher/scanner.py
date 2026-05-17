from __future__ import annotations

import bz2
import gzip
import ipaddress
import lzma
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator


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
ROTATED_LOG_RE = re.compile(r"\.log(?:\.\d+)?(?:\.(?:gz|bz2|xz))?$", re.IGNORECASE)

SUSPICIOUS_PATH_PARTS = (
    "../",
    "%2e%2e",
    "/.env",
    "/.git",
    "wp-login.php",
    "xmlrpc.php",
    "phpmyadmin",
    "adminer",
    "shell",
    "webshell",
    "cmd=",
    "exec=",
    "passwd",
    "/etc/",
    "base64",
    "eval(",
    "union+select",
    "union%20select",
    "<script",
    "%3cscript",
)


@dataclass(frozen=True)
class ScanOptions:
    root: Path
    include_private: bool = False
    max_line_bytes: int = 1024 * 1024


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
    user_agent: str = ""
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
    files_scanned: int
    events: list[Event]
    ip_stats: dict[str, IpStats]


def scan_backup(options: ScanOptions) -> ScanResult:
    root = options.root.resolve()
    events: list[Event] = []
    files_scanned = 0

    for log_path in discover_log_files(root):
        files_scanned += 1
        for event in scan_log_file(root, log_path, options):
            events.append(event)

    return ScanResult(
        root=root,
        files_scanned=files_scanned,
        events=events,
        ip_stats=build_ip_stats(events),
    )


def discover_log_files(root: Path) -> Iterator[Path]:
    search_root = root / "var" / "log"
    if not search_root.exists():
        search_root = root

    for path in search_root.rglob("*"):
        if path.is_file() and is_probable_log(path):
            yield path


def is_probable_log(path: Path) -> bool:
    name = path.name.lower()
    full_name = str(path).lower()
    if ROTATED_LOG_RE.search(name):
        return True
    if LOG_NAME_RE.search(name):
        return True
    return "/var/log/" in full_name.replace("\\", "/") and (
        name.endswith((".gz", ".bz2", ".xz")) or "." not in name
    )


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


def open_log_binary(path: Path) -> BinaryIO:
    suffix = path.suffix.lower()
    if suffix == ".gz":
        return gzip.open(path, "rb")
    if suffix == ".bz2":
        return bz2.open(path, "rb")
    if suffix == ".xz":
        return lzma.open(path, "rb")
    return path.open("rb")


def parse_line(
    root: Path,
    path: Path,
    line_number: int,
    line: str,
    options: ScanOptions,
) -> Iterable[Event]:
    source = str(path.relative_to(root))

    web_event = parse_web_line(source, line_number, line, options)
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
            raw=line,
        )


def parse_web_line(
    source: str,
    line_number: int,
    line: str,
    options: ScanOptions,
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

    kind = "suspicious_web_request" if is_suspicious_url(url) else "web_request"
    return Event(
        ip=ip,
        kind=kind,
        source=source,
        line_number=line_number,
        timestamp=match.group("timestamp"),
        method=method,
        url=url,
        status=match.group("status"),
        user_agent=match.group("user_agent") or "",
        raw=line,
    )


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
    lowered = url.lower()
    return any(part in lowered for part in SUSPICIOUS_PATH_PARTS)


def build_ip_stats(events: Iterable[Event]) -> dict[str, IpStats]:
    stats: dict[str, IpStats] = defaultdict(lambda: IpStats(ip=""))
    for event in events:
        item = stats[event.ip]
        item.ip = event.ip
        item.total_events += 1
        item.sources[event.source] += 1

        if event.kind == "web_request":
            item.web_requests += 1
        elif event.kind == "suspicious_web_request":
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

    return dict(stats)
