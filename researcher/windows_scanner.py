from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from .artifacts import ArtifactScan, iter_text_lines
from .scanner import (
    Event,
    ScanOptions,
    ScanResult,
    build_ip_stats,
    normalize_ip,
    relative_source,
)
from .threats import classify_url_threat

FAILED_LOGON_RE = re.compile(r"<EventID>4625</EventID>.*?<Data Name=['\"]IpAddress['\"]>(?P<ip>[^<]+)</Data>", re.DOTALL)
SUCCESS_LOGON_RE = re.compile(r"<EventID>4624</EventID>.*?<Data Name=['\"]IpAddress['\"]>(?P<ip>[^<]+)</Data>", re.DOTALL)


def scan_windows_backup(options: ScanOptions) -> ScanResult:
    from .windows_artifacts import scan_windows_artifacts

    root = options.root.resolve()
    events: list[Event] = []
    scanned_files: list[str] = []
    skipped_files: list[str] = []

    for log_path in discover_iis_logs(root):
        scanned_files.append(relative_source(root, log_path))
        for event in scan_iis_log(root, log_path, options):
            events.append(event)

    security_evtx = root / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    if security_evtx.exists():
        evtx_events, evtx_note = scan_security_evtx(root, security_evtx, options)
        if evtx_events:
            scanned_files.append(relative_source(root, security_evtx))
            events.extend(evtx_events)
        elif evtx_note:
            skipped_files.append(evtx_note)

    artifacts = scan_windows_artifacts(
        root,
        yara_rules=options.yara_rules,
        builtin_yara=options.builtin_yara,
    )

    return ScanResult(
        root=root,
        os_type="windows",
        files_scanned=len(scanned_files),
        scanned_files=scanned_files,
        skipped_files=skipped_files,
        events=events,
        ip_stats=build_ip_stats(events),
        artifacts=artifacts,
    )


def discover_iis_logs(root: Path) -> Iterator[Path]:
    logs_root = root / "inetpub" / "logs" / "LogFiles"
    if not logs_root.exists():
        return
    for path in logs_root.rglob("*"):
        if path.is_file() and path.suffix.lower() == ".log":
            yield path


def scan_iis_log(root: Path, path: Path, options: ScanOptions) -> Iterator[Event]:
    source = relative_source(root, path)
    fields: list[str] = []

    for line_number, line in iter_text_lines(path):
        if line.startswith("#Fields:"):
            fields = line.split(":", 1)[1].strip().split()
            continue
        if line.startswith("#") or not line.strip() or not fields:
            continue

        row = split_w3c_fields(fields, line)
        if row is None:
            continue

        ip = normalize_ip(row.get("c-ip", ""), options.include_private)
        if not ip:
            continue

        url = row.get("cs-uri-stem", "")
        if row.get("cs-uri-query") and row["cs-uri-query"] != "-":
            url = f"{url}?{row['cs-uri-query']}"
        status = row.get("sc-status", "")
        method = row.get("cs-method", "")
        user_agent = row.get("cs(User-Agent)", "")
        timestamp = f"{row.get('date', '')} {row.get('time', '')}".strip()
        threat_kind = classify_url_threat(url)
        kind = threat_kind or "web_request"

        yield Event(
            ip=ip,
            kind=kind,
            source=source,
            line_number=line_number,
            timestamp=timestamp,
            method=method,
            url=url,
            status=status,
            user_agent=user_agent,
            category="web",
            raw=line,
        )


def split_w3c_fields(fields: list[str], line: str) -> dict[str, str] | None:
    parts = line.split()
    if len(parts) == len(fields):
        return dict(zip(fields, parts))
    if len(parts) < len(fields):
        return None
    if "cs(User-Agent)" not in fields:
        return dict(zip(fields, parts[: len(fields)]))

    ua_index = fields.index("cs(User-Agent)")
    before = fields[:ua_index]
    after = fields[ua_index + 1 :]
    before_count = len(before)
    after_count = len(after)
    merged = parts[:before_count]
    ua_end = len(parts) - after_count
    merged.append(" ".join(parts[before_count:ua_end]))
    merged.extend(parts[ua_end:])
    if len(merged) != len(fields):
        return None
    return dict(zip(fields, merged))


def scan_security_evtx(root: Path, path: Path, options: ScanOptions) -> tuple[list[Event], str | None]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore[import-not-found]
    except ImportError:
        return [], f"{relative_source(root, path)} - python-evtx not installed"

    source = relative_source(root, path)
    events: list[Event] = []
    try:
        with Evtx(str(path)) as log:
            for line_number, record in enumerate(log.records(), start=1):
                xml = record.xml()
                for pattern, kind in ((FAILED_LOGON_RE, "failed_login"), (SUCCESS_LOGON_RE, "successful_login")):
                    match = pattern.search(xml)
                    if not match:
                        continue
                    ip = normalize_ip(match.group("ip"), options.include_private)
                    if ip and ip not in {"-", "::1", "127.0.0.1"}:
                        events.append(
                            Event(
                                ip=ip,
                                kind=kind,
                                source=source,
                                line_number=line_number,
                                category="auth",
                                raw=xml[:500],
                            )
                        )
    except OSError as error:
        return [], f"{source} - {error}"
    return events, None
