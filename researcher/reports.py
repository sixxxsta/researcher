from __future__ import annotations

import csv
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import DOMAIN_RE, HASH_RE, SUSPICIOUS_COMMAND_RE, URL_RE, ArtifactFinding
from .scanner import Event, IpStats, ScanResult


def write_reports(result: ScanResult, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    ranked = rank_attackers(result.ip_stats.values())

    write_executive_summary(out_dir / "summary.txt", result, ranked)
    write_markdown_report(out_dir / "report.md", result, ranked)
    write_attackers_txt(out_dir / "attackers.txt", result, ranked)
    write_scanned_files_txt(out_dir / "scanned_files.txt", result)
    write_events_csv(out_dir / "events.csv", result.events)
    write_split_event_reports(out_dir / "events", result.events)
    write_timeline_reports(out_dir, result)
    write_compromise_indicators(out_dir / "indicators", result, ranked)
    write_ioc_exports(out_dir / "iocs", result)
    write_artifact_reports(out_dir, result.artifacts.findings)
    write_downloaded_payloads_report(out_dir / "commands" / "downloaded_payloads.txt", result)
    write_network_artifacts_report(out_dir / "network" / "network_artifacts.txt", result)
    write_summary_json(out_dir / "summary.json", result, ranked)


def rank_attackers(stats: Any) -> list[IpStats]:
    return sorted(
        stats,
        key=lambda item: (
            risk_score(item),
            item.web_requests,
            item.failed_logins,
            item.suspicious_web_requests,
            item.total_events,
        ),
        reverse=True,
    )


def write_attackers_txt(path: Path, result: ScanResult, ranked: list[IpStats]) -> None:
    lines: list[str] = []
    lines.append("Researcher forensic scan report")
    lines.append(f"Generated UTC: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Root: {result.root}")
    lines.append(f"Log files scanned: {result.files_scanned}")
    lines.append(f"Unique IPs: {len(result.ip_stats)}")
    lines.append("")
    lines.append("Ranking is sorted by attack score:")
    lines.append("score = web_requests + failed_logins + suspicious_web_requests*5 + successful_logins*3")
    lines.append("")
    if result.skipped_files:
        lines.append("Skipped inputs:")
        for skipped in result.skipped_files:
            lines.append(f"   {skipped}")
        lines.append("")

    if not ranked:
        lines.append("No IP evidence found.")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return

    for index, item in enumerate(ranked, start=1):
        lines.append(f"{index}. {item.ip}")
        lines.append(f"   attack_score: {item.attack_score}")
        lines.append(f"   total_events: {item.total_events}")
        lines.append(f"   web_requests: {item.web_requests}")
        lines.append(f"   suspicious_web_requests: {item.suspicious_web_requests}")
        lines.append(f"   failed_logins: {item.failed_logins}")
        lines.append(f"   successful_logins: {item.successful_logins}")
        lines.append(f"   other_hits: {item.other_hits}")
        append_counter(lines, "statuses", item.statuses)
        append_counter(lines, "top_urls", item.urls)
        append_counter(lines, "users", item.users)
        append_counter(lines, "user_agents", item.user_agents)
        append_counter(lines, "referrers", item.referrers)
        append_counter(lines, "sources", item.sources)
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_scanned_files_txt(path: Path, result: ScanResult) -> None:
    event_counts = Counter(event.source for event in result.events)
    category_counts = Counter(event.category for event in result.events)
    lines = [
        "Scanned log files",
        f"Root: {result.root}",
        f"Total files: {result.files_scanned}",
        "",
        "Event categories:",
    ]
    if category_counts:
        for category, count in category_counts.most_common():
            lines.append(f"  {category}: {count}")
    else:
        lines.append("  no events extracted")

    lines.append("")
    lines.append("Files:")
    for source in sorted(result.scanned_files):
        lines.append(f"  {source} - events: {event_counts[source]}")

    if result.skipped_files:
        lines.append("")
        lines.append("Skipped:")
        for skipped in result.skipped_files:
            lines.append(f"  {skipped}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_counter(lines: list[str], label: str, counter: Counter[str], limit: int = 8) -> None:
    if not counter:
        return
    values = ", ".join(f"{value} ({count})" for value, count in counter.most_common(limit))
    lines.append(f"   {label}: {values}")


def write_events_csv(path: Path, events: list[Event]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "kind",
                "timestamp",
                "source",
                "category",
                "line_number",
                "method",
                "url",
                "status",
                "user",
                "referrer",
                "user_agent",
                "raw",
            ],
        )
        writer.writeheader()
        for event in events:
            writer.writerow(
                {
                    "ip": event.ip,
                    "kind": event.kind,
                    "timestamp": event.timestamp,
                    "source": event.source,
                    "category": event.category,
                    "line_number": event.line_number,
                    "method": event.method,
                    "url": event.url,
                    "status": event.status,
                    "user": event.user,
                    "referrer": event.referrer,
                    "user_agent": event.user_agent,
                    "raw": event.raw,
                }
            )


def write_executive_summary(path: Path, result: ScanResult, ranked: list[IpStats]) -> None:
    high_findings = [finding for finding in result.artifacts.findings if finding.severity == "high"]
    medium_findings = [finding for finding in result.artifacts.findings if finding.severity == "medium"]
    successful = [event for event in result.events if event.kind == "successful_login"]
    suspicious_web = [event for event in result.events if event.kind == "suspicious_web_request"]
    compromise = compromise_candidates(result)

    lines = [
        "Researcher executive summary",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        f"Root: {result.root}",
        "",
        "Totals:",
        f"  scanned log inputs: {result.files_scanned}",
        f"  events: {len(result.events)}",
        f"  unique IPs: {len(result.ip_stats)}",
        f"  artifact findings: {len(result.artifacts.findings)}",
        f"  high artifact findings: {len(high_findings)}",
        f"  medium artifact findings: {len(medium_findings)}",
        f"  successful logins: {len(successful)}",
        f"  suspicious web requests: {len(suspicious_web)}",
        f"  brute-force-then-success candidates: {len(compromise)}",
        "",
        "Top suspicious IPs:",
    ]
    if ranked:
        for item in ranked[:10]:
            lines.append(
                f"  {item.ip} score={risk_score(item)} level={risk_level(item)} "
                f"events={item.total_events} failed={item.failed_logins} "
                f"success={item.successful_logins} suspicious_web={item.suspicious_web_requests}"
            )
    else:
        lines.append("  none")

    lines.extend(["", "Important artifact findings:"])
    important = sorted(result.artifacts.findings, key=finding_sort_key)[:25]
    if important:
        for finding in important:
            where = f"{finding.path}:{finding.line_number}" if finding.line_number else finding.path
            lines.append(f"  [{finding.severity}] {finding.kind} {where} {finding.value or finding.detail}")
    else:
        lines.append("  none")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_markdown_report(path: Path, result: ScanResult, ranked: list[IpStats]) -> None:
    high_findings = [finding for finding in result.artifacts.findings if finding.severity == "high"]
    medium_findings = [finding for finding in result.artifacts.findings if finding.severity == "medium"]
    successful = [event for event in result.events if event.kind == "successful_login"]
    suspicious_web = [event for event in result.events if event.kind == "suspicious_web_request"]
    compromise = compromise_candidates(result)

    lines = [
        "# Researcher Incident Report",
        "",
        f"- Generated UTC: `{datetime.now(timezone.utc).isoformat()}`",
        f"- Root: `{result.root}`",
        f"- Scanned log inputs: `{result.files_scanned}`",
        f"- Events: `{len(result.events)}`",
        f"- Unique IPs: `{len(result.ip_stats)}`",
        f"- Artifact findings: `{len(result.artifacts.findings)}`",
        "",
        "## Executive Summary",
        "",
        f"- Successful logins: **{len(successful)}**",
        f"- Suspicious web requests: **{len(suspicious_web)}**",
        f"- Brute-force-then-success candidates: **{len(compromise)}**",
        f"- High artifact findings: **{len(high_findings)}**",
        f"- Medium artifact findings: **{len(medium_findings)}**",
        "",
        "## Top Suspicious IPs",
        "",
    ]
    if ranked:
        lines.extend(
            markdown_table(
                ["IP", "Risk", "Score", "Events", "Failed", "Success", "Suspicious Web", "Top Sources"],
                [
                    [
                        item.ip,
                        risk_level(item),
                        str(risk_score(item)),
                        str(item.total_events),
                        str(item.failed_logins),
                        str(item.successful_logins),
                        str(item.suspicious_web_requests),
                        markdown_counter(item.sources, 3),
                    ]
                    for item in ranked[:10]
                ],
            )
        )
    else:
        lines.append("No IP evidence found.")

    lines.extend(["", "## Successful Login After Brute Force", ""])
    if compromise:
        lines.extend(
            markdown_table(
                ["IP", "Failed Logins", "Successful Logins", "Users", "Sources"],
                [
                    [
                        item.ip,
                        str(item.failed_logins),
                        str(item.successful_logins),
                        markdown_counter(item.users, 5),
                        markdown_counter(item.sources, 5),
                    ]
                    for item in compromise[:20]
                ],
            )
        )
    else:
        lines.append("No IP had both failed and successful login evidence.")

    lines.extend(["", "## Important Artifact Findings", ""])
    important = sorted(result.artifacts.findings, key=finding_sort_key)[:30]
    if important:
        lines.extend(
            markdown_table(
                ["Severity", "Kind", "Path", "Line", "Value"],
                [
                    [
                        finding.severity,
                        finding.kind,
                        finding.path,
                        str(finding.line_number or ""),
                        truncate_markdown(finding.value or finding.detail, 140),
                    ]
                    for finding in important
                ],
            )
        )
    else:
        lines.append("No artifact findings.")

    lines.extend(["", "## Suspicious Web Requests", ""])
    if suspicious_web:
        lines.extend(
            markdown_table(
                ["IP", "Status", "URL", "Source", "Line"],
                [
                    [
                        event.ip,
                        event.status,
                        truncate_markdown(event.url, 100),
                        event.source,
                        str(event.line_number),
                    ]
                    for event in suspicious_web[:30]
                ],
            )
        )
    else:
        lines.append("No suspicious web requests found.")

    lines.extend(["", "## Report Files", ""])
    lines.extend(
        [
            "- `summary.txt` - short text summary.",
            "- `attackers.txt` - detailed IP ranking.",
            "- `timeline.csv` and `timeline.txt` - chronological events and artifacts.",
            "- `events.csv` and `events/` - raw event tables.",
            "- `indicators/` - risk scores and compromise indicators.",
            "- `iocs/` - IP, URL, domain, hash, email and user-agent exports.",
            "- `accounts/`, `persistence/`, `commands/`, `web_compromise/`, `filesystem/`, `secrets/`, `archives/` - artifact triage.",
            "- `yara/` - YARA matches or YARA availability/compile diagnostics when `--yara-rules` is used.",
        ]
    )

    if result.skipped_files:
        lines.extend(["", "## Skipped Inputs", ""])
        for skipped in result.skipped_files:
            lines.append(f"- `{skipped}`")

    lines.extend(["", "## Suggested Manual Checks", ""])
    lines.extend(
        [
            "1. Verify all critical/high findings against the original evidence paths.",
            "2. Review successful SSH logins and nearby sudo/history activity.",
            "3. Inspect webshell-like files and upload directories manually.",
            "4. Check persistence findings before restoring the server.",
            "5. Export IOCs from `iocs/` into blocking and hunting systems.",
        ]
    )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_split_event_reports(out_dir: Path, events: list[Event]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    by_category: dict[str, list[Event]] = {}
    by_source: dict[str, list[Event]] = {}
    for event in events:
        by_category.setdefault(event.category, []).append(event)
        by_source.setdefault(event.source, []).append(event)

    for category, category_events in sorted(by_category.items()):
        write_events_csv(out_dir / f"{category}.csv", category_events)

    source_dir = out_dir / "by-source"
    source_dir.mkdir(exist_ok=True)
    for source, source_events in sorted(by_source.items()):
        write_events_csv(source_dir / f"{safe_filename(source)}.csv", source_events)


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return cleaned.strip("._") or "log"


def write_timeline_reports(out_dir: Path, result: ScanResult) -> None:
    rows: list[dict[str, Any]] = []
    for event in result.events:
        rows.append(
            {
                "sort_time": event_sort_time(event),
                "timestamp": event.timestamp,
                "record_type": "event",
                "kind": event.kind,
                "category": event.category,
                "source": event.source,
                "line_number": event.line_number,
                "ip": event.ip,
                "summary": event.url or event.user or event.raw[:180],
                "raw": event.raw,
            }
        )
    for finding in result.artifacts.findings:
        rows.append(
            {
                "sort_time": finding.mtime,
                "timestamp": finding.mtime,
                "record_type": "artifact",
                "kind": finding.kind,
                "category": finding.category,
                "source": finding.path,
                "line_number": finding.line_number,
                "ip": "",
                "summary": finding.value or finding.detail,
                "raw": finding.value or finding.detail,
            }
        )

    rows.sort(key=lambda row: row["sort_time"] or "9999")
    timeline_csv = out_dir / "timeline.csv"
    with timeline_csv.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = ["timestamp", "record_type", "kind", "category", "source", "line_number", "ip", "summary", "raw"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row[name] for name in fieldnames})

    lines = ["Researcher timeline", ""]
    for row in rows[:1000]:
        lines.append(
            f"{row['timestamp'] or 'unknown'} [{row['record_type']}/{row['kind']}] "
            f"{row['source']}:{row['line_number']} {row['ip']} {row['summary']}"
        )
    (out_dir / "timeline.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_compromise_indicators(out_dir: Path, result: ScanResult, ranked: list[IpStats]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    candidates = compromise_candidates(result)
    lines = ["Successful compromise indicators", ""]
    if not candidates:
        lines.append("No IPs had both failed and successful login evidence.")
    for item in candidates:
        lines.append(
            f"{item.ip} failed_logins={item.failed_logins} successful_logins={item.successful_logins} "
            f"score={risk_score(item)} users={', '.join(item.users)} sources={', '.join(item.sources)}"
        )
    (out_dir / "successful_logins_after_bruteforce.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    with (out_dir / "risk_scores.csv").open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "ip",
            "risk_level",
            "risk_score",
            "events",
            "web_requests",
            "suspicious_web_requests",
            "failed_logins",
            "successful_logins",
            "top_sources",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in ranked:
            writer.writerow(
                {
                    "ip": item.ip,
                    "risk_level": risk_level(item),
                    "risk_score": risk_score(item),
                    "events": item.total_events,
                    "web_requests": item.web_requests,
                    "suspicious_web_requests": item.suspicious_web_requests,
                    "failed_logins": item.failed_logins,
                    "successful_logins": item.successful_logins,
                    "top_sources": "; ".join(f"{source} ({count})" for source, count in item.sources.most_common(5)),
                }
            )


def write_ioc_exports(out_dir: Path, result: ScanResult) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    urls = set(result.artifacts.urls)
    domains = set(result.artifacts.domains)
    hashes = set(result.artifacts.hashes)
    user_agents = set()
    referrers = set()

    for event in result.events:
        if event.url:
            urls.add(event.url)
        if event.user_agent:
            user_agents.add(event.user_agent)
        if event.referrer and event.referrer != "-":
            referrers.add(event.referrer)
        text = " ".join([event.raw, event.url, event.user_agent, event.referrer])
        urls.update(URL_RE.findall(text))
        domains.update(domain.lower() for domain in DOMAIN_RE.findall(text))
        hashes.update(HASH_RE.findall(text))

    write_lines(out_dir / "ips.txt", sorted(result.ip_stats))
    write_lines(out_dir / "urls.txt", sorted(urls))
    write_lines(out_dir / "domains.txt", sorted(domains))
    write_lines(out_dir / "user_agents.txt", sorted(user_agents))
    write_lines(out_dir / "referrers.txt", sorted(referrers))
    write_lines(out_dir / "hashes.txt", sorted(hashes))
    write_lines(out_dir / "emails.txt", sorted(result.artifacts.emails))


def write_artifact_reports(out_dir: Path, findings: list[ArtifactFinding]) -> None:
    by_category: dict[str, list[ArtifactFinding]] = {}
    for finding in findings:
        by_category.setdefault(finding.category, []).append(finding)

    directory_by_category = {
        "accounts": "accounts",
        "persistence": "persistence",
        "commands": "commands",
        "web_compromise": "web_compromise",
        "filesystem": "filesystem",
        "secrets": "secrets",
        "archives": "archives",
        "yara": "yara",
    }
    for category, category_findings in sorted(by_category.items()):
        directory = out_dir / directory_by_category.get(category, "artifacts")
        directory.mkdir(parents=True, exist_ok=True)
        write_findings_csv(directory / f"{category}.csv", category_findings)
        write_findings_txt(directory / f"{category}.txt", category_findings)

    write_findings_csv(out_dir / "artifacts.csv", findings)


def write_downloaded_payloads_report(path: Path, result: ScanResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["Downloaded payload and suspicious command hints", ""]
    matches = 0
    for event in result.events:
        if SUSPICIOUS_COMMAND_RE.search(event.raw):
            matches += 1
            lines.append(f"[event] {event.source}:{event.line_number} ip={event.ip} {event.raw}")
    for finding in result.artifacts.findings:
        text = " ".join([finding.value, finding.detail])
        if SUSPICIOUS_COMMAND_RE.search(text):
            matches += 1
            where = f"{finding.path}:{finding.line_number}" if finding.line_number else finding.path
            lines.append(f"[artifact/{finding.severity}] {where} {text}")
    if matches == 0:
        lines.append("No wget/curl/base64/chmod/reverse-shell-like command hints found.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_network_artifacts_report(path: Path, result: ScanResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    user_agents = Counter()
    referrers = Counter()
    statuses = Counter()
    sources = Counter()
    for event in result.events:
        if event.user_agent:
            user_agents[event.user_agent] += 1
        if event.referrer and event.referrer != "-":
            referrers[event.referrer] += 1
        if event.status:
            statuses[event.status] += 1
        if event.source:
            sources[event.source] += 1

    lines = ["Network artifacts", ""]
    append_counter(lines, "top_user_agents", user_agents, 30)
    append_counter(lines, "top_referrers", referrers, 30)
    append_counter(lines, "http_statuses", statuses, 30)
    append_counter(lines, "network_sources", sources, 30)
    if len(lines) == 2:
        lines.append("No network artifacts extracted.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_findings_csv(path: Path, findings: list[ArtifactFinding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = ["severity", "kind", "category", "path", "line_number", "mtime", "size", "sha256", "detail", "value"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in sorted(findings, key=finding_sort_key):
            writer.writerow({name: getattr(finding, name) for name in fieldnames})


def write_findings_txt(path: Path, findings: list[ArtifactFinding]) -> None:
    lines = [path.stem, ""]
    for finding in sorted(findings, key=finding_sort_key):
        where = f"{finding.path}:{finding.line_number}" if finding.line_number else finding.path
        lines.append(f"[{finding.severity}] {finding.kind} {where}")
        if finding.mtime or finding.size:
            lines.append(f"  mtime={finding.mtime} size={finding.size} sha256={finding.sha256}")
        if finding.detail:
            lines.append(f"  detail={finding.detail}")
        if finding.value:
            lines.append(f"  value={finding.value}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(line for line in lines if line) + ("\n" if lines else ""), encoding="utf-8")


def markdown_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    output = [
        "| " + " | ".join(escape_markdown_cell(header) for header in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        output.append("| " + " | ".join(escape_markdown_cell(value) for value in row) + " |")
    return output


def markdown_counter(counter: Counter[str], limit: int) -> str:
    if not counter:
        return ""
    return ", ".join(f"{key} ({count})" for key, count in counter.most_common(limit))


def escape_markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def truncate_markdown(value: str, limit: int) -> str:
    cleaned = value.replace("\n", " ").strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def write_summary_json(path: Path, result: ScanResult, ranked: list[IpStats]) -> None:
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "root": str(result.root),
        "files_scanned": result.files_scanned,
        "unique_ips": len(result.ip_stats),
        "events": len(result.events),
        "scanned_files": result.scanned_files,
        "skipped_files": result.skipped_files,
        "attackers": [serialize_ip_stats(item) for item in ranked],
        "artifact_findings": [serialize_finding(finding) for finding in result.artifacts.findings],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def serialize_ip_stats(item: IpStats) -> dict[str, Any]:
    return {
        "ip": item.ip,
        "attack_score": item.attack_score,
        "risk_score": risk_score(item),
        "risk_level": risk_level(item),
        "total_events": item.total_events,
        "web_requests": item.web_requests,
        "suspicious_web_requests": item.suspicious_web_requests,
        "failed_logins": item.failed_logins,
        "successful_logins": item.successful_logins,
        "other_hits": item.other_hits,
        "statuses": dict(item.statuses.most_common()),
        "top_urls": dict(item.urls.most_common(25)),
        "user_agents": dict(item.user_agents.most_common(25)),
        "referrers": dict(item.referrers.most_common(25)),
        "users": dict(item.users.most_common(25)),
        "sources": dict(item.sources.most_common()),
    }


def serialize_finding(finding: ArtifactFinding) -> dict[str, Any]:
    return {
        "severity": finding.severity,
        "kind": finding.kind,
        "category": finding.category,
        "path": finding.path,
        "line_number": finding.line_number,
        "detail": finding.detail,
        "value": finding.value,
        "mtime": finding.mtime,
        "size": finding.size,
        "sha256": finding.sha256,
    }


def compromise_candidates(result: ScanResult) -> list[IpStats]:
    return [
        item
        for item in rank_attackers(result.ip_stats.values())
        if item.failed_logins > 0 and item.successful_logins > 0
    ]


def risk_score(item: IpStats) -> int:
    return (
        item.total_events
        + item.failed_logins * 2
        + item.suspicious_web_requests * 8
        + item.successful_logins * 12
        + (20 if item.failed_logins and item.successful_logins else 0)
    )


def risk_level(item: IpStats) -> str:
    score = risk_score(item)
    if item.failed_logins and item.successful_logins:
        return "critical"
    if score >= 100 or item.successful_logins:
        return "high"
    if score >= 25 or item.suspicious_web_requests:
        return "medium"
    return "low"


def finding_sort_key(finding: ArtifactFinding) -> tuple[int, str, str]:
    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return (severity_order.get(finding.severity, 4), finding.category, finding.path)


def event_sort_time(event: Event) -> str:
    parsed = parse_event_time(event.timestamp)
    if parsed:
        return parsed
    return event.timestamp or ""


def parse_event_time(value: str) -> str:
    if not value:
        return ""
    formats = [
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
    return value
