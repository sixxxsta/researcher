from __future__ import annotations

import csv
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .scanner import Event, IpStats, ScanResult


def write_reports(result: ScanResult, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    ranked = rank_attackers(result.ip_stats.values())

    write_attackers_txt(out_dir / "attackers.txt", result, ranked)
    write_scanned_files_txt(out_dir / "scanned_files.txt", result)
    write_events_csv(out_dir / "events.csv", result.events)
    write_split_event_reports(out_dir / "events", result.events)
    write_summary_json(out_dir / "summary.json", result, ranked)


def rank_attackers(stats: Any) -> list[IpStats]:
    return sorted(
        stats,
        key=lambda item: (
            item.attack_score,
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
                    "user_agent": event.user_agent,
                    "raw": event.raw,
                }
            )


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
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def serialize_ip_stats(item: IpStats) -> dict[str, Any]:
    return {
        "ip": item.ip,
        "attack_score": item.attack_score,
        "total_events": item.total_events,
        "web_requests": item.web_requests,
        "suspicious_web_requests": item.suspicious_web_requests,
        "failed_logins": item.failed_logins,
        "successful_logins": item.successful_logins,
        "other_hits": item.other_hits,
        "statuses": dict(item.statuses.most_common()),
        "top_urls": dict(item.urls.most_common(25)),
        "users": dict(item.users.most_common(25)),
        "sources": dict(item.sources.most_common()),
    }
