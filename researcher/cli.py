from __future__ import annotations

import argparse
from pathlib import Path

from .reports import write_reports
from .scanner import ScanOptions, scan_backup


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="researcher-scan",
        description="Scan a readonly-mounted Linux backup and extract attacker IP evidence from logs.",
    )
    parser.add_argument(
        "--root",
        required=True,
        type=Path,
        help="Path to the mounted backup root, for example /mnt/server-backup.",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Directory where reports will be written.",
    )
    parser.add_argument(
        "--include-private",
        action="store_true",
        help="Include private/reserved/local IPs in attacker rankings.",
    )
    parser.add_argument(
        "--max-line-bytes",
        type=int,
        default=1024 * 1024,
        help="Skip individual log lines larger than this many bytes. Default: 1048576.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    options = ScanOptions(
        root=args.root,
        include_private=args.include_private,
        max_line_bytes=args.max_line_bytes,
    )
    result = scan_backup(options)
    write_reports(result, args.out)

    print(f"Scanned {result.files_scanned} log files, found {len(result.ip_stats)} IPs.")
    print(f"Reports written to: {args.out}")
    return 0
