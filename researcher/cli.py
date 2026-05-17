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
        default=True,
        help="Include private/reserved/local IPs in attacker rankings. This is the default.",
    )
    parser.add_argument(
        "--public-only",
        action="store_false",
        dest="include_private",
        help="Only include globally routable public IPs.",
    )
    parser.add_argument(
        "--max-line-bytes",
        type=int,
        default=1024 * 1024,
        help="Skip individual log lines larger than this many bytes. Default: 1048576.",
    )
    return parser


def validate_root(parser: argparse.ArgumentParser, raw_root: Path) -> Path:
    root = raw_root.expanduser()
    if root.exists() and root.is_dir():
        return root

    details = [
        f"received: {raw_root}",
        f"expanded: {root}",
        f"current directory: {Path.cwd()}",
    ]
    if not root.exists():
        details.append("problem: expanded path does not exist")
    elif not root.is_dir():
        details.append("problem: expanded path exists but is not a directory")

    parser.error("--root is not a readable mounted directory\n  " + "\n  ".join(details))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = validate_root(parser, args.root)
    out = args.out.expanduser()

    options = ScanOptions(
        root=root,
        include_private=args.include_private,
        max_line_bytes=args.max_line_bytes,
    )
    result = scan_backup(options)
    write_reports(result, out)

    print(f"Scanned {result.files_scanned} log files, found {len(result.ip_stats)} IPs.")
    if result.files_scanned == 0:
        print("No log files were discovered. Check that --root points to the mounted Linux filesystem root.")
    print(f"Reports written to: {out}")
    return 0
