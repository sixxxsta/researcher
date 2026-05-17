# Researcher

Readonly CLI triage tool for mounted Linux server backups. It scans log files, extracts IP evidence, detects common SSH/web attack patterns, and writes reports.

## Usage

Mount the server backup readonly, for example with `guestmount`, then run:

```bash
python -m researcher --root /mnt/server-backup --out ./report
```

Or install the local package and use the console script:

```bash
pip install -e .
researcher-scan --root /mnt/server-backup --out ./report
```

By default, all IPs are included. That is useful in incident response because logs often contain proxy, VPN, LAN, or reserved-range addresses. If you only want globally routable public IPs, use:

```bash
researcher-scan --root /mnt/server-backup --out ./report --public-only
```

## What It Reads

The scanner searches under `/var/log` inside the mounted backup. If `/var/log` is missing, it scans the supplied root. It supports plain and rotated/compressed logs, including:

- `access.log`, `access.log.1`, `access.log.2.gz`
- `auth.log`, `auth.log.1`, `secure`, `secure-20260517`
- `syslog`, `messages`, `audit.log`, `ufw.log`, `cron`
- nginx/apache/httpd-style access and error logs
- gzip, bzip2, and xz compressed logs
- systemd journal from `/var/log/journal` when `journalctl` is available on the scanning host

## Reports

The output directory contains:

- `attackers.txt` - human-readable ranking of IPs sorted by attack score and request volume.
- `events.csv` - raw event table with source file, category, line number, timestamp, IP, URL/status/user, and original line.
- `events/` - split CSV reports by category and by original source file, so nginx access logs, auth logs, and system logs do not get mixed together.
- `scanned_files.txt` - inventory of every scanned log file and how many events were extracted from it.
- `summary.json` - machine-readable summary with per-IP counters.

Attack score is:

```text
web_requests + failed_logins + suspicious_web_requests*5 + successful_logins*3
```

Suspicious web requests are flagged when URLs contain common probes such as `.env`, `.git`, `wp-login.php`, `xmlrpc.php`, `phpmyadmin`, traversal payloads, shell/cmd parameters, or similar indicators.
