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

By default, private/local/reserved IPs are excluded from rankings. Include them with:

```bash
researcher-scan --root /mnt/server-backup --out ./report --include-private
```

## What It Reads

The scanner searches under `/var/log` inside the mounted backup. If `/var/log` is missing, it scans the supplied root. It supports plain and rotated/compressed logs, including:

- `access.log`, `access.log.1`, `access.log.2.gz`
- `auth.log`, `auth.log.1`, `secure`, `secure-20260517`
- `syslog`, `messages`, `audit.log`, `ufw.log`, `cron`
- nginx/apache/httpd-style access and error logs
- gzip, bzip2, and xz compressed logs

## Reports

The output directory contains:

- `attackers.txt` - human-readable ranking of IPs sorted by attack score and request volume.
- `events.csv` - raw event table with source file, line number, timestamp, IP, URL/status/user, and original line.
- `summary.json` - machine-readable summary with per-IP counters.

Attack score is:

```text
web_requests + failed_logins + suspicious_web_requests*5 + successful_logins*3
```

Suspicious web requests are flagged when URLs contain common probes such as `.env`, `.git`, `wp-login.php`, `xmlrpc.php`, `phpmyadmin`, traversal payloads, shell/cmd parameters, or similar indicators.
