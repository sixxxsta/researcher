from __future__ import annotations

import gzip
import tempfile
import unittest
from pathlib import Path

from researcher.cli import main


class SmokeTest(unittest.TestCase):
    def test_scans_plain_and_gz_rotated_logs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            out = base / "out"
            logs = root / "var" / "log" / "nginx"
            logs.mkdir(parents=True)

            (logs / "access.log").write_text(
                '198.51.100.24 - - [17/May/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 12 "-" "curl"\n'
                '203.0.113.8 - - [17/May/2026:10:01:00 +0000] "GET /index.html HTTP/1.1" 200 42 "-" "Mozilla"\n',
                encoding="utf-8",
            )
            with gzip.open(logs / "access.log.1.gz", "wt", encoding="utf-8") as handle:
                handle.write(
                    '198.51.100.24 - - [17/May/2026:10:02:00 +0000] "POST /wp-login.php HTTP/1.1" 403 9 "-" "bot"\n'
                )

            auth_log = root / "var" / "log" / "auth.log"
            auth_log.write_text(
                "May 17 10:03:00 host sshd[1]: Failed password for root from 198.51.100.24 port 22 ssh2\n",
                encoding="utf-8",
            )

            exit_code = main(["--root", str(root), "--out", str(out)])

            self.assertEqual(exit_code, 0)
            attackers = (out / "attackers.txt").read_text(encoding="utf-8")
            events = (out / "events.csv").read_text(encoding="utf-8")
            scanned_files = (out / "scanned_files.txt").read_text(encoding="utf-8")
            self.assertIn("198.51.100.24", attackers)
            self.assertIn("suspicious_web_requests: 2", attackers)
            self.assertIn("failed_logins: 1", attackers)
            self.assertIn("access.log.1.gz", events)
            self.assertIn("category", events)
            self.assertIn("nginx/access.log - events: 2", scanned_files)
            self.assertTrue((out / "events" / "web.csv").exists())
            self.assertTrue((out / "events" / "auth.csv").exists())


if __name__ == "__main__":
    unittest.main()
