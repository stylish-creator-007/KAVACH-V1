#!/usr/bin/env python3
"""
KAVACH Log Analyzer (compact)
Monitors logs for errors, warnings, and suspicious activity.
"""

import os
import re
import time
import logging

class LogAnalyzer:
    def __init__(self, log_paths=None):
        self.logger = logging.getLogger(__name__)
        self.log_paths = log_paths or [
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/messages"
        ]
        # Patterns to detect
        self.patterns = {
            "ERROR": re.compile(r"\berror\b", re.IGNORECASE),
            "WARNING": re.compile(r"\bwarn(ing)?\b", re.IGNORECASE),
            "FAILED LOGIN": re.compile(r"failed password|authentication failure", re.IGNORECASE),
            "SUSPICIOUS": re.compile(r"unauthorized|malware|attack|denied", re.IGNORECASE)
        }

    def analyze(self):
        """Analyze log files for suspicious patterns"""
        findings = []

        for log_file in self.log_paths:
            if not os.path.exists(log_file):
                continue
            try:
                with open(log_file, "r", errors="ignore") as f:
                    for line in f.readlines()[-200:]:  # Only read last 200 lines
                        for label, pattern in self.patterns.items():
                            if pattern.search(line):
                                findings.append((label, line.strip()))
            except Exception as e:
                self.logger.debug(f"Error reading {log_file}: {e}")

        return findings


def clear_console():
    os.system("cls" if os.name == "nt" else "clear")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    analyzer = LogAnalyzer()

    try:
        while True:
            clear_console()
            print("📜 KAVACH-V1 :: Log Analyzer\n" + "-" * 50)

            findings = analyzer.analyze()
            if findings:
                print(f"⚠️  Detected {len(findings)} potential issues:\n")
                for label, line in findings[-10:]:  # show only last 10
                    print(f"[{label}] {line[:100]}...")
            else:
                print("✅ No suspicious log activity detected.")

            print("\n(Refreshing every 10s — Ctrl+C to stop)")
            time.sleep(10)

    except KeyboardInterrupt:
        print("\n🛑 Log Analyzer stopped by user.")
