import re
import logging
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import os
import time
import psutil

class WebAttackProtector:
    """
    Detects common web attack patterns in URLs, query params, and request bodies:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Path Traversal
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # SQL Injection patterns (compact set)
        self.sql_injection_patterns = [
            re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
            re.compile(r"(\bunion\b|\bor\b|\band\b).*(select|insert|drop|update|delete)", re.IGNORECASE),
            re.compile(r"(select.+from|insert\s+into|drop\s+table|update\s+\w+\s+set)", re.IGNORECASE),
        ]

        # XSS patterns
        self.xss_patterns = [
            re.compile(r"<script.*?>", re.IGNORECASE),
            re.compile(r"javascript\s*:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE),
            re.compile(r"alert\s*\(", re.IGNORECASE),
            re.compile(r"document\.cookie", re.IGNORECASE),
        ]

        # Path traversal patterns
        self.path_traversal_patterns = [
            re.compile(r"\.\./"),
            re.compile(r"(/etc/passwd)|(/boot|/proc/)", re.IGNORECASE)
        ]

    # -------------------------
    # Core analyzers
    # -------------------------
    def analyze_text_for_patterns(self, text):
        """Return list of matched categories found in text."""
        detections = []

        if not text:
            return detections

        # SQLi checks
        for p in self.sql_injection_patterns:
            if p.search(text):
                detections.append("SQL_INJECTION")

        # XSS checks
        for p in self.xss_patterns:
            if p.search(text):
                detections.append("XSS")

        # Path traversal checks
        for p in self.path_traversal_patterns:
            if p.search(text):
                detections.append("PATH_TRAVERSAL")

        return list(dict.fromkeys(detections))  # deduplicate preserving order

    def analyze_url(self, url):
        """
        Analyze URL (including path and query parameters) and return detections list.
        """
        parsed = urlparse(url)
        detections = []

        # analyze path
        path = parsed.path or ""
        detections += self.analyze_text_for_patterns(path)

        # analyze query params
        qs = parse_qs(parsed.query)
        for key, vals in qs.items():
            combined = key + " " + " ".join(vals)
            detections += self.analyze_text_for_patterns(combined)

        return list(dict.fromkeys(detections))

    def analyze_request(self, method="GET", url="", headers=None, body=""):
        """
        Analyze a simulated HTTP request: returns summary dict:
        { 'url': ..., 'detections': [...], 'checked_parts': {...} }
        """
        headers = headers or {}
        detections = []

        # URL detections
        url_dets = self.analyze_url(url)
        detections += url_dets

        # Headers (common header-based attacks)
        header_text = " ".join(f"{k}:{v}" for k, v in headers.items())
        detections += self.analyze_text_for_patterns(header_text)

        # Body detections
        detections += self.analyze_text_for_patterns(body)

        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "method": method,
            "url": url,
            "detections": list(dict.fromkeys(detections))
        }

    # -------------------------
    # Utilities for console output
    # -------------------------
    def compact_output(self, result):
        """
        Returns a single-line compact human-readable summary for a single request result.
        Example:
        [14:12:05] GET /login.php?user=1' -- DET: SQL_INJECTION,XSS
        """
        t = datetime.utcnow().strftime("%H:%M:%S")
        dets = ",".join(result["detections"]) if result["detections"] else "NONE"
        parsed = urlparse(result["url"])
        short_path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        return f"[{t}] {result['method']:4} {short_path:40} DET: {dets}"

    def top_processes_summary(self, n=5):
        """
        Return a small list of top n processes by cpu for display:
        ['PID 1421|CPU 92.3%|gnome-shell', ...]
        """
        procs = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                info = proc.info
                procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        procs_sorted = sorted(procs, key=lambda p: (p.get('cpu_percent') or 0.0), reverse=True)[:n]
        lines = []
        for p in procs_sorted:
            name = (p.get('name') or "")[:20]
            cpu = (p.get('cpu_percent') or 0.0)
            lines.append(f"PID{p.get('pid'):5}|CPU{cpu:5.1f}%|{name}")
        return lines

# -------------------------
# Standalone compact runner
# -------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s - %(levelname)s - %(message)s",
                        datefmt="%H:%M:%S")
    protector = WebAttackProtector()

    # sample requests to test (compact)
    sample_requests = [
        {"method": "GET", "url": "/search?q=normal+term", "body": ""},
        {"method": "GET", "url": "/product?id=123", "body": ""},
        {"method": "GET", "url": "/login?user=admin'--&pass=abc", "body": ""},
        {"method": "POST", "url": "/comment", "body": "<script>alert(1)</script>Nice post!"},
        {"method": "GET", "url": "/download?file=../../etc/passwd", "body": ""},
        {"method": "POST", "url": "/submit", "body": "name=foo&comment=hello"},
    ]

    try:
        while True:
            os.system("clear")
            print("🛡️ KAVACH-V1 :: Web Protector (compact)\n" + "-"*72)

            # Analyze sample requests and print compact lines
            for req in sample_requests:
                url_full = req["url"]
                # ensure URL has path root for display clarity
                if not url_full.startswith("/"):
                    url_full = "/" + url_full
                result = protector.analyze_request(method=req.get("method","GET"), url=url_full, body=req.get("body",""))
                print(protector.compact_output(result))

            # print a one-line processes summary
            print("\nTop processes:", " | ".join(protector.top_processes_summary(4)))

            print("\nRefresh every 6s (Ctrl+C to stop).")
            time.sleep(6)

    except KeyboardInterrupt:
        print("\n🛑 Web Protector stopped by user.")
