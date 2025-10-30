import os
import psutil
import logging
from datetime import datetime

class ApplicationShield:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.quarantined_apps = set()

    def shield(self, app_name: str):
        """
        Simulates application protection.
        Returns True if the app is safe, False if blocked/quarantined.
        """
        suspicious_keywords = ["hack", "exploit", "inject", "stealer", "miner", "ransom"]
        if any(word in app_name.lower() for word in suspicious_keywords):
            self.quarantine_app(app_name)
            return False

        self.logger.info(f"✅ Application {app_name} verified as safe.")
        return True

    def quarantine_app(self, app_name: str):
        """Quarantine suspicious or malicious application."""
        if app_name in self.quarantined_apps:
            self.logger.warning(f"⚠️ {app_name} already quarantined.")
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.quarantined_apps.add(app_name)
        self.logger.warning(f"🚫 Suspicious app detected and quarantined: {app_name} at {timestamp}")

    def scan_running_processes(self):
        """Scan running processes for malicious behavior."""
        detected = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                app_name = proc.info['name'] or ''
                if not self.shield(app_name):
                    detected.append({"pid": proc.info['pid'], "app": app_name})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return detected


# ----------------- Example Simulation -----------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    shield = ApplicationShield()

    # Simulate scanning system apps
    print("\n🛡️ Application Shield Active — Scanning for threats...\n")
    threats = shield.scan_running_processes()

    # Simulate new apps being loaded
    test_apps = ["chrome.exe", "ransomX", "injector", "notepad.exe", "crypto_miner", "vscode"]

    for app in test_apps:
        shield.shield(app)

    if threats or shield.quarantined_apps:
        print("\n🚨 Threat Summary:")
        for app in shield.quarantined_apps:
            print(f" - {app}")
    else:
        print("\n✅ No suspicious applications found.")
