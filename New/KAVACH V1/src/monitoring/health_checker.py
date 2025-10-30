#!/usr/bin/env python3
"""
KAVACH System Health Checker (compact)
Checks CPU, memory, disk, and network stats with quick status output.
"""

import psutil
import time
import os

class HealthChecker:
    def check(self):
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        net = psutil.net_io_counters()

        # Basic status logic
        status = "OK"
        if cpu > 85 or memory > 90 or disk > 95:
            status = "⚠️ HIGH LOAD"
        elif cpu > 70 or memory > 80:
            status = "🟡 Moderate Load"

        return {
            "status": status,
            "cpu": f"{cpu:.1f}%",
            "memory": f"{memory:.1f}%",
            "disk": f"{disk:.1f}%",
            "net_sent": f"{net.bytes_sent / (1024**2):.2f} MB",
            "net_recv": f"{net.bytes_recv / (1024**2):.2f} MB"
        }

def clear_console():
    os.system("cls" if os.name == "nt" else "clear")

def display_health():
    hc = HealthChecker()
    try:
        while True:
            data = hc.check()
            clear_console()
            print("🩺 KAVACH-V1 :: System Health Monitor\n" + "-" * 45)
            print(f"CPU: {data['cpu']} | MEM: {data['memory']} | DISK: {data['disk']}")
            print(f"NET: ↑ {data['net_sent']}  ↓ {data['net_recv']}")
            print(f"STATUS: {data['status']}")
            print("\n(Refreshing every 3s — Ctrl+C to stop)")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n🛑 Health Monitor stopped by user.")

if __name__ == "__main__":
    display_health()
