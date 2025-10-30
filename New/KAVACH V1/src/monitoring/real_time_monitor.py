#!/usr/bin/env python3
"""
KAVACH-V1 :: Real-Time System Monitor (compact)
Displays live system resource usage with auto-refresh.
"""

import psutil
import time
import logging
import os
from datetime import datetime
from threading import Thread

class RealTimeMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.monitor_thread = None
        self.metrics_history = {
            'cpu': [],
            'memory': [],
            'network_sent': [],
            'network_recv': [],
            'disk': []
        }

    def start_monitoring(self):
        """Start real-time system monitoring"""
        if self.monitoring:
            return

        self.monitoring = True
        self.monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("✅ Real-time monitoring started")

    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("🛑 Real-time monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            net = psutil.net_io_counters()

            self.metrics_history['cpu'].append(cpu)
            self.metrics_history['memory'].append(mem)
            self.metrics_history['disk'].append(disk)
            self.metrics_history['network_sent'].append(net.bytes_sent)
            self.metrics_history['network_recv'].append(net.bytes_recv)

            os.system("clear")
            print("📊 KAVACH-V1 :: Real-Time System Monitor\n" + "-" * 50)
            print(f"🕒 Time: {datetime.now().strftime('%H:%M:%S')}")
            print(f"🧠 CPU: {cpu:.1f}% | 💾 Memory: {mem:.1f}% | 🗄️ Disk: {disk:.1f}%")
            print(f"📡 Network: ↑ {net.bytes_sent / (1024**2):.2f} MB  ↓ {net.bytes_recv / (1024**2):.2f} MB")

            # Quick status summary
            if cpu > 85 or mem > 90 or disk > 95:
                print("\n⚠️  Status: HIGH LOAD DETECTED")
            elif cpu > 70 or mem > 80:
                print("\n🟡 Status: MODERATE LOAD")
            else:
                print("\n✅ Status: Stable and healthy")

            print("\n(Refreshing every 2s — Ctrl+C to stop)")
            time.sleep(2)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="[%(levelname)s] %(message)s")

    monitor = RealTimeMonitor()

    try:
        monitor.start_monitoring()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        print("\nExiting monitor.")
