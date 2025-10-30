import psutil
import time
from src.utils.logger import CyberLogger


class HealthChecker:
    """Performs system health checks (CPU, memory, and disk usage)."""

    def __init__(self):
        self.logger = CyberLogger("HealthChecker")

    def initialize_system_health(self):
        """Initial setup — check and log baseline system health."""
        self.logger.info("🩺 Initializing system health monitoring...")
        baseline = self.get_system_status()
        self.logger.info(f"✅ Baseline system health: {baseline}")

    def get_system_status(self):
        """Return current system metrics."""
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        return {
            "CPU": f"{cpu}%",
            "Memory": f"{memory}%",
            "Disk": f"{disk}%"
        }

    def continuous_health_monitor(self):
        """Continuously log system health every 10 seconds."""
        self.logger.info("🏃 Starting continuous health monitoring...")
        try:
            while True:
                status = self.get_system_status()
                self.logger.info(f"📊 System Health: {status}")
                time.sleep(10)
        except KeyboardInterrupt:
            self.logger.warning("🛑 Health monitoring stopped by user.")
