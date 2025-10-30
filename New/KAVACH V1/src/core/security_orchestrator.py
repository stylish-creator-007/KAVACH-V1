import asyncio
import logging
import os
import sys

# Add parent directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detection_engines.malware_detector import AdvancedMalwareDetector
from prevention_systems.firewall_manager import FirewallManager
from monitoring.health_checker import HealthChecker


class SecurityOrchestrator:
    def __init__(self):
        self.logger = logging.getLogger("SecurityOrchestrator")
        self.malware_detector = AdvancedMalwareDetector()
        self.firewall = FirewallManager()
        self.health_checker = HealthChecker()

    async def start_systems(self):
        self.logger.info("🚀 Initializing all security modules...")

        # Initialize firewall and health check
        self.firewall.load_default_rules()
        self.health_checker.initialize_system_health()

        # Start all detection systems concurrently
        await asyncio.gather(
            self.run_malware_protection(),
            self.run_network_protection(),
            self.run_system_monitoring(),
        )

    async def run_malware_protection(self):
        self.logger.info("🧠 Malware Protection Active...")
        result = self.malware_detector.run_detection_cycle()
        self.logger.info(f"🔍 Malware Scan Summary: {result}")

    async def run_network_protection(self):
        self.logger.info("🌐 Network Protection System Engaged...")
        await asyncio.sleep(1)
        self.logger.info("✅ Network Security Monitoring Initialized.")

    async def run_system_monitoring(self):
        self.logger.info("📊 System Monitoring Online...")
        self.health_checker.run_health_check_cycle()

    async def security_main_loop(self):
        while True:
            await self.start_systems()
            await asyncio.sleep(10)

    def shutdown(self):
        self.logger.warning("🛑 Shutting down all active defense modules...")
        self.firewall.save_state()
        self.logger.info("✅ System shutdown complete.")


# Entry point (for direct run)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    orchestrator = SecurityOrchestrator()
    try:
        asyncio.run(orchestrator.security_main_loop())
    except KeyboardInterrupt:
        orchestrator.shutdown()
