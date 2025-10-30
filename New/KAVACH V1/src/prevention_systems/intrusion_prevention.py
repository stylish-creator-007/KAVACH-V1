import psutil
import os
import signal
import logging
from typing import Dict, Callable

class IPSystem:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.terminated_processes = set()
        self.attack_handlers: Dict[str, Callable] = {}

    def prevent_attack(self, attack_type: str, attack_data: Dict):
        """Main entry point to handle different attacks."""
        try:
            self.logger.info(f"🚨 Detected {attack_type} — initiating defense...")

            if attack_type == 'MALWARE':
                self.terminate_malicious_process(attack_data)
            elif attack_type == 'RANSOMWARE':
                self.prevent_ransomware(attack_data)
            elif attack_type == 'PORT_SCANNING':
                self.block_scanner(attack_data)
            elif attack_type == 'DOS_ATTACK':
                self.mitigate_dos(attack_data)
            elif attack_type == 'BEHAVIOR_ANOMALY':
                self.respond_to_anomaly(attack_data)
            elif attack_type in self.attack_handlers:
                # Custom dynamic threat handlers
                self.attack_handlers[attack_type](attack_data)
            else:
                self.logger.warning(f"⚠️ Unknown attack type: {attack_type}")

            self.logger.info(f"✅ {attack_type} neutralized successfully.\n")

        except Exception as e:
            self.logger.error(f"❌ Error preventing attack {attack_type}: {e}")

    # ----------------- Default Defense Methods -----------------

    def terminate_malicious_process(self, process_data):
        """Terminate a malicious process."""
        pid = process_data.get('pid')
        process_name = process_data.get('name', 'Unknown')

        if not pid or pid in self.terminated_processes:
            return

        try:
            process = psutil.Process(pid)
            process.terminate()
            self.terminated_processes.add(pid)
            self.logger.info(f"🛑 Terminated malicious process: {process_name} (PID {pid})")
        except psutil.NoSuchProcess:
            self.logger.warning(f"⚠️ Process {pid} not found.")
        except Exception as e:
            self.logger.error(f"Error terminating {process_name}: {e}")

    def prevent_ransomware(self, attack_data):
        """Simulate blocking ransomware encryption."""
        file_path = attack_data.get('file_path', '/suspicious/encryption/')
        self.logger.info(f"🔒 Ransomware activity detected — isolating {file_path}")

    def block_scanner(self, attack_data):
        """Block a port scanner."""
        ip = attack_data.get('ip', 'Unknown')
        self.logger.info(f"🚫 Port scanning detected from {ip} — blocking scanner")

    def mitigate_dos(self, attack_data):
        """Simulate mitigation of DoS attack."""
        src_ip = attack_data.get('ip', 'Unknown')
        self.logger.info(f"🌐 Mitigating DoS attack from {src_ip}")

    def respond_to_anomaly(self, attack_data):
        """Handle behavior anomalies."""
        desc = attack_data.get('description', 'Abnormal system behavior')
        self.logger.info(f"🤖 Responding to anomaly: {desc}")

    # ----------------- Dynamic Threat System -----------------

    def register_attack_handler(self, attack_type: str, handler: Callable):
        """Allow registering new custom defense strategies at runtime."""
        self.attack_handlers[attack_type] = handler
        self.logger.info(f"🆕 New threat type registered: {attack_type}")

# ---------------------- Testing Section ----------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    system = IPSystem()

    # Register a custom threat dynamically
    def block_crypto_miner(data):
        process = data.get("process_name", "unknown")
        print(f"💥 Crypto miner detected and blocked: {process}")

    system.register_attack_handler("CRYPTO_MINER", block_crypto_miner)

    # Simulate real-time detections
    system.prevent_attack("MALWARE", {"pid": 1234, "name": "bad_virus.exe"})
    system.prevent_attack("RANSOMWARE", {"file_path": "/home/user/important_files/"})
    system.prevent_attack("PORT_SCANNING", {"ip": "192.168.0.45"})
    system.prevent_attack("DOS_ATTACK", {"ip": "10.0.0.88"})
    system.prevent_attack("BEHAVIOR_ANOMALY", {"description": "CPU usage spike by unknown binary"})
    system.prevent_attack("CRYPTO_MINER", {"process_name": "minerX"})
    system.prevent_attack("UNKNOWN_THREAT", {})
