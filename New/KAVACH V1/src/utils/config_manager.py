import json
import os
from typing import Dict, Any
import logging

class ConfigManager:
    def __init__(self, config_file='config/cybershield_config.json'):
        self.config_file = config_file
        self.logger = logging.getLogger(__name__)
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create defaults"""
        default_config = {
            "security": {
                "threat_level_threshold": 80,
                "auto_block_malicious_ips": True,
                "emergency_shutdown_enabled": True,
                "shutdown_threshold": 20
            },
            "monitoring": {
                "file_system_monitoring": True,
                "network_monitoring": True,
                "process_monitoring": True,
                "behavior_analysis": True
            },
            "logging": {
                "level": "INFO",
                "max_file_size_mb": 100,
                "backup_count": 5
            },
            "prevention": {
                "auto_quarantine": True,
                "block_suspicious_ports": True,
                "terminate_malicious_processes": True
            }
        }

        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                    self.logger.info("✅ Configuration loaded successfully.")
                    return config_data
            else:
                self.logger.warning("⚠️ Config file not found — creating default config.")
                os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
                with open(self.config_file, 'w') as f:
                    json.dump(default_config, f, indent=4)
                return default_config

        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            return default_config

    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            self.logger.info("💾 Configuration saved successfully.")
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")

# === TEST BLOCK (only runs when executed directly) ===
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    manager = ConfigManager()
    print("\n🧩 Current Configuration:")
    print(json.dumps(manager.config, indent=4))

    # Modify something for demo
    manager.config["security"]["threat_level_threshold"] = 90
    manager.save_config()

    print("\n✅ Updated 'threat_level_threshold' to 90 and saved.")

