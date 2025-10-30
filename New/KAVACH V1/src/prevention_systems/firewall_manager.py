"""
firewall_manager.py
-------------------
Manages network firewall rules, traffic filtering, and policy enforcement
for the KAVACH Cybersecurity Platform.
"""

import time
import logging
import random


class FirewallManager:
    """Simulated Firewall Manager for threat blocking and rule enforcement."""

    def __init__(self):
        self.logger = logging.getLogger("FirewallManager")
        self.active_rules = []
        self.blocked_ips = set()

    def load_default_rules(self):
        """Load predefined or baseline firewall rules."""
        self.active_rules = [
            {"id": 1, "rule": "Block known malicious IPs", "status": "active"},
            {"id": 2, "rule": "Allow internal traffic", "status": "active"},
            {"id": 3, "rule": "Monitor suspicious ports", "status": "active"},
        ]
        self.logger.info("✅ Default firewall rules loaded successfully.")

    def block_ip(self, ip):
        """Block a specific IP address."""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.logger.warning(f"🚫 IP {ip} has been blocked by the firewall.")
        else:
            self.logger.info(f"ℹ️ IP {ip} is already blocked.")

    def allow_ip(self, ip):
        """Remove an IP from the blocklist."""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.logger.info(f"✅ IP {ip} removed from blocklist.")
        else:
            self.logger.info(f"ℹ️ IP {ip} was not blocked.")

    def simulate_traffic_scan(self):
        """Simulate scanning and blocking suspicious IP traffic."""
        suspicious_ips = [
            f"192.168.1.{random.randint(50, 200)}"
            for _ in range(random.randint(1, 4))
        ]

        for ip in suspicious_ips:
            if random.random() < 0.3:  # 30% chance to detect as threat
                self.block_ip(ip)
            else:
                self.logger.info(f"✅ Traffic from {ip} deemed safe.")

        return {
            "checked_ips": suspicious_ips,
            "blocked": list(self.blocked_ips),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def run_firewall_cycle(self):
        """Simulate a complete firewall monitoring cycle."""
        self.logger.info("🔐 Firewall cycle initiated...")
        self.load_default_rules()
        result = self.simulate_traffic_scan()
        self.logger.info("🛡️ Firewall cycle completed successfully.")
        return result


if __name__ == "__main__":
    # Test the FirewallManager in standalone mode
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
    fw = FirewallManager()
    report = fw.run_firewall_cycle()
    print("\nFirewall Summary:")
    print(f"Checked IPs: {report['checked_ips']}")
    print(f"Blocked IPs: {report['blocked']}")
    print(f"Timestamp : {report['timestamp']}")

