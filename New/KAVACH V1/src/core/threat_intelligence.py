import json
import requests
from datetime import datetime, timedelta
import logging
import os  # Added for file existence checks

class ThreatIntelligence:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.malware_signatures = {}
        self.phishing_domains = set()
        self.malicious_ips = set()
        self.last_update = None

    def load_local_threat_data(self):
        """Load local threat intelligence databases"""
        try:
            # Check if files exist before loading
            sig_file = 'data/threat_signatures.json'
            domain_file = 'data/phishing_domains.txt'
            ip_file = 'data/malicious_ips.txt'
            
            if not os.path.exists(sig_file):
                self.logger.warning(f"Threat signatures file not found: {sig_file}")
                return
            if not os.path.exists(domain_file):
                self.logger.warning(f"Phishing domains file not found: {domain_file}")
                return
            if not os.path.exists(ip_file):
                self.logger.warning(f"Malicious IPs file not found: {ip_file}")
                return
            
            # Load malware signatures
            with open(sig_file, 'r') as f:
                self.malware_signatures = json.load(f)

            # Load phishing domains
            with open(domain_file, 'r') as f:
                self.phishing_domains = set(line.strip() for line in f if line.strip())

            # Load malicious IPs
            with open(ip_file, 'r') as f:
                self.malicious_ips = set(line.strip() for line in f if line.strip())

            self.last_update = datetime.now()
            self.logger.info("✅ Local threat intelligence loaded")

        except Exception as e:
            self.logger.error(f"Error loading threat data: {e}")
    
    def update_threat_intelligence(self):
        """Update threat intelligence from external sources"""
        if self.last_update and datetime.now() - self.last_update < timedelta(hours=1):
            self.logger.info("Threat intelligence update skipped (last update < 1 hour ago)")
            return  # Update only once per hour
        
        try:
            # Example: Fetch from a public API (replace with real source, e.g., VirusTotal or abuse.ch)
            # Note: This is a mock; real APIs require keys and may have rate limits
            response = requests.get("https://api.mockthreatintel.com/malicious_ips", timeout=10)
            if response.status_code == 200:
                new_ips = response.json().get("ips", [])
                self.malicious_ips.update(new_ips)
                self.last_update = datetime.now()
                self.logger.info(f"✅ Threat intelligence updated with {len(new_ips)} new IPs")
            else:
                self.logger.warning(f"Failed to update threat intelligence: HTTP {response.status_code}")
        
        except requests.RequestException as e:
            self.logger.error(f"Error updating threat intelligence: {e}")
    
    def check_ip(self, ip):
        """Check if an IP is malicious"""
        return ip in self.malicious_ips
    
    def check_domain(self, domain):
        """Check if a domain is phishing-related"""
        return domain in self.phishing_domains
    
    def check_signature(self, signature):
        """Check if a signature matches known malware"""
        return signature in self.malware_signatures

# Example usage (for testing standalone)
if __name__ == "__main__":
    ti = ThreatIntelligence()
    ti.load_local_threat_data()
    ti.update_threat_intelligence()
    print("Malicious IP check for 192.168.1.1:", ti.check_ip("192.168.1.1"))
