import json
import requests
from datetime import datetime, timedelta
import logging

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
            # Load malware signatures
            with open('data/threat_signatures.json', 'r') as f:
                self.malware_signatures = json.load(f)
            
            # Load phishing domains
            with open('data/phishing_domains.txt', 'r') as f:
                self.phishing_domains = set(line.strip() for line in f if line.strip())
            
            # Load malicious IPs
            with open('data/malicious_ips.txt', 'r') as f:
                self.malicious_ips = set(line.strip() for line in f if line.strip())
                
            self.last_update = datetime.now()
            self.logger.info("✅ Local threat intelligence loaded")
            
        except Exception as e:
            self.logger.error(f"Error loading threat data: {e}")
    
    def update_threat_intelligence(self):
        """Update threat intelligence from external sources"""
        if self.last_update and datetime.now() - self.last_update < timedelta(hours=1):
            return  # Update only once per hour
        
        try:
            # Fetch from abuse.ch
            response = requests.get('https://feodotracker.abuse.ch/downloads/ipblocklist.json', timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if 'ip_address' in entry:
                        self.malicious_ips.add(entry['ip_address'])
            
            # Update local files
            with open('data/malicious_ips.txt', 'w') as f:
                for ip in self.malicious_ips:
                    f.write(f"{ip}\n")
                    
            self.last_update = datetime.now()
            self.logger.info("✅ Threat intelligence updated")
            
        except Exception as e:
            self.logger.warning(f"Could not update threat intelligence: {e}")
    
    def is_malicious_ip(self, ip_address: str) -> bool:
        """Check if IP is in malicious database"""
        return ip_address in self.malicious_ips
    
    def is_phishing_domain(self, domain: str) -> bool:
        """Check if domain is in phishing database"""
        return domain in self.phishing_domains
    
    def get_malware_signature(self, file_hash: str) -> str:
        """Get malware type by file hash"""
        return self.malware_signatures.get(file_hash, "UNKNOWN")