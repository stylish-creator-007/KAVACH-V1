import asyncio
import threading
import logging
from datetime import datetime
from typing import Dict, List
import psutil
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_engines.malware_detector import AdvancedMalwareDetector
from detection_engines.network_analyzer import NetworkSecurityMonitor
from detection_engines.web_protector import WebAttackProtector
from detection_engines.email_security import PhishingDetector
from detection_engines.behavioral_analyzer import BehavioralAnalyzer
from prevention_systems.firewall_manager import DynamicFirewall
from prevention_systems.intrusion_prevention import IPSystem
from core.emergency_controller import EmergencyController

class SecurityOrchestrator:
    def __init__(self):
        self.logger = self.setup_logging()
        self.running = True
        self.threat_level = 0
        self.detected_attacks = []
        
        # Initialize all security modules
        self.modules = {
            'malware_detector': AdvancedMalwareDetector(),
            'network_monitor': NetworkSecurityMonitor(),
            'web_protector': WebAttackProtector(),
            'phishing_detector': PhishingDetector(),
            'behavior_analyzer': BehavioralAnalyzer(),
            'firewall': DynamicFirewall(),
            'ips': IPSystem(),
            'emergency_controller': EmergencyController()
        }
        
        self.logger.info("KAVACH Initialized")

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cybershield.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    async def start_protection(self):
        """Start all security systems"""
    self.logger.info("Starting Comprehensive Protection Systems")
        
        # Start all monitoring threads
     threads = [
            threading.Thread(target=self.malware_protection_loop, daemon=True),
            threading.Thread(target=self.network_protection_loop, daemon=True),
            threading.Thread(target=self.web_protection_loop, daemon=True),
            threading.Thread(target=self.email_protection_loop, daemon=True),
            threading.Thread(target=self.behavior_monitoring_loop, daemon=True),
            threading.Thread(target=self.system_health_monitor, daemon=True)
        ]
        for thread in threads:
            thread.start()
        # Main security loop
        await self.security_main_loop()

    async def security_main_loop(self):
        """Main security monitoring loop"""
        while self.running:
            try:
                # Check system health
                system_health = self.modules['emergency_controller'].assess_system_health()
                
                if system_health < 30:
                    self.logger.critical("🆘 System health critical - preparing emergency shutdown")
                    self.modules['emergency_controller'].initiate_graceful_shutdown("System health critical")
                
                # Log system status every 30 seconds
                if int(datetime.now().timestamp()) % 30 == 0:
                    self.log_status()
                
                await asyncio.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Error in security main loop: {e}")

    def malware_protection_loop(self):
        """Continuous malware detection"""
        while self.running:
            try:
                # Real-time file system monitoring
                self.modules['malware_detector'].monitor_file_system()
                
                # Process monitoring
                suspicious_processes = self.modules['malware_detector'].scan_running_processes()
                for process in suspicious_processes:
                    self.respond_to_threat('MALWARE', process)
                    
            except Exception as e:
                self.logger.error(f"Malware protection error: {e}")
            
            threading.Event().wait(2)

    def network_protection_loop(self):
        """Network security monitoring"""
        while self.running:
            try:
                # Detect various network attacks
                attacks = self.modules['network_monitor'].detect_network_attacks()
                
                for attack in attacks:
                    self.respond_to_threat(attack['type'], attack['data'])
                    
            except Exception as e:
                self.logger.error(f"Network protection error: {e}")
            
            threading.Event().wait(1)

    def web_protection_loop(self):
        """Web application protection"""
        while self.running:
            try:
                # Monitor for web attacks
                web_threats = self.modules['web_protector'].detect_web_attacks()
                
                for threat in web_threats:
                    self.respond_to_threat(threat['type'], threat['data'])
                    
            except Exception as e:
                self.logger.error(f"Web protection error: {e}")
            
            threading.Event().wait(3)

    def email_protection_loop(self):
        """Email security monitoring"""
        while self.running:
            try:
                # Phishing detection
                phishing_attempts = self.modules['phishing_detector'].monitor_emails()
                
                for attempt in phishing_attempts:
                    self.respond_to_threat('PHISHING', attempt)
                    
            except Exception as e:
                self.logger.error(f"Email protection error: {e}")
            
            threading.Event().wait(5)

    def behavior_monitoring_loop(self):
        """Behavioral analysis monitoring"""
        while self.running:
            try:
                # Analyze system behavior
                anomalies = self.modules['behavior_analyzer'].detect_anomalies()
                
                for anomaly in anomalies:
                    self.respond_to_threat('BEHAVIOR_ANOMALY', anomaly)
                    
            except Exception as e:
                self.logger.error(f"Behavior monitoring error: {e}")
            
            threading.Event().wait(10)

    def system_health_monitor(self):
        """Monitor overall system health"""
        while self.running:
            try:
                cpu_usage = psutil.cpu_percent(interval=1)
                memory_usage = psutil.virtual_memory().percent
                disk_usage = psutil.disk_usage('/').percent
                
                if cpu_usage > 90 or memory_usage > 90 or disk_usage > 95:
                    self.logger.warning(f"High system usage - CPU: {cpu_usage}%, Memory: {memory_usage}%, Disk: {disk_usage}%")
                    
            except Exception as e:
                self.logger.error(f"Health monitor error: {e}")
            
            threading.Event().wait(10)

    def respond_to_threat(self, threat_type: str, threat_data: Dict):
        """Respond to detected threats"""
        self.logger.warning(f"Threat Detected: {threat_type} - {threat_data}")
        self.detected_attacks.append({
            'timestamp': datetime.now(),
            'type': threat_type,
            'data': threat_data
        })
        
        # Auto-block threats
        if threat_type in ['MALWARE', 'RANSOMWARE', 'DOS_ATTACK', 'PORT_SCANNING']:
            self.modules['firewall'].block_threat(threat_data)
            self.modules['ips'].prevent_attack(threat_type, threat_data)
        
        # Increase threat level
        self.threat_level = min(100, self.threat_level + 10)

    def log_status(self):
        """Log current system status"""
        status = {
            'threat_level': self.threat_level,
            'total_detected_attacks': len(self.detected_attacks),
            'system_health': self.modules['emergency_controller'].assess_system_health(),
            'timestamp': datetime.now()
        }
        self.logger.info(f"System Status: {status}")

    def shutdown(self):
        """Graceful shutdown"""
        self.logger.info("Shutting down KAVACH")
        self.running = False
        # Stop all modules
        for module in self.modules.values():
            if hasattr(module, 'stop_monitoring'):
                module.stop_monitoring()