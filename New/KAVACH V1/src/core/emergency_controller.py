import psutil
import os
import signal
import subprocess
import logging
import sys
import json
from datetime import datetime

class EmergencyController:
    def __init__(self):
        self.critical_threshold = 85  # System usage percentage
        self.security_processes = ['KAVACH', 'security_service']
        self.logger = logging.getLogger(__name__)
        self.emergency_mode = False
        
    def assess_system_health(self):
        """Comprehensive system health assessment"""
        health_score = 100
        
        try:
            # CPU Health
            cpu_usage = psutil.cpu_percent(interval=1)
            if cpu_usage > 80:
                health_score -= 20
            elif cpu_usage > 90:
                health_score -= 40
            
            # Memory Health
            memory = psutil.virtual_memory()
            if memory.percent > 85:
                health_score -= 20
            
            # Disk Health
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                health_score -= 10
            
            # Security Process Health
            if not self.are_security_processes_running():
                health_score -= 30
                
        except Exception as e:
            self.logger.error(f"Health assessment error: {e}")
            health_score = 0
        
        return max(0, health_score)
    
    def are_security_processes_running(self):
        """Check if critical security processes are running"""
        try:
            for process in psutil.process_iter(['name']):
                for security_process in self.security_processes:
                    if security_process.lower() in process.info['name'].lower():
                        return True
        except Exception as e:
            self.logger.error(f"Process check error: {e}")
        return False
    
    def initiate_graceful_shutdown(self, reason="System compromise detected"):
        """Initiate emergency shutdown procedure"""
        if self.emergency_mode:
            return
        self.emergency_mode = True
        self.logger.critical(f"INITIATING EMERGENCY SHUTDOWN: {reason}")
        
        try:
            # Step 1: Isolate from network
            self.isolate_network()
            
            # Step 2: Preserve forensic data
            self.preserve_forensic_data()
            
            # Step 3: Kill suspicious processes
            self.terminate_suspicious_processes()
            
            # Step 4: Secure shutdown
            self.secure_shutdown()
            
        except Exception as e:
            self.logger.error(f"Emergency shutdown error: {e}")
            # Force immediate shutdown
            os._exit(1)
    
    def isolate_network(self):
        """Isolate system from network"""
        try:
            if os.name == 'nt':  # Windows
                subprocess.run(['netsh', 'interface', 'set', 'interface', 'name="Ethernet"', 'admin=disable'], 
                             capture_output=True, timeout=10)
                subprocess.run(['netsh', 'interface', 'set', 'interface', 'name="Wi-Fi"', 'admin=disable'],
                             capture_output=True, timeout=10)
            else:  # Linux
                subprocess.run(['ifconfig', 'eth0', 'down'], capture_output=True, timeout=10)
                subprocess.run(['ifconfig', 'wlan0', 'down'], capture_output=True, timeout=10)
                
            self.logger.info("Network isolation completed")
        except Exception as e:
            self.logger.error(f"Network isolation failed: {e}")
    
    def preserve_forensic_data(self):
        """Preserve evidence before shutdown"""
        try:
            # Create forensic snapshot
            forensic_data = {
                'timestamp': datetime.now().isoformat(),
                'running_processes': [],
                'network_connections': [],
                'system_metrics': {
                    'cpu_usage': psutil.cpu_percent(),
                    'memory_usage': psutil.virtual_memory()._asdict(),
                    'disk_usage': psutil.disk_usage('/')._asdict()
                },
                'shutdown_reason': 'EMERGENCY_SECURITY_BREACH'
            }
            
            # Collect process information
            for process in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
                try:
                    forensic_data['running_processes'].append(process.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Collect network information
            for conn in psutil.net_connections():
                try:
                    forensic_data['network_connections'].append({
                        'fd': conn.fd,
                        'family': conn.family,
                        'type': conn.type,
                        'laddr': conn.laddr,
                        'raddr': conn.raddr,
                        'status': conn.status,
                        'pid': conn.pid
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Save to secure location
            with open('/tmp/kavach_forensic.json', 'w') as f:
                json.dump(forensic_data, f, indent=2, default=str)
                
            self.logger.info("Forensic data preserved")
            
        except Exception as e:
            self.logger.error(f"Forensic data preservation failed: {e}")
    
    def terminate_suspicious_processes(self):
        """Terminate potentially malicious processes"""
        suspicious_keywords = ['crypto', 'lock', 'encrypt', 'ransom', 'malware', 'trojan', 'worm', 'keylogger']
        
        for process in psutil.process_iter(['pid', 'name']):
            try:
                process_name = process.info['name'].lower() if process.info['name'] else ''
                if any(keyword in process_name for keyword in suspicious_keywords):
                    os.kill(process.info['pid'], signal.SIGTERM)
                    self.logger.warning(f"Terminated suspicious process: {process_name} (PID: {process.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
                continue
    
    def secure_shutdown(self):
        """Final secure shutdown"""
        self.logger.critical("Performing secure shutdown...")
        # Give time for logs to be written
        import time
        time.sleep(2)
        # Exit the application
        sys.exit(1)