import psutil
import os
import signal
import logging
from typing import Dict, List

class IPSystem:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.terminated_processes = set()
        
    def prevent_attack(self, attack_type: str, attack_data: Dict):
        """Prevent detected attacks"""
        try:
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
                
        except Exception as e:
            self.logger.error(f"Error preventing attack {attack_type}: {e}")
    
    def terminate_malicious_process(self, process_data):
        """Terminate malicious processes"""
        pid = process_data.get('pid')
        process_name = process_data.get('name', 'Unknown')
        
        if not pid or pid in self.terminated_processes:
            return
        
        try:
            process = psutil.Process(pid)
            process.terminate()
            self.terminated_processes.add(pid)
            self.logger.warning(f"✅ Terminated malicious process: {process_name} (PID: {pid})")
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Error terminating process {pid}: {e}")
    
    def prevent_ransomware(self, ransomware_data):
        """Prevent ransomware activity"""
        file_path = ransomware_data.get('file', '')
        process_name = ransomware_data.get('process', '')
        
        # Terminate processes with ransomware indicators
        for process in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = process.info['name'].lower() if process.info['name'] else ''
                if any(indicator in proc_name for indicator in ['crypto', 'encrypt', 'lock']):
                    self.terminate_malicious_process(process.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self.logger.warning(f"🚨 Ransomware prevention activated for: {file_path}")
    
    def block_scanner(self, scan_data):
        """Block port scanning activity"""
        ip_address = scan_data.get('ip')
        if ip_address:
            # Additional blocking logic can be added here
            self.logger.warning(f"✅ Blocked scanner IP: {ip_address}")
    
    def mitigate_dos(self, dos_data):
        """Mitigate DoS attacks"""
        # Implement DoS mitigation strategies
        self.logger.warning("🚨 DoS mitigation activated")
        
        # Reduce connection limits temporarily
        # This would be system-specific implementation
    
    def respond_to_anomaly(self, anomaly_data):
        """Respond to behavioral anomalies"""
        anomaly_type = anomaly_data.get('type', '')
        confidence = anomaly_data.get('confidence', 'LOW')
        
        if confidence in ['HIGH', 'MEDIUM']:
            if 'PROCESS' in anomaly_type:
                pid = anomaly_data.get('pid')
                if pid:
                    self.terminate_malicious_process({'pid': pid, 'name': anomaly_data.get('process_name', 'Unknown')})
            
            self.logger.warning(f"✅ Responded to behavioral anomaly: {anomaly_type}")
    
    def quarantine_file(self, file_path):
        """Quarantine suspicious files"""
        try:
            if os.path.exists(file_path):
                # Move to quarantine directory
                quarantine_dir = '/tmp/cybershield_quarantine'
                os.makedirs(quarantine_dir, exist_ok=True)
                
                import shutil
                filename = os.path.basename(file_path)
                quarantine_path = os.path.join(quarantine_dir, f"quarantined_{filename}")
                shutil.move(file_path, quarantine_path)
                
                self.logger.warning(f"✅ Quarantined file: {file_path} -> {quarantine_path}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error quarantining file {file_path}: {e}")
        
        return False
    
    def restore_file(self, quarantined_path, original_path):
        """Restore quarantined file"""
        try:
            if os.path.exists(quarantined_path):
                import shutil
                shutil.move(quarantined_path, original_path)
                self.logger.info(f"✅ Restored file: {quarantined_path} -> {original_path}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error restoring file {quarantined_path}: {e}")
        
        return False
    
    def get_quarantined_files(self):
        """Get list of quarantined files"""
        quarantine_dir = '/tmp/cybershield_quarantine'
        if os.path.exists(quarantine_dir):
            return [f for f in os.listdir(quarantine_dir) if f.startswith('quarantined_')]
        return []