import subprocess
import platform
import logging
from typing import Set

class DynamicFirewall:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.blocked_ips: Set[str] = set()
        self.blocked_ports: Set[int] = set()
        self.is_windows = platform.system() == "Windows"
        
    def block_threat(self, threat_data):
        """Block threat based on threat data"""
        try:
            threat_type = threat_data.get('type', '')
            
            if threat_type in ['PORT_SCANNING', 'CONNECTION_FLOOD', 'DOS_ATTACK']:
                ip = threat_data.get('ip')
                if ip and ip not in self.blocked_ips:
                    self.block_ip(ip)
            
            elif threat_type == 'SUSPICIOUS_PORT':
                port = threat_data.get('local_address', '').split(':')[-1]
                if port.isdigit():
                    self.block_port(int(port))
                    
        except Exception as e:
            self.logger.error(f"Error blocking threat: {e}")
    
    def block_ip(self, ip_address):
        """Block IP address in firewall"""
        if ip_address in self.blocked_ips:
            return
            
        self.blocked_ips.add(ip_address)
        
        try:
            if self.is_windows:
                # Windows firewall rule
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=CyberShield_Block_{ip_address}',
                    'dir=in', 'action=block', f'remoteip={ip_address}'
                ], capture_output=True, timeout=10)
                self.logger.info(f"✅ Blocked IP in Windows firewall: {ip_address}")
            else:
                # Linux iptables rule
                subprocess.run([
                    'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'
                ], capture_output=True, timeout=10)
                self.logger.info(f"✅ Blocked IP in iptables: {ip_address}")
                
        except Exception as e:
            self.logger.error(f"❌ Error blocking IP {ip_address}: {e}")
    
    def block_port(self, port):
        """Block specific port"""
        if port in self.blocked_ports:
            return
            
        self.blocked_ports.add(port)
        
        try:
            if self.is_windows:
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=CyberShield_Block_Port_{port}',
                    'dir=in', 'action=block', 'protocol=TCP', f'localport={port}'
                ], capture_output=True, timeout=10)
                self.logger.info(f"✅ Blocked port in Windows firewall: {port}")
            else:
                subprocess.run([
                    'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'
                ], capture_output=True, timeout=10)
                self.logger.info(f"✅ Blocked port in iptables: {port}")
                
        except Exception as e:
            self.logger.error(f"❌ Error blocking port {port}: {e}")
    
    def unblock_ip(self, ip_address):
        """Unblock IP address"""
        if ip_address not in self.blocked_ips:
            return
            
        self.blocked_ips.remove(ip_address)
        
        try:
            if self.is_windows:
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name=CyberShield_Block_{ip_address}'
                ], capture_output=True, timeout=10)
            else:
                subprocess.run([
                    'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'
                ], capture_output=True, timeout=10)
                
            self.logger.info(f"✅ Unblocked IP: {ip_address}")
            
        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip_address}: {e}")
    
    def get_blocked_ips(self):
        """Get list of blocked IPs"""
        return list(self.blocked_ips)
    
    def get_blocked_ports(self):
        """Get list of blocked ports"""
        return list(self.blocked_ports)
    
    def clear_all_rules(self):
        """Clear all firewall rules created by CyberShield"""
        try:
            if self.is_windows:
                # Remove all CyberShield rules
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    'name=CyberShield_Block'
                ], capture_output=True, timeout=10)
            else:
                # Flush iptables rules (be careful with this in production)
                subprocess.run([
                    'iptables', '-F'
                ], capture_output=True, timeout=10)
                
            self.blocked_ips.clear()
            self.blocked_ports.clear()
            self.logger.info("✅ Cleared all CyberShield firewall rules")
            
        except Exception as e:
            self.logger.error(f"Error clearing firewall rules: {e}")