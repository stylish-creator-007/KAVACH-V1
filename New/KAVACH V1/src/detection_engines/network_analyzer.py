import socket
import struct
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import psutil
import subprocess
import platform
import logging

class NetworkSecurityMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.connection_thresholds = {
            'syn_flood': 1000,  # SYN packets per minute
            'udp_flood': 5000,  # UDP packets per minute
            'icmp_flood': 1000  # ICMP packets per minute
        }
        self.packet_counts = defaultdict(lambda: defaultdict(int))
        self.time_windows = defaultdict(lambda: deque())
        self.blocked_ips = set()
        self.port_scan_threshold = 50  # Ports per IP
        self.suspicious_ports = {4444, 9999, 1337, 31337, 12345, 54321}  # Common malware ports
        
    def detect_network_attacks(self):
        """Detect various network attacks"""
        detected_attacks = []
        
        try:
            # Get network connections
            connections = psutil.net_connections()
            
            # Analyze for different attack types
            detected_attacks.extend(self.detect_port_scanning(connections))
            detected_attacks.extend(self.detect_dos_attacks())
            detected_attacks.extend(self.detect_suspicious_connections(connections))
            detected_attacks.extend(self.detect_connection_floods(connections))
            
        except Exception as e:
            self.logger.error(f"Network attack detection error: {e}")
        
        return detected_attacks
    
    def detect_port_scanning(self, connections):
        """Detect port scanning activity"""
        ip_port_counts = defaultdict(set)
        detected_scans = []
        
        for conn in connections:
            if hasattr(conn, 'raddr') and conn.raddr:
                ip_port_counts[conn.raddr.ip].add(conn.raddr.port)
        
        for ip, ports in ip_port_counts.items():
            if len(ports) > self.port_scan_threshold:
                detected_scans.append({
                    'type': 'PORT_SCANNING',
                    'ip': ip,
                    'ports_scanned': len(ports),
                    'action': 'BLOCK_IP'
                })
                self.block_ip(ip)
                self.logger.warning(f"Port scanning detected from {ip} - {len(ports)} ports scanned")
        
        return detected_scans
    
    def detect_dos_attacks(self):
        """Detect DoS/DDoS attacks"""
        detected_attacks = []
        
        try:
            # Get network IO counters
            net_io = psutil.net_io_counters()
            packet_rate = (net_io.packets_sent + net_io.packets_recv) / 60  # Packets per second approx
            
            # Simple packet rate based detection
            if packet_rate > 10000:  # 10k packets per second
                detected_attacks.append({
                    'type': 'POTENTIAL_DOS',
                    'packet_rate': packet_rate,
                    'action': 'INCREASE_MONITORING'
                })
                self.logger.warning(f"High packet rate detected: {packet_rate:.2f} packets/sec")
            
            # Connection rate detection
            current_connections = len(psutil.net_connections())
            if current_connections > 1000:
                detected_attacks.append({
                    'type': 'HIGH_CONNECTION_COUNT',
                    'connections': current_connections,
                    'action': 'INVESTIGATE'
                })
                
        except Exception as e:
            self.logger.error(f"DoS detection error: {e}")
        
        return detected_attacks
    
    def detect_suspicious_connections(self, connections):
        """Detect suspicious network connections"""
        suspicious = []
        
        for conn in connections:
            try:
                # Check for connections to known malicious ports
                if hasattr(conn, 'laddr') and conn.laddr and conn.laddr.port in self.suspicious_ports:
                    suspicious.append({
                        'type': 'SUSPICIOUS_PORT',
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'action': 'TERMINATE_CONNECTION'
                    })
                    self.logger.warning(f"Suspicious connection on port {conn.laddr.port}")
                
                # Check for established connections to unknown external IPs
                if (conn.status == 'ESTABLISHED' and 
                    hasattr(conn, 'raddr') and conn.raddr and 
                    not self.is_private_ip(conn.raddr.ip)):
                    suspicious.append({
                        'type': 'EXTERNAL_CONNECTION',
                        'remote_ip': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'action': 'MONITOR'
                    })
                    
            except Exception as e:
                continue
        
        return suspicious
    
    def detect_connection_floods(self, connections):
        """Detect connection flood attacks"""
        flood_detections = []
        ip_connection_counts = defaultdict(int)
        
        for conn in connections:
            if hasattr(conn, 'raddr') and conn.raddr:
                ip_connection_counts[conn.raddr.ip] += 1
        
        for ip, count in ip_connection_counts.items():
            if count > 100:  # More than 100 connections from single IP
                flood_detections.append({
                    'type': 'CONNECTION_FLOOD',
                    'ip': ip,
                    'connection_count': count,
                    'action': 'BLOCK_IP'
                })
                self.block_ip(ip)
                self.logger.warning(f"Connection flood from {ip} - {count} connections")
        
        return flood_detections
    
    def is_private_ip(self, ip):
        """Check if IP is in private range"""
        try:
            ip_obj = socket.inet_aton(ip)
            # Check for private IP ranges
            if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.16.'):
                return True
            return False
        except:
            return False
    
    def block_ip(self, ip_address):
        """Block IP address using system firewall"""
        if ip_address in self.blocked_ips:
            return
            
        self.blocked_ips.add(ip_address)
        
        try:
            if platform.system() == "Windows":
                # Windows firewall rule
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=CyberShield_Block_{ip_address}',
                    'dir=in', 'action=block', f'remoteip={ip_address}'
                ], capture_output=True, timeout=10)
            else:
                # Linux iptables rule
                subprocess.run([
                    'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'
                ], capture_output=True, timeout=10)
                
            self.logger.info(f"Blocked IP: {ip_address}")
            
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip_address}: {e}")
    
    def start_continuous_monitoring(self):
        """Start continuous network monitoring"""
        def monitor_loop():
            while True:
                try:
                    attacks = self.detect_network_attacks()
                    for attack in attacks:
                        self.logger.warning(f"Network Attack: {attack}")
                    
                    threading.Event().wait(5)  # Check every 5 seconds
                    
                except Exception as e:
                    self.logger.error(f"Network monitoring error: {e}")
                    threading.Event().wait(10)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    self.logger.info("Continuous network monitoring started")