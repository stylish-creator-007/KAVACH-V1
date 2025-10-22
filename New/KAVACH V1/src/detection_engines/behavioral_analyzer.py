import psutil
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta

class BehavioralAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.process_behavior = defaultdict(lambda: deque(maxlen=100))
        self.network_behavior = defaultdict(lambda: deque(maxlen=100))
        self.user_behavior = defaultdict(lambda: deque(maxlen=100))
        self.anomaly_threshold = 3.0  # Standard deviations for anomaly detection
        
    def detect_anomalies(self):
        """Detect behavioral anomalies across system"""
        anomalies = []
        
        try:
            anomalies.extend(self.detect_process_anomalies())
            anomalies.extend(self.detect_network_anomalies())
            anomalies.extend(self.detect_user_anomalies())
            anomalies.extend(self.detect_system_anomalies())
            
        except Exception as e:
            self.logger.error(f"Behavioral analysis error: {e}")
        
        return anomalies
    
    def detect_process_anomalies(self):
        """Detect anomalous process behavior"""
        anomalies = []
        current_time = time.time()
        
        for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                process_info = process.info
                pid = process_info['pid']
                name = process_info['name']
                
                # Track process behavior
                behavior_data = {
                    'timestamp': current_time,
                    'cpu': process_info['cpu_percent'] or 0,
                    'memory': process_info['memory_percent'] or 0,
                    'name': name
                }
                
                self.process_behavior[pid].append(behavior_data)
                
                # Check for anomalies
                if len(self.process_behavior[pid]) > 10:
                    recent_cpu = [data['cpu'] for data in list(self.process_behavior[pid])[-5:]]
                    avg_cpu = sum(recent_cpu) / len(recent_cpu)
                    
                    # Sudden CPU spike
                    if avg_cpu > 80 and max(recent_cpu) > 90:
                        anomalies.append({
                            'type': 'PROCESS_CPU_SPIKE',
                            'pid': pid,
                            'process_name': name,
                            'cpu_usage': avg_cpu,
                            'confidence': 'HIGH'
                        })
                        self.logger.warning(f"Process CPU spike: {name} (PID: {pid}) - CPU: {avg_cpu}%")
                    
                    # Sudden memory spike
                    recent_memory = [data['memory'] for data in list(self.process_behavior[pid])[-5:]]
                    avg_memory = sum(recent_memory) / len(recent_memory)
                    
                    if avg_memory > 50 and max(recent_memory) > 70:
                        anomalies.append({
                            'type': 'PROCESS_MEMORY_SPIKE',
                            'pid': pid,
                            'process_name': name,
                            'memory_usage': avg_memory,
                            'confidence': 'HIGH'
                        })
                        self.logger.warning(f"Process memory spike: {name} (PID: {pid}) - Memory: {avg_memory}%")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return anomalies
    
    def detect_network_anomalies(self):
        """Detect anomalous network behavior"""
        anomalies = []
        
        try:
            connections = psutil.net_connections()
            current_time = time.time()
            
            # Track connection patterns
            connection_data = {
                'timestamp': current_time,
                'total_connections': len(connections),
                'established': len([c for c in connections if c.status == 'ESTABLISHED']),
                'listening': len([c for c in connections if c.status == 'LISTEN']),
            }
            
            self.network_behavior['system'].append(connection_data)
            
            # Check for connection floods
            if len(self.network_behavior['system']) > 5:
                recent_connections = [data['total_connections'] for data in list(self.network_behavior['system'])[-5:]]
                avg_connections = sum(recent_connections) / len(recent_connections)
                
                if avg_connections > 1000 and max(recent_connections) > 1500:
                    anomalies.append({
                        'type': 'NETWORK_CONNECTION_FLOOD',
                        'connection_count': avg_connections,
                        'confidence': 'HIGH'
                    })
            
            # Analyze per-process network activity
            process_connections = defaultdict(list)
            for conn in connections:
                if conn.pid:
                    process_connections[conn.pid].append(conn)
            
            for pid, conns in process_connections.items():
                if len(conns) > 50:  # Process with many connections
                    try:
                        process = psutil.Process(pid)
                        process_name = process.name()
                        
                        anomalies.append({
                            'type': 'PROCESS_NETWORK_ACTIVITY',
                            'pid': pid,
                            'process_name': process_name,
                            'connection_count': len(conns),
                            'confidence': 'MEDIUM'
                        })
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
        except Exception as e:
            self.logger.error(f"Network behavior analysis error: {e}")
        
        return anomalies
    
    def detect_user_anomalies(self):
        """Detect anomalous user behavior"""
        anomalies = []
        
        try:
            # Track login sessions (simplified)
            users = psutil.users()
            current_time = time.time()
            
            user_data = {
                'timestamp': current_time,
                'active_users': len(users),
                'user_names': [user.name for user in users]
            }
            
            self.user_behavior['sessions'].append(user_data)
            
            # Check for unusual login patterns
            if len(self.user_behavior['sessions']) > 10:
                recent_users = [data['active_users'] for data in list(self.user_behavior['sessions'])[-10:]]
                avg_users = sum(recent_users) / len(recent_users)
                
                # Sudden increase in active users
                if len(users) > avg_users * 2 and len(users) > 1:
                    anomalies.append({
                        'type': 'UNUSUAL_USER_ACTIVITY',
                        'active_users': len(users),
                        'average_users': avg_users,
                        'confidence': 'MEDIUM'
                    })
                    
        except Exception as e:
            self.logger.error(f"User behavior analysis error: {e}")
        
        return anomalies
    
    def detect_system_anomalies(self):
        """Detect system-wide anomalies"""
        anomalies = []
        
        try:
            # CPU usage anomalies
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                anomalies.append({
                    'type': 'HIGH_SYSTEM_CPU',
                    'cpu_usage': cpu_percent,
                    'confidence': 'HIGH'
                })
            
            # Memory usage anomalies
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                anomalies.append({
                    'type': 'HIGH_SYSTEM_MEMORY',
                    'memory_usage': memory.percent,
                    'confidence': 'HIGH'
                })
            
            # Disk activity anomalies
            disk_io = psutil.disk_io_counters()
            if disk_io and disk_io.write_bytes > 100 * 1024 * 1024:  # 100MB written
                anomalies.append({
                    'type': 'HIGH_DISK_WRITE',
                    'bytes_written': disk_io.write_bytes,
                    'confidence': 'MEDIUM'
                })
                
        except Exception as e:
            self.logger.error(f"System anomaly detection error: {e}")
        
        return anomalies
    
    def calculate_behavior_baseline(self):
        """Calculate baseline behavior patterns"""
        # This would establish normal behavior patterns over time
        # For now, it's a placeholder for more advanced analytics
        pass
    
    def is_behavior_anomalous(self, current_behavior, baseline):
        """Check if current behavior deviates from baseline"""
        # Simplified anomaly detection
        if not baseline:
            return False
        
        # Calculate deviation (simplified)
        deviation = abs(current_behavior - baseline) / baseline if baseline > 0 else 0
        return deviation > self.anomaly_threshold