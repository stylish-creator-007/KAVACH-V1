import psutil
import time
import logging
from datetime import datetime
from threading import Thread

class RealTimeMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.monitor_thread = None
        self.metrics_history = {
            'cpu': [],
            'memory': [],
            'network': [],
            'disk': []
        }
        
    def start_monitoring(self):
        """Start real-time system monitoring"""
        if self.monitoring:
            return
            
        self.monitoring = True
        self.monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("✅ Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("✅ Real-time monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Collect system metrics
                metrics = self._collect_metrics()
                
                # Store in history
                self._update_metrics_history(metrics)
                
                # Check for critical conditions
                self._check_critical_conditions(metrics)
                
                time.sleep(2)  # Monitor every 2 seconds
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(5)
    
    def _collect_metrics(self):
        """Collect system metrics"""
        timestamp = datetime.now()
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        
        # Disk usage
        disk = psutil.disk_usage('/')
        
        # Network I/O
        net_io = psutil.net_io_counters()
        
        # Process count
        process_count = len(psutil.pids())
        
        return {
            'timestamp': timestamp,
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_used_gb': memory.used / (1024**3),
            'disk_percent': disk.percent,
            'network_bytes_sent': net_io.bytes_sent,
            'network_bytes_recv': net_io.bytes_recv,
            'process_count': process_count
        }
    
    def _update_metrics_history(self, metrics):
        """Update metrics history"""
        for key in ['cpu', 'memory', 'disk']:
            if f"{key}_percent" in metrics:
                self.metrics_history[key].append({
                    'timestamp': metrics['timestamp'],
                    'value': metrics[f"{key}_percent"]
                })
                # Keep only last 100 readings
                if len(self.metrics_history[key]) > 100:
                    self.metrics_history[key].pop(0)
    
    def _check_critical_conditions(self, metrics):
        """Check for critical system conditions"""
        warnings = []
        
        # CPU critical
        if metrics['cpu_percent'] > 95:
            warnings.append(f"CRITICAL: CPU usage at {metrics['cpu_percent']}%")
        
        # Memory critical
        if metrics['memory_percent'] > 95:
            warnings.append(f"CRITICAL: Memory usage at {metrics['memory_percent']}%")
        
        # Disk critical
        if metrics['disk_percent'] > 98:
            warnings.append(f"CRITICAL: Disk usage at {metrics['disk_percent']}%")
        
        # Log warnings
        for warning in warnings:
            self.logger.warning(f"🚨 {warning}")
    
    def get_system_health(self):
        """Get current system health status"""
        try:
            metrics = self._collect_metrics()
            
            health_score = 100
            
            # Deduct points based on usage
            if metrics['cpu_percent'] > 80:
                health_score -= 20
            if metrics['memory_percent'] > 80:
                health_score -= 20
            if metrics['disk_percent'] > 90:
                health_score -= 10
            
            return {
                'health_score': max(0, health_score),
                'status': 'HEALTHY' if health_score > 80 else 'WARNING' if health_score > 60 else 'CRITICAL',
                'metrics': metrics
            }
            
        except Exception as e:
            self.logger.error(f"Health check error: {e}")
            return {'health_score': 0, 'status': 'UNKNOWN', 'metrics': {}}
    
    def get_metrics_history(self, metric_type='cpu', limit=50):
        """Get historical metrics"""
        return list(self.metrics_history.get(metric_type, []))[-limit:]