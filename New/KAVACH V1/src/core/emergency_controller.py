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
        self.critical_threshold = 85  # System usage percentage for triggering alerts
        self.security_processes = ['KAVACH', 'security_service']  # Processes to protect or monitor
        self.logger = logging.getLogger(__name__)
        self.emergency_mode = False
        self.health_history = []  # Store recent health scores for trends

    def assess_system_health(self):
        """Comprehensive system health assessment"""
        health_score = 100

        try:
            # CPU Health
            cpu_usage = psutil.cpu_percent(interval=1)
            if cpu_usage > 90:
                health_score -= 40  # Severe penalty for very high CPU
            elif cpu_usage > 80:
                health_score -= 20  # Moderate penalty

            # Memory Health
            memory = psutil.virtual_memory()
            if memory.percent > 85:
                health_score -= 20

            # Disk Health
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                health_score -= 10

            # Additional checks (e.g., network or process count)
            process_count = len(psutil.pids())
            if process_count > 500:  # Arbitrary threshold; adjust as needed
                health_score -= 5

            # Store history for trends
            self.health_history.append((datetime.now(), health_score))
            if len(self.health_history) > 10:  # Keep last 10 checks
                self.health_history.pop(0)

            self.logger.info(f"System health assessed: Score {health_score} (CPU: {cpu_usage}%, Mem: {memory.percent}%, Disk: {disk.percent}%)")
            return health_score

        except Exception as e:
            self.logger.error(f"Error assessing system health: {e}")
            return 0  # Return 0 on failure to indicate critical issue

    def trigger_emergency(self, reason):
        """Enter emergency mode and take corrective actions"""
        if self.emergency_mode:
            self.logger.warning("Emergency mode already active")
            return

        self.emergency_mode = True
        self.logger.critical(f"🚨 EMERGENCY MODE ACTIVATED: {reason}")

        # Actions: Kill non-essential processes, alert, etc.
        self.kill_non_essential_processes()
        self.send_alert(reason)
        # Add more: e.g., shutdown services, notify admin

    def kill_non_essential_processes(self):
        """Kill processes that are not in the security list"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] not in self.security_processes:
                    try:
                        os.kill(proc.info['pid'], signal.SIGTERM)  # Graceful kill
                        self.logger.info(f"Killed non-essential process: {proc.info['name']} (PID: {proc.info['pid']})")
                    except (psutil.NoSuchProcess, OSError):
                        pass  # Process already gone
        except Exception as e:
            self.logger.error(f"Error killing processes: {e}")

    def send_alert(self, reason):
        """Send an alert (e.g., log to file, email, or integrate with external system)"""
        alert_data = {
            "timestamp": datetime.now().isoformat(),
            "reason": reason,
            "health_history": self.health_history[-5:]  # Last 5 scores
        }
        try:
            with open('logs/emergency_alerts.json', 'a') as f:
                json.dump(alert_data, f)
                f.write('\n')
            self.logger.info("Emergency alert logged")
        except Exception as e:
            self.logger.error(f"Error sending alert: {e}")

    def monitor_and_respond(self):
        """Continuous monitoring loop"""
        while True:
            health = self.assess_system_health()
            if health < self.critical_threshold:
                self.trigger_emergency(f"Health score dropped to {health}")
            time.sleep(60)  # Check every minute; import time if needed

    def exit_emergency(self):
        """Exit emergency mode"""
        self.emergency_mode = False
        self.logger.info("Emergency mode deactivated")

# Example usage (for testing standalone)
if __name__ == "__main__":
    controller = EmergencyController()
    health = controller.assess_system_health()
    print(f"Current health score: {health}")
    if health < 50:
        controller.trigger_emergency("Test low health")
