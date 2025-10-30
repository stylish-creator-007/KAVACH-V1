import psutil
import time
import logging
from collections import defaultdict, deque
from datetime import datetime


class BehavioralAnalyzer:
    """
    Monitors behavioral patterns of system processes, users, and networks.
    Detects anomalies based on CPU, memory, and process activity changes.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.process_behavior = defaultdict(lambda: deque(maxlen=100))
        self.network_behavior = defaultdict(lambda: deque(maxlen=100))
        self.user_behavior = defaultdict(lambda: deque(maxlen=100))
        self.anomaly_threshold = 3.0  # Standard deviations for anomaly detection

    # -------------------------------------------------------------------------
    # MAIN ENTRY
    # -------------------------------------------------------------------------

    def detect_anomalies(self):
        """Run all anomaly detectors and collect results."""
        anomalies = []

        try:
            anomalies.extend(self.detect_process_anomalies())
            anomalies.extend(self.detect_network_anomalies())
            anomalies.extend(self.detect_user_anomalies())
            anomalies.extend(self.detect_system_anomalies())
        except Exception as e:
            self.logger.error(f"Behavioral analysis error: {e}")

        return anomalies

    # -------------------------------------------------------------------------
    # PROCESS MONITORING
    # -------------------------------------------------------------------------

    def detect_process_anomalies(self):
        """Detect anomalous process behavior using CPU and memory metrics."""
        anomalies = []
        current_time = time.time()

        for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = process.info
                pid = info['pid']
                name = info['name']
                cpu = info['cpu_percent']
                mem = info['memory_percent']

                self.process_behavior[pid].append((current_time, cpu, mem))

                # Check CPU spike anomaly
                if cpu > 90:
                    anomalies.append(f"High CPU usage by {name} (PID {pid}): {cpu}%")

                # Check memory usage anomaly
                if mem > 80:
                    anomalies.append(f"High memory usage by {name} (PID {pid}): {mem}%")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                self.logger.error(f"Process anomaly detection error: {e}")

        return anomalies

    # -------------------------------------------------------------------------
    # NETWORK MONITORING
    # -------------------------------------------------------------------------

    def detect_network_anomalies(self):
        """Detect anomalies in network I/O patterns."""
        anomalies = []
        try:
            net_io = psutil.net_io_counters(pernic=True)
            timestamp = datetime.now().strftime("%H:%M:%S")

            for iface, stats in net_io.items():
                key = iface
                self.network_behavior[key].append((timestamp, stats.bytes_sent, stats.bytes_recv))

                # Check for high network usage
                if stats.bytes_sent > 5_000_000 or stats.bytes_recv > 5_000_000:
                    anomalies.append(
                        f"High network traffic on {iface} (Sent: {stats.bytes_sent / 1e6:.2f} MB, "
                        f"Recv: {stats.bytes_recv / 1e6:.2f} MB)"
                    )

        except Exception as e:
            self.logger.error(f"Network anomaly detection error: {e}")

        return anomalies

    # -------------------------------------------------------------------------
    # USER BEHAVIOR MONITORING
    # -------------------------------------------------------------------------

    def detect_user_anomalies(self):
        """Detect anomalies in user sessions or activity."""
        anomalies = []
        try:
            users = psutil.users()
            for user in users:
                self.user_behavior[user.name].append(datetime.now())
                # Example check: multiple active sessions
                if len(self.user_behavior[user.name]) > 5:
                    anomalies.append(f"Multiple logins detected for user: {user.name}")

        except Exception as e:
            self.logger.error(f"User anomaly detection error: {e}")

        return anomalies

    # -------------------------------------------------------------------------
    # SYSTEM-WIDE ANOMALIES
    # -------------------------------------------------------------------------

    def detect_system_anomalies(self):
        """Detect system-level anomalies like high CPU load or low memory."""
        anomalies = []
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()

            if cpu_percent > 85:
                anomalies.append(f"System CPU usage high: {cpu_percent}%")

            if memory.percent > 85:
                anomalies.append(f"System memory usage high: {memory.percent}%")

        except Exception as e:
            self.logger.error(f"System anomaly detection error: {e}")

        return anomalies

    # -------------------------------------------------------------------------
    # LOGGING & UTILITIES
    # -------------------------------------------------------------------------

    def summarize_behavior(self):
        """Summarize behavioral statistics for reporting."""
        summary = {
            "total_tracked_processes": len(self.process_behavior),
            "total_network_interfaces": len(self.network_behavior),
            "tracked_users": len(self.user_behavior),
        }
        self.logger.info(f"Behavior summary: {summary}")
        return summary


# =============================================================================
# TEST RUNNER (for standalone execution)
# =============================================================================
if __name__ == "__main__":
    import time
    import os

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S"
    )

    analyzer = BehavioralAnalyzer()

    print("\n🧠 Starting real-time Behavioral Analysis Monitor...")
    print("Press Ctrl + C to stop.\n")

    try:
        while True:
            anomalies = analyzer.detect_anomalies()
            summary = analyzer.summarize_behavior()

            os.system('clear')  # clears terminal for a live dashboard feel
            print("🧠 KAVACH-V1 :: Behavioral Analyzer\n" + "-" * 50)

            if anomalies:
                print("\n⚠️  Detected Anomalies:")
                for a in anomalies:
                    print(f"  • {a}")
            else:
                print("\n✅ No anomalies detected this cycle.")

            print("\n📊 Summary:")
            for key, value in summary.items():
                print(f"  • {key}: {value}")

            print("\n" + "-" * 50)
            time.sleep(5)  # wait 5 seconds before next scan

    except KeyboardInterrupt:
        print("\n🛑 Behavioral Analyzer stopped by user.\n")
