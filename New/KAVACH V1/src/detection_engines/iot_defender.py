"""KAVACH IoT Defender"""

import logging
import socket
import time

class IoTDefender:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def defend(self, device):
        """Simulate IoT protection logic and return report"""
        start = time.time()

        report = {
            "device": device,
            "reachable": False,
            "ports": {},
            "risks": [],
            "analysis_time_seconds": 0.0
        }

        common_ports = {
            22: "ssh",
            23: "telnet",
            80: "http",
            443: "https",
            1883: "mqtt",
            554: "rtsp"
        }

        for port, service in common_ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                result = s.connect_ex((device, port))
                if result == 0:
                    report["reachable"] = True
                    report["ports"][port] = {"service": service, "open": True}
                    # Example risk conditions
                    if port in (22, 23):
                        report["risks"].append({
                            "port": port,
                            "service": service,
                            "reason": f"{service.upper()} may be exposed — check security configs"
                        })
                else:
                    report["ports"][port] = {"service": service, "open": False}
            except Exception as e:
                self.logger.debug(f"{device}:{port} - {e}")
            finally:
                s.close()

        report["analysis_time_seconds"] = time.time() - start
        return report


# ---------------------------------------------------
# Compact Standalone Test Runner
# ---------------------------------------------------
if __name__ == "__main__":
    import os
    import logging
    import time

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s - %(levelname)s - %(message)s",
                        datefmt="%H:%M:%S")
    defender = IoTDefender()

    sample_devices = [
        "127.0.0.1",
        "localhost",
    ]

    try:
        while True:
            os.system("clear")
            print("🔐 KAVACH-V1 :: IoT Defender (compact)\n" + "-" * 60)

            for dev in sample_devices:
                report = defender.defend(dev)
                open_ports = [f"{p}/{info['service']}" for p, info in report['ports'].items() if info['open']]
                open_ports_str = ", ".join(open_ports) if open_ports else "none"

                print(f"{report['device']:15} | reach: {str(report['reachable']):5} | "
                      f"ports: {open_ports_str} | risks: {len(report['risks'])} | "
                      f"{report['analysis_time_seconds']:.2f}s")

                if report["risks"]:
                    for r in report["risks"][:2]:
                        print(f"  - {r['port']}/{r['service']}: {r['reason']}")
                    if len(report["risks"]) > 2:
                        print(f"  - +{len(report['risks']) - 2} more risks...")

            print("\nRefresh every 20s (Ctrl+C to stop).")
            time.sleep(20)

    except KeyboardInterrupt:
        print("\n🛑 IoT Defender stopped by user.")
