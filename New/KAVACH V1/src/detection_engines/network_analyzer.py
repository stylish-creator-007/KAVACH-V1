#!/usr/bin/env python3
"""
Compact Network Security Monitor (auto-refresh)

- Uses psutil.net_connections() to snapshot active TCP connections.
- Detects simple port-scan heuristics and connection floods.
- Auto-refreshes and prints a compact summary every N seconds.

Place this file where you want and run: python3 network_analyzer.py
Requires: psutil
"""

import time
import os
import psutil
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta

REFRESH_INTERVAL = 5   # seconds between refreshes (auto-refresh)
PORT_SCAN_THRESHOLD = 30   # number of distinct remote ports touched by an IP -> port scan
FLOOD_WINDOW_SECONDS = 60  # sliding window for flood detection
FLOOD_CONN_THRESHOLD = 80  # number of new connections from same IP within window -> flood
SUSPICIOUS_PORTS = {4444, 9999, 1337, 31337, 12345, 54321}  # example suspicious ports

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("network_analyzer")


class NetworkSecurityMonitor:
    def __init__(self):
        # map remote_ip -> deque of timestamped connection events (for flood detection)
        self.conn_events = defaultdict(lambda: deque())
        # track last-run time for pruning
        self.last_run = datetime.utcnow()

    def _gather_connections(self):
        """Return list of psutil connection info (filtered to TCP ESTABLISHED or LISTEN/other useful)."""
        try:
            conns = psutil.net_connections(kind='inet')
            # keep only TCP/UDP with remote address (skip unix sockets)
            filtered = []
            for c in conns:
                # c.raddr may be empty for listening sockets
                laddr = getattr(c, "laddr", None)
                raddr = getattr(c, "raddr", None)
                proto = c.type  # socket.SOCK_STREAM or SOCK_DGRAM
                family = c.family
                status = getattr(c, "status", "")
                filtered.append({
                    "fd": c.fd,
                    "family": family,
                    "type": proto,
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": status,
                    "pid": c.pid
                })
            return filtered
        except Exception as e:
            logger.debug(f"Error gathering connections: {e}")
            return []

    def _update_events(self, now, connections):
        """Record connection events for flood detection from remote IPs."""
        for c in connections:
            r = c.get("raddr")
            if not r:
                continue
            remote_ip = r[0]
            # record this event
            dq = self.conn_events[remote_ip]
            dq.append(now)
        # prune old events beyond FLOOD_WINDOW_SECONDS
        cutoff = now - timedelta(seconds=FLOOD_WINDOW_SECONDS)
        for ip, dq in list(self.conn_events.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                # keep some empty dicts? clean up to save memory
                del self.conn_events[ip]

    def detect_port_scanning(self, connections):
        """
        Heuristic: if a remote IP has connections to many distinct remote ports
        in the current snapshot, flag as possible port scan.
        """
        port_map = defaultdict(set)  # ip -> set(ports)
        scans = []

        for c in connections:
            r = c.get("raddr")
            if not r:
                continue
            ip, port = r[0], r[1]
            port_map[ip].add(port)

        for ip, ports in port_map.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                scans.append(f"Possible port scan from {ip} (ports={len(ports)})")

        return scans

    def detect_suspicious_ports(self, connections):
        """Flag remote IPs connected to suspicious well-known ports."""
        alerts = []
        offenders = defaultdict(set)  # ip -> set(suspicious_ports)
        for c in connections:
            r = c.get("raddr")
            if not r:
                continue
            ip, port = r[0], r[1]
            if port in SUSPICIOUS_PORTS:
                offenders[ip].add(port)
        for ip, ports in offenders.items():
            alerts.append(f"Suspicious ports contacted by {ip}: {sorted(list(ports))}")
        return alerts

    def detect_connection_floods(self):
        """
        Flood detection: if a remote IP has created many connection events within the sliding window.
        Uses self.conn_events which is continuously pruned.
        """
        floods = []
        for ip, dq in self.conn_events.items():
            if len(dq) >= FLOOD_CONN_THRESHOLD:
                floods.append(f"Connection flood suspected from {ip} ({len(dq)} events in last {FLOOD_WINDOW_SECONDS}s)")
        return floods

    def top_remote_ips(self, connections, n=5):
        """Return top remote IPs by number of connections in the snapshot."""
        counts = defaultdict(int)
        for c in connections:
            r = c.get("raddr")
            if not r:
                continue
            counts[r[0]] += 1
        sorted_ips = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n]
        return sorted_ips

    def run_cycle(self):
        """Run one detection cycle and return compact results."""
        now = datetime.utcnow()
        conns = self._gather_connections()
        # update events for flood detection
        self._update_events(now, conns)

        port_scans = self.detect_port_scanning(conns)
        suspicious_ports = self.detect_suspicious_ports(conns)
        floods = self.detect_connection_floods()
        top_ips = self.top_remote_ips(conns, n=5)

        # Compact summary
        summary = {
            "timestamp": now.isoformat() + "Z",
            "total_connections": len(conns),
            "top_remote_ips": top_ips,
            "port_scans": port_scans,
            "suspicious_ports": suspicious_ports,
            "floods": floods
        }
        self.last_run = now
        return summary


def clear_console():
    os.system("cls" if os.name == "nt" else "clear")


def pretty_print_cycle(summary):
    """Print a compact, easy-to-read block for a single cycle."""
    ts = summary.get("timestamp", "")[11:19]  # HH:MM:SS
    total = summary.get("total_connections", 0)
    top = summary.get("top_remote_ips", [])
    port_scans = summary.get("port_scans", [])
    suspicious_ports = summary.get("suspicious_ports", [])
    floods = summary.get("floods", [])

    clear_console()
    print("🌐 KAVACH-V1 :: Network Monitor (compact)\n" + "-" * 60)
    print(f"[{ts}] connections: {total} | top remote IPs: " +
          ", ".join([f"{ip}({cnt})" for ip, cnt in top]) if top else f"[{ts}] connections: {total}")

    # show findings succinctly (max 4 lines total)
    findings = port_scans + suspicious_ports + floods
    if findings:
        print("\n⚠️  Alerts:")
        for f in findings[:6]:  # show up to 6 alerts
            print(f"  • {f}")
        if len(findings) > 6:
            print(f"  • +{len(findings) - 6} more alerts...")
    else:
        print("\n✅ No suspicious network activity detected in this cycle.")

    print("\n(Refresh every {}s — Ctrl+C to stop)".format(REFRESH_INTERVAL))


def main():
    monitor = NetworkSecurityMonitor()
    try:
        while True:
            summary = monitor.run_cycle()
            pretty_print_cycle(summary)
            time.sleep(REFRESH_INTERVAL)
    except KeyboardInterrupt:
        print("\n🛑 Network Monitor stopped by user.")
    except Exception as e:
        logger.error(f"Unhandled error in monitor: {e}")


if __name__ == "__main__":
    main()
