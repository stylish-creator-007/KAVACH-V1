#!/usr/bin/env python3
"""
KAVACH - Military Grade Cybersecurity Platform
Advanced threat detection and prevention system
"""

import asyncio
import signal
import sys
import os

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from core.security_orchestrator import SecurityOrchestrator
from utils.logger import setup_logging

class KAVACH:
    def __init__(self):
        setup_logging()
        self.security_orchestrator = SecurityOrchestrator()
        self.setup_signal_handlers()

    def setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.security_orchestrator.shutdown()
        sys.exit(0)

    async def run(self):
        print("""
        KAVACH Cybersecurity Platform Starting...

        Features:
        - Advanced Malware Detection
        - Ransomware Protection
        - Network Attack Prevention
        - Phishing Detection
        - Web Application Firewall
        - Behavioral Analysis
        - Real-time Monitoring
        - Emergency Shutdown

        Monitoring all security threats...
        """)
        try:
            await self.security_orchestrator.start_protection()
        except KeyboardInterrupt:
            print("\nShutdown requested by user...")
            self.security_orchestrator.shutdown()
        except Exception as e:
            print(f"Critical error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    # Check if running with appropriate privileges
    if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("Please run with administrator privileges for full functionality")
        print("   sudo python main.py")
        sys.exit(1)

    app = KAVACH()
    asyncio.run(app.run())