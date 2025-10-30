#!/usr/bin/env python3
"""
KAVACH - Military Grade Cybersecurity Platform
Main entry point to initialize and orchestrate all modules.
"""

import asyncio
import signal
import sys
import os

# --- Setup environment path ---
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.core.security_orchestrator import SecurityOrchestrator
from src.utils.logger import setup_logging


class KAVACH:
    def __init__(self):
        setup_logging()
        self.security_orchestrator = SecurityOrchestrator()
        self.setup_signal_handlers()

    def setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print(f"\n⚠️ Received signal {signum}, shutting down gracefully...")
        self.security_orchestrator.shutdown()
        sys.exit(0)

    async def run(self):
        print("""
====================================================
🛡️  KAVACH Cybersecurity Platform Starting...
====================================================

Features:
 - Advanced Malware Detection
 - Network Intrusion Prevention
 - Real-Time System Monitoring
 - Threat Intelligence Analysis
 - Automated Firewall & Access Control

⚙️  Initializing...
""")

        await self.security_orchestrator.security_main_loop()


if __name__ == "__main__":
    kavach = KAVACH()
    try:
        asyncio.run(kavach.run())
    except KeyboardInterrupt:
        print("\n🛑 Termination requested by user.")
        kavach.security_orchestrator.shutdown()
