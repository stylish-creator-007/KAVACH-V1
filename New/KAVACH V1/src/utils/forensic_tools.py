import os
import json
import psutil
import tarfile
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import logging

class ForensicTools:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.output_dir = Path("evidence")
        self.output_dir.mkdir(exist_ok=True)

    def collect(self):
        """Collect system forensic evidence"""
        try:
            timestamp = self._utc_timestamp()
            session_dir = self.output_dir / f"evidence_{timestamp}"
            session_dir.mkdir(parents=True, exist_ok=True)

            self.logger.info("🕵️ KAVACH Forensic Collector — running (best-effort)")

            collected_files = []

            # Collect system info
            sysinfo_file = session_dir / "system_info.txt"
            with open(sysinfo_file, "w") as f:
                f.write(f"System: {os.uname()}\n")
                f.write(f"Boot time: {datetime.fromtimestamp(psutil.boot_time())}\n")
                f.write(f"CPU usage: {psutil.cpu_percent(interval=1)}%\n")
                f.write(f"Memory: {psutil.virtual_memory()}\n")
            collected_files.append(str(sysinfo_file))

            # Collect process info
            proc_file = session_dir / "processes.json"
            with open(proc_file, "w") as f:
                json.dump([p.info for p in psutil.process_iter(['pid', 'name', 'username', 'cmdline'])], f, indent=2)
            collected_files.append(str(proc_file))

            # Collect network connections
            net_file = session_dir / "network_connections.json"
            with open(net_file, "w") as f:
                json.dump([conn._asdict() for conn in psutil.net_connections()], f, indent=2)
            collected_files.append(str(net_file))

            # Collect mounts and open files
            mounts_file = session_dir / "mounts.txt"
            with open(mounts_file, "w") as f:
                subprocess.run(["mount"], stdout=f, stderr=subprocess.DEVNULL)
            collected_files.append(str(mounts_file))

            lsof_file = session_dir / "lsof.txt"
            with open(lsof_file, "w") as f:
                subprocess.run(["lsof", "-n"], stdout=f, stderr=subprocess.DEVNULL)
            collected_files.append(str(lsof_file))

            # Create tar archive
            archive_path = f"{session_dir}.tar.gz"
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(session_dir, arcname=session_dir.name)

            print(f"\n🔎 Collected {len(collected_files)} files -> {session_dir} | archive: {archive_path}\n")
            print("Collected files:")
            for f in collected_files:
                print(f" • {f}")
            print(f"\nArchive: {archive_path}")
            print("\n✅ Done — evidence saved locally. Handle files securely.\n")

            return collected_files

        except Exception as e:
            self.logger.error(f"Error during forensic collection: {e}")
            print(f"❌ Forensic collection failed: {e}")

    def _utc_timestamp(self):
        """Return safe UTC timestamp"""
        return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


if __name__ == "__main__":
    collector = ForensicTools()
    collector.collect()


