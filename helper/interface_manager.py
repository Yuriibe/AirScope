import subprocess
import time


class InterfaceManager:
    def __init__(self, iface="wlan0"):
        self.iface = iface

    def __enter__(self):
        print("🔧 Setting interface to monitor mode...")
        self.set_monitor_mode()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        print("\n⚠️  Restoring interface...")
        try:
            self.restore_managed_mode()
        except RuntimeError as e:
            print(f"⚠️  Could not restore interface: {e}")

    def run_cmd(self, cmd):
        """Run a shell command, raising if it fails."""
        result = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if result.returncode != 0:
            stderr = result.stderr.decode(errors="ignore").strip()
            raise RuntimeError(f"Command failed ({result.returncode}): {cmd}" + (f" — {stderr}" if stderr else ""))

    def set_monitor_mode(self):
        """Put interface into monitor mode."""
        self.run_cmd(f"ip link set {self.iface} down")
        self.run_cmd(f"iw dev {self.iface} set type monitor")
        self.run_cmd(f"ip link set {self.iface} up")

    def restore_managed_mode(self):
        """Restore interface to managed mode (normal Wi-Fi)."""
        self.run_cmd(f"ip link set {self.iface} down")
        self.run_cmd(f"iw dev {self.iface} set type managed")
        self.run_cmd(f"ip link set {self.iface} up")

    def set_channel(self, ch):
        """Set Wi-Fi channel."""
        try:
            self.run_cmd(f"iw dev {self.iface} set channel {ch}")
            # print(f"🔄 Switched to channel {ch}")
            time.sleep(0.5)  # Kurze Pause nach Channel-Wechsel
        except RuntimeError as e:
            print(f"Error setting channel {ch}: {e}")
