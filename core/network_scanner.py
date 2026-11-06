import time
from scapy.all import sniff


class NetworkScanner:
    def __init__(self, interface_manager, config):
        self.interface_manager = interface_manager
        self.config = config

    def channel_hopper(self):
        """Background thread: hop through channels."""
        channels = self.config.CHANNELS
        while True:
            for ch in channels:
                try:
                    self.interface_manager.set_channel(ch)
                    time.sleep(self.config.CHANNEL_DWELL_TIME)
                except Exception as e:
                    print(f"Channel hop error: {e}")
                    time.sleep(1.0)

    def start_sniffing(self, packet_handlers):
        """Sniff session with error handling; restarts on any capture error without growing the stack"""
        while True:
            try:
                print("🔍 Starting packet capture...")
                sniff(iface=self.interface_manager.iface, prn=packet_handlers.packet_handler, store=0)
                return
            except KeyboardInterrupt:
                print("\n🛑 Capture interrupted by user")
                return
            except Exception as e:
                # Scapy can raise all sorts of things (OSError on a dead socket,
                # struct.error/Scapy_Exception on a malformed/truncated frame, etc.)
                # while dissecting a captured frame - any of those must not take
                # the whole unattended capture down.
                print(f"⚠️ Capture error: {e}")
                print("🔄 Restarting in 3 seconds...")
                time.sleep(3)
