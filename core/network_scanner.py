import time
from scapy.all import sniff


class NetworkScanner:
    def __init__(self, interface_manager, config, channel_state=None):
        self.interface_manager = interface_manager
        self.config = config
        self.channel_state = channel_state

    def channel_hopper(self):
        """Background thread: hop through channels, unless paused for a deauth burst."""
        channels = self.config.CHANNELS
        while True:
            for ch in channels:
                if self.channel_state and self.channel_state.paused.is_set():
                    time.sleep(0.2)
                    continue
                try:
                    self.interface_manager.set_channel(ch)
                    if self.channel_state:
                        self.channel_state.current = ch
                except Exception as e:
                    print(f"Channel hop error: {e}")
                    time.sleep(1.0)
                    continue

                # Dwell in short steps so a pause request is picked up promptly
                dwell_remaining = self.config.CHANNEL_DWELL_TIME
                while dwell_remaining > 0:
                    if self.channel_state and self.channel_state.paused.is_set():
                        break
                    step = min(0.2, dwell_remaining)
                    time.sleep(step)
                    dwell_remaining -= step

    def start_sniffing(self, packet_handlers):
        """Sniff session with error handling; restarts on socket errors without growing the stack"""
        while True:
            try:
                print("🔍 Starting packet capture...")
                sniff(iface=self.interface_manager.iface, prn=packet_handlers.packet_handler, store=0)
                return
            except KeyboardInterrupt:
                print("\n🛑 Capture interrupted by user")
                return
            except OSError as e:
                print(f"⚠️ Socket error: {e}")
                print("🔄 Restarting in 3 seconds...")
                time.sleep(3)
