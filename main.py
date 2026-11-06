import threading

from scapy.config import conf

from config.settings import Config
from core.channel_state import ChannelState
from core.deauth_attacker import DeauthAttacker
from core.network_scanner import NetworkScanner
from core.packet_handler import PacketHandlers
from display.formatter import NetworkFormatter, DataStore
from helper.interface_manager import InterfaceManager
from helper.persistence_manager import PersistenceManager
from helper.vendor_manager import VendorManager
from web.server import app, WebDataBridge
import web.server

conf.debug_dissector = 2

# Track discovered APs and clients
seen_aps = {}
seen_clients = {}
deauth_events = []

# --- Main ---
if __name__ == "__main__":
    vendor_manager = VendorManager(Config.VENDOR_DB_PATH)
    channel_state = ChannelState()
    packet_handlers = PacketHandlers(seen_aps, seen_clients, deauth_events, channel_state)

    # Initialize web bridge before starting Flask
    web.server.web_bridge = WebDataBridge(seen_aps, seen_clients, vendor_manager, deauth_events)
    print(f"DEBUG: Initialized web_bridge with {len(seen_aps)} APs and {len(seen_clients)} clients")

    persistence_manager = PersistenceManager(
        seen_aps, seen_clients, Config.DB_PATH, Config.STALE_TIMEOUT
    )

    with InterfaceManager(Config.INTERFACE) as iface_manager:
        scanner = NetworkScanner(iface_manager, Config, channel_state)
        formatter = NetworkFormatter(
            DataStore(seen_aps, seen_clients),
            vendor_manager.find_vendor_by_mac
        )
        deauth_attacker = DeauthAttacker(iface_manager, seen_aps, deauth_events, channel_state)
        web.server.deauth_attacker = deauth_attacker

        threading.Thread(
            target=lambda: app.run(host='0.0.0.0', port=5000, debug=False),
            daemon=True
        ).start()

        print("🚀 Starting channel hopper...")
        threading.Thread(target=scanner.channel_hopper, daemon=True).start()
        threading.Thread(target=formatter.periodic_summary, daemon=True).start()
        threading.Thread(
            target=persistence_manager.run_periodic,
            args=(Config.PERSIST_INTERVAL,),
            daemon=True
        ).start()

        print("🔍 Sniffing across channels (Ctrl+C to stop)...")
        scanner.start_sniffing(packet_handlers)