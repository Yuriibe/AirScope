import time
from config.settings import Config


class DataStore:
    def __init__(self, seen_aps, seen_clients):
        self.seen_aps = seen_aps
        self.seen_clients = seen_clients


class NetworkFormatter:
    def __init__(self, data_store, vendor_lookup_func):
        self.data_store = data_store
        self.vendor_lookup_func = vendor_lookup_func

    def format_ap_summary(self):
        """Format access points section"""
        print("\n" + "=" * 70)
        print("📡 DISCOVERED ACCESS POINTS")
        print("=" * 70)

        # Snapshot first: dict(...) is atomic under the GIL, unlike iterating the live dict
        # while the sniffer thread inserts new keys concurrently.
        clients_snapshot = dict(self.data_store.seen_clients)
        for bssid, ap_info in dict(self.data_store.seen_aps).items():
            connected_count = sum(1 for client_info in clients_snapshot.values()
                                  if client_info['connected_to'] == bssid)
            vendor = self.vendor_lookup_func(bssid)
            print(f"SSID: {ap_info['ssid']:<20} | BSSID: {bssid} | Clients: {connected_count} | Vendor: {vendor}")

    def format_client_summary(self):
        """Format clients section"""
        print("\n" + "=" * 70)
        print("👥 DISCOVERED CLIENTS")
        print("=" * 70)

        for client_mac, client_info in dict(self.data_store.seen_clients).items():
            if client_info['connected_to']:
                status = f"Connected to: {client_info['ssid']} ({client_info['connected_to']})"
            elif client_info['probes']:
                status = f"Probing for: {', '.join(client_info['probes'][:3])}"
            else:
                status = "Status unknown"

            vendor = self.vendor_lookup_func(client_mac)
            print(f"Client: {client_mac} | {status} | Vendor: {vendor}")

    def print_full_summary(self):
        """Print complete network summary"""
        self.format_ap_summary()
        self.format_client_summary()

        print(f"\n📊 Total APs: {len(self.data_store.seen_aps)}")
        print(f"📊 Total Clients: {len(self.data_store.seen_clients)}")
        print("=" * 70)

    def periodic_summary(self):
        """Print summary every interval"""
        while True:
            time.sleep(Config.SUMMARY_INTERVAL)
            self.print_full_summary()
