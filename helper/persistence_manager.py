import sqlite3
import time


class PersistenceManager:
    """Periodically writes discovered APs/clients to SQLite, then prunes
    stale in-memory entries so a long-running capture doesn't grow RAM
    forever or lose everything on a crash."""

    def __init__(self, seen_aps, seen_clients, db_path, stale_timeout):
        self.seen_aps = seen_aps
        self.seen_clients = seen_clients
        self.db_path = db_path
        self.stale_timeout = stale_timeout
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS access_points (
                bssid TEXT PRIMARY KEY,
                ssid TEXT,
                last_seen REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                mac TEXT PRIMARY KEY,
                connected_to TEXT,
                ssid TEXT,
                probes TEXT,
                last_seen REAL
            )
        """)
        conn.commit()
        conn.close()

    def persist_and_prune(self):
        now = time.time()
        # Snapshot first: dict(...) is atomic under the GIL, unlike iterating the
        # live dict while the sniffer thread concurrently inserts new keys.
        aps_snapshot = dict(self.seen_aps)
        clients_snapshot = {mac: dict(info) for mac, info in self.seen_clients.items()}

        conn = sqlite3.connect(self.db_path)
        for bssid, info in aps_snapshot.items():
            conn.execute(
                "INSERT OR REPLACE INTO access_points (bssid, ssid, last_seen) VALUES (?, ?, ?)",
                (bssid, info['ssid'], info['last_seen'])
            )
        for mac, info in clients_snapshot.items():
            conn.execute(
                "INSERT OR REPLACE INTO clients (mac, connected_to, ssid, probes, last_seen) VALUES (?, ?, ?, ?, ?)",
                (mac, info.get('connected_to'), info.get('ssid'), ','.join(info.get('probes', [])), info['last_seen'])
            )
        conn.commit()
        conn.close()

        # Prune in-memory entries that are already safely persisted above.
        for bssid, info in aps_snapshot.items():
            if now - info['last_seen'] > self.stale_timeout:
                self.seen_aps.pop(bssid, None)
        for mac, info in clients_snapshot.items():
            if now - info['last_seen'] > self.stale_timeout:
                self.seen_clients.pop(mac, None)

    def run_periodic(self, interval):
        """Background thread entry point."""
        while True:
            time.sleep(interval)
            try:
                self.persist_and_prune()
            except Exception as e:
                print(f"⚠️  Persistence error: {e}")
