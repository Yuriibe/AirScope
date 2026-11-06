import os
import threading
import time

from scapy.utils import wrpcap


class HandshakeCapture:
    """Buffers EAPOL frames for an active (bssid, client_mac) capture
    session and writes them to a .pcap file once enough frames are seen
    (a full 4-way handshake) or the timeout expires, whichever is first."""

    def __init__(self, seen_aps, output_dir="captures"):
        self.seen_aps = seen_aps
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.active = {}   # (bssid, client_mac) -> {record, packets, done, min_frames}
        self.history = []  # newest last; records are shared dicts, mutated in place
        self.lock = threading.Lock()

    def start_session(self, bssid, client_mac, timeout=15, min_frames=4):
        key = (bssid, client_mac)
        ap_info = self.seen_aps.get(bssid, {})
        record = {
            'bssid': bssid,
            'client_mac': client_mac,
            'ssid': ap_info.get('ssid', 'Unknown'),
            'time': time.time(),
            'status': 'capturing',
            'frame_count': 0,
            'path': None
        }
        done = threading.Event()

        with self.lock:
            self.active[key] = {'record': record, 'packets': [], 'done': done, 'min_frames': min_frames}
            self.history.append(record)

        def wait_and_finalize():
            done.wait(timeout)
            self._finalize(key)

        threading.Thread(target=wait_and_finalize, daemon=True).start()
        return record

    def on_packet(self, pkt):
        """Called by packet_handler for every frame carrying an EAPOL layer."""
        bssid = pkt.addr3
        peers = (pkt.addr1, pkt.addr2)
        with self.lock:
            for key, session in self.active.items():
                if key[0] == bssid and key[1] in peers:
                    session['packets'].append(pkt)
                    session['record']['frame_count'] = len(session['packets'])
                    if len(session['packets']) >= session['min_frames']:
                        session['done'].set()

    def _finalize(self, key):
        with self.lock:
            session = self.active.pop(key, None)
        if session is None:
            return
        record = session['record']
        packets = session['packets']
        if packets:
            filename = f"handshake_{key[0].replace(':', '')}_{int(record['time'])}.pcap"
            path = os.path.join(self.output_dir, filename)
            wrpcap(path, packets)
            record['path'] = path
            record['status'] = 'complete' if len(packets) >= session['min_frames'] else 'partial'
        else:
            record['status'] = 'no_data'

    def get_history(self, limit=50):
        with self.lock:
            return list(self.history[-limit:])
