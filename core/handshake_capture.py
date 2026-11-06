import os
import threading
import time

from scapy.utils import wrpcap


class HandshakeCapture:
    """Buffers EAPOL frames seen for an AP (from any client that
    authenticates against it - like airodump-ng --bssid, no client has to
    be picked up front) and writes them to a .pcap once a full handshake's
    worth of frames is seen or the timeout expires, whichever is first."""

    def __init__(self, seen_aps, output_dir="captures"):
        self.seen_aps = seen_aps
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.active = {}   # bssid -> {record, packets, client_macs, done, min_frames}
        self.history = []  # newest last; records are shared dicts, mutated in place
        self.lock = threading.Lock()

    def start_session(self, bssid, timeout=15, min_frames=4):
        ap_info = self.seen_aps.get(bssid, {})
        record = {
            'bssid': bssid,
            'ssid': ap_info.get('ssid', 'Unknown'),
            'time': time.time(),
            'status': 'capturing',
            'frame_count': 0,
            'client_macs': [],
            'path': None
        }
        done = threading.Event()

        with self.lock:
            self.active[bssid] = {
                'record': record, 'packets': [], 'client_macs': set(),
                'done': done, 'min_frames': min_frames
            }
            self.history.append(record)

        def wait_and_finalize():
            done.wait(timeout)
            self._finalize(bssid)

        threading.Thread(target=wait_and_finalize, daemon=True).start()
        return record

    def on_packet(self, pkt):
        """Called by packet_handler for every frame carrying an EAPOL layer."""
        bssid = pkt.addr3
        client = pkt.addr1 if pkt.addr2 == bssid else pkt.addr2
        with self.lock:
            session = self.active.get(bssid)
            if session is None:
                return
            session['packets'].append(pkt)
            session['client_macs'].add(client)
            session['record']['frame_count'] = len(session['packets'])
            session['record']['client_macs'] = sorted(session['client_macs'])
            if len(session['packets']) >= session['min_frames']:
                session['done'].set()

    def _finalize(self, bssid):
        with self.lock:
            session = self.active.pop(bssid, None)
        if session is None:
            return
        record = session['record']
        packets = session['packets']
        if packets:
            filename = f"handshake_{bssid.replace(':', '')}_{int(record['time'])}.pcap"
            path = os.path.join(self.output_dir, filename)
            wrpcap(path, packets)
            record['path'] = path
            record['status'] = 'complete' if len(packets) >= session['min_frames'] else 'partial'
        else:
            record['status'] = 'no_data'

    def get_history(self, limit=50):
        with self.lock:
            return list(self.history[-limit:])
