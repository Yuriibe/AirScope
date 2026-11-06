import time

from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL


class PacketHandlers:
    def __init__(self, seen_aps, seen_clients, deauth_events=None, channel_state=None, handshake_capture=None):
        self.seen_aps = seen_aps
        self.seen_clients = seen_clients
        self.deauth_events = deauth_events if deauth_events is not None else []
        self.channel_state = channel_state
        self.handshake_capture = handshake_capture

    def handle_beacon_frame(self, pkt):
        """Handle Access Point beacon frames"""
        ssid = pkt.info.decode(errors="ignore")
        bssid = pkt.addr2
        channel = self.channel_state.current if self.channel_state else None

        if ssid:
            self.seen_aps[bssid] = {'ssid': ssid, 'last_seen': time.time(), 'channel': channel}
        elif bssid not in self.seen_aps:
            self.seen_aps[bssid] = {'ssid': '<hidden>', 'last_seen': time.time(), 'channel': channel}
        else:
            self.seen_aps[bssid]['last_seen'] = time.time()
            self.seen_aps[bssid]['channel'] = channel

    def handle_probe_request(self, pkt):
        """Handle client probe requests"""
        client = pkt.addr2
        ssid = pkt.info.decode(errors="ignore")

        if client not in self.seen_clients:
            self.seen_clients[client] = {
                'connected_to': None,
                'ssid': None,
                'probes': [],
                'last_seen': time.time()
            }

        # Track what SSIDs this client is probing for
        if ssid and ssid not in self.seen_clients[client]['probes']:
            self.seen_clients[client]['probes'].append(ssid)
        self.seen_clients[client]['last_seen'] = time.time()

    def handle_association_request(self, pkt):
        """Handle client association/reassociation requests"""
        client = pkt.addr2
        ap_bssid = pkt.addr1

        if client not in self.seen_clients:
            self.seen_clients[client] = {'connected_to': None, 'ssid': None, 'probes': [], 'last_seen': time.time()}

        ap_info = self.seen_aps.get(ap_bssid, {})
        self.seen_clients[client]['connected_to'] = ap_bssid
        self.seen_clients[client]['ssid'] = ap_info.get('ssid', 'Unknown')
        self.seen_clients[client]['last_seen'] = time.time()
        print(f"[ASSOC] Client {client} associating with {ap_bssid}")

    def handle_disassociation(self, pkt):
        """Handle disassociation frames - client leaving an AP"""
        client = pkt.addr2
        if client in self.seen_clients:
            self.seen_clients[client]['connected_to'] = None
            self.seen_clients[client]['last_seen'] = time.time()

    def handle_deauthentication(self, pkt):
        """Handle deauthentication frames - clear connection state and log the event"""
        src = pkt.addr2
        dst = pkt.addr1
        bssid = pkt.addr3
        now = time.time()

        for mac in (src, dst):
            if mac in self.seen_clients:
                self.seen_clients[mac]['connected_to'] = None
                self.seen_clients[mac]['last_seen'] = now

        # While channel_state is paused, only our own DeauthAttacker holds the
        # channel - these are our own frames looping back through the sniffer,
        # not a third-party attack. DeauthAttacker logs its own 'self' event
        # once the burst finishes, so skip logging here to avoid flooding the
        # event log with hundreds of duplicate "observed" entries.
        if self.channel_state and self.channel_state.paused.is_set():
            return

        self.deauth_events.append({
            'time': now,
            'src': src,
            'dst': dst,
            'bssid': bssid,
            'source': 'observed'
        })

    def handle_data_frame(self, pkt):
        """Handle data frames to track active connections"""
        src = pkt.addr2
        dst = pkt.addr1
        now = time.time()

        # Client to AP traffic
        if src in self.seen_clients and dst in self.seen_aps:
            self.seen_clients[src]['connected_to'] = dst
            self.seen_clients[src]['ssid'] = self.seen_aps.get(dst, {}).get('ssid', 'Unknown')
            self.seen_clients[src]['last_seen'] = now

        # AP to Client traffic
        elif src in self.seen_aps and dst in self.seen_clients:
            self.seen_clients[dst]['connected_to'] = src
            self.seen_clients[dst]['ssid'] = self.seen_aps.get(src, {}).get('ssid', 'Unknown')
            self.seen_clients[dst]['last_seen'] = now

    def handle_eapol(self, pkt):
        """Hand WPA 4-way handshake frames to an active HandshakeCapture session, if any"""
        if self.handshake_capture:
            self.handshake_capture.on_packet(pkt)

    def packet_handler(self, pkt):
        """Main packet processing dispatcher"""
        if not pkt.haslayer(Dot11):
            return

        if pkt.haslayer(EAPOL):
            self.handle_eapol(pkt)

        # Management frames
        if pkt.type == 0:
            if pkt.subtype == 8:  # Beacon frames
                self.handle_beacon_frame(pkt)
            elif pkt.subtype == 4:  # Probe requests
                self.handle_probe_request(pkt)
            elif pkt.subtype in (0, 2):  # Association / reassociation requests
                self.handle_association_request(pkt)
            elif pkt.subtype == 10:  # Disassociation
                self.handle_disassociation(pkt)
            elif pkt.subtype == 12:  # Deauthentication
                self.handle_deauthentication(pkt)

        # Data frames
        elif pkt.type == 2:
            self.handle_data_frame(pkt)
