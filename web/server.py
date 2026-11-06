import os
import threading

from flask import Flask, render_template, jsonify, request, send_from_directory

from config.settings import Config

app = Flask(__name__)

web_bridge = None
deauth_attacker = None
handshake_capture = None

class WebDataBridge:
    def __init__(self, seen_aps, seen_clients, vendor_manager, deauth_events=None):
        self.seen_aps = seen_aps
        self.seen_clients = seen_clients
        self.vendor_manager = vendor_manager
        self.deauth_events = deauth_events if deauth_events is not None else []

    def get_network_data(self):
        """Format data for web consumption"""
        networks = []
        # Snapshot first: dict(...) is atomic under the GIL, unlike iterating the live dict
        # while the sniffer thread inserts new keys concurrently (avoids a RuntimeError).
        aps_snapshot = dict(self.seen_aps)
        clients_snapshot = dict(self.seen_clients)
        for bssid, ap_info in aps_snapshot.items():
            ssid = ap_info['ssid']
            clients = []
            for client_mac, client_info in clients_snapshot.items():
                connected_to = client_info.get("connected_to")
                probes = client_info.get("probes", [])

                if connected_to == bssid:
                    status = "connected"
                elif not connected_to and ssid in probes:
                    status = "probing"
                else:
                    continue

                clients.append({
                    "mac": client_mac,
                    "vendor": self.vendor_manager.find_vendor_by_mac(client_mac),
                    "status": status,
                    "connected_to": connected_to,
                    "probes": probes
                })

            networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "vendor": self.vendor_manager.find_vendor_by_mac(bssid),
                "client_count": len([c for c in clients if c["status"] == "connected"]),
                "clients": clients
            })
        return networks

    def get_deauth_targets(self):
        """Known APs with their known connected/probing clients, for the target picker"""
        return self.get_network_data()

    def _describe_actor(self, mac, bssid):
        """Human-readable label for a MAC seen in a deauth frame"""
        if mac == "ff:ff:ff:ff:ff:ff":
            return "Alle Clients (Broadcast)"
        if mac == bssid:
            return "Access Point"
        vendor = self.vendor_manager.find_vendor_by_mac(mac)
        return f"{mac} ({vendor})"

    def get_deauth_events(self, limit=300, group_window=2.0):
        """Deauth events, newest first. A burst between the same two MACs
        (either direction - AP->client and client->AP both happen per burst)
        within group_window seconds collapses into one row with a count, so
        hundreds of frames read as one event instead of a wall of duplicates."""
        raw = list(self.deauth_events)[-limit:]

        groups = []
        for event in raw:
            source = event.get('source', 'observed')
            # frozenset ignores direction, so AP->client and client->AP frames
            # from the same burst merge into a single group.
            key = (frozenset((event['src'], event['dst'])), event['bssid'], source)
            if groups and groups[-1]['key'] == key and event['time'] - groups[-1]['last_time'] <= group_window:
                groups[-1]['count'] += event.get('count', 1)
                groups[-1]['last_time'] = event['time']
            else:
                groups.append({
                    'key': key,
                    'attacker': event['src'],
                    'target': event['dst'],
                    'bssid': event['bssid'],
                    'source': source,
                    'first_time': event['time'],
                    'last_time': event['time'],
                    'count': event.get('count', 1)
                })

        result = []
        for g in groups:
            ap_info = self.seen_aps.get(g['bssid'], {})
            result.append({
                "time": g['last_time'],
                "first_time": g['first_time'],
                "count": g['count'],
                "attacker": self._describe_actor(g['attacker'], g['bssid']),
                "target": self._describe_actor(g['target'], g['bssid']),
                "ssid": ap_info.get('ssid', 'Unknown'),
                "source": g['source']
            })
        result.reverse()
        return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/graph')
def graph():
    return render_template('networkGraph.html')

@app.route('/deauth')
def deauth_page():
    return render_template('deauth.html')


@app.route('/api/networks')
def get_networks():
    global web_bridge
    print(f"DEBUG: get_networks called, web_bridge is: {web_bridge}")
    if web_bridge is None:
        print("DEBUG: web_bridge is None")
        return jsonify([])

    data = web_bridge.get_network_data()
    print(f"DEBUG: Returning {len(data)} networks to web interface")
    return jsonify(data)


@app.route('/api/deauth/targets')
def get_deauth_targets():
    if web_bridge is None:
        return jsonify([])
    return jsonify(web_bridge.get_deauth_targets())


@app.route('/api/deauth/events')
def get_deauth_events():
    if web_bridge is None:
        return jsonify([])
    return jsonify(web_bridge.get_deauth_events())


@app.route('/api/deauth/start', methods=['POST'])
def start_deauth():
    if deauth_attacker is None:
        return jsonify({"error": "Deauth attacker not initialized"}), 503

    payload = request.get_json(force=True, silent=True) or {}
    bssid = payload.get('bssid')
    client_mac = payload.get('client_mac') or None
    count = int(payload.get('count', 20))

    if not bssid:
        return jsonify({"error": "bssid is required"}), 400

    def run_attack():
        try:
            deauth_attacker.send_deauth(bssid, client_mac, count)
        except Exception as e:
            print(f"⚠️  Deauth attack error: {e}")

    threading.Thread(target=run_attack, daemon=True).start()
    return jsonify({"status": "started", "bssid": bssid, "client_mac": client_mac, "count": count})


@app.route('/api/handshake/events')
def get_handshake_events():
    if handshake_capture is None:
        return jsonify([])
    events = list(reversed(handshake_capture.get_history()))
    for event in events:
        event['can_download'] = bool(event.get('path'))
    return jsonify(events)


@app.route('/api/handshake/start', methods=['POST'])
def start_handshake():
    if handshake_capture is None or deauth_attacker is None:
        return jsonify({"error": "Not initialized"}), 503

    payload = request.get_json(force=True, silent=True) or {}
    bssid = payload.get('bssid')
    deauth_count = int(payload.get('deauth_count', Config.HANDSHAKE_DEAUTH_COUNT))
    timeout = float(payload.get('timeout', Config.HANDSHAKE_TIMEOUT))

    if not bssid:
        return jsonify({"error": "bssid is required"}), 400

    handshake_capture.start_session(bssid, timeout=timeout)

    def trigger_deauth():
        try:
            # Broadcast: kick every currently connected client at once, like
            # `aireplay-ng --deauth -a <bssid>` with no -c - whoever
            # reconnects first gets caught by the capture session above.
            deauth_attacker.send_deauth(bssid, client_mac=None, count=deauth_count)
        except Exception as e:
            print(f"⚠️  Deauth during handshake capture failed: {e}")

    threading.Thread(target=trigger_deauth, daemon=True).start()
    return jsonify({"status": "started", "bssid": bssid, "timeout": timeout})


@app.route('/api/handshake/download/<filename>')
def download_handshake(filename):
    directory = os.path.abspath(Config.CAPTURE_DIR)
    return send_from_directory(directory, os.path.basename(filename), as_attachment=True)


def start_server(seen_aps, seen_clients, vendor_manager, host='0.0.0.0', port=5000):
    """Initialize and start the Flask server"""
    global web_bridge
    print(f"DEBUG: Initializing web_bridge with {len(seen_aps)} APs and {len(seen_clients)} clients")
    web_bridge = WebDataBridge(seen_aps, seen_clients, vendor_manager)
    print("DEBUG: web_bridge initialized successfully")
    app.run(host=host, port=port, debug=False, threaded=True)