import threading

from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

web_bridge = None
deauth_attacker = None

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

    def get_deauth_events(self, limit=100):
        """Most recent deauth events (observed and self-sent), newest first"""
        events = []
        for event in list(self.deauth_events)[-limit:]:
            ap_info = self.seen_aps.get(event['bssid'], {})
            events.append({
                "time": event['time'],
                "src": event['src'],
                "dst": event['dst'],
                "bssid": event['bssid'],
                "ssid": ap_info.get('ssid', 'Unknown'),
                "source": event.get('source', 'observed')
            })
        events.reverse()
        return events

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


def start_server(seen_aps, seen_clients, vendor_manager, host='0.0.0.0', port=5000):
    """Initialize and start the Flask server"""
    global web_bridge
    print(f"DEBUG: Initializing web_bridge with {len(seen_aps)} APs and {len(seen_clients)} clients")
    web_bridge = WebDataBridge(seen_aps, seen_clients, vendor_manager)
    print("DEBUG: web_bridge initialized successfully")
    app.run(host=host, port=port, debug=False, threaded=True)