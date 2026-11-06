from flask import Flask, render_template, jsonify

app = Flask(__name__)

web_bridge = None

class WebDataBridge:
    def __init__(self, seen_aps, seen_clients, vendor_manager):
        self.seen_aps = seen_aps
        self.seen_clients = seen_clients
        self.vendor_manager = vendor_manager

    def get_network_data(self):
        """Format data for web consumption"""
        networks = []
        for bssid, ssid in self.seen_aps.items():
            clients = []
            for client_mac, client_info in self.seen_clients.items():
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/graph')
def graph():
    return render_template('networkGraph.html')



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


def start_server(seen_aps, seen_clients, vendor_manager, host='0.0.0.0', port=5000):
    """Initialize and start the Flask server"""
    global web_bridge
    print(f"DEBUG: Initializing web_bridge with {len(seen_aps)} APs and {len(seen_clients)} clients")
    web_bridge = WebDataBridge(seen_aps, seen_clients, vendor_manager)
    print("DEBUG: web_bridge initialized successfully")
    app.run(host=host, port=port, debug=True, threaded=True)