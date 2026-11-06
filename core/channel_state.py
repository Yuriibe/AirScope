import threading


class ChannelState:
    """Shared record of the channel the monitor-mode interface currently
    sits on, plus a pause flag so a deauth burst can pin the interface to
    one channel without the hopper switching it away mid-attack."""

    def __init__(self):
        self.current = None
        self.paused = threading.Event()
