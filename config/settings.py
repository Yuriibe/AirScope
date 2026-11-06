class Config:
    INTERFACE = "wlan0"
    # https://maclookup.app/downloads/json-database
    VENDOR_DB_PATH = "mac-vendors-export.json"
    CHANNELS = [1, 6, 11]
    CHANNEL_DWELL_TIME = 5.0
    SUMMARY_INTERVAL = 5

    DB_PATH = "airscope.db"
    PERSIST_INTERVAL = 30.0  # seconds between persistence/prune passes
    STALE_TIMEOUT = 300.0    # seconds of inactivity before an AP/client is pruned from memory

    CAPTURE_DIR = "captures"       # where handshake .pcap files are written
    HANDSHAKE_TIMEOUT = 15.0       # seconds to wait for a full handshake before giving up
    HANDSHAKE_DEAUTH_COUNT = 10    # deauth repetitions sent to force a reconnect
