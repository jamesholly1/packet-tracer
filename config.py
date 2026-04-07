# config.py — Central constants for the packet tracer.
# Import this module in other modules; never hardcode these values elsewhere.

# ---------------------------------------------------------------------------
# Capture settings
# ---------------------------------------------------------------------------

# Network interface to sniff on during live capture.
# On Linux this is typically "eth0" or "wlan0"; on macOS "en0".
# Live capture requires root/sudo — prefer PCAP_FILE_PATH for development.
DEFAULT_INTERFACE: str = "eth0"

# Path to the default pcap file used when running without live capture.
# Place sample captures in the samples/ directory.
PCAP_FILE_PATH: str = "samples/sample.pcap"

# ---------------------------------------------------------------------------
# Anomaly detection thresholds
# ---------------------------------------------------------------------------

# Time window (seconds) in which SYN packets are counted to detect a port scan.
# If a single source sends SYNs to many distinct ports within this window, it
# is flagged as a potential port scan.
PORT_SCAN_WINDOW_SECONDS: int = 10

# Maximum number of SYN packets from one source (within PORT_SCAN_WINDOW_SECONDS)
# before an alert is raised. Tuned to avoid false positives on chatty clients.
MAX_SYNS_BEFORE_ALERT: int = 20

# Maximum number of unsolicited ARP replies from a single MAC address within
# PORT_SCAN_WINDOW_SECONDS before an ARP spoofing alert is raised.
# Gratuitous ARPs are legitimate, but repeated ones suggest cache poisoning.
ARP_REPLY_THRESHOLD: int = 5
