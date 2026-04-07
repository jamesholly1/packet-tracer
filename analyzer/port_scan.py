# analyzer/port_scan.py — Detects horizontal port scan activity.
#
# A port scan is when one source IP sends SYN packets to many different
# destination ports within a short window — classic reconnaissance behaviour.
# We track distinct destination ports per source rather than raw SYN count
# so that legitimate high-volume connections to a single port (e.g. a busy
# web server) don't produce false positives.

from collections import defaultdict

from analyzer.models import Alert, Severity
from config import MAX_SYNS_BEFORE_ALERT, PORT_SCAN_WINDOW_SECONDS
from dissector.models import ParsedPacket


class PortScanDetector:
    """Detects port scan attempts based on SYN packet patterns.

    State is maintained internally across calls to analyze(). Each instance
    tracks its own window — do not share instances across threads.
    """

    def __init__(self) -> None:
        # Maps src_ip -> list of (timestamp, dst_port) for SYN packets seen
        # within the current window. Old entries are pruned on each call.
        self._syn_log: dict[str, list[tuple[float, int]]] = defaultdict(list)

    def analyze(self, packet: ParsedPacket) -> list[Alert]:
        """Examine one packet and return any new alerts triggered.

        Args:
            packet: A fully dissected packet from the Dissector.

        Returns:
            A list of Alert objects — empty if no anomaly was detected.
        """
        # We only care about TCP SYN packets (no ACK flag = new connection attempt).
        # "S" in flags means SYN is set; "A" absent means no ACK — pure SYN.
        if not packet.tcp or not packet.ip:
            return []

        flags = packet.tcp.flags
        # Pure SYN: flag string is exactly "S". SYN-ACK is "SA" — skip that,
        # it's the server responding, not an attacker probing.
        if flags != "S":
            return []

        src_ip = packet.ip.src_ip
        dst_port = packet.tcp.dst_port
        now = packet.timestamp

        # Record this SYN and prune anything outside the time window.
        self._syn_log[src_ip].append((now, dst_port))
        self._syn_log[src_ip] = [
            (ts, port)
            for ts, port in self._syn_log[src_ip]
            if now - ts <= PORT_SCAN_WINDOW_SECONDS
        ]

        # Count distinct destination ports in the window.
        distinct_ports = {port for _, port in self._syn_log[src_ip]}

        if len(distinct_ports) > MAX_SYNS_BEFORE_ALERT:
            return [Alert(
                alert_type="PORT_SCAN",
                severity=Severity.HIGH,
                src_ip=src_ip,
                message=(
                    f"{src_ip} sent SYNs to {len(distinct_ports)} distinct ports "
                    f"within {PORT_SCAN_WINDOW_SECONDS}s — possible port scan"
                ),
                timestamp=now,
                evidence={
                    "distinct_port_count": len(distinct_ports),
                    "sampled_ports": sorted(distinct_ports)[:20],  # cap evidence size
                    "window_seconds": PORT_SCAN_WINDOW_SECONDS,
                },
            )]

        return []
