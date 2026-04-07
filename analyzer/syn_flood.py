# analyzer/syn_flood.py — Detects SYN flood DoS attacks.
#
# A SYN flood overwhelms a target by sending a huge volume of TCP SYN packets
# without completing the three-way handshake. The target's connection table
# fills with half-open connections and it can't accept legitimate ones.
#
# Detection strategy: count SYN packets arriving at a specific (dst_ip, dst_port)
# within the time window. A high count toward one target suggests a flood,
# whereas a port scan spreads across many ports (handled by PortScanDetector).

from collections import defaultdict

from analyzer.models import Alert, Severity
from config import MAX_SYNS_BEFORE_ALERT, PORT_SCAN_WINDOW_SECONDS
from dissector.models import ParsedPacket


class SYNFloodDetector:
    """Detects SYN flood attacks against a specific destination IP and port.

    State is maintained internally across calls to analyze(). Each instance
    tracks its own window — do not share instances across threads.
    """

    def __init__(self) -> None:
        # Maps (dst_ip, dst_port) -> list of timestamps of SYNs received.
        self._syn_log: dict[tuple[str, int], list[float]] = defaultdict(list)

    def analyze(self, packet: ParsedPacket) -> list[Alert]:
        """Examine one packet and return any new alerts triggered.

        Args:
            packet: A fully dissected packet from the Dissector.

        Returns:
            A list of Alert objects — empty if no anomaly was detected.
        """
        if not packet.tcp or not packet.ip:
            return []

        # Same SYN filter as PortScanDetector — pure SYNs only.
        if packet.tcp.flags != "S":
            return []

        dst_ip = packet.ip.dst_ip
        dst_port = packet.tcp.dst_port
        src_ip = packet.ip.src_ip
        now = packet.timestamp

        key = (dst_ip, dst_port)
        self._syn_log[key].append(now)

        # Prune timestamps outside the sliding window.
        self._syn_log[key] = [
            ts for ts in self._syn_log[key]
            if now - ts <= PORT_SCAN_WINDOW_SECONDS
        ]

        syn_count = len(self._syn_log[key])

        if syn_count > MAX_SYNS_BEFORE_ALERT:
            return [Alert(
                alert_type="SYN_FLOOD",
                severity=Severity.HIGH,
                src_ip=src_ip,  # most recent source — floods may spoof src IPs
                message=(
                    f"{syn_count} SYNs to {dst_ip}:{dst_port} "
                    f"within {PORT_SCAN_WINDOW_SECONDS}s — possible SYN flood"
                ),
                timestamp=now,
                evidence={
                    "syn_count": syn_count,
                    "target_ip": dst_ip,
                    "target_port": dst_port,
                    "window_seconds": PORT_SCAN_WINDOW_SECONDS,
                },
            )]

        return []
