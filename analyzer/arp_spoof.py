# analyzer/arp_spoof.py — Detects ARP cache poisoning / spoofing attacks.
#
# ARP spoofing works by broadcasting fake ARP replies that associate the
# attacker's MAC address with a victim's IP address. Other hosts update their
# ARP caches and start sending traffic to the attacker instead of the real host.
#
# Two complementary signals are used:
#   1. IP-MAC conflict: the same IP is claimed by more than one MAC address.
#      This is the strongest indicator — legitimate hosts don't change their MAC.
#   2. Gratuitous ARP rate: a single MAC sends too many unsolicited ARP replies.
#      Gratuitous ARPs are normal during boot or IP change, but a high rate
#      suggests automated poisoning.

from collections import defaultdict

from analyzer.models import Alert, Severity
from config import ARP_REPLY_THRESHOLD, PORT_SCAN_WINDOW_SECONDS
from dissector.models import ParsedPacket

# ARP operation code for a reply packet (RFC 826).
_ARP_REPLY = 2


class ARPSpoofDetector:
    """Detects ARP cache poisoning via IP-MAC conflicts and gratuitous ARP rate.

    State is maintained internally across calls to analyze(). Each instance
    tracks its own window — do not share instances across threads.
    """

    def __init__(self) -> None:
        # Maps ip -> set of MAC addresses that have claimed that IP.
        # If the set grows beyond 1 entry, we have a conflict.
        self._ip_mac_table: dict[str, set[str]] = defaultdict(set)

        # Maps sender_mac -> list of timestamps of ARP replies sent.
        # Used to detect high-rate gratuitous ARP flooding.
        self._reply_log: dict[str, list[float]] = defaultdict(list)

    def analyze(self, packet: ParsedPacket) -> list[Alert]:
        """Examine one packet and return any new alerts triggered.

        Args:
            packet: A fully dissected packet from the Dissector.

        Returns:
            A list of Alert objects — may contain multiple if both detection
            signals fire on the same packet.
        """
        if not packet.arp:
            return []

        arp = packet.arp

        # Only examine ARP replies — requests are broadcasts asking "who has X?"
        # and are not themselves an attack vector.
        if arp.op != _ARP_REPLY:
            return []

        alerts: list[Alert] = []
        sender_ip = arp.sender_ip
        sender_mac = arp.sender_mac
        now = packet.timestamp

        # --- Signal 1: IP-MAC conflict ---
        # Record the MAC that is claiming this IP. If it differs from any
        # previously seen MAC, the IP is being claimed by multiple hosts.
        known_macs = self._ip_mac_table[sender_ip]
        known_macs.add(sender_mac)

        if len(known_macs) > 1:
            alerts.append(Alert(
                alert_type="ARP_SPOOF",
                severity=Severity.HIGH,
                src_ip=sender_ip,
                message=(
                    f"IP {sender_ip} is being claimed by {len(known_macs)} "
                    f"different MAC addresses — possible ARP cache poisoning"
                ),
                timestamp=now,
                evidence={
                    "conflicting_macs": list(known_macs),
                    "sender_ip": sender_ip,
                },
            ))

        # --- Signal 2: Gratuitous ARP rate ---
        # Track how many ARP replies this MAC has sent in the window.
        self._reply_log[sender_mac].append(now)
        self._reply_log[sender_mac] = [
            ts for ts in self._reply_log[sender_mac]
            if now - ts <= PORT_SCAN_WINDOW_SECONDS
        ]

        reply_count = len(self._reply_log[sender_mac])
        if reply_count > ARP_REPLY_THRESHOLD:
            alerts.append(Alert(
                alert_type="ARP_FLOOD",
                severity=Severity.MEDIUM,
                src_ip=sender_ip,
                message=(
                    f"MAC {sender_mac} sent {reply_count} ARP replies "
                    f"within {PORT_SCAN_WINDOW_SECONDS}s — possible gratuitous ARP flood"
                ),
                timestamp=now,
                evidence={
                    "sender_mac": sender_mac,
                    "reply_count": reply_count,
                    "window_seconds": PORT_SCAN_WINDOW_SECONDS,
                },
            ))

        return alerts
