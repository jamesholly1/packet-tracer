# dissector/arp.py — Parses ARP messages (EtherType 0x0806).
#
# ARP operates at Layer 2/3 and has no IP header, so it sits alongside IP
# rather than inside it. We parse it here so the anomaly detector can track
# IP-to-MAC mappings without touching raw scapy objects.

from scapy.layers.l2 import ARP
from scapy.packet import Packet

from dissector.models import ARPInfo


class ARPDissector:
    """Extracts fields from the ARP layer of a scapy packet."""

    def parse(self, packet: Packet) -> ARPInfo | None:
        """Return an ARPInfo if the packet contains an ARP layer, else None.

        Args:
            packet: A raw scapy Packet object.

        Returns:
            ARPInfo with operation code and sender/target MAC+IP pairs, or
            None if no ARP layer is present.
        """
        if not packet.haslayer(ARP):
            return None

        arp = packet[ARP]

        return ARPInfo(
            # op=1 is a request ("who has 192.168.1.1?"),
            # op=2 is a reply  ("192.168.1.1 is at aa:bb:cc:dd:ee:ff").
            # Unsolicited op=2 replies (gratuitous ARP) are the main spoof vector.
            op=arp.op,
            sender_mac=arp.hwsrc,
            sender_ip=arp.psrc,
            target_mac=arp.hwdst,
            target_ip=arp.pdst,
        )
