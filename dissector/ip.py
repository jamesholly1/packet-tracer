# dissector/ip.py — Parses the IPv4 header (Layer 3).

from scapy.layers.inet import IP
from scapy.packet import Packet

from dissector.models import IPInfo


class IPDissector:
    """Extracts fields from the IPv4 layer of a scapy packet."""

    def parse(self, packet: Packet) -> IPInfo | None:
        """Return an IPInfo if the packet has an IP layer, else None.

        Args:
            packet: A raw scapy Packet object.

        Returns:
            IPInfo with addresses, protocol number, TTL, and flags, or None
            if no IPv4 layer is present (e.g. pure ARP or IPv6 packets).
        """
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]

        return IPInfo(
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol=ip.proto,
            ttl=ip.ttl,
            # ip.flags is a scapy FlagValue object; str() gives "DF", "MF", etc.
            # DF = Don't Fragment, MF = More Fragments (fragmented packet stream)
            flags=str(ip.flags),
        )
