# dissector/udp.py — Parses the UDP datagram header (Layer 4).

from scapy.layers.inet import UDP
from scapy.packet import Packet

from dissector.models import UDPInfo


class UDPDissector:
    """Extracts fields from the UDP layer of a scapy packet."""

    def parse(self, packet: Packet) -> UDPInfo | None:
        """Return a UDPInfo if the packet has a UDP layer, else None.

        Args:
            packet: A raw scapy Packet object.

        Returns:
            UDPInfo with ports and payload length, or None if no UDP layer
            is present.
        """
        if not packet.haslayer(UDP):
            return None

        udp = packet[UDP]

        return UDPInfo(
            src_port=udp.sport,
            dst_port=udp.dport,
            # udp.len includes the 8-byte UDP header itself plus the payload.
            # Subtract 8 to get the pure payload size if needed downstream.
            length=udp.len,
        )
