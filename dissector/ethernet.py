# dissector/ethernet.py — Parses the Ethernet II frame header (Layer 2).

from scapy.layers.l2 import Ether
from scapy.packet import Packet

from dissector.models import EthernetInfo


class EthernetDissector:
    """Extracts fields from the Ethernet layer of a scapy packet."""

    def parse(self, packet: Packet) -> EthernetInfo | None:
        """Return an EthernetInfo if the packet has an Ethernet layer, else None.

        Args:
            packet: A raw scapy Packet object.

        Returns:
            EthernetInfo with MAC addresses and EtherType, or None if the
            packet has no Ethernet layer (e.g. raw IP captured on a tunnel).
        """
        if not packet.haslayer(Ether):
            return None

        eth = packet[Ether]

        return EthernetInfo(
            src_mac=eth.src,
            dst_mac=eth.dst,
            # eth.type is an integer; common values:
            # 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6, 0x8100 = VLAN
            ethertype=eth.type,
        )
