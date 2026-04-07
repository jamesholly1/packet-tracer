# dissector/dissector.py — Top-level Dissector that chains all protocol parsers.
#
# This is the single entry point the rest of the codebase uses. It calls each
# protocol-specific dissector in order and assembles the results into a
# ParsedPacket. Adding support for a new protocol means writing a new dissector
# class and wiring it in here — nothing else needs to change.

from scapy.packet import Packet

from dissector.arp import ARPDissector
from dissector.dns import DNSDissector
from dissector.ethernet import EthernetDissector
from dissector.http import HTTPDissector
from dissector.ip import IPDissector
from dissector.models import ParsedPacket
from dissector.tcp import TCPDissector
from dissector.udp import UDPDissector


class Dissector:
    """Parses a raw scapy Packet into a structured ParsedPacket.

    Each protocol layer is handled by a dedicated dissector class. If a layer
    is absent in the packet, the corresponding field in ParsedPacket is None.
    """

    def __init__(self) -> None:
        # Instantiate each sub-dissector once and reuse across many packets.
        # They hold no per-packet state, so this is safe.
        self._ethernet = EthernetDissector()
        self._ip = IPDissector()
        self._tcp = TCPDissector()
        self._udp = UDPDissector()
        self._dns = DNSDissector()
        self._http = HTTPDissector()
        self._arp = ARPDissector()

    def parse(self, packet: Packet) -> ParsedPacket:
        """Dissect a single packet into a ParsedPacket.

        Args:
            packet: A raw scapy Packet, as returned by PcapReader or LiveCapture.

        Returns:
            ParsedPacket with every detected layer populated and absent layers
            set to None.
        """
        # packet.time is the capture timestamp as a float (Unix epoch seconds).
        # It comes from the pcap record header or the OS clock for live capture.
        timestamp = float(packet.time)

        # summary() gives a compact one-line description — handy for logging
        # packets that don't match any known protocol.
        raw_summary = packet.summary()

        return ParsedPacket(
            timestamp=timestamp,
            raw_summary=raw_summary,
            ethernet=self._ethernet.parse(packet),
            ip=self._ip.parse(packet),
            tcp=self._tcp.parse(packet),
            udp=self._udp.parse(packet),
            dns=self._dns.parse(packet),
            http=self._http.parse(packet),
            arp=self._arp.parse(packet),
        )
