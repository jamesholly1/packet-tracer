# dissector/tcp.py — Parses the TCP segment header (Layer 4).

from scapy.layers.inet import TCP
from scapy.packet import Packet

from dissector.models import TCPInfo


class TCPDissector:
    """Extracts fields from the TCP layer of a scapy packet."""

    def parse(self, packet: Packet) -> TCPInfo | None:
        """Return a TCPInfo if the packet has a TCP layer, else None.

        Args:
            packet: A raw scapy Packet object.

        Returns:
            TCPInfo with ports, flags, sequence numbers, and window size,
            or None if no TCP layer is present.
        """
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]

        return TCPInfo(
            src_port=tcp.sport,
            dst_port=tcp.dport,
            # tcp.flags is a scapy FlagValue; str() produces a compact string
            # of set flag letters, e.g. "S" (SYN), "SA" (SYN-ACK), "FA" (FIN-ACK).
            # Flag letters: F=FIN, S=SYN, R=RST, P=PSH, A=ACK, U=URG
            flags=str(tcp.flags),
            seq=tcp.seq,
            ack=tcp.ack,
            # Window size advertises how many bytes the receiver can buffer.
            # A shrinking window can indicate congestion or a slow receiver.
            window=tcp.window,
        )
