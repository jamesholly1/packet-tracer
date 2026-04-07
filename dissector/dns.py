# dissector/dns.py — Parses DNS messages carried inside UDP (or TCP) packets.
#
# DNS uses a binary wire format. Scapy decodes it into DNSQR (query records)
# and DNSRR (resource records), which we translate into plain strings here.

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Packet

from dissector.models import DNSInfo


# Map numeric DNS QTYPE values to human-readable names.
# A full list is in RFC 1035 §3.2.2 and updated RFCs.
_QTYPE_NAMES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


class DNSDissector:
    """Extracts query and answer fields from a DNS-carrying packet."""

    def parse(self, packet: Packet) -> DNSInfo | None:
        """Return a DNSInfo if the packet contains a DNS layer, else None.

        Only the first question record is captured (virtually all real-world
        DNS messages have exactly one question). All answer records are
        collected into the answers list.

        Args:
            packet: A raw scapy Packet object.

        Returns:
            DNSInfo, or None if no DNS layer is found.
        """
        if not packet.haslayer(DNS):
            return None

        dns = packet[DNS]

        # dns.qr: 0 = query, 1 = response (the QR bit in the DNS header)
        is_response = bool(dns.qr)

        # Extract the first question record.
        # We use haslayer() rather than checking dns.qdcount because newer
        # versions of scapy may leave qdcount as None when qd is set implicitly.
        query_name = ""
        query_type = "UNKNOWN"
        if dns.haslayer(DNSQR):
            qr = dns[DNSQR]
            # qname is bytes ending with b'.'; decode to a plain string.
            query_name = qr.qname.decode(errors="replace").rstrip(".")
            query_type = _QTYPE_NAMES.get(qr.qtype, str(qr.qtype))

        # Collect all answer records into a list of strings.
        # Scapy 2.5+ stores dns.an as a PacketListField (a plain Python list).
        # Older scapy chained records via rr.payload — we handle both forms.
        answers: list[str] = []
        if is_response and dns.an:
            an = dns.an
            if isinstance(an, list):
                # New-style: iterate the list directly.
                for rr in an:
                    if isinstance(rr, DNSRR):
                        answers.append(str(rr.rdata))
            else:
                # Old-style: walk the chain via .payload.
                rr = an
                while rr and isinstance(rr, DNSRR):
                    answers.append(str(rr.rdata))
                    rr = rr.payload

        return DNSInfo(
            is_response=is_response,
            query_name=query_name,
            query_type=query_type,
            answers=answers,
        )
