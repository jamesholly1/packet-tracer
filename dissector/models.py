# dissector/models.py — Dataclasses representing each parsed protocol layer.
#
# Why dataclasses? They give us typed, structured objects with free __repr__
# and __eq__, which makes debugging and testing much easier than raw dicts.
# Each field is Optional so layers that aren't present in a packet are None.

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EthernetInfo:
    """Parsed Ethernet II frame header (Layer 2)."""

    src_mac: str   # Source MAC address, e.g. "aa:bb:cc:dd:ee:ff"
    dst_mac: str   # Destination MAC address
    ethertype: int  # EtherType value — 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6


@dataclass
class IPInfo:
    """Parsed IPv4 header (Layer 3)."""

    src_ip: str    # Source IP address
    dst_ip: str    # Destination IP address
    protocol: int  # IP protocol number — 6 = TCP, 17 = UDP, 1 = ICMP
    ttl: int       # Time-to-live; useful for OS fingerprinting and traceroute
    flags: str     # Fragmentation flags as a string, e.g. "DF" (don't fragment)


@dataclass
class TCPInfo:
    """Parsed TCP segment header (Layer 4)."""

    src_port: int  # Source port
    dst_port: int  # Destination port
    flags: str     # Scapy flag string, e.g. "S"=SYN, "SA"=SYN-ACK, "A"=ACK, "PA"=PSH+ACK
    seq: int       # Sequence number
    ack: int       # Acknowledgement number
    window: int    # Receive window size


@dataclass
class UDPInfo:
    """Parsed UDP datagram header (Layer 4)."""

    src_port: int  # Source port
    dst_port: int  # Destination port
    length: int    # Total length of UDP header + payload in bytes


@dataclass
class DNSInfo:
    """Parsed DNS message (rides inside UDP port 53, or occasionally TCP)."""

    is_response: bool        # False = query, True = response (QR bit)
    query_name: str          # The domain name being queried, e.g. "example.com."
    query_type: str          # Record type: "A", "AAAA", "MX", "CNAME", etc.
    answers: list[str] = field(default_factory=list)  # Resolved values in the response


@dataclass
class HTTPInfo:
    """Best-effort parse of an HTTP/1.x request or response from a TCP payload.

    HTTP is an application-layer protocol that scapy doesn't decode natively.
    We inspect the raw TCP payload for recognisable HTTP syntax. Fields are
    None when the payload isn't HTTP or the field wasn't found.
    """

    method: str | None       # Request method: "GET", "POST", etc. None for responses.
    path: str | None         # Request URI path, e.g. "/index.html"
    host: str | None         # Value of the Host: header
    status_code: int | None  # HTTP response status code, e.g. 200, 404


@dataclass
class ParsedPacket:
    """Fully parsed representation of a single captured packet.

    Each layer field is populated only if that layer was present in the
    original packet; otherwise it is None. This avoids KeyError-style bugs
    throughout the rest of the codebase — callers check `if pkt.ip:` first.
    """

    timestamp: float          # Unix epoch time from the packet capture
    raw_summary: str          # Scapy's own one-line summary — useful as a fallback

    ethernet: EthernetInfo | None = None
    ip: IPInfo | None = None
    tcp: TCPInfo | None = None
    udp: UDPInfo | None = None
    dns: DNSInfo | None = None
    http: HTTPInfo | None = None
