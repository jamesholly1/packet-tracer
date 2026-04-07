# tests/conftest.py — Shared pytest fixtures used across all test modules.
#
# Fixtures build real scapy packets and ParsedPacket objects so tests stay
# isolated from the filesystem and network while still exercising real code.

import pytest
from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP

from dissector.models import (
    ARPInfo,
    EthernetInfo,
    IPInfo,
    ParsedPacket,
    TCPInfo,
    UDPInfo,
)


# ---------------------------------------------------------------------------
# Raw scapy packet fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tcp_syn_packet():
    """A minimal TCP SYN packet — used to test TCP/IP/Ethernet dissectors."""
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
        / TCP(sport=54321, dport=80, flags="S", seq=1000, ack=0, window=65535)
    )


@pytest.fixture
def udp_dns_packet():
    """A UDP DNS query for 'example.com'."""
    return (
        Ether()
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )


@pytest.fixture
def dns_response_packet():
    """A DNS response resolving 'example.com' to '93.184.216.34'."""
    return (
        Ether()
        / IP(src="8.8.8.8", dst="10.0.0.1")
        / UDP(sport=53, dport=12345)
        / DNS(
            qr=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", rdata="93.184.216.34"),
        )
    )


@pytest.fixture
def arp_reply_packet():
    """An ARP reply — sender claims 192.168.1.1 is at aa:bb:cc:dd:ee:ff."""
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=2,
            hwsrc="aa:bb:cc:dd:ee:ff",
            psrc="192.168.1.1",
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst="0.0.0.0",
        )
    )


@pytest.fixture
def arp_request_packet():
    """An ARP request — who has 192.168.1.1?"""
    return (
        Ether(src="11:22:33:44:55:66", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc="11:22:33:44:55:66", psrc="192.168.1.50",
              pdst="192.168.1.1")
    )


# ---------------------------------------------------------------------------
# ParsedPacket fixtures — used directly by analyzer tests without going
# through the dissector, so detection logic is tested in isolation.
# ---------------------------------------------------------------------------

def _make_syn(src_ip: str, dst_ip: str, dst_port: int, timestamp: float = 0.0) -> ParsedPacket:
    """Helper: build a minimal ParsedPacket representing a pure TCP SYN."""
    return ParsedPacket(
        timestamp=timestamp,
        raw_summary="",
        ethernet=EthernetInfo(src_mac="aa:bb:cc:dd:ee:01", dst_mac="ff:ff:ff:ff:ff:ff", ethertype=0x0800),
        ip=IPInfo(src_ip=src_ip, dst_ip=dst_ip, protocol=6, ttl=64, flags="DF"),
        tcp=TCPInfo(src_port=12345, dst_port=dst_port, flags="S", seq=0, ack=0, window=65535),
    )


def _make_arp_reply(sender_ip: str, sender_mac: str, timestamp: float = 0.0) -> ParsedPacket:
    """Helper: build a minimal ParsedPacket representing an ARP reply."""
    return ParsedPacket(
        timestamp=timestamp,
        raw_summary="",
        arp=ARPInfo(
            op=2,
            sender_ip=sender_ip,
            sender_mac=sender_mac,
            target_ip="0.0.0.0",
            target_mac="ff:ff:ff:ff:ff:ff",
        ),
    )


@pytest.fixture
def make_syn():
    """Factory fixture for creating SYN ParsedPackets in analyzer tests."""
    return _make_syn


@pytest.fixture
def make_arp_reply():
    """Factory fixture for creating ARP reply ParsedPackets in analyzer tests."""
    return _make_arp_reply
