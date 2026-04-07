# tests/test_dissector.py — Tests for each protocol dissector and the top-level Dissector.

import pytest
from scapy.all import Ether, IP, TCP

from dissector.arp import ARPDissector
from dissector.dissector import Dissector
from dissector.dns import DNSDissector
from dissector.ethernet import EthernetDissector
from dissector.ip import IPDissector
from dissector.tcp import TCPDissector
from dissector.udp import UDPDissector


# ---------------------------------------------------------------------------
# EthernetDissector
# ---------------------------------------------------------------------------

class TestEthernetDissector:
    def setup_method(self):
        self.d = EthernetDissector()

    def test_parses_mac_addresses(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        assert result is not None
        assert result.src_mac == "aa:bb:cc:dd:ee:01"
        assert result.dst_mac == "aa:bb:cc:dd:ee:02"

    def test_parses_ethertype_ipv4(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        assert result.ethertype == 0x0800  # IPv4

    def test_returns_none_without_ethernet_layer(self):
        # A raw IP packet has no Ethernet header.
        raw_ip = IP(src="1.1.1.1", dst="2.2.2.2") / TCP()
        assert self.d.parse(raw_ip) is None


# ---------------------------------------------------------------------------
# IPDissector
# ---------------------------------------------------------------------------

class TestIPDissector:
    def setup_method(self):
        self.d = IPDissector()

    def test_parses_addresses(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        assert result is not None
        assert result.src_ip == "10.0.0.1"
        assert result.dst_ip == "10.0.0.2"

    def test_parses_ttl(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        assert result.ttl == 64

    def test_parses_protocol_tcp(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        assert result.protocol == 6  # TCP

    def test_returns_none_without_ip_layer(self, arp_reply_packet):
        # ARP packets have no IP layer.
        assert self.d.parse(arp_reply_packet) is None


# ---------------------------------------------------------------------------
# TCPDissector
# ---------------------------------------------------------------------------

class TestTCPDissector:
    def setup_method(self):
        self.d = TCPDissector()

    def test_parses_ports(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        assert result is not None
        assert result.src_port == 54321
        assert result.dst_port == 80

    def test_parses_syn_flag(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        assert result.flags == "S"

    def test_parses_syn_ack_flag(self):
        pkt = Ether() / IP() / TCP(flags="SA")
        result = self.d.parse(pkt)
        assert result.flags == "SA"

    def test_parses_window_and_seq(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        assert result.seq == 1000
        assert result.window == 65535

    def test_returns_none_without_tcp_layer(self, udp_dns_packet):
        assert self.d.parse(udp_dns_packet) is None


# ---------------------------------------------------------------------------
# UDPDissector
# ---------------------------------------------------------------------------

class TestUDPDissector:
    def setup_method(self):
        self.d = UDPDissector()

    def test_parses_ports(self, udp_dns_packet):
        result = self.d.parse(udp_dns_packet)
        assert result is not None
        assert result.src_port == 12345
        assert result.dst_port == 53

    def test_returns_none_without_udp_layer(self, tcp_syn_packet):
        assert self.d.parse(tcp_syn_packet) is None


# ---------------------------------------------------------------------------
# DNSDissector
# ---------------------------------------------------------------------------

class TestDNSDissector:
    def setup_method(self):
        self.d = DNSDissector()

    def test_parses_query(self, udp_dns_packet):
        result = self.d.parse(udp_dns_packet)
        assert result is not None
        assert result.is_response is False
        assert "example.com" in result.query_name
        assert result.query_type == "A"

    def test_parses_response(self, dns_response_packet):
        result = self.d.parse(dns_response_packet)
        assert result is not None
        assert result.is_response is True
        assert "93.184.216.34" in result.answers

    def test_returns_none_without_dns_layer(self, tcp_syn_packet):
        assert self.d.parse(tcp_syn_packet) is None


# ---------------------------------------------------------------------------
# ARPDissector
# ---------------------------------------------------------------------------

class TestARPDissector:
    def setup_method(self):
        self.d = ARPDissector()

    def test_parses_arp_reply(self, arp_reply_packet):
        result = self.d.parse(arp_reply_packet)
        assert result is not None
        assert result.op == 2
        assert result.sender_ip == "192.168.1.1"
        assert result.sender_mac == "aa:bb:cc:dd:ee:ff"

    def test_parses_arp_request(self, arp_request_packet):
        result = self.d.parse(arp_request_packet)
        assert result is not None
        assert result.op == 1
        assert result.target_ip == "192.168.1.1"

    def test_returns_none_without_arp_layer(self, tcp_syn_packet):
        assert self.d.parse(tcp_syn_packet) is None


# ---------------------------------------------------------------------------
# Top-level Dissector
# ---------------------------------------------------------------------------

class TestDissector:
    def setup_method(self):
        self.d = Dissector()

    def test_full_tcp_packet_populates_ethernet_ip_tcp(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        assert result.ethernet is not None
        assert result.ip is not None
        assert result.tcp is not None
        assert result.udp is None
        assert result.dns is None
        assert result.arp is None

    def test_dns_packet_populates_udp_and_dns(self, udp_dns_packet):
        result = self.d.parse(udp_dns_packet)
        assert result.udp is not None
        assert result.dns is not None
        assert result.tcp is None

    def test_arp_packet_populates_arp_field(self, arp_reply_packet):
        result = self.d.parse(arp_reply_packet)
        assert result.arp is not None
        assert result.ip is None

    def test_timestamp_is_populated(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        # Scapy sets time=0.0 on crafted packets; just check it's a float.
        assert isinstance(result.timestamp, float)

    def test_raw_summary_is_non_empty(self, tcp_syn_packet):
        result = self.d.parse(tcp_syn_packet)
        assert len(result.raw_summary) > 0
