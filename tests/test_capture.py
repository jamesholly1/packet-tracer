# tests/test_capture.py — Tests for the capture module.

import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from capture.pcap_reader import PcapReader


def test_pcap_reader_raises_for_missing_file():
    """PcapReader should raise FileNotFoundError immediately on construction
    if the path does not exist — not later when iterating."""
    with pytest.raises(FileNotFoundError):
        PcapReader("nonexistent/path/file.pcap")


def test_pcap_reader_stream(tmp_path):
    """stream() should yield the same number of packets that were written."""
    pcap_file = tmp_path / "test.pcap"

    # Write 3 packets to a temporary file.
    packets = [
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=80, flags="S"),
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=81, flags="S"),
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=82, flags="S"),
    ]
    wrpcap(str(pcap_file), packets)

    reader = PcapReader(str(pcap_file))
    result = list(reader.stream())

    assert len(result) == 3


def test_pcap_reader_read_all(tmp_path):
    """read_all() should return a list with every packet in the file."""
    pcap_file = tmp_path / "test.pcap"
    packets = [Ether() / IP() / TCP(dport=i) for i in range(5)]
    wrpcap(str(pcap_file), packets)

    reader = PcapReader(str(pcap_file))
    result = reader.read_all()

    assert isinstance(result, list)
    assert len(result) == 5


def test_pcap_reader_stream_preserves_order(tmp_path):
    """Packets should be yielded in the same order they were written."""
    pcap_file = tmp_path / "test.pcap"
    ports = [100, 200, 300]
    packets = [Ether() / IP() / TCP(dport=p, flags="S") for p in ports]
    wrpcap(str(pcap_file), packets)

    reader = PcapReader(str(pcap_file))
    result_ports = [pkt[TCP].dport for pkt in reader.stream()]

    assert result_ports == ports


def test_pcap_reader_integrates_with_sample(tmp_path):
    """End-to-end: write a realistic mixed-protocol capture and stream it back."""
    from scapy.all import ARP, DNS, DNSQR, UDP

    pcap_file = tmp_path / "mixed.pcap"
    packets = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80, flags="S"),
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="test.com")),
        Ether() / ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.254"),
    ]
    wrpcap(str(pcap_file), packets)

    reader = PcapReader(str(pcap_file))
    streamed = list(reader.stream())
    assert len(streamed) == len(packets)
