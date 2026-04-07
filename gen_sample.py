"""gen_sample.py — Generates a sample.pcap with both normal and attack traffic.

Demonstrates all three anomaly detectors:
  - Port scan:  one source SYNs to 25 different ports in quick succession
  - SYN flood:  25 SYNs hammering the same target IP:port
  - ARP spoof:  two different MACs both claiming the same IP
"""

from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap

pkts = []

# ------------------------------------------------------------------
# Normal traffic — a clean TCP handshake + DNS query
# ------------------------------------------------------------------
pkts += [
    Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/TCP(sport=12345, dport=80, flags="S"),
    Ether()/IP(src="8.8.8.8", dst="192.168.1.10")/TCP(sport=80, dport=12345, flags="SA"),
    Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/TCP(sport=12345, dport=80, flags="A"),
    Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=54321, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")),
]

# ------------------------------------------------------------------
# Attack 1: Port scan
# 192.168.1.99 sends SYNs to 25 different ports — classic nmap-style scan.
# This will cross the MAX_SYNS_BEFORE_ALERT=20 threshold and fire PORT_SCAN.
# ------------------------------------------------------------------
scan_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
              143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
              8443, 8888, 9000, 9200, 27017]

for port in scan_ports:
    pkts.append(
        Ether(src="de:ad:be:ef:00:01", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="192.168.1.99", dst="192.168.1.1")
        / TCP(sport=54321, dport=port, flags="S")
    )

# ------------------------------------------------------------------
# Attack 2: SYN flood
# 192.168.1.88 hammers port 80 on the same target 25 times.
# This will cross MAX_SYNS_BEFORE_ALERT=20 and fire SYN_FLOOD.
# ------------------------------------------------------------------
for i in range(25):
    pkts.append(
        Ether(src="ca:fe:ba:be:00:02", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="192.168.1.88", dst="192.168.1.50")
        / TCP(sport=10000 + i, dport=80, flags="S")
    )

# ------------------------------------------------------------------
# Attack 3: ARP spoofing
# Two different MACs both claim to be 192.168.1.1 (the gateway).
# The real router has MAC aa:bb:cc:dd:ee:01; the attacker has 02.
# This fires ARP_SPOOF (IP-MAC conflict) and ARP_FLOOD (rate).
# ------------------------------------------------------------------
for _ in range(6):  # 6 replies > ARP_REPLY_THRESHOLD=5 → also fires ARP_FLOOD
    pkts.append(
        Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.1",
              hwdst="ff:ff:ff:ff:ff:ff", pdst="0.0.0.0")
    )

# Attacker's fake ARP reply — same IP, different MAC
pkts.append(
    Ether(src="aa:bb:cc:dd:ee:02", dst="ff:ff:ff:ff:ff:ff")
    / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:02", psrc="192.168.1.1",
          hwdst="ff:ff:ff:ff:ff:ff", pdst="0.0.0.0")
)

wrpcap("samples/sample.pcap", pkts)
print(f"Written samples/sample.pcap — {len(pkts)} packets")
