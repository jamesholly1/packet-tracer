# Packet Tracer

An educational Python network monitoring tool for learning security skills. Captures and parses network packets, then detects common attack patterns in real time using a live terminal dashboard.

Built with [scapy](https://scapy.net/), [rich](https://github.com/Textualize/rich), and pytest.

---

## What it does

| Layer | What happens |
|---|---|
| **Capture** | Reads packets from a `.pcap` file or sniffs a live network interface |
| **Dissect** | Parses each packet into typed Python objects — Ethernet, IP, TCP, UDP, DNS, HTTP, ARP |
| **Analyze** | Runs anomaly detectors on every packet and fires alerts when thresholds are crossed |
| **Display** | Renders a live terminal dashboard: rolling packet table on top, alert panel below |

### Detectors

| Alert | What triggers it | Severity |
|---|---|---|
| `PORT_SCAN` | One source IP sends SYNs to more than 20 distinct ports within 10 seconds | HIGH |
| `SYN_FLOOD` | More than 20 SYNs arrive at the same destination IP:port within 10 seconds | HIGH |
| `ARP_SPOOF` | Two different MAC addresses both claim ownership of the same IP address | HIGH |
| `ARP_FLOOD` | A single MAC sends more than 5 gratuitous ARP replies within 10 seconds | MEDIUM |

All thresholds are constants in `config.py` — tune them without touching detector code.

---

## Project structure

```
packet-tracer/
├── capture/            # Packet input — pcap file reader and live sniffer
│   ├── pcap_reader.py  # PcapReader: stream packets lazily from a .pcap file
│   └── live_capture.py # LiveCapture: sniff a live interface via scapy
├── dissector/          # Protocol parsing — converts raw scapy packets to dataclasses
│   ├── models.py       # ParsedPacket + per-layer dataclasses (IPInfo, TCPInfo, …)
│   ├── dissector.py    # Dissector: chains all sub-dissectors into one parse() call
│   ├── ethernet.py     # Layer 2 — MAC addresses, EtherType
│   ├── ip.py           # Layer 3 — src/dst IP, protocol, TTL, flags
│   ├── tcp.py          # Layer 4 — ports, flags (S/SA/A/…), seq/ack, window
│   ├── udp.py          # Layer 4 — ports, length
│   ├── dns.py          # Application — query name/type, answer records
│   ├── http.py         # Application — best-effort HTTP/1.x request/response parse
│   └── arp.py          # Layer 2/3 — op code, sender/target IP+MAC
├── analyzer/           # Anomaly detection — stateful sliding-window detectors
│   ├── models.py       # Alert dataclass, Severity enum
│   ├── engine.py       # AnalyzerEngine: runs all detectors, returns flat alert list
│   ├── port_scan.py    # PortScanDetector
│   ├── syn_flood.py    # SYNFloodDetector
│   └── arp_spoof.py    # ARPSpoofDetector (covers both ARP_SPOOF and ARP_FLOOD)
├── display/            # Terminal UI — built with rich
│   ├── packet_table.py # PacketTable: colour-coded rolling table of recent packets
│   ├── alert_display.py# AlertDisplay: severity-coloured alert rows
│   └── dashboard.py    # Dashboard: Live layout (70% packets / 30% alerts)
├── tests/              # pytest test suite — 47 tests
├── samples/            # Place .pcap files here for testing
├── gen_sample.py       # Generates a sample.pcap with normal + attack traffic
├── main.py             # CLI entrypoint
├── config.py           # All constants and thresholds
└── requirements.txt
```

---

## Installation

**Requirements:** Python 3.11+, pip

```powershell
# Clone the repo
git clone https://github.com/jamesholly1/packet-tracer.git
cd packet-tracer

# Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1       # Windows PowerShell
# source .venv/bin/activate       # Linux / macOS

# Install dependencies
pip install -r requirements.txt
```

> **Windows:** Live capture also requires [Npcap](https://npcap.com/) to be installed.  
> **Linux/macOS:** Live capture requires running with `sudo`.

---

## Usage

### Read from a pcap file (no privileges needed)

```powershell
python main.py --pcap samples/sample.pcap
```

### Generate a sample pcap with attack traffic

```powershell
python gen_sample.py
python main.py --pcap samples/sample.pcap
```

This generates a capture containing a port scan, a SYN flood, and ARP spoofing — all three alert types will fire in the dashboard.

### Live capture

```powershell
# Windows (run terminal as Administrator)
python main.py --live --iface "Ethernet"

# Linux / macOS
sudo python main.py --live --iface eth0
```

### All options

```
python main.py --help

options:
  --pcap FILE          Path to a .pcap file (default: samples/sample.pcap)
  --live               Capture live from a network interface
  --iface INTERFACE    Interface for live capture (default: eth0)
  --max-packets N      Rows to show in the packet table (default: 50)
```

---

## Dashboard

```
┌─────────────────────────────── Packet Capture ───────────────────────────────┐
│ Time     │ Proto │ Source          │ Destination     │ Info                   │
│ 14:22:01 │ TCP   │ 192.168.1.10   │ 8.8.8.8         │ 12345 → 80 [S]        │
│ 14:22:01 │ DNS   │ 192.168.1.10   │ 8.8.8.8         │ Q example.com A        │
│ 14:22:01 │ TCP   │ 192.168.1.99   │ 192.168.1.1     │ 54321 → 22 [S]        │
│ ...      │       │                 │                  │                        │
└──────────────────────────────────────────────────────────────────────────────┘
┌─ Alerts (2) ─────────────────────────────────────────────────────────────────┐
│ Severity │ Type       │ Source IP     │ Message                               │
│ !! HIGH  │ PORT_SCAN  │ 192.168.1.99  │ sent SYNs to 25 distinct ports…      │
│ !! HIGH  │ SYN_FLOOD  │ 192.168.1.88  │ 25 SYNs to 192.168.1.50:80…         │
└──────────────────────────────────────────────────────────────────────────────┘
```

- Protocol column is colour-coded: HTTP=cyan, DNS=magenta, TCP=blue, UDP=green, ARP=yellow
- Alerts: HIGH=red, MEDIUM=yellow, LOW=cyan
- Press **Ctrl-C** to stop live capture — a summary of all alerts is printed on exit

---

## Running the tests

```powershell
pytest tests/ -v
```

47 tests across three modules:

| File | What's tested |
|---|---|
| `tests/test_capture.py` | PcapReader — missing file error, stream order, read_all |
| `tests/test_dissector.py` | Every dissector layer + top-level Dissector |
| `tests/test_analyzer.py` | Each detector below/above threshold, evidence content, AnalyzerEngine |

Tests use real scapy packets and real dataclasses — no mocking.

---

## Configuration

All tunable values are in `config.py`:

```python
DEFAULT_INTERFACE = "eth0"          # Interface for live capture
PCAP_FILE_PATH = "samples/sample.pcap"  # Default pcap path

PORT_SCAN_WINDOW_SECONDS = 10       # Sliding window for SYN counting
MAX_SYNS_BEFORE_ALERT = 20          # Distinct ports (scan) or total SYNs (flood)
ARP_REPLY_THRESHOLD = 5             # Unsolicited ARP replies before ARP_FLOOD alert
```

---

## How the detectors work

### Port scan detection

Tracks how many **distinct destination ports** a source IP has sent pure SYN packets to within the last `PORT_SCAN_WINDOW_SECONDS`. Counting distinct ports (not raw SYN count) avoids false positives from a client making many connections to the same service.

### SYN flood detection

Tracks how many SYNs arrive at each **(dst_ip, dst_port)** pair within the window. A high count against one target suggests a DoS attempt to exhaust the server's half-open connection table.

### ARP spoof detection

Maintains an IP → set-of-MACs table. If a second MAC address claims an IP that is already owned by a different MAC, that is a strong indicator of cache poisoning. A separate rate check catches automated flooding tools even before a MAC conflict is seen.

---

## Learning notes

- **Why scapy?** It gives direct access to every packet field and lets you craft arbitrary packets — essential for understanding protocols at the bit level.
- **Why dataclasses instead of dicts?** Typed fields catch bugs at development time and make the data model self-documenting.
- **Why sliding windows instead of global counters?** Global counters would flag hosts that are simply active for a long time. A sliding window only looks at *recent* behaviour, which is what actually indicates an attack.
- **Why is HTTP parsing "best-effort"?** HTTP/1.x is a plaintext protocol, so we can inspect the raw TCP payload. HTTPS (TLS) encrypts the payload — content is unreadable without the private key.
