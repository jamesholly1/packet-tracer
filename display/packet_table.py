# display/packet_table.py — Builds a rich Table from a list of ParsedPackets.
#
# Keeps display logic completely separate from parsing and detection logic.
# Nothing here modifies packet data — it only reads and formats it.

from datetime import datetime

from rich.table import Table
from rich.text import Text

from dissector.models import ParsedPacket

# Number of recent packets the table shows before older rows scroll off.
_DEFAULT_MAX_ROWS = 50


def _protocol_label(packet: ParsedPacket) -> str:
    """Return the highest-layer protocol name present in the packet."""
    # Check from application layer down so we show the most useful label.
    if packet.http:
        return "HTTP"
    if packet.dns:
        return "DNS"
    if packet.tcp:
        return "TCP"
    if packet.udp:
        return "UDP"
    if packet.arp:
        return "ARP"
    return "OTHER"


def _info_summary(packet: ParsedPacket) -> str:
    """Return a compact one-line description of the packet's payload."""
    if packet.http:
        h = packet.http
        if h.method:
            # HTTP request
            host = h.host or ""
            return f"{h.method} {host}{h.path or '/'}"
        if h.status_code:
            return f"HTTP {h.status_code}"

    if packet.dns:
        d = packet.dns
        if d.is_response and d.answers:
            return f"R {d.query_name} → {', '.join(d.answers[:2])}"
        return f"Q {d.query_name} {d.query_type}"

    if packet.tcp:
        t = packet.tcp
        return f"{t.src_port} → {t.dst_port} [{t.flags}]"

    if packet.udp:
        u = packet.udp
        return f"{u.src_port} → {u.dst_port}"

    if packet.arp:
        a = packet.arp
        if a.op == 1:
            return f"Who has {a.target_ip}? Tell {a.sender_ip}"
        return f"{a.sender_ip} is at {a.sender_mac}"

    # Fall back to scapy's own summary for unknown protocols.
    return packet.raw_summary[:60]


def _src_dst(packet: ParsedPacket) -> tuple[str, str]:
    """Return (source, destination) display strings for the packet."""
    if packet.ip:
        return packet.ip.src_ip, packet.ip.dst_ip
    if packet.arp:
        return packet.arp.sender_ip, packet.arp.target_ip
    if packet.ethernet:
        return packet.ethernet.src_mac, packet.ethernet.dst_mac
    return "?", "?"


# Colour each protocol label to make the table easier to scan at a glance.
_PROTOCOL_COLOURS: dict[str, str] = {
    "HTTP": "bright_cyan",
    "DNS": "bright_magenta",
    "TCP": "bright_blue",
    "UDP": "green",
    "ARP": "yellow",
    "OTHER": "dim",
}


class PacketTable:
    """Renders a scrolling rich Table of recent captured packets."""

    def __init__(self, max_rows: int = _DEFAULT_MAX_ROWS) -> None:
        """
        Args:
            max_rows: Maximum number of packet rows to display at once.
                      Oldest rows are dropped when the limit is reached.
        """
        self.max_rows = max_rows
        # Internal rolling buffer of packets to display.
        self._packets: list[ParsedPacket] = []

    def add(self, packet: ParsedPacket) -> None:
        """Append a packet to the display buffer, dropping the oldest if full.

        Args:
            packet: A ParsedPacket to add to the visible table.
        """
        self._packets.append(packet)
        # Keep only the most recent max_rows packets to avoid unbounded growth.
        if len(self._packets) > self.max_rows:
            self._packets = self._packets[-self.max_rows:]

    def build(self) -> Table:
        """Construct and return a fresh rich Table from the current buffer.

        Called on every Live refresh cycle — rich replaces the previous render
        in-place in the terminal, so we always build from scratch.

        Returns:
            A rich Table ready to be passed to Console.print() or Live.update().
        """
        table = Table(
            title="Packet Capture",
            show_header=True,
            header_style="bold white",
            border_style="bright_black",
            expand=True,
        )

        table.add_column("Time", style="dim", width=10, no_wrap=True)
        table.add_column("Proto", width=6, no_wrap=True)
        table.add_column("Source", min_width=15)
        table.add_column("Destination", min_width=15)
        table.add_column("Info", ratio=1)

        for pkt in self._packets:
            proto = _protocol_label(pkt)
            colour = _PROTOCOL_COLOURS.get(proto, "white")
            proto_text = Text(proto, style=colour)

            src, dst = _src_dst(pkt)
            info = _info_summary(pkt)

            # Format timestamp as HH:MM:SS — full date is rarely needed in a
            # live view and takes up too much column space.
            ts = datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S")

            table.add_row(ts, proto_text, src, dst, info)

        return table
