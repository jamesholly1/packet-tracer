# gui/packet_table.py — QTableWidget displaying live captured packets.

from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem

from dissector.models import ParsedPacket
from gui.styles import PROTOCOL_COLOURS

_MAX_ROWS = 200  # Keep the last N packets; discard older ones to limit memory.


def _protocol_label(p: ParsedPacket) -> str:
    if p.http:    return "HTTP"
    if p.dns:     return "DNS"
    if p.tcp:     return "TCP"
    if p.udp:     return "UDP"
    if p.arp:     return "ARP"
    return "OTHER"


def _src_dst(p: ParsedPacket) -> tuple[str, str]:
    if p.ip:       return p.ip.src_ip, p.ip.dst_ip
    if p.arp:      return p.arp.sender_ip, p.arp.target_ip
    if p.ethernet: return p.ethernet.src_mac, p.ethernet.dst_mac
    return "?", "?"


def _info(p: ParsedPacket) -> str:
    if p.http:
        h = p.http
        if h.method:
            return f"{h.method} {h.host or ''}{h.path or '/'}"
        if h.status_code:
            return f"HTTP {h.status_code}"
    if p.dns:
        d = p.dns
        if d.is_response and d.answers:
            return f"R {d.query_name} → {', '.join(d.answers[:2])}"
        return f"Q {d.query_name} {d.query_type}"
    if p.tcp:
        t = p.tcp
        return f"{t.src_port} → {t.dst_port} [{t.flags}]"
    if p.udp:
        u = p.udp
        return f"{u.src_port} → {u.dst_port}"
    if p.arp:
        a = p.arp
        if a.op == 1:
            return f"Who has {a.target_ip}? Tell {a.sender_ip}"
        return f"{a.sender_ip} is at {a.sender_mac}"
    return p.raw_summary[:80]


class PacketTableWidget(QTableWidget):
    """Scrolling table of recently captured packets."""

    _COLUMNS = ["Time", "Proto", "Source", "Destination", "Info"]

    def __init__(self, parent=None) -> None:
        super().__init__(0, len(self._COLUMNS), parent)

        self.setHorizontalHeaderLabels(self._COLUMNS)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)

        hdr = self.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        self.verticalHeader().setDefaultSectionSize(22)

    def add_packet(self, packet: ParsedPacket) -> None:
        """Append a packet row, trimming the oldest if over _MAX_ROWS."""
        # Trim oldest row first to avoid unbounded growth.
        if self.rowCount() >= _MAX_ROWS:
            self.removeRow(0)

        row = self.rowCount()
        self.insertRow(row)

        proto = _protocol_label(packet)
        colour = QColor(PROTOCOL_COLOURS.get(proto, "#c0caf5"))
        src, dst = _src_dst(packet)
        ts = datetime.fromtimestamp(packet.timestamp).strftime("%H:%M:%S")

        values = [ts, proto, src, dst, _info(packet)]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            if col == 1:  # Protocol column gets its colour
                item.setForeground(colour)
            self.setItem(row, col, item)

        # Auto-scroll to newest row.
        self.scrollToBottom()
