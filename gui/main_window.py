# gui/main_window.py — Top-level QMainWindow for the Packet Tracer desktop app.

import os

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSplitter,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from analyzer.models import Alert
from config import DEFAULT_INTERFACE, PCAP_FILE_PATH
from dissector.models import ParsedPacket
from gui.alert_panel import AlertPanelWidget
from gui.capture_thread import CaptureThread
from gui.packet_table import PacketTableWidget
from gui.what_now_dialog import WhatNowDialog


def _get_interfaces() -> list[tuple[str, str]]:
    """Return a list of (display_name, device_id) tuples for available interfaces.

    Uses scapy's interface list. On Windows with Npcap, scapy exposes friendly
    names alongside the NPF device IDs. Falls back to raw device IDs if not.

    Returns:
        List of (label, device_id) — label shown in dropdown, device_id passed
        to LiveCapture.
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        # Each entry has 'name' (friendly) and 'guid' — build NPF device id.
        result = []
        for iface in ifaces:
            name = iface.get("name", "Unknown")
            guid = iface.get("guid", "")
            device = f"\\Device\\NPF_{guid}" if guid else name
            result.append((name, device))
        return result if result else _fallback_interfaces()
    except Exception:
        return _fallback_interfaces()


def _fallback_interfaces() -> list[tuple[str, str]]:
    """Fall back to raw scapy interface list when friendly names aren't available."""
    try:
        from scapy.all import get_if_list
        ifaces = get_if_list()
        return [(i, i) for i in ifaces]
    except Exception:
        return [(DEFAULT_INTERFACE, DEFAULT_INTERFACE)]


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Packet Tracer — Security Monitor")
        self.setMinimumSize(1000, 680)
        self.resize(1200, 760)

        self._thread: CaptureThread | None = None
        self._packet_count = 0

        self._build_ui()
        self._update_status("Ready")

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Assemble the full window layout."""
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        root.addWidget(self._build_toolbar())
        root.addWidget(self._build_main_pane(), stretch=1)

        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)

    def _build_toolbar(self) -> QWidget:
        """Top bar: mode selector, interface/file picker, start/stop button."""
        bar = QGroupBox("Capture")
        layout = QHBoxLayout(bar)
        layout.setSpacing(12)

        # Mode radio buttons
        self._radio_live = QRadioButton("Live Interface")
        self._radio_pcap = QRadioButton("PCAP File")
        self._radio_live.setChecked(True)
        self._radio_live.toggled.connect(self._on_mode_changed)
        layout.addWidget(self._radio_live)
        layout.addWidget(self._radio_pcap)

        layout.addSpacing(12)

        # Interface dropdown (shown in live mode)
        self._iface_label = QLabel("Interface:")
        self._iface_combo = QComboBox()
        self._iface_combo.setMinimumWidth(200)
        for label, device in _get_interfaces():
            self._iface_combo.addItem(label, userData=device)
        # Pre-select the configured default interface if present.
        for i in range(self._iface_combo.count()):
            if DEFAULT_INTERFACE in (self._iface_combo.itemData(i) or ""):
                self._iface_combo.setCurrentIndex(i)
                break
        layout.addWidget(self._iface_label)
        layout.addWidget(self._iface_combo)

        # PCAP path widgets (hidden in live mode)
        self._pcap_label = QLabel("File:")
        self._pcap_label.setVisible(False)
        self._pcap_path_label = QLabel(PCAP_FILE_PATH)
        self._pcap_path_label.setStyleSheet("color: #a9b1d6;")
        self._pcap_path_label.setVisible(False)
        self._browse_btn = QPushButton("Browse…")
        self._browse_btn.setVisible(False)
        self._browse_btn.clicked.connect(self._on_browse)
        layout.addWidget(self._pcap_label)
        layout.addWidget(self._pcap_path_label)
        layout.addWidget(self._browse_btn)

        self._pcap_file = PCAP_FILE_PATH  # currently selected pcap path

        layout.addStretch()

        # Start / Stop button
        self._start_btn = QPushButton("▶  Start")
        self._start_btn.setMinimumWidth(100)
        self._start_btn.clicked.connect(self._on_start_stop)
        layout.addWidget(self._start_btn)

        return bar

    def _build_main_pane(self) -> QSplitter:
        """Vertical splitter: packets on top, alerts on bottom."""
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Packet table
        pkt_group = QGroupBox("Live Packets")
        pkt_layout = QVBoxLayout(pkt_group)
        pkt_layout.setContentsMargins(4, 4, 4, 4)
        self._packet_table = PacketTableWidget()
        pkt_layout.addWidget(self._packet_table)
        splitter.addWidget(pkt_group)

        # Alert panel
        alert_group = QGroupBox("Alerts")
        alert_layout = QVBoxLayout(alert_group)
        alert_layout.setContentsMargins(4, 4, 4, 4)
        self._alert_panel = AlertPanelWidget()
        self._alert_panel.what_now_requested.connect(self._on_what_now)
        alert_layout.addWidget(self._alert_panel)
        splitter.addWidget(alert_group)

        splitter.setSizes([480, 220])
        return splitter

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_mode_changed(self) -> None:
        """Toggle visibility of interface vs pcap path controls."""
        live = self._radio_live.isChecked()
        self._iface_label.setVisible(live)
        self._iface_combo.setVisible(live)
        self._pcap_label.setVisible(not live)
        self._pcap_path_label.setVisible(not live)
        self._browse_btn.setVisible(not live)

    def _on_browse(self) -> None:
        """Open a file dialog to select a pcap file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if path:
            self._pcap_file = path
            # Show only the filename to save space.
            self._pcap_path_label.setText(os.path.basename(path))
            self._pcap_path_label.setToolTip(path)

    def _on_start_stop(self) -> None:
        """Start or stop the capture depending on current state."""
        if self._thread and self._thread.isRunning():
            self._stop_capture()
        else:
            self._start_capture()

    def _start_capture(self) -> None:
        """Initialise and start the capture thread."""
        self._packet_count = 0
        self._packet_table.clearContents()
        self._packet_table.setRowCount(0)
        self._alert_panel.clear()

        if self._radio_live.isChecked():
            device = self._iface_combo.currentData() or self._iface_combo.currentText()
            self._thread = CaptureThread(mode="live", interface=device)
        else:
            self._thread = CaptureThread(mode="pcap", pcap_path=self._pcap_file)

        self._thread.packet_ready.connect(self._on_packet)
        self._thread.alert_ready.connect(self._on_alert)
        self._thread.error_occurred.connect(self._on_error)
        self._thread.capture_finished.connect(self._on_capture_finished)
        self._thread.start()

        self._start_btn.setText("■  Stop")
        self._start_btn.setObjectName("danger")
        self._start_btn.setStyleSheet("")  # force stylesheet re-evaluation
        mode = "live interface" if self._radio_live.isChecked() else "PCAP file"
        self._update_status(f"Capturing — {mode}")

    def _stop_capture(self) -> None:
        """Ask the capture thread to stop."""
        if self._thread:
            self._thread.stop()
        # Button text is reset in _on_capture_finished when the thread exits.

    def _on_packet(self, packet: ParsedPacket) -> None:
        """Receive a parsed packet from the capture thread and display it."""
        self._packet_count += 1
        self._packet_table.add_packet(packet)
        alert_count = len(self._alert_panel._alerts)
        self._update_status(
            f"Capturing — {self._packet_count} packets  |  {alert_count} alerts"
        )

    def _on_alert(self, alert: Alert) -> None:
        """Receive an alert from the capture thread and display it."""
        self._alert_panel.add_alert(alert)
        alert_count = len(self._alert_panel._alerts)
        self._update_status(
            f"Capturing — {self._packet_count} packets  |  "
            f"{alert_count} alert{'s' if alert_count != 1 else ''}  ⚠",
            warning=True,
        )

    def _on_error(self, message: str) -> None:
        """Show a dialog for fatal capture errors (e.g. permission denied)."""
        QMessageBox.critical(
            self,
            "Capture Error",
            f"{message}\n\nFor live capture on Windows, run as Administrator "
            "and ensure Npcap is installed.",
        )
        self._reset_start_button()

    def _on_capture_finished(self) -> None:
        """Called when the capture thread exits cleanly."""
        self._reset_start_button()
        self._update_status(
            f"Stopped — {self._packet_count} packets captured"
        )

    def _on_what_now(self, alert: Alert) -> None:
        """Open the What Now dialog for the selected alert."""
        dialog = WhatNowDialog(alert, parent=self)
        dialog.exec()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _reset_start_button(self) -> None:
        self._start_btn.setText("▶  Start")
        self._start_btn.setObjectName("")
        self._start_btn.setStyleSheet("")

    def _update_status(self, message: str, warning: bool = False) -> None:
        colour = "#f7768e" if warning else "#565f89"
        self._status_bar.showMessage(message)
        self._status_bar.setStyleSheet(
            f"QStatusBar {{ color: {colour}; }}"
        )

    def closeEvent(self, event) -> None:  # type: ignore[override]
        """Stop the capture thread cleanly before the window closes."""
        if self._thread and self._thread.isRunning():
            self._thread.stop()
            self._thread.wait(2000)  # wait up to 2 s for clean exit
        event.accept()
