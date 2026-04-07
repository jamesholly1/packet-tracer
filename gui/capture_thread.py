# gui/capture_thread.py — QThread that runs packet capture in the background.
#
# Qt requires that all GUI updates happen on the main thread. Packet capture
# is blocking (it loops forever), so it must run on a worker thread. We use
# Qt signals to safely pass data back to the main thread for display.

from PyQt6.QtCore import QThread, pyqtSignal

from analyzer.engine import AnalyzerEngine
from analyzer.models import Alert
from capture.live_capture import LiveCapture
from capture.pcap_reader import PcapReader
from dissector.dissector import Dissector
from dissector.models import ParsedPacket


class CaptureThread(QThread):
    """Worker thread that captures packets and emits them to the GUI.

    Emits packet_ready and alert_ready signals — connect these to GUI slots
    on the main thread. Qt guarantees signal delivery is thread-safe.
    """

    # Emitted once for every captured and dissected packet.
    packet_ready = pyqtSignal(object)   # carries a ParsedPacket

    # Emitted once for every Alert produced by the analyzer.
    alert_ready = pyqtSignal(object)    # carries an Alert

    # Emitted if a fatal error stops the capture (e.g. permission denied).
    error_occurred = pyqtSignal(str)

    # Emitted when the thread finishes (end of pcap file or stop() called).
    capture_finished = pyqtSignal()

    def __init__(
        self,
        mode: str = "pcap",
        pcap_path: str = "",
        interface: str = "",
    ) -> None:
        """
        Args:
            mode:       "pcap" to read a file, "live" to sniff an interface.
            pcap_path:  Path to the .pcap file (used when mode="pcap").
            interface:  Network interface name (used when mode="live").
        """
        super().__init__()
        self.mode = mode
        self.pcap_path = pcap_path
        self.interface = interface

        self._dissector = Dissector()
        self._engine = AnalyzerEngine()
        self._running = False

    def run(self) -> None:
        """Entry point called by QThread.start(). Runs the capture loop."""
        self._running = True
        try:
            if self.mode == "pcap":
                self._run_pcap()
            else:
                self._run_live()
        except Exception as exc:
            self.error_occurred.emit(str(exc))
        finally:
            self.capture_finished.emit()

    def stop(self) -> None:
        """Signal the capture loop to stop gracefully.

        For pcap mode this takes effect at the next packet boundary.
        For live mode scapy's sniff() is interrupted via the stop_filter.
        """
        self._running = False

    def _process(self, raw_packet) -> None:  # type: ignore[no-untyped-def]
        """Dissect and analyse one raw scapy packet, emitting results."""
        parsed: ParsedPacket = self._dissector.parse(raw_packet)
        self.packet_ready.emit(parsed)

        alerts: list[Alert] = self._engine.analyze(parsed)
        for alert in alerts:
            self.alert_ready.emit(alert)

    def _run_pcap(self) -> None:
        """Stream through a pcap file, processing each packet."""
        reader = PcapReader(self.pcap_path)
        for raw in reader.stream():
            if not self._running:
                break
            self._process(raw)

    def _run_live(self) -> None:
        """Sniff live packets until stop() is called."""
        capture = LiveCapture(interface=self.interface)
        # stop_filter lets scapy check _running after each packet so the thread
        # exits cleanly when stop() is called rather than blocking indefinitely.
        capture.start(
            callback=self._process,
            stop_filter=lambda _: not self._running,
        )
