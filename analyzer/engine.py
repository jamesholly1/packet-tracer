# analyzer/engine.py — Runs all detectors against each packet.
#
# AnalyzerEngine is the single entry point for the rest of the codebase.
# Adding a new detector means instantiating it here — nothing else changes.

from analyzer.arp_spoof import ARPSpoofDetector
from analyzer.models import Alert
from analyzer.port_scan import PortScanDetector
from analyzer.syn_flood import SYNFloodDetector
from dissector.models import ParsedPacket


class AnalyzerEngine:
    """Chains all anomaly detectors and aggregates their alerts.

    Each detector maintains its own state across packets. Feed packets in
    capture order via analyze() to get consistent time-window behaviour.
    """

    def __init__(self) -> None:
        # All detectors are stateful and must be shared across packets, so we
        # instantiate them once here rather than per-packet.
        self._detectors = [
            PortScanDetector(),
            SYNFloodDetector(),
            ARPSpoofDetector(),
        ]

    def analyze(self, packet: ParsedPacket) -> list[Alert]:
        """Run all detectors against a single packet.

        Args:
            packet: A ParsedPacket produced by Dissector.parse().

        Returns:
            Combined list of Alert objects from all detectors. Empty list
            means the packet triggered no anomalies.
        """
        alerts: list[Alert] = []
        for detector in self._detectors:
            # Each detector returns its own list (possibly empty).
            # Extend rather than append to keep the result flat.
            alerts.extend(detector.analyze(packet))
        return alerts
