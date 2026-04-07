# tests/test_analyzer.py — Tests for each anomaly detector and AnalyzerEngine.
#
# Detector logic is tested using ParsedPacket objects built directly from
# dataclasses (via conftest fixtures) rather than going through the dissector.
# This keeps detector tests isolated from parsing bugs.

from analyzer.arp_spoof import ARPSpoofDetector
from analyzer.engine import AnalyzerEngine
from analyzer.models import Severity
from analyzer.port_scan import PortScanDetector
from analyzer.syn_flood import SYNFloodDetector
from config import MAX_SYNS_BEFORE_ALERT


# ---------------------------------------------------------------------------
# PortScanDetector
# ---------------------------------------------------------------------------

class TestPortScanDetector:
    def setup_method(self):
        self.detector = PortScanDetector()

    def test_no_alert_below_threshold(self, make_syn):
        """Fewer SYNs than the threshold should produce no alerts."""
        for port in range(MAX_SYNS_BEFORE_ALERT):
            alerts = self.detector.analyze(make_syn("10.0.0.1", "10.0.0.2", port))
        assert alerts == []

    def test_alert_fires_above_threshold(self, make_syn):
        """One SYN past the threshold should trigger a PORT_SCAN alert."""
        alerts = []
        for port in range(MAX_SYNS_BEFORE_ALERT + 1):
            alerts = self.detector.analyze(make_syn("10.0.0.1", "10.0.0.2", port))
        assert len(alerts) == 1
        assert alerts[0].alert_type == "PORT_SCAN"
        assert alerts[0].severity == Severity.HIGH

    def test_alert_identifies_correct_source(self, make_syn):
        """The alert src_ip should match the scanning host."""
        for port in range(MAX_SYNS_BEFORE_ALERT + 1):
            alerts = self.detector.analyze(make_syn("192.168.5.5", "10.0.0.1", port))
        assert alerts[0].src_ip == "192.168.5.5"

    def test_different_sources_tracked_independently(self, make_syn):
        """SYNs from different IPs should not accumulate toward each other's threshold."""
        # Send MAX_SYNS_BEFORE_ALERT - 1 packets per source so neither is close
        # to the threshold on its own, regardless of what the other source does.
        for port in range(MAX_SYNS_BEFORE_ALERT - 1):
            self.detector.analyze(make_syn("10.0.0.1", "10.0.0.2", port))
            self.detector.analyze(make_syn("10.0.0.3", "10.0.0.2", port))

        # One more from 10.0.0.1 reaches exactly MAX_SYNS_BEFORE_ALERT distinct
        # ports — still not above the threshold, so no alert should fire.
        alerts = self.detector.analyze(make_syn("10.0.0.1", "10.0.0.2", 9999))
        assert alerts == []

    def test_syn_ack_does_not_count(self, make_syn):
        """SYN-ACK packets (server responses) should be ignored — only pure SYNs count."""
        from dissector.models import ParsedPacket, IPInfo, TCPInfo
        pkt = make_syn("10.0.0.1", "10.0.0.2", 80)
        # Overwrite the TCP flags to simulate a SYN-ACK.
        pkt.tcp.flags = "SA"
        for _ in range(MAX_SYNS_BEFORE_ALERT + 5):
            alerts = self.detector.analyze(pkt)
        assert alerts == []


# ---------------------------------------------------------------------------
# SYNFloodDetector
# ---------------------------------------------------------------------------

class TestSYNFloodDetector:
    def setup_method(self):
        self.detector = SYNFloodDetector()

    def test_no_alert_below_threshold(self, make_syn):
        for i in range(MAX_SYNS_BEFORE_ALERT):
            alerts = self.detector.analyze(make_syn(f"10.0.0.{i % 254 + 1}", "192.168.1.1", 80))
        assert alerts == []

    def test_alert_fires_above_threshold(self, make_syn):
        """Many SYNs to the same dst IP:port should trigger SYN_FLOOD."""
        alerts = []
        for i in range(MAX_SYNS_BEFORE_ALERT + 1):
            alerts = self.detector.analyze(make_syn(f"10.0.0.{i % 254 + 1}", "192.168.1.1", 80))
        assert len(alerts) == 1
        assert alerts[0].alert_type == "SYN_FLOOD"
        assert alerts[0].severity == Severity.HIGH

    def test_evidence_contains_target_info(self, make_syn):
        """Alert evidence should identify the target IP and port."""
        alerts = []
        for i in range(MAX_SYNS_BEFORE_ALERT + 1):
            alerts = self.detector.analyze(make_syn("10.0.0.1", "172.16.0.1", 443))
        assert alerts[0].evidence["target_ip"] == "172.16.0.1"
        assert alerts[0].evidence["target_port"] == 443

    def test_flood_to_different_ports_does_not_trigger(self, make_syn):
        """SYNs spread across different ports should not trigger SYN_FLOOD
        (that pattern is a port scan, handled by PortScanDetector)."""
        alerts = []
        for port in range(MAX_SYNS_BEFORE_ALERT + 1):
            alerts = self.detector.analyze(make_syn("10.0.0.1", "192.168.1.1", port))
        # Each (dst_ip, dst_port) bucket only has 1 SYN — no flood.
        assert alerts == []


# ---------------------------------------------------------------------------
# ARPSpoofDetector
# ---------------------------------------------------------------------------

class TestARPSpoofDetector:
    def setup_method(self):
        self.detector = ARPSpoofDetector()

    def test_no_alert_for_single_mac(self, make_arp_reply):
        """A single MAC consistently claiming an IP is normal — no alert."""
        for _ in range(3):
            alerts = self.detector.analyze(
                make_arp_reply("192.168.1.1", "aa:bb:cc:dd:ee:01")
            )
        assert alerts == []

    def test_alert_fires_on_ip_mac_conflict(self, make_arp_reply):
        """Two different MACs claiming the same IP should fire ARP_SPOOF."""
        self.detector.analyze(make_arp_reply("192.168.1.1", "aa:bb:cc:dd:ee:01"))
        alerts = self.detector.analyze(make_arp_reply("192.168.1.1", "aa:bb:cc:dd:ee:02"))

        spoof_alerts = [a for a in alerts if a.alert_type == "ARP_SPOOF"]
        assert len(spoof_alerts) == 1
        assert spoof_alerts[0].severity == Severity.HIGH

    def test_conflicting_macs_appear_in_evidence(self, make_arp_reply):
        """The evidence dict should list all MACs that have claimed the IP."""
        self.detector.analyze(make_arp_reply("10.0.0.1", "aa:aa:aa:aa:aa:01"))
        alerts = self.detector.analyze(make_arp_reply("10.0.0.1", "bb:bb:bb:bb:bb:02"))

        spoof = next(a for a in alerts if a.alert_type == "ARP_SPOOF")
        macs = spoof.evidence["conflicting_macs"]
        assert "aa:aa:aa:aa:aa:01" in macs
        assert "bb:bb:bb:bb:bb:02" in macs

    def test_arp_flood_fires_above_threshold(self, make_arp_reply):
        """More ARP replies than ARP_REPLY_THRESHOLD should fire ARP_FLOOD."""
        from config import ARP_REPLY_THRESHOLD
        alerts = []
        for _ in range(ARP_REPLY_THRESHOLD + 1):
            alerts = self.detector.analyze(
                make_arp_reply("192.168.1.1", "aa:bb:cc:dd:ee:01")
            )
        flood_alerts = [a for a in alerts if a.alert_type == "ARP_FLOOD"]
        assert len(flood_alerts) == 1
        assert flood_alerts[0].severity == Severity.MEDIUM

    def test_arp_request_is_ignored(self, make_arp_reply):
        """ARP requests (op=1) should never trigger an alert."""
        from dissector.models import ARPInfo, ParsedPacket
        request = ParsedPacket(
            timestamp=0.0,
            raw_summary="",
            arp=ARPInfo(op=1, sender_ip="10.0.0.1", sender_mac="aa:bb:cc:dd:ee:01",
                        target_ip="10.0.0.254", target_mac="ff:ff:ff:ff:ff:ff"),
        )
        for _ in range(20):
            alerts = self.detector.analyze(request)
        assert alerts == []


# ---------------------------------------------------------------------------
# AnalyzerEngine
# ---------------------------------------------------------------------------

class TestAnalyzerEngine:
    def setup_method(self):
        self.engine = AnalyzerEngine()

    def test_returns_empty_list_for_normal_packet(self, make_syn):
        """A single benign packet should produce no alerts."""
        alerts = self.engine.analyze(make_syn("10.0.0.1", "10.0.0.2", 80))
        assert alerts == []

    def test_returns_list_type(self, make_syn):
        """analyze() must always return a list, never None."""
        result = self.engine.analyze(make_syn("10.0.0.1", "10.0.0.2", 80))
        assert isinstance(result, list)

    def test_port_scan_detected_through_engine(self, make_syn):
        """A port scan pattern fed through the engine should produce alerts."""
        alerts = []
        for port in range(MAX_SYNS_BEFORE_ALERT + 1):
            alerts = self.engine.analyze(make_syn("10.0.0.99", "10.0.0.1", port))
        assert any(a.alert_type == "PORT_SCAN" for a in alerts)
