# analyzer/models.py — Data types produced by anomaly detectors.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Alert severity levels.

    Using str as a mixin means Severity.HIGH == "HIGH" is True, which makes
    serialisation and display straightforward without extra conversion.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class Alert:
    """A single anomaly detection event.

    Produced by a detector and consumed by the display layer. All fields are
    populated by the detector — callers should not mutate an Alert after creation.
    """

    alert_type: str        # Short identifier, e.g. "PORT_SCAN", "SYN_FLOOD", "ARP_SPOOF"
    severity: Severity     # How serious this event is
    src_ip: str            # IP address that triggered the alert (attacker / suspect)
    message: str           # Human-readable description of what was detected
    timestamp: float       # Capture time of the packet that crossed the threshold
    evidence: dict = field(default_factory=dict)  # Supporting data (ports seen, MACs, etc.)
