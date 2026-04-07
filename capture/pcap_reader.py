# capture/pcap_reader.py — Reads packets from a .pcap file using scapy.
# This is the default capture mode and works without elevated privileges.

from pathlib import Path
from typing import Generator

from scapy.packet import Packet
from scapy.utils import PcapReader as ScapyPcapReader


class PcapReader:
    """Reads packets from a saved .pcap file.

    Prefer this over LiveCapture during development — no root required and
    results are reproducible. Uses a streaming approach (one packet at a time)
    so large capture files don't blow up memory.
    """

    def __init__(self, filepath: str) -> None:
        """
        Args:
            filepath: Path to the .pcap file to read.

        Raises:
            FileNotFoundError: If the file does not exist at the given path.
        """
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"pcap file not found: {self.filepath}")

    def stream(self) -> Generator[Packet, None, None]:
        """Yield packets one at a time from the pcap file.

        Using a generator rather than loading all packets into a list keeps
        memory usage flat regardless of file size — important for large captures.

        Yields:
            Each scapy Packet in capture order.
        """
        # ScapyPcapReader is a context manager that reads lazily from disk.
        with ScapyPcapReader(str(self.filepath)) as reader:
            for packet in reader:
                yield packet

    def read_all(self) -> list[Packet]:
        """Read the entire pcap file into a list.

        Only use this for small files or in tests where you need random access.
        For processing large captures, prefer stream() instead.

        Returns:
            List of all packets in capture order.
        """
        return list(self.stream())
