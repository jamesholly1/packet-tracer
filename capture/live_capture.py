# capture/live_capture.py — Live packet capture from a network interface.
#
# IMPORTANT: Live capture requires root/sudo on Linux/macOS.
# On Windows, WinPcap or Npcap must be installed (https://npcap.com/).
# Run with: sudo python main.py --live   (Linux/macOS)
#           Run as Administrator          (Windows)

from typing import Callable

from scapy.packet import Packet
from scapy.sendrecv import sniff

from config import DEFAULT_INTERFACE


class LiveCapture:
    """Captures packets in real time from a network interface using scapy.

    Wraps scapy's sniff() to keep the rest of the codebase decoupled from
    scapy's API. Packets are passed to a caller-supplied callback so the
    capture loop stays separate from any processing logic (no global state).
    """

    def __init__(self, interface: str = DEFAULT_INTERFACE) -> None:
        """
        Args:
            interface: Network interface to sniff on (e.g. 'eth0', 'en0').
                       Defaults to DEFAULT_INTERFACE from config.py.
        """
        self.interface = interface

    def start(
        self,
        callback: Callable[[Packet], None],
        count: int = 0,
        timeout: int | None = None,
        stop_filter: Callable[[Packet], bool] | None = None,
    ) -> None:
        """Begin capturing packets and invoke callback for each one.

        Blocks until `count` packets are captured, `timeout` seconds elapse,
        or `stop_filter` returns True. Pass count=0 and timeout=None to run
        indefinitely (Ctrl-C to stop in CLI mode).

        Args:
            callback:    Function called with each captured Packet.
            count:       Stop after this many packets. 0 means no limit.
            timeout:     Stop after this many seconds. None means no limit.
            stop_filter: Called after each packet; sniff stops when it returns
                         True. Used by the GUI thread to stop capture cleanly.

        Raises:
            PermissionError: Raised by scapy if the process lacks the privileges
                             needed to open a raw socket on the interface.
        """
        # store_=False tells scapy not to accumulate packets in memory —
        # we handle them immediately in the callback instead.
        sniff(
            iface=self.interface,
            prn=callback,
            count=count,
            timeout=timeout,
            store=False,
            stop_filter=stop_filter,
        )
