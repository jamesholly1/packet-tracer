# display/dashboard.py — Orchestrates the live terminal dashboard.
#
# Dashboard owns the rich Live context and a Layout split into two panels:
#   - Top: rolling packet table (most recent N packets)
#   - Bottom: alerts table (all alerts since start)
#
# Usage:
#   dashboard = Dashboard()
#   with dashboard.live_context():
#       for packet in reader.stream():
#           parsed = dissector.parse(packet)
#           alerts = engine.analyze(parsed)
#           dashboard.update(parsed, alerts)

from contextlib import contextmanager
from typing import Generator

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from analyzer.models import Alert
from display.alert_display import AlertDisplay
from display.packet_table import PacketTable
from dissector.models import ParsedPacket

# Refresh rate in frames per second. 4 fps keeps CPU low while still feeling
# responsive. For very high-throughput captures, lower this further.
_REFRESH_RATE = 4


class Dashboard:
    """Live terminal dashboard combining the packet table and alerts panel.

    Designed to be used as a context manager via live_context(). Outside that
    context, update() falls back to plain Console.print() so the class is
    also usable in non-interactive / piped-output scenarios.
    """

    def __init__(self, max_packets: int = 50) -> None:
        """
        Args:
            max_packets: How many packets to keep visible in the packet table.
        """
        self._console = Console()
        self._packet_table = PacketTable(max_rows=max_packets)
        self._alert_display = AlertDisplay()
        self._live: Live | None = None  # Set while inside live_context()

    @contextmanager
    def live_context(self) -> Generator[None, None, None]:
        """Context manager that starts and stops the rich Live display.

        Inside this block, calls to update() will refresh the terminal in-place.
        On exit (or Ctrl-C), the final state is left visible in the terminal.

        Example:
            with dashboard.live_context():
                for pkt in packets:
                    dashboard.update(pkt, engine.analyze(pkt))
        """
        layout = self._build_layout()
        with Live(
            layout,
            console=self._console,
            refresh_per_second=_REFRESH_RATE,
            screen=False,   # screen=False keeps scroll history intact
        ) as live:
            self._live = live
            try:
                yield
            finally:
                self._live = None

    def update(self, packet: ParsedPacket, alerts: list[Alert]) -> None:
        """Add a packet and any new alerts to the display.

        If called inside live_context(), the terminal is refreshed at the next
        tick. If called outside, packets are silently buffered and each alert
        is printed inline immediately.

        Args:
            packet: The latest parsed packet to append to the table.
            alerts: Alerts produced by AnalyzerEngine for this packet.
        """
        self._packet_table.add(packet)

        for alert in alerts:
            self._alert_display.add(alert)
            if self._live is None:
                # Not in a live context — print alerts immediately so they
                # aren't silently swallowed.
                self._console.print(self._alert_display.format_inline(alert))

        if self._live is not None:
            # Rebuild the layout with fresh data and push to the live display.
            self._live.update(self._build_layout())

    def print_summary(self) -> None:
        """Print a final summary of all alerts to the console.

        Useful to call after the capture loop ends to give a clean recap of
        everything detected during the session.
        """
        alerts = self._alert_display._alerts
        if not alerts:
            self._console.print(Text("\nNo anomalies detected.", style="green"))
            return

        self._console.print(f"\n[bold]Session summary — {len(alerts)} alert(s):[/bold]")
        self._console.print(self._alert_display.build())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_layout(self) -> Layout:
        """Construct a fresh Layout from the current packet and alert state.

        Returns:
            A rich Layout with the packet table on top and alerts below.
        """
        layout = Layout()

        # Divide vertically: packets get 70% of height, alerts get 30%.
        # minimum=3 prevents the alert panel collapsing to nothing when empty.
        layout.split_column(
            Layout(name="packets", ratio=7),
            Layout(name="alerts", ratio=3, minimum=3),
        )

        layout["packets"].update(
            Panel(self._packet_table.build(), border_style="bright_black")
        )

        alert_count = len(self._alert_display._alerts)
        alert_colour = "red" if alert_count else "bright_black"
        layout["alerts"].update(
            Panel(
                self._alert_display.build(),
                title=f"[{alert_colour}]Alerts ({alert_count})[/{alert_colour}]",
                border_style=alert_colour,
            )
        )

        return layout
