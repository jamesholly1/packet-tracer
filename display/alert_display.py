# display/alert_display.py — Formats Alert objects for rich terminal output.

from rich.table import Table
from rich.text import Text

from analyzer.models import Alert, Severity

# Map severity levels to terminal colours.
_SEVERITY_COLOURS: dict[Severity, str] = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
}

_SEVERITY_ICONS: dict[Severity, str] = {
    Severity.HIGH: "!! ",
    Severity.MEDIUM: "!  ",
    Severity.LOW: "i  ",
}


class AlertDisplay:
    """Maintains a list of fired alerts and renders them as a rich Table."""

    def __init__(self) -> None:
        self._alerts: list[Alert] = []

    def add(self, alert: Alert) -> None:
        """Append a new alert to the display list.

        Args:
            alert: An Alert produced by a detector in the analyzer module.
        """
        self._alerts.append(alert)

    def build(self) -> Table:
        """Construct and return a rich Table of all recorded alerts.

        Returns:
            A rich Table ready for Console.print() or Live.update().
            Shows the most recent alerts at the bottom (capture order).
        """
        table = Table(
            title=f"Alerts ({len(self._alerts)})",
            show_header=True,
            header_style="bold white",
            border_style="red",
            expand=True,
        )

        table.add_column("Severity", width=10, no_wrap=True)
        table.add_column("Type", width=12, no_wrap=True)
        table.add_column("Source IP", width=16, no_wrap=True)
        table.add_column("Message", ratio=1)

        for alert in self._alerts:
            colour = _SEVERITY_COLOURS.get(alert.severity, "white")
            icon = _SEVERITY_ICONS.get(alert.severity, "")
            severity_text = Text(f"{icon}{alert.severity.value}", style=colour)

            table.add_row(
                severity_text,
                Text(alert.alert_type, style="bold"),
                alert.src_ip,
                alert.message,
            )

        return table

    def format_inline(self, alert: Alert) -> Text:
        """Format a single alert as a one-line rich Text for immediate printing.

        Used when streaming mode prints alerts as they arrive rather than
        rendering them inside a Live layout.

        Args:
            alert: The alert to format.

        Returns:
            A rich Text object ready for Console.print().
        """
        colour = _SEVERITY_COLOURS.get(alert.severity, "white")
        icon = _SEVERITY_ICONS.get(alert.severity, "")
        return Text(
            f"{icon}[{alert.alert_type}] {alert.src_ip} — {alert.message}",
            style=colour,
        )
