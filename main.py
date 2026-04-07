# main.py — Entrypoint for the Packet Tracer tool.
#
# Defaults to the desktop GUI. Use --cli for the original terminal dashboard.
#
# GUI usage:
#   python main.py
#
# CLI usage:
#   python main.py --cli --pcap samples/sample.pcap
#   python main.py --cli --live --iface "eth0"
#
# NOTE: Live capture requires elevated privileges.
#   Windows: run as Administrator (Npcap must be installed — https://npcap.com)
#   Linux/macOS: run with sudo

import argparse
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Packet Tracer — capture, dissect, and detect network anomalies"
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run the terminal dashboard instead of the desktop GUI",
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        default="samples/sample.pcap",
        help="Path to a .pcap file (CLI mode, default: samples/sample.pcap)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Capture live from a network interface (CLI mode)",
    )
    parser.add_argument(
        "--iface",
        metavar="INTERFACE",
        default=None,
        help="Network interface for live capture (CLI mode)",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=50,
        help="Rows shown in CLI packet table (default: 50)",
    )
    return parser.parse_args()


def run_gui() -> None:
    """Launch the PyQt6 desktop application."""
    from PyQt6.QtWidgets import QApplication
    from gui.main_window import MainWindow
    from gui.styles import DARK_THEME

    app = QApplication(sys.argv)
    app.setApplicationName("Packet Tracer")
    app.setStyleSheet(DARK_THEME)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


def run_cli(args: argparse.Namespace) -> None:
    """Run the original rich terminal dashboard."""
    from rich.console import Console
    from analyzer import AnalyzerEngine
    from capture import LiveCapture, PcapReader
    from config import DEFAULT_INTERFACE, PCAP_FILE_PATH
    from display import Dashboard
    from dissector import Dissector

    console = Console()
    dissector = Dissector()
    engine = AnalyzerEngine()
    dashboard = Dashboard(max_packets=args.max_packets)

    if args.live:
        iface = args.iface or DEFAULT_INTERFACE
        console.print(f"[dim]Live capture on [bold]{iface}[/bold] — Ctrl-C to stop[/dim]")
        capture = LiveCapture(interface=iface)

        def on_packet(raw):
            parsed = dissector.parse(raw)
            dashboard.update(parsed, engine.analyze(parsed))

        try:
            with dashboard.live_context():
                capture.start(callback=on_packet)
        except KeyboardInterrupt:
            pass
    else:
        pcap_path = args.pcap or PCAP_FILE_PATH
        try:
            reader = PcapReader(pcap_path)
        except FileNotFoundError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")
            sys.exit(1)

        console.print(f"[dim]Reading [bold]{pcap_path}[/bold]…[/dim]")
        with dashboard.live_context():
            for raw in reader.stream():
                parsed = dissector.parse(raw)
                dashboard.update(parsed, engine.analyze(parsed))

    dashboard.print_summary()


def main() -> None:
    args = parse_args()
    if args.cli:
        run_cli(args)
    else:
        run_gui()


if __name__ == "__main__":
    main()
