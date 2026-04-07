# main.py — Entrypoint for the packet tracer tool.
#
# Usage:
#   python main.py                        # read default pcap file
#   python main.py --pcap path/to/file.pcap
#   python main.py --live                 # live capture (requires root/sudo or
#                                         # Administrator on Windows + Npcap)
#   python main.py --live --iface eth0    # specify interface

import argparse
import sys

from rich.console import Console

from analyzer import AnalyzerEngine
from capture import LiveCapture, PcapReader
from config import DEFAULT_INTERFACE, PCAP_FILE_PATH
from display import Dashboard
from dissector import Dissector

console = Console()


def parse_args() -> argparse.Namespace:
    """Define and parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Packet Tracer — capture, dissect, and detect anomalies"
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        default=PCAP_FILE_PATH,
        help=f"Path to a .pcap file to read (default: {PCAP_FILE_PATH})",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Capture live from a network interface instead of reading a file",
    )
    parser.add_argument(
        "--iface",
        metavar="INTERFACE",
        default=DEFAULT_INTERFACE,
        help=f"Network interface for live capture (default: {DEFAULT_INTERFACE})",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=50,
        help="Number of packets to show in the live table (default: 50)",
    )
    return parser.parse_args()


def run_pcap(args: argparse.Namespace) -> None:
    """Read and process packets from a pcap file."""
    dissector = Dissector()
    engine = AnalyzerEngine()
    dashboard = Dashboard(max_packets=args.max_packets)

    try:
        reader = PcapReader(args.pcap)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

    console.print(f"[dim]Reading from [bold]{args.pcap}[/bold]…[/dim]")

    with dashboard.live_context():
        for raw_packet in reader.stream():
            parsed = dissector.parse(raw_packet)
            alerts = engine.analyze(parsed)
            dashboard.update(parsed, alerts)

    dashboard.print_summary()


def run_live(args: argparse.Namespace) -> None:
    """Capture and process packets live from a network interface."""
    dissector = Dissector()
    engine = AnalyzerEngine()
    dashboard = Dashboard(max_packets=args.max_packets)

    console.print(
        f"[dim]Starting live capture on [bold]{args.iface}[/bold] "
        f"— press Ctrl-C to stop…[/dim]"
    )
    # NOTE: Live capture requires elevated privileges.
    # On Linux/macOS: run with sudo.
    # On Windows: run as Administrator and ensure Npcap is installed.

    capture = LiveCapture(interface=args.iface)

    def on_packet(raw_packet) -> None:  # type: ignore[no-untyped-def]
        parsed = dissector.parse(raw_packet)
        alerts = engine.analyze(parsed)
        dashboard.update(parsed, alerts)

    try:
        with dashboard.live_context():
            capture.start(callback=on_packet)
    except KeyboardInterrupt:
        pass  # Clean exit on Ctrl-C — summary is printed below

    dashboard.print_summary()


def main() -> None:
    """Main entry point — dispatch to pcap or live mode."""
    args = parse_args()
    if args.live:
        run_live(args)
    else:
        run_pcap(args)


if __name__ == "__main__":
    main()
