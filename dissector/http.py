# dissector/http.py — Best-effort HTTP/1.x parser from raw TCP payload bytes.
#
# Scapy does not have a built-in HTTP dissector in its base install, so we
# inspect the raw payload text ourselves. This handles the common cases
# (GET/POST requests, numeric status responses) but is not a full HTTP parser.
# HTTPS traffic is encrypted and will not be parseable here.

from scapy.layers.inet import TCP
from scapy.packet import Packet

from dissector.models import HTTPInfo


# HTTP/1.x request methods defined in RFC 7231 + common extensions.
_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}

# Standard HTTP ports — port 8080 and 8000 are common dev/proxy ports.
_HTTP_PORTS = {80, 8080, 8000, 8888}


class HTTPDissector:
    """Attempts to parse HTTP/1.x request or response data from TCP payloads."""

    def parse(self, packet: Packet) -> HTTPInfo | None:
        """Return an HTTPInfo if the TCP payload looks like HTTP, else None.

        We check for packets on known HTTP ports whose payload starts with
        a recognised HTTP method (request) or "HTTP/" (response). Binary or
        encrypted payloads are skipped without error.

        Args:
            packet: A raw scapy Packet object.

        Returns:
            HTTPInfo with whatever fields could be extracted, or None if
            the packet is not HTTP traffic.
        """
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]

        # Only examine traffic on ports we expect to carry HTTP.
        # This avoids wasting time decoding every TCP payload.
        if tcp.dport not in _HTTP_PORTS and tcp.sport not in _HTTP_PORTS:
            return None

        # Extract the raw payload bytes and attempt a UTF-8 decode.
        # If the payload is binary (e.g. TLS handshake on port 443), errors
        # would raise UnicodeDecodeError — we catch that and return None.
        raw = bytes(tcp.payload)
        if not raw:
            return None

        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            # Non-text payload on an HTTP port — likely TLS or binary data.
            return None

        first_line = text.split("\r\n", 1)[0]
        parts = first_line.split(" ", 2)

        # --- Detect HTTP request ---
        # Request first line format: METHOD /path HTTP/1.x
        if parts[0] in _HTTP_METHODS:
            method = parts[0]
            path = parts[1] if len(parts) > 1 else None
            host = _extract_header(text, "Host")
            return HTTPInfo(method=method, path=path, host=host, status_code=None)

        # --- Detect HTTP response ---
        # Response first line format: HTTP/1.x STATUS_CODE reason
        if parts[0].startswith("HTTP/"):
            status_code: int | None = None
            if len(parts) > 1:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
            return HTTPInfo(method=None, path=None, host=None, status_code=status_code)

        # Payload on an HTTP port but doesn't match request or response syntax.
        return None


def _extract_header(text: str, header_name: str) -> str | None:
    """Pull the value of a named HTTP header from the raw request text.

    Args:
        text:        Full decoded HTTP message text.
        header_name: Header field name to look for (case-insensitive).

    Returns:
        The header value string, or None if the header is absent.
    """
    # Headers are separated by CRLF; search line-by-line after the first.
    for line in text.split("\r\n")[1:]:
        if line.lower().startswith(header_name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return None
