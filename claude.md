# CLAUDE.md — Packet Tracer / Network Monitor

## Project purpose
Educational Python network monitoring tool for learning security skills.
Captures, parses, and analyzes packets. Detects common attack patterns.
Owner: James Holly — learning project, not production.

## Architecture
```
packet-tracer/
├── capture/        # Packet capture (scapy) — pcap file or live interface
├── dissector/      # Protocol parsing — Ethernet, IP, TCP, UDP, HTTP, DNS
├── analyzer/       # Anomaly detection rules — port scans, ARP spoof, floods
├── display/        # CLI output — live packet table, alerts
├── tests/          # Unit tests per module
├── samples/        # Sample .pcap files for testing without live capture
├── main.py         # Entrypoint
├── config.py       # Constants, thresholds, interface name
└── requirements.txt
```

## Stack
- Python 3.11+
- scapy — capture and packet crafting
- pyshark — optional, for reading complex pcap files
- rich — CLI tables and live display
- pytest — testing

## Key constraints
- Live capture requires root/sudo — always document this in READMEs and comments
- Default to pcap file mode so the tool works without elevated privileges
- Each module must be independently importable and testable
- No global state — pass packet data explicitly between layers

## Code conventions
- Type hints on all function signatures
- Docstrings on every class and public function
- Inline comments explaining *why*, not just *what* — this is a learning project
- One class per file where possible
- Constants in config.py, never hardcoded in modules

## Phase tracking
- [x] Phase 1: Project scaffold + config
- [x] Phase 2: Capture module
- [x] Phase 3: Protocol dissector
- [x] Phase 4: Anomaly detection
- [x] Phase 5: CLI display
- [x] Phase 6: Tests + sample pcap integration
- [ ] Phase 7: README + docs

## Notes for Claude Code
- Prefer explicit over clever — this is a learning codebase
- When adding a new module, update the phase checklist above
- If scapy behavior is platform-specific (Linux vs macOS), note it in comments
- Do not add a web frontend unless explicitly asked

## Environment
- OS: Windows 11, editor: VS Code
- Terminal: PowerShell (use PowerShell syntax for shell commands, e.g. `$env:VAR` not `export VAR=`)
- Git Bash is available as an alternative if Unix-style commands are needed
