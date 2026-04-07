# gui/alert_content.py — Static "What Now?" content for each alert type.
#
# Each entry contains three sections shown as tabs in the What Now dialog:
#   - overview:  what the attack is and how it works
#   - immediate: actions to take right now
#   - prevent:   long-term defences

from dataclasses import dataclass


@dataclass
class AlertContent:
    """Static educational content for one alert type."""
    title: str
    overview: str   # HTML string
    immediate: str  # HTML string
    prevent: str    # HTML string


CONTENT: dict[str, AlertContent] = {

    "PORT_SCAN": AlertContent(
        title="Port Scan Detected",
        overview="""
<h3>What is a port scan?</h3>
<p>A port scan is a reconnaissance technique where an attacker probes a target host
by sending connection requests to many different ports in quick succession.
The goal is to discover which services are running — open ports reveal potential
entry points.</p>

<h3>How it works</h3>
<p>The most common method is a <b>TCP SYN scan</b> (also called a "half-open" scan).
The attacker sends a SYN packet to each port:</p>
<ul>
  <li><b>Open port:</b> the server replies with SYN-ACK → attacker knows the service exists</li>
  <li><b>Closed port:</b> the server replies with RST → port is closed</li>
  <li><b>Filtered port:</b> no reply → a firewall is dropping the packets</li>
</ul>
<p>The attacker never completes the three-way handshake, making the scan harder
to detect in basic logs. Tools like <b>nmap</b> automate this across thousands
of ports in seconds.</p>

<h3>Why it matters</h3>
<p>A port scan itself causes no damage, but it is almost always a precursor to an
attack. The attacker is building a map of your network before choosing their
next move.</p>
""",
        immediate="""
<h3>Right now</h3>
<ol>
  <li><b>Identify the source IP</b> — check whether it belongs to an internal host,
  a known vendor, or an external address. Internal scans may indicate a compromised
  machine on your network.</li>
  <li><b>Block the IP at your firewall</b> if the scan is external and unsolicited.
  Most firewalls allow you to add a temporary deny rule.</li>
  <li><b>Check which ports were probed</b> — the evidence panel shows the list.
  Cross-reference against your known services. Any unexpected open ports are worth
  investigating immediately.</li>
  <li><b>Review recent auth logs</b> on any services the scan hit (SSH, RDP, HTTP)
  for login attempts that may have followed.</li>
</ol>

<h3>Assess the risk</h3>
<p>A single scan from an external IP is common background internet noise.
Repeated scans from the same source, or scans originating from inside your
network, are significantly more concerning.</p>
""",
        prevent="""
<h3>Firewall rules</h3>
<p>Only expose ports that external users genuinely need. A default-deny inbound
policy means only explicitly allowed ports are reachable — everything else appears
filtered to a scanner.</p>

<h3>Intrusion Detection / Prevention (IDS/IPS)</h3>
<p>Tools like <b>Snort</b>, <b>Suricata</b>, or cloud-native equivalents can
automatically detect and block scan patterns in real time.</p>

<h3>Port knocking</h3>
<p>Hide sensitive services (e.g. SSH) behind port knocking — the port only opens
after the client sends a specific sequence of connection attempts to other ports.
Scanners will never see it.</p>

<h3>Minimise your attack surface</h3>
<p>Audit running services regularly. Disable or uninstall anything that doesn't
need to be network-accessible. Every closed port is one less thing to worry about.</p>
""",
    ),

    "SYN_FLOOD": AlertContent(
        title="SYN Flood Attack Detected",
        overview="""
<h3>What is a SYN flood?</h3>
<p>A SYN flood is a <b>Denial-of-Service (DoS)</b> attack that exploits the TCP
three-way handshake. The attacker sends a massive volume of SYN packets to a
target server but never completes the handshake.</p>

<h3>How it works</h3>
<p>When a server receives a SYN, it allocates resources for a half-open connection
and sends a SYN-ACK, waiting for the final ACK. In a SYN flood:</p>
<ol>
  <li>The attacker sends thousands of SYNs — often with <b>spoofed source IPs</b>
  so the server's SYN-ACKs go nowhere.</li>
  <li>The server's connection table fills with half-open connections.</li>
  <li>Legitimate clients are refused — the server can't accept new connections.</li>
</ol>
<p>This is one of the oldest and most common DDoS techniques, still widely used
because it requires very little bandwidth from the attacker.</p>

<h3>Spoofed IPs</h3>
<p>The source IP in the alert may <b>not be the real attacker</b> — SYN floods
frequently spoof random source addresses. Blocking that IP alone won't stop the
attack.</p>
""",
        immediate="""
<h3>Right now</h3>
<ol>
  <li><b>Enable SYN cookies</b> on the target server if not already active.
  SYN cookies allow the server to handle SYNs without allocating connection state
  until the handshake completes — the most effective immediate mitigation.</li>
  <li><b>Rate-limit inbound SYN packets</b> at the firewall or router.
  Drop SYNs from any single source above a safe threshold per second.</li>
  <li><b>Check whether the source IP is spoofed</b> — if all SYNs share the same
  source, it may be a real IP you can block. Randomised sources indicate spoofing.</li>
  <li><b>Contact your ISP or upstream provider</b> for volumetric attacks —
  they can apply upstream filtering (blackhole routing) before traffic reaches
  your network.</li>
  <li><b>Monitor service health</b> — check whether the targeted service is still
  responding to legitimate requests.</li>
</ol>
""",
        prevent="""
<h3>SYN cookies (most important)</h3>
<p>Enable SYN cookies at the OS level. Linux: <code>sysctl net.ipv4.tcp_syncookies=1</code>.
This makes the server stateless until the handshake completes, neutralising the attack.</p>

<h3>Firewall rate limiting</h3>
<p>Configure your firewall to limit the SYN rate per source IP. Most enterprise
firewalls and cloud security groups support this natively.</p>

<h3>Increase the SYN backlog</h3>
<p>Increase <code>net.ipv4.tcp_max_syn_backlog</code> to tolerate higher volumes
of half-open connections — buys time while other mitigations kick in.</p>

<h3>DDoS protection services</h3>
<p>For persistent or high-volume attacks, consider cloud-based DDoS scrubbing
services (Cloudflare, AWS Shield, Akamai) that absorb attack traffic before it
reaches your infrastructure.</p>

<h3>Ingress filtering (BCP38)</h3>
<p>Encourage your ISP to implement BCP38 ingress filtering, which prevents
spoofed packets from leaving their network — reduces the pool of spoofed SYN
flood sources industry-wide.</p>
""",
    ),

    "ARP_SPOOF": AlertContent(
        title="ARP Spoofing / Cache Poisoning Detected",
        overview="""
<h3>What is ARP spoofing?</h3>
<p>ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local
network. ARP spoofing poisons the ARP cache of other hosts by sending fake ARP
replies, redirecting their traffic to the attacker's machine.</p>

<h3>How it works</h3>
<ol>
  <li>The attacker broadcasts fake ARP replies:
  <i>"192.168.1.1 (the gateway) is at MY MAC address"</i></li>
  <li>Other devices update their ARP cache and start sending gateway-bound traffic
  to the attacker instead.</li>
  <li>The attacker silently forwards traffic to the real gateway — a classic
  <b>Man-in-the-Middle (MITM)</b> attack. Neither the victim nor the server
  know the traffic is being intercepted.</li>
</ol>

<h3>What the attacker can do</h3>
<ul>
  <li><b>Eavesdrop</b> on unencrypted traffic (HTTP, Telnet, FTP credentials)</li>
  <li><b>Strip HTTPS</b> using tools like SSLstrip (downgrades HTTPS to HTTP)</li>
  <li><b>Inject content</b> into web pages or DNS responses</li>
  <li><b>Disrupt traffic</b> by dropping packets (DoS)</li>
</ul>

<h3>Why this alert fired</h3>
<p>Two different MAC addresses have claimed the same IP address via ARP replies.
One of them is likely the legitimate owner; the other is the attacker.</p>
""",
        immediate="""
<h3>Right now</h3>
<ol>
  <li><b>Identify which MAC is legitimate</b> — check your router/switch's DHCP
  lease table to find the expected MAC for the disputed IP. The other MAC is the
  attacker.</li>
  <li><b>Find the attacker's physical port</b> — on a managed switch, look up the
  rogue MAC in the MAC address table to identify which port it's connected to, then
  disconnect it.</li>
  <li><b>Add static ARP entries</b> for your critical hosts (gateway, DNS server)
  immediately. Static entries can't be overwritten by ARP replies:
  <br><code>arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff</code></li>
  <li><b>Assume traffic was intercepted</b> — any unencrypted credentials sent
  during the attack window should be treated as compromised. Change passwords for
  services that were active.</li>
  <li><b>Check for SSLstrip</b> — verify that HTTPS connections were not downgraded
  by checking browser padlock status and HSTS headers.</li>
</ol>
""",
        prevent="""
<h3>Dynamic ARP Inspection (DAI)</h3>
<p>Enable DAI on managed switches. It validates ARP packets against a trusted
DHCP snooping binding table and drops ARP replies that don't match — completely
prevents ARP spoofing at the switch level.</p>

<h3>Static ARP entries</h3>
<p>For a small number of critical hosts (gateway, DNS), add permanent static ARP
entries to all machines on the network. These cannot be poisoned by ARP replies.</p>

<h3>Use encrypted protocols</h3>
<p>Even if ARP spoofing succeeds, encrypted traffic (HTTPS, SSH, VPN) cannot be
read by the attacker. Ensure HSTS is enabled on web services so browsers refuse
HTTP downgrade attempts.</p>

<h3>Network segmentation</h3>
<p>ARP only works within a broadcast domain. VLANs isolate groups of hosts so an
attacker on one VLAN cannot spoof hosts on another.</p>

<h3>802.1X port authentication</h3>
<p>Require authentication before a device can join the network — prevents
unauthorised devices from connecting in the first place.</p>
""",
    ),

    "ARP_FLOOD": AlertContent(
        title="Gratuitous ARP Flood Detected",
        overview="""
<h3>What is a gratuitous ARP flood?</h3>
<p>A <b>gratuitous ARP</b> is an unsolicited ARP reply — a host announces its own
IP-to-MAC mapping without being asked. This is legitimate during network boot,
IP address changes, or failover events, but should happen rarely.</p>

<h3>Why a flood is suspicious</h3>
<p>Automated ARP spoofing tools (e.g. <b>arpspoof</b>, <b>Ettercap</b>) send
gratuitous ARP replies at a high rate to ensure that poisoned ARP cache entries
don't expire before they can be exploited. A single MAC sending many ARP replies
in a short window strongly suggests an active spoofing tool.</p>

<h3>Relationship to ARP_SPOOF</h3>
<p>An ARP flood alert may appear alongside or before an ARP_SPOOF alert.
The flood is the <i>mechanism</i>; cache poisoning is the <i>goal</i>.</p>
""",
        immediate="""
<h3>Right now</h3>
<ol>
  <li><b>Identify the flooding MAC address</b> — shown in the alert evidence.
  Cross-reference it against your known device inventory.</li>
  <li><b>Locate the device</b> — use your switch's MAC address table to find
  which port the MAC is connected to, then inspect or disconnect the device.</li>
  <li><b>Check for an active MITM</b> — run <code>arp -a</code> on other hosts
  to see if their ARP cache has been poisoned (duplicate MACs for different IPs
  is a red flag).</li>
  <li><b>Flush poisoned ARP caches</b> on affected hosts:
  <br>Windows: <code>arp -d *</code>
  <br>Linux: <code>ip neigh flush all</code></li>
</ol>
""",
        prevent="""
<h3>Rate-limit ARP traffic</h3>
<p>Configure managed switches to rate-limit ARP packets per port. Most enterprise
switches support ARP storm control — drop ARP packets above a set rate threshold.</p>

<h3>Dynamic ARP Inspection (DAI)</h3>
<p>DAI validates every ARP packet on untrusted switch ports against the DHCP
snooping table. It blocks gratuitous ARPs from unauthorised sources entirely.</p>

<h3>Port security</h3>
<p>Lock switch ports to their expected MAC addresses. If an unauthorised device
plugs in or a MAC changes unexpectedly, the port shuts down automatically.</p>

<h3>Monitor with this tool</h3>
<p>The ARP flood detector here uses a sliding time window. You can lower
<code>ARP_REPLY_THRESHOLD</code> in <code>config.py</code> to make it more
sensitive to lower-rate attacks.</p>
""",
    ),
}


def get_content(alert_type: str) -> AlertContent:
    """Return the static content for a given alert type.

    Falls back to a generic entry if the alert type is not recognised,
    so new detector types don't cause a KeyError in the dialog.

    Args:
        alert_type: The alert_type string from an Alert object.

    Returns:
        AlertContent with overview, immediate, and prevent sections.
    """
    return CONTENT.get(alert_type, AlertContent(
        title=f"Alert: {alert_type}",
        overview="<p>An anomaly was detected. Review the evidence for details.</p>",
        immediate="<p>Investigate the source IP and review recent network logs.</p>",
        prevent="<p>Ensure firewall rules and IDS signatures are up to date.</p>",
    ))
