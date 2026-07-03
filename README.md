
# IDS_GUARD 🚨

<img width="1365" height="767" alt="Screenshot 2026-07-01 132315" src="https://github.com/user-attachments/assets/6ecf73b2-c9e0-468c-8f1c-0bfa97b02dc3" />

**IDS_GUARD** is a terminal-based Python Intrusion Detection System. It captures live traffic with **Scapy**, runs it through a rule-based, stateful detection engine, and renders everything on a full-screen **Rich** dashboard — alerts, live packet stream, protocol breakdown, top talkers, top targeted ports, and blocked IPs, all updating in real time.

It also ships with a **demo mode** that simulates realistic + attack traffic, so you can see the full dashboard in action without root privileges or a live network.

```
┌───────────────────────────── PyIDS ─────────────────────────────┐
│ PACKETS  ALERTS  CRITICAL  HIGH  MEDIUM  LOW  BYTES RX  BLOCKED │
├───────────────────────────┬───────────────────────────────────┤
│ 🚨 Alerts                 │ ⚡ Alert Severity                  │
│ SYN_FLOOD, PORT_SCAN, ...  │ 🚫 Blocked IPs                    │
├───────────────────────────┼───────────────────────────────────┤
│ 📡 Live Packet Stream      │ 📊 Protocol Breakdown              │
│                            │ 🔝 Top Talkers                    │
│                            │ 🎯 Top Target Ports                │
└───────────────────────────┴───────────────────────────────────┘
```

## Features

- **Live packet capture** on any interface via Scapy, with optional BPF filter support (`--filter "tcp port 80"`).
- **Demo mode** (`--demo`) — generates simulated normal + attack traffic so the dashboard and detection engine can be explored without root access or real network traffic.
- **Rule-based detection engine** with stateful, time-windowed tracking:

  | Rule | Detects |
  |---|---|
  | `BLOCKLIST_HIT` | Traffic to/from IPs matching known malicious prefixes |
  | `SYN_FLOOD` / `SYN_FLOOD_ONGOING` | Excessive SYN packets from one source → possible SYN flood |
  | `PORT_SCAN` / `PORT_SCAN_WIDE` | One source probing many distinct destination ports |
  | `SUSPICIOUS_PORT` | Connections to high-risk ports (Telnet, SMB, RDP, VNC, Redis, Meterpreter default, etc.) |
  | `ICMP_FLOOD` | Excessive ICMP traffic → ping flood / recon |
  | `DNS_FLOOD` | Excessive DNS queries → amplification/tunneling |
  | `DNS_TUNNEL_SUSPECTED` | Abnormally long DNS query names |
  | `ARP_SPOOFING` | An IP's MAC address changing in observed ARP replies → cache poisoning |
  | `NULL_SCAN` / `XMAS_SCAN` | Stealth TCP scans (no flags, or FIN+PSH+URG) |
  | `LATERAL_MOVEMENT` | Internal-to-internal traffic on sensitive ports (SSH, RDP, SMB, VNC) |

- **Severity levels** — `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, each with its own color/icon and rolled up into a live severity breakdown chart.
- **Full-screen live dashboard** (via `rich.Layout` + `rich.Live`):
  - Header stat cards (packets, alerts by severity, bytes received, blocked IPs)
  - Scrolling alerts table (id, time, severity, rule, src/dst IP, protocol, detail)
  - Live packet stream (time, protocol, src:port, dst:port, flags, length, service)
  - Protocol breakdown bar chart
  - Top talkers and top targeted ports, with bar visualizations
  - Blocked IPs panel
- **Interface listing** — `--list-ifaces` prints all interfaces Scapy can see, for picking `--iface`.
- **Session summary** — on exit, prints total packets, total/critical/high alerts, IPs blocked, and data seen.

## Requirements

- Python 3.8+
- [Npcap](https://npcap.com/) (Windows only, required by Scapy for packet capture)
- Root / Administrator privileges for **live** capture (not required in `--demo` mode)

```bash
pip install scapy rich
```

## Usage

**Live capture (default interface):**
```bash
sudo python3 ids.py
```

**Live capture on a specific interface:**
```bash
sudo python3 ids.py --iface eth0
```

**Live capture with a BPF filter:**
```bash
sudo python3 ids.py --iface wlan0 --filter "tcp"
```

**Demo mode (no root required, simulated attack traffic):**
```bash
python3 ids.py --demo
```

**List available interfaces:**
```bash
python3 ids.py --list-ifaces
```

Press **Q** or **Ctrl+C** to stop. A session summary is printed on exit.

### CLI options

| Flag | Description |
|---|---|
| `-i`, `--iface` | Network interface to capture on (default: auto) |
| `-f`, `--filter` | BPF filter string, e.g. `"tcp port 80"` |
| `--demo` | Run with simulated traffic, no root needed |
| `--list-ifaces` | List available interfaces and exit |

## How It Works

1. **Capture** — Scapy sniffs packets (or `DemoTrafficGenerator` synthesizes them in demo mode) and hands each one to `DetectionEngine.analyze()`.
2. **Parsing** — each packet is classified by layer (IP/IPv6, TCP/UDP/ICMP/ARP) and application protocol (HTTP/HTTPS/DNS inferred from ports), producing a `PacketRecord` for the live packet stream.
3. **Detection** — depending on protocol, the packet is run through the relevant stateful checks (SYN flood, port scan, suspicious port, ICMP/DNS flood, ARP spoofing, NULL/XMAS scan, lateral movement, blocklist match). Each tracker prunes its own rolling time window (typically 5–10s) to catch sustained abuse rather than one-off spikes.
4. **Alerting** — matches are converted into `Alert` records with a severity, added to a thread-safe queue, and rolled into running stats (`Stats.alerts_by_sev`, `total_packets`, `top_talkers`, `top_targets`, `port_hits`, etc.).
5. **Dashboard** — a `rich.Live` loop rebuilds the full `Layout` every ~0.25s from current state: header stats, alerts table, packet stream, protocol/talker/port charts, severity breakdown, and blocked IPs.

## Demo Mode

`--demo` is useful for exploring the tool, taking screenshots, or testing without a live network or root access. It generates a mix of normal traffic (from private IP ranges) and simulated attacks (from a small set of known-bad-looking IPs) so most detection rules fire naturally within a minute or two.

## Disclaimer

PyIDS is a detection and visibility tool — it does **not** block or drop traffic itself (the "Blocked IPs" panel reflects IPs matched against the internal blocklist, for visibility, not active enforcement). Use it only on networks and systems you own or have explicit permission to monitor. The included blocklist prefixes are illustrative/simulated, not a maintained threat-intel feed — don't rely on them for production defense.

## License

MIT (or your preferred license — update this section as needed).
