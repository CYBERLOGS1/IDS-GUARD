#!/usr/bin/env python3
"""
PyIDS — Python Intrusion Detection System
Packet capture via Scapy · Terminal dashboard via Rich
Run with: sudo python3 ids.py [--iface eth0] [--demo]
"""

import argparse
import collections
import ipaddress
import json
import os
import random
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ── Rich imports ──────────────────────────────────────────────────────────────
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from rich import box

# ── Scapy imports ─────────────────────────────────────────────────────────────
from scapy.all import (
    IP, IPv6, TCP, UDP, ICMP, DNS, ARP,
    sniff, get_if_list, conf
)
from scapy.layers.http import HTTPRequest, HTTPResponse

# ─────────────────────────────────────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange3",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "dim white",
}

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

PROTO_STYLE = {
    "TCP":  "green",
    "UDP":  "cyan",
    "ICMP": "magenta",
    "ARP":  "yellow",
    "DNS":  "blue",
    "HTTP": "bright_green",
    "?":    "dim white",
}

# Well-known port → service name
PORT_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 179: "BGP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "ORACLE",
    3306: "MYSQL", 3389: "RDP", 4444: "METERPRETER",
    5432: "POSTGRES", 5900: "VNC", 6379: "REDIS",
    6660: "IRC", 6667: "IRC", 6668: "IRC", 6669: "IRC",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 9200: "ELASTICSEARCH",
    27017: "MONGODB",
}

# Suspicious destination ports that often indicate scanning/attacks
SUSPICIOUS_PORTS = {
    23, 135, 137, 138, 139, 445, 1433, 3389, 4444,
    5900, 6379, 9200, 27017, 6660, 6667, 6668, 6669,
}

# Private / reserved IP ranges (RFC1918 + loopback + link-local)
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# Known malicious IP prefixes (simulated blocklist)
BLOCKLIST_PREFIXES = [
    "185.220.", "185.234.", "45.33.", "198.199.",
    "104.21.", "205.185.", "89.248.", "193.32.",
]


@dataclass
class Alert:
    id: int
    timestamp: str
    severity: str
    rule: str
    src_ip: str
    dst_ip: str
    proto: str
    detail: str
    port: int = 0
    count: int = 1


@dataclass
class PacketRecord:
    timestamp: str
    src_ip: str
    dst_ip: str
    proto: str
    length: int
    sport: int = 0
    dport: int = 0
    flags: str = ""
    info: str = ""


@dataclass
class Stats:
    total_packets: int = 0
    alerts_total: int = 0
    alerts_by_sev: Dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    })
    proto_counts: Dict[str, int] = field(default_factory=lambda: collections.defaultdict(int))
    bytes_in: int = 0
    bytes_out: int = 0
    top_talkers: Dict[str, int] = field(default_factory=lambda: collections.defaultdict(int))
    top_targets: Dict[str, int] = field(default_factory=lambda: collections.defaultdict(int))
    port_hits: Dict[int, int] = field(default_factory=lambda: collections.defaultdict(int))
    start_time: float = field(default_factory=time.time)
    blocked_ips: set = field(default_factory=set)


# ─────────────────────────────────────────────────────────────────────────────
#  DETECTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class DetectionEngine:
    """Rule-based detection engine with stateful tracking."""

    def __init__(self, stats: Stats, alert_queue: list, lock: threading.Lock):
        self.stats = stats
        self.alerts = alert_queue
        self.lock = lock
        self._alert_id = 0

        # Stateful trackers
        self._syn_tracker: Dict[str, List[float]] = collections.defaultdict(list)  # SYN flood
        self._port_scan_tracker: Dict[str, set] = collections.defaultdict(set)     # port scan
        self._icmp_tracker: Dict[str, List[float]] = collections.defaultdict(list) # ICMP flood
        self._dns_tracker: Dict[str, List[float]] = collections.defaultdict(list)  # DNS flood
        self._arp_table: Dict[str, str] = {}                                        # ARP spoofing
        self._http_paths: Dict[str, List[str]] = collections.defaultdict(list)     # dir traversal

        # Thresholds
        self.SYN_THRESHOLD = 20        # SYN packets per 5s → SYN flood
        self.PORT_SCAN_THRESHOLD = 15  # distinct ports per 10s → port scan
        self.ICMP_THRESHOLD = 30       # ICMP per 5s → ping flood
        self.DNS_THRESHOLD = 50        # DNS per 5s → DNS flood

    def _new_alert(self, severity, rule, src, dst, proto, detail, port=0) -> Alert:
        self._alert_id += 1
        return Alert(
            id=self._alert_id,
            timestamp=datetime.now().strftime("%H:%M:%S"),
            severity=severity,
            rule=rule,
            src_ip=src,
            dst_ip=dst,
            proto=proto,
            detail=detail,
            port=port,
        )

    def _add_alert(self, alert: Alert):
        with self.lock:
            self.alerts.append(alert)
            if len(self.alerts) > 200:
                self.alerts.pop(0)
            self.stats.alerts_total += 1
            self.stats.alerts_by_sev[alert.severity] += 1

    def _is_private(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in PRIVATE_NETS)
        except ValueError:
            return False

    def _is_blocklisted(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in BLOCKLIST_PREFIXES)

    def _prune_window(self, lst: list, window: float) -> list:
        now = time.time()
        return [t for t in lst if now - t < window]

    # ── Individual detection rules ────────────────────────────────────────────

    def check_blocklist(self, src: str, dst: str, proto: str, pkt) -> None:
        for ip, direction in [(src, "source"), (dst, "destination")]:
            if self._is_blocklisted(ip):
                self._add_alert(self._new_alert(
                    "CRITICAL", "BLOCKLIST_HIT",
                    src, dst, proto,
                    f"Packet {direction} matches known malicious IP prefix"
                ))
                with self.lock:
                    self.stats.blocked_ips.add(ip)

    def check_syn_flood(self, src: str, dst: str, flags: str, dport: int) -> None:
        if "S" not in flags or "A" in flags:
            return
        now = time.time()
        key = f"{src}->{dst}"
        self._syn_tracker[key].append(now)
        self._syn_tracker[key] = self._prune_window(self._syn_tracker[key], 5)
        count = len(self._syn_tracker[key])
        if count == self.SYN_THRESHOLD:
            self._add_alert(self._new_alert(
                "HIGH", "SYN_FLOOD",
                src, dst, "TCP",
                f"{count} SYN packets in 5s → possible SYN flood",
                port=dport
            ))
        elif count > self.SYN_THRESHOLD and count % 10 == 0:
            self._add_alert(self._new_alert(
                "CRITICAL", "SYN_FLOOD_ONGOING",
                src, dst, "TCP",
                f"Ongoing SYN flood: {count} SYNs in 5s",
                port=dport
            ))

    def check_port_scan(self, src: str, dst: str, dport: int, flags: str) -> None:
        if "R" in flags:
            return
        key = f"{src}->{dst}"
        self._port_scan_tracker[key].add(dport)
        count = len(self._port_scan_tracker[key])
        if count == self.PORT_SCAN_THRESHOLD:
            self._add_alert(self._new_alert(
                "HIGH", "PORT_SCAN",
                src, dst, "TCP",
                f"Scanning detected: {count} distinct ports probed",
                port=dport
            ))
        elif count > self.PORT_SCAN_THRESHOLD and count % 5 == 0:
            self._add_alert(self._new_alert(
                "HIGH", "PORT_SCAN_WIDE",
                src, dst, "TCP",
                f"Wide port scan: {count} ports probed on target",
                port=dport
            ))

    def check_suspicious_port(self, src: str, dst: str, dport: int, proto: str) -> None:
        if dport in SUSPICIOUS_PORTS:
            svc = PORT_SERVICES.get(dport, str(dport))
            severity = "CRITICAL" if dport in {4444, 6667, 23} else "MEDIUM"
            self._add_alert(self._new_alert(
                severity, "SUSPICIOUS_PORT",
                src, dst, proto,
                f"Connection attempt to suspicious port {dport}/{svc}",
                port=dport
            ))

    def check_icmp_flood(self, src: str, dst: str) -> None:
        now = time.time()
        self._icmp_tracker[src].append(now)
        self._icmp_tracker[src] = self._prune_window(self._icmp_tracker[src], 5)
        count = len(self._icmp_tracker[src])
        if count == self.ICMP_THRESHOLD:
            self._add_alert(self._new_alert(
                "MEDIUM", "ICMP_FLOOD",
                src, dst, "ICMP",
                f"{count} ICMP packets in 5s → possible ping flood / recon"
            ))

    def check_dns_anomaly(self, src: str, dst: str, pkt) -> None:
        now = time.time()
        self._dns_tracker[src].append(now)
        self._dns_tracker[src] = self._prune_window(self._dns_tracker[src], 5)
        count = len(self._dns_tracker[src])
        if count == self.DNS_THRESHOLD:
            self._add_alert(self._new_alert(
                "HIGH", "DNS_FLOOD",
                src, dst, "DNS",
                f"{count} DNS queries in 5s → possible DNS amplification/tunneling"
            ))
        # Check for long DNS names (DNS tunneling indicator)
        if pkt.haslayer(DNS) and pkt[DNS].qd:
            try:
                qname = pkt[DNS].qd.qname.decode(errors="ignore")
                if len(qname) > 100:
                    self._add_alert(self._new_alert(
                        "HIGH", "DNS_TUNNEL_SUSPECTED",
                        src, dst, "DNS",
                        f"Unusually long DNS query ({len(qname)} chars): possible tunneling",
                    ))
            except Exception:
                pass

    def check_arp_spoofing(self, pkt) -> None:
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        if arp.op != 2:  # only ARP replies
            return
        ip, mac = arp.psrc, arp.hwsrc
        if ip in self._arp_table and self._arp_table[ip] != mac:
            old_mac = self._arp_table[ip]
            self._add_alert(self._new_alert(
                "CRITICAL", "ARP_SPOOFING",
                ip, "BROADCAST", "ARP",
                f"ARP cache poisoning: {ip} changed {old_mac} → {mac}"
            ))
        self._arp_table[ip] = mac

    def check_null_xmas_scan(self, src: str, dst: str, flags: str, dport: int) -> None:
        flag_set = set(flags)
        if not flags or flags == "":  # NULL scan
            self._add_alert(self._new_alert(
                "HIGH", "NULL_SCAN",
                src, dst, "TCP",
                f"TCP NULL scan detected (no flags) → stealth recon",
                port=dport
            ))
        elif flag_set == {"F", "P", "U"}:  # XMAS scan
            self._add_alert(self._new_alert(
                "HIGH", "XMAS_SCAN",
                src, dst, "TCP",
                f"TCP XMAS scan detected (FIN+PSH+URG) → stealth recon",
                port=dport
            ))

    def check_private_to_private_unusual(self, src: str, dst: str, dport: int) -> None:
        """Flag internal lateral movement on sensitive ports."""
        LATERAL_PORTS = {22, 3389, 445, 135, 5900}
        if self._is_private(src) and self._is_private(dst) and dport in LATERAL_PORTS:
            svc = PORT_SERVICES.get(dport, str(dport))
            self._add_alert(self._new_alert(
                "MEDIUM", "LATERAL_MOVEMENT",
                src, dst, "TCP",
                f"Internal lateral movement via {svc} (port {dport})",
                port=dport
            ))

    # ── Main dispatch ─────────────────────────────────────────────────────────

    def analyze(self, pkt) -> Optional[PacketRecord]:
        """Analyze one packet, update stats, return a PacketRecord."""
        try:
            proto = "?"
            src = dst = "?"
            sport = dport = 0
            flags = ""
            length = len(pkt)
            info = ""

            # ── Layer 3 ───────────────────────────────────────────────────
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst

            # ── Layer 4 / Application ─────────────────────────────────────
            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                raw_flags = pkt[TCP].flags
                flags = str(raw_flags)

                # Determine application layer
                if dport in (80, 8080) or sport in (80, 8080):
                    proto = "HTTP"
                elif dport in (443, 8443) or sport in (443, 8443):
                    proto = "HTTPS"
                elif dport == 53 or sport == 53:
                    proto = "DNS"

                info = PORT_SERVICES.get(dport, PORT_SERVICES.get(sport, ""))

                # Detection checks
                if src != "?":
                    self.check_blocklist(src, dst, proto, pkt)
                    self.check_syn_flood(src, dst, flags, dport)
                    self.check_port_scan(src, dst, dport, flags)
                    self.check_suspicious_port(src, dst, dport, proto)
                    self.check_null_xmas_scan(src, dst, flags, dport)
                    self.check_private_to_private_unusual(src, dst, dport)

            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                info = PORT_SERVICES.get(dport, PORT_SERVICES.get(sport, ""))

                if pkt.haslayer(DNS):
                    proto = "DNS"
                    if src != "?":
                        self.check_dns_anomaly(src, dst, pkt)
                elif src != "?":
                    self.check_blocklist(src, dst, proto, pkt)
                    self.check_suspicious_port(src, dst, dport, proto)

            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                if src != "?":
                    self.check_icmp_flood(src, dst)
                    self.check_blocklist(src, dst, proto, pkt)

            elif pkt.haslayer(ARP):
                proto = "ARP"
                self.check_arp_spoofing(pkt)

            # ── Update global stats ───────────────────────────────────────
            with self.lock:
                self.stats.total_packets += 1
                self.stats.proto_counts[proto] += 1
                self.stats.bytes_in += length
                if src != "?":
                    self.stats.top_talkers[src] += 1
                if dst != "?":
                    self.stats.top_targets[dst] += 1
                if dport:
                    self.stats.port_hits[dport] += 1

            return PacketRecord(
                timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                src_ip=src,
                dst_ip=dst,
                proto=proto,
                length=length,
                sport=sport,
                dport=dport,
                flags=flags,
                info=info,
            )

        except Exception:
            return None


# ─────────────────────────────────────────────────────────────────────────────
#  DEMO TRAFFIC GENERATOR  (when --demo flag is used)
# ─────────────────────────────────────────────────────────────────────────────

class DemoTrafficGenerator:
    """Synthesizes realistic + attack packets for demo mode (no root needed)."""

    NORMAL_IPS = [
        "192.168.1.10", "192.168.1.25", "192.168.1.30",
        "10.0.0.5", "10.0.0.20", "172.16.0.8",
    ]
    ATTACK_IPS = [
        "185.220.101.42", "45.33.32.156", "198.199.88.15",
        "89.248.167.77", "193.32.127.201",
    ]
    EXTERNAL_IPS = [
        "8.8.8.8", "1.1.1.1", "208.67.222.222",
        "93.184.216.34", "151.101.193.69",
    ]

    def __init__(self, engine: DetectionEngine, packet_log: list, lock: threading.Lock):
        self.engine = engine
        self.packet_log = packet_log
        self.lock = lock
        self._running = False
        self._thread = None

    def _make_pkt(self, src, dst, proto="TCP", sport=1024, dport=80,
                  flags="S", icmp_type=8, arp_op=1,
                  src_mac="aa:bb:cc:dd:ee:ff",
                  payload_len=64):
        """Create a minimal Scapy packet for demo simulation."""
        from scapy.all import Ether, Raw
        base = IP(src=src, dst=dst)
        if proto == "TCP":
            return base / TCP(sport=sport, dport=dport, flags=flags) / Raw(b"X" * payload_len)
        elif proto == "UDP":
            return base / UDP(sport=sport, dport=dport) / Raw(b"X" * payload_len)
        elif proto == "ICMP":
            return base / ICMP(type=icmp_type) / Raw(b"X" * payload_len)
        elif proto == "ARP":
            return Ether(src=src_mac) / ARP(op=arp_op, psrc=src, pdst=dst, hwsrc=src_mac)
        elif proto == "DNS":
            qname = b"example.com."
            dns_payload = DNS(rd=1, qd=None)
            return base / UDP(sport=sport, dport=53) / Raw(b"X" * 20)
        return base / Raw(b"X" * payload_len)

    def _emit(self, pkt):
        rec = self.engine.analyze(pkt)
        if rec:
            with self.lock:
                self.packet_log.append(rec)
                if len(self.packet_log) > 500:
                    self.packet_log.pop(0)

    def _run(self):
        # Scenario schedule: (delay, generator_func)
        scenarios = [
            (0.0,  self._normal_burst),
            (3.0,  self._syn_flood_attack),
            (6.0,  self._normal_burst),
            (9.0,  self._port_scan_attack),
            (12.0, self._normal_burst),
            (15.0, self._icmp_flood_attack),
            (18.0, self._normal_burst),
            (21.0, self._arp_spoof_attack),
            (24.0, self._normal_burst),
            (27.0, self._blocklist_hit),
            (30.0, self._normal_burst),
            (33.0, self._lateral_movement),
            (36.0, self._normal_burst),
            (39.0, self._dns_flood_attack),
        ]

        start = time.time()
        scenario_idx = 0
        cycle_offset = 0.0
        CYCLE = 42.0

        while self._running:
            now = time.time() - start
            cycle_t = (now % CYCLE)

            # Run next scenario if due
            if scenario_idx < len(scenarios):
                due = scenarios[scenario_idx][0]
                if cycle_t >= due or cycle_t >= CYCLE - 0.1:
                    scenarios[scenario_idx][1]()
                    scenario_idx = (scenario_idx + 1) % len(scenarios)
                    if scenario_idx == 0:
                        pass  # cycle reset handled by mod

            # Always drip normal traffic
            self._normal_drip()
            time.sleep(random.uniform(0.05, 0.2))

    def _normal_drip(self):
        """Background normal traffic."""
        src = random.choice(self.NORMAL_IPS)
        dst = random.choice(self.EXTERNAL_IPS + self.NORMAL_IPS)
        proto = random.choice(["TCP", "TCP", "TCP", "UDP", "ICMP"])
        dport = random.choice([80, 443, 53, 22, 8080, 443, 443])
        sport = random.randint(1024, 65000)
        if proto == "TCP":
            flags = random.choice(["S", "SA", "A", "PA", "FA"])
            self._emit(self._make_pkt(src, dst, "TCP", sport, dport, flags))
        elif proto == "UDP":
            self._emit(self._make_pkt(src, dst, "UDP", sport, dport))
        elif proto == "ICMP":
            self._emit(self._make_pkt(src, dst, "ICMP"))

    def _normal_burst(self):
        for _ in range(random.randint(5, 15)):
            self._normal_drip()
            time.sleep(0.02)

    def _syn_flood_attack(self):
        """Simulate SYN flood from attacker."""
        attacker = random.choice(self.ATTACK_IPS)
        victim = random.choice(self.NORMAL_IPS)
        for _ in range(35):
            sport = random.randint(1024, 65000)
            self._emit(self._make_pkt(attacker, victim, "TCP", sport, 80, "S"))
            time.sleep(0.03)

    def _port_scan_attack(self):
        """Simulate port scan (many different ports)."""
        attacker = random.choice(self.ATTACK_IPS)
        victim = random.choice(self.NORMAL_IPS)
        ports = random.sample(range(1, 10000), 25)
        for dport in ports:
            self._emit(self._make_pkt(attacker, victim, "TCP",
                                      random.randint(1024, 65000), dport, "S"))
            time.sleep(0.04)

    def _icmp_flood_attack(self):
        """Simulate ICMP flood."""
        attacker = random.choice(self.ATTACK_IPS)
        victim = random.choice(self.NORMAL_IPS)
        for _ in range(40):
            self._emit(self._make_pkt(attacker, victim, "ICMP"))
            time.sleep(0.02)

    def _arp_spoof_attack(self):
        """Simulate ARP cache poisoning."""
        from scapy.all import Ether, ARP as ScapyARP
        victim_ip = random.choice(self.NORMAL_IPS)
        spoofer_mac = "de:ad:be:ef:ca:fe"
        # First, register legitimate mapping
        legit = self._make_pkt(victim_ip, "192.168.1.1", "ARP",
                               src_mac="aa:bb:cc:11:22:33", arp_op=2)
        self._emit(legit)
        time.sleep(0.5)
        # Then spoof with different MAC
        spoof = self._make_pkt(victim_ip, "192.168.1.1", "ARP",
                               src_mac=spoofer_mac, arp_op=2)
        self._emit(spoof)

    def _blocklist_hit(self):
        """Simulate connection from blacklisted IP."""
        attacker = random.choice(self.ATTACK_IPS)
        victim = random.choice(self.NORMAL_IPS)
        for port in [80, 443, 22]:
            self._emit(self._make_pkt(attacker, victim, "TCP",
                                      random.randint(1024, 65000), port, "S"))
            time.sleep(0.1)

    def _lateral_movement(self):
        """Simulate internal lateral movement."""
        src = random.choice(self.NORMAL_IPS)
        targets = [ip for ip in self.NORMAL_IPS if ip != src]
        for dst in random.sample(targets, min(3, len(targets))):
            for port in [445, 3389, 22]:
                self._emit(self._make_pkt(src, dst, "TCP",
                                          random.randint(1024, 65000), port, "S"))
                time.sleep(0.05)

    def _dns_flood_attack(self):
        """Simulate DNS flood."""
        attacker = random.choice(self.ATTACK_IPS)
        dns_server = "8.8.8.8"
        for _ in range(60):
            self._emit(self._make_pkt(attacker, dns_server, "DNS",
                                      random.randint(1024, 65000), 53))
            time.sleep(0.02)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False


# ─────────────────────────────────────────────────────────────────────────────
#  DASHBOARD RENDERER
# ─────────────────────────────────────────────────────────────────────────────

class Dashboard:
    def __init__(self, stats: Stats, alerts: list, packet_log: list, lock: threading.Lock, demo: bool):
        self.stats = stats
        self.alerts = alerts
        self.packet_log = packet_log
        self.lock = lock
        self.demo = demo

    # ── Header ────────────────────────────────────────────────────────────────
    def _header(self) -> Panel:
        elapsed = int(time.time() - self.stats.start_time)
        h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
        mode = "[bold yellow]⚠ DEMO MODE[/]" if self.demo else "[bold green]● LIVE[/]"
        title = Text.assemble(
            ("  PyIDS ", "bold white"),
            ("│ ", "dim white"),
            ("Intrusion Detection System ", "bold cyan"),
            ("│ ", "dim white"),
            (f"Uptime: {h:02d}:{m:02d}:{s:02d} ", "dim white"),
            ("│ ", "dim white"),
        )
        title.append_text(Text.from_markup(mode))
        return Panel(Align.center(title), style="bold blue", height=3)

    # ── Stats row ─────────────────────────────────────────────────────────────
    def _stats_row(self) -> Table:
        with self.lock:
            pkts  = self.stats.total_packets
            alerts = self.stats.alerts_total
            crit  = self.stats.alerts_by_sev["CRITICAL"]
            high  = self.stats.alerts_by_sev["HIGH"]
            med   = self.stats.alerts_by_sev["MEDIUM"]
            low   = self.stats.alerts_by_sev["LOW"]
            kb    = self.stats.bytes_in / 1024
            blocked = len(self.stats.blocked_ips)

        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)

        def stat_card(value, label, style):
            t = Table.grid()
            t.add_column(justify="center")
            t.add_row(Text(str(value), style=f"bold {style}", justify="center"))
            t.add_row(Text(label, style="dim white", justify="center"))
            return Panel(t, style=style, padding=(0, 1))

        grid.add_row(
            stat_card(pkts,    "PACKETS",   "white"),
            stat_card(alerts,  "ALERTS",    "yellow"),
            stat_card(crit,    "CRITICAL",  "red"),
            stat_card(high,    "HIGH",      "orange3"),
            stat_card(med,     "MEDIUM",    "yellow"),
            stat_card(low,     "LOW",       "cyan"),
            stat_card(f"{kb:.1f}k", "BYTES RX", "green"),
            stat_card(blocked, "BLOCKED",   "magenta"),
        )
        return grid

    # ── Alerts table ──────────────────────────────────────────────────────────
    def _alerts_table(self) -> Panel:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold white",
            expand=True,
            show_edge=False,
        )
        table.add_column("#",       style="dim white",  width=4,  no_wrap=True)
        table.add_column("TIME",    style="dim white",  width=10, no_wrap=True)
        table.add_column("SEV",     width=10, no_wrap=True)
        table.add_column("RULE",    style="bold white", width=22, no_wrap=True)
        table.add_column("SRC IP",  style="cyan",       width=16, no_wrap=True)
        table.add_column("DST IP",  style="green",      width=16, no_wrap=True)
        table.add_column("PROTO",   width=7, no_wrap=True)
        table.add_column("DETAIL",  style="dim white")

        with self.lock:
            recent = list(reversed(self.alerts))[:14]

        for a in recent:
            style = SEVERITY_STYLE.get(a.severity, "white")
            icon  = SEVERITY_ICON.get(a.severity, "")
            proto_style = PROTO_STYLE.get(a.proto, "white")
            table.add_row(
                str(a.id),
                a.timestamp,
                Text(f"{icon} {a.severity}", style=style),
                a.rule,
                a.src_ip,
                a.dst_ip,
                Text(a.proto, style=proto_style),
                a.detail,
            )

        return Panel(table, title="[bold red]🚨 Alerts[/]", border_style="red", padding=(0, 1))

    # ── Packet log ────────────────────────────────────────────────────────────
    def _packet_log(self) -> Panel:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold white",
            expand=True,
            show_edge=False,
        )
        table.add_column("TIME",   style="dim white", width=14, no_wrap=True)
        table.add_column("PROTO",  width=7,  no_wrap=True)
        table.add_column("SRC",    style="cyan",  width=21, no_wrap=True)
        table.add_column("DST",    style="green", width=21, no_wrap=True)
        table.add_column("FLAGS",  style="yellow", width=8, no_wrap=True)
        table.add_column("LEN",    style="dim white", width=6, no_wrap=True, justify="right")
        table.add_column("SERVICE",style="dim white", width=12, no_wrap=True)

        with self.lock:
            recent = list(reversed(self.packet_log))[:12]

        for p in recent:
            proto_style = PROTO_STYLE.get(p.proto, "white")
            src = f"{p.src_ip}:{p.sport}" if p.sport else p.src_ip
            dst = f"{p.dst_ip}:{p.dport}" if p.dport else p.dst_ip
            table.add_row(
                p.timestamp,
                Text(p.proto, style=proto_style),
                src[:20],
                dst[:20],
                p.flags[:7] if p.flags else "-",
                str(p.length),
                p.info[:11] if p.info else "-",
            )

        return Panel(table, title="[bold green]📡 Live Packet Stream[/]",
                     border_style="green", padding=(0, 1))

    # ── Protocol chart ────────────────────────────────────────────────────────
    def _proto_chart(self) -> Panel:
        with self.lock:
            counts = dict(self.stats.proto_counts)
        total = max(sum(counts.values()), 1)
        protos = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:8]

        rows = []
        for proto, count in protos:
            pct = count / total
            bar_width = int(pct * 24)
            style = PROTO_STYLE.get(proto, "white")
            bar = "█" * bar_width + "░" * (24 - bar_width)
            rows.append(
                Text.assemble(
                    (f"{proto:<7}", style),
                    (" ", ""),
                    (bar, style),
                    (f"  {count:>5}  ", "white"),
                    (f"{pct*100:5.1f}%", "dim white"),
                )
            )

        content = Text("\n").join(rows) if rows else Text("No data yet", style="dim white")
        return Panel(content, title="[bold cyan]📊 Protocol Breakdown[/]",
                     border_style="cyan", padding=(0, 1))

    # ── Top talkers ───────────────────────────────────────────────────────────
    def _top_talkers(self) -> Panel:
        with self.lock:
            talkers = sorted(self.stats.top_talkers.items(),
                             key=lambda x: x[1], reverse=True)[:8]
        table = Table(box=box.SIMPLE, show_header=False, expand=True, show_edge=False, padding=(0, 1))
        table.add_column("IP",    style="cyan")
        table.add_column("COUNT", style="yellow", justify="right")
        table.add_column("BAR")

        if not talkers:
            table.add_row("—", "0", "")
        else:
            max_c = talkers[0][1] or 1
            for ip, cnt in talkers:
                bar_w = int((cnt / max_c) * 16)
                table.add_row(ip, str(cnt), Text("█" * bar_w, style="cyan"))

        return Panel(table, title="[bold cyan]🔝 Top Talkers[/]",
                     border_style="cyan", padding=(0, 1))

    # ── Top targeted ports ────────────────────────────────────────────────────
    def _top_ports(self) -> Panel:
        with self.lock:
            ports = sorted(self.stats.port_hits.items(),
                           key=lambda x: x[1], reverse=True)[:8]
        table = Table(box=box.SIMPLE, show_header=False, expand=True, show_edge=False, padding=(0, 1))
        table.add_column("PORT/SVC", style="green")
        table.add_column("HITS",     style="yellow", justify="right")
        table.add_column("BAR")

        if not ports:
            table.add_row("—", "0", "")
        else:
            max_c = ports[0][1] or 1
            for port, cnt in ports:
                svc = PORT_SERVICES.get(port, "")
                label = f"{port}/{svc}" if svc else str(port)
                bar_w = int((cnt / max_c) * 16)
                table.add_row(label, str(cnt), Text("█" * bar_w, style="green"))

        return Panel(table, title="[bold green]🎯 Top Target Ports[/]",
                     border_style="green", padding=(0, 1))

    # ── Alert severity breakdown ──────────────────────────────────────────────
    def _sev_breakdown(self) -> Panel:
        with self.lock:
            sev = dict(self.stats.alerts_by_sev)
        total = max(sum(sev.values()), 1)
        lines = []
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = sev.get(s, 0)
            pct = cnt / total
            bar_w = int(pct * 18)
            style = SEVERITY_STYLE[s]
            icon  = SEVERITY_ICON[s]
            lines.append(Text.assemble(
                (f"{icon} {s:<9}", style),
                ("█" * bar_w + "░" * (18 - bar_w), style),
                (f"  {cnt:>4}", "white"),
            ))
        content = Text("\n").join(lines)
        return Panel(content, title="[bold yellow]⚡ Alert Severity[/]",
                     border_style="yellow", padding=(0, 1))

    # ── Blocked IPs ───────────────────────────────────────────────────────────
    def _blocked_ips(self) -> Panel:
        with self.lock:
            blocked = list(self.stats.blocked_ips)[:8]
        table = Table(box=box.SIMPLE, show_header=False, expand=True, show_edge=False, padding=(0, 1))
        table.add_column("IP", style="red")
        table.add_column("STATUS", style="dim white")
        if not blocked:
            table.add_row("None detected", "")
        else:
            for ip in blocked:
                table.add_row(ip, "🚫 BLOCKED")
        return Panel(table, title="[bold red]🚫 Blocked IPs[/]",
                     border_style="red", padding=(0, 1))

    # ── Footer ────────────────────────────────────────────────────────────────
    def _footer(self) -> Panel:
        keys = Text.assemble(
            ("  Q", "bold yellow"), ("/", "dim white"), ("Ctrl+C", "bold yellow"),
            ("  Quit  ", "dim white"),
            ("│  ", "dim white"),
            ("PyIDS v1.0", "bold cyan"),
            ("  │  Powered by ", "dim white"),
            ("Scapy", "bold green"),
            (" + ", "dim white"),
            ("Rich", "bold magenta"),
        )
        return Panel(Align.center(keys), style="dim blue", height=3)

    # ── Full layout ───────────────────────────────────────────────────────────
    def build(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header",  size=3),
            Layout(name="stats",   size=5),
            Layout(name="main",    ratio=1),
            Layout(name="bottom",  ratio=1),
            Layout(name="footer",  size=3),
        )
        layout["header"].update(self._header())
        layout["stats"].update(self._stats_row())

        # Main row: alerts (wide) + side panels
        layout["main"].split_row(
            Layout(name="alerts",   ratio=3),
            Layout(name="side_top", ratio=1),
        )
        layout["main"]["alerts"].update(self._alerts_table())
        layout["main"]["side_top"].split_column(
            Layout(self._sev_breakdown()),
            Layout(self._blocked_ips()),
        )

        # Bottom row: packet log + charts
        layout["bottom"].split_row(
            Layout(name="packets", ratio=3),
            Layout(name="charts",  ratio=1),
        )
        layout["bottom"]["packets"].update(self._packet_log())
        layout["bottom"]["charts"].split_column(
            Layout(self._proto_chart()),
            Layout(self._top_talkers()),
            Layout(self._top_ports()),
        )

        layout["footer"].update(self._footer())
        return layout


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="PyIDS — Python Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 ids.py                    # Live capture on default interface
  sudo python3 ids.py --iface eth0       # Live capture on specific interface
       python3 ids.py --demo             # Demo mode (no root required)
  sudo python3 ids.py --iface wlan0 --filter "tcp"
        """
    )
    parser.add_argument("--iface", "-i", default=None,
                        help="Network interface to capture on (default: auto)")
    parser.add_argument("--filter", "-f", default=None,
                        help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("--demo", action="store_true",
                        help="Run in demo mode with simulated traffic (no root needed)")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="List available network interfaces and exit")
    return parser.parse_args()

import os,platform

OS = platform.system()  # "Windows" | "Linux" | "Darwin"

def main():
    args = parse_args()

    if args.list_ifaces:
        console = Console()
        console.print("\n[bold cyan]Available network interfaces:[/]\n")
        for iface in get_if_list():
            console.print(f"  [green]•[/] {iface}")
        console.print()
        sys.exit(0)

    # Check for root if not in demo mode
    import ctypes
    if not args.demo and not ctypes.windll.shell32.IsUserAnAdmin():
        console = Console()
        console.print("\n[bold red]Error:[/] Root privileges required for live packet capture.")
        console.print("[dim]Run with [bold]sudo python3 ids.py[/] or use [bold]--demo[/] mode.[/]\n")
        sys.exit(1)

    elif OS != "Windows" and not args.demo and os.geteuid() != 0:
        console = Console()
        console.print("\n[bold red]Error:[/] Root privileges required for live packet capture.")
        console.print("[dim]Run with [bold]sudo python3 ids.py[/] or use [bold]--demo[/] mode.[/]\n")
        sys.exit(1)

    # ── Shared state ──────────────────────────────────────────────────────────
    lock       = threading.Lock()
    stats      = Stats()
    alerts     = []
    packet_log = []

    engine    = DetectionEngine(stats, alerts, lock)
    dashboard = Dashboard(stats, alerts, packet_log, lock, args.demo)

    console = Console()
    running = threading.Event()
    running.set()

    def handle_exit(sig, frame):
        running.clear()

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # ── Packet callback (for live mode) ───────────────────────────────────────
    def pkt_callback(pkt):
        if not running.is_set():
            return
        rec = engine.analyze(pkt)
        if rec:
            with lock:
                packet_log.append(rec)
                if len(packet_log) > 500:
                    packet_log.pop(0)

    # ── Start capture / demo ──────────────────────────────────────────────────
    generator = None

    if args.demo:
        generator = DemoTrafficGenerator(engine, packet_log, lock)
        generator.start()
        mode_str = "[bold yellow]DEMO MODE[/] — simulated attack traffic"
    else:
        iface = args.iface
        bpf   = args.filter or ""

        def _sniff():
            try:
                sniff(
                    iface=iface,
                    filter=bpf,
                    prn=pkt_callback,
                    store=False,
                    stop_filter=lambda _: not running.is_set(),
                )
            except Exception as e:
                console.print(f"\n[red]Sniff error:[/] {e}")
                running.clear()

        sniff_thread = threading.Thread(target=_sniff, daemon=True)
        sniff_thread.start()
        iface_str = iface or "default"
        mode_str = f"[bold green]LIVE[/] on [cyan]{iface_str}[/]"
        if bpf:
            mode_str += f"  filter: [yellow]{bpf}[/]"

    console.print(f"\n[bold cyan]PyIDS[/] started — {mode_str}\n")

    # ── Live dashboard loop ───────────────────────────────────────────────────
    try:
        with Live(
            dashboard.build(),
            console=console,
            refresh_per_second=4,
            screen=True,
        ) as live:
            while running.is_set():
                live.update(dashboard.build())
                time.sleep(0.25)
    except Exception as e:
        running.clear()
        console.print(f"\n[red]Dashboard error:[/] {e}")
        raise

    # ── Shutdown ──────────────────────────────────────────────────────────────
    if generator:
        generator.stop()

    console.print("\n[bold cyan]PyIDS[/] stopped.")

    # Summary
    console.print(f"\n[bold white]Session Summary[/]")
    console.print(f"  Packets captured : [cyan]{stats.total_packets}[/]")
    console.print(f"  Total alerts     : [yellow]{stats.alerts_total}[/]")
    console.print(f"  Critical alerts  : [red]{stats.alerts_by_sev['CRITICAL']}[/]")
    console.print(f"  High alerts      : [orange3]{stats.alerts_by_sev['HIGH']}[/]")
    console.print(f"  IPs blocked      : [magenta]{len(stats.blocked_ips)}[/]")
    console.print(f"  Data seen        : [green]{stats.bytes_in/1024:.1f} KB[/]\n")


if __name__ == "__main__":
    main()