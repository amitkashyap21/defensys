#!/usr/bin/env python3
"""
DefenSys — Module 2: Network & Firewall Security Auditor
Lead Maintainer: Member 2 (Network & Firewall Security Lead)
Target Architecture: Linux / RHEL / Debian / Kali (Python 3 + Bash)

Scope & Capabilities:
- Deep socket inspection (ss -tlpn, ss -ulpn) identifying listening services,
  protocols, PIDs, and process names.
- Interface binding analysis detecting dangerous wildcard exposures (0.0.0.0, [::])
  vs. restricted loopback bindings (127.0.0.1, ::1).
- Detection of sensitive databases/caches and legacy plaintext protocols exposed
  to untrusted network interfaces.
- Interface discovery via 'ip addr' / 'ip -j addr'.
"""

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# Configure logging
logger = logging.getLogger("defensys.module2")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [Module-2:Network] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# Well-known insecure/cleartext ports and descriptions
INSECURE_PROTOCOLS: Dict[int, Dict[str, str]] = {
    21: {"name": "FTP", "desc": "Unencrypted File Transfer Protocol (plaintext credentials)", "severity": "HIGH"},
    23: {"name": "Telnet", "desc": "Unencrypted Telnet remote shell (plaintext transmission)", "severity": "CRITICAL"},
    69: {"name": "TFTP", "desc": "Trivial File Transfer Protocol without authentication", "severity": "HIGH"},
    80: {"name": "HTTP", "desc": "Unencrypted Hypertext Transfer Protocol (cleartext web traffic)", "severity": "MEDIUM"},
    110: {"name": "POP3", "desc": "Unencrypted Post Office Protocol v3", "severity": "MEDIUM"},
    143: {"name": "IMAP", "desc": "Unencrypted Internet Message Access Protocol", "severity": "MEDIUM"},
    512: {"name": "rexec", "desc": "Legacy BSD remote execution service", "severity": "CRITICAL"},
    513: {"name": "rlogin", "desc": "Legacy BSD remote login service", "severity": "CRITICAL"},
    514: {"name": "rsh", "desc": "Legacy BSD remote shell service", "severity": "CRITICAL"},
    5900: {"name": "VNC", "desc": "Unencrypted Virtual Network Computing remote desktop", "severity": "HIGH"},
    5901: {"name": "VNC:1", "desc": "Unencrypted Virtual Network Computing remote desktop display 1", "severity": "HIGH"},
}

# Sensitive internal database and caching ports that must never be bound to wildcard
SENSITIVE_SERVICES: Dict[int, Dict[str, str]] = {
    3306: {"name": "MySQL/MariaDB", "desc": "Relational Database exposed without perimeter isolation", "severity": "HIGH"},
    5432: {"name": "PostgreSQL", "desc": "PostgreSQL Database exposed on wildcard interface", "severity": "HIGH"},
    6379: {"name": "Redis", "desc": "In-memory datastore frequently targeted for unauthenticated RCE", "severity": "CRITICAL"},
    11211: {"name": "Memcached", "desc": "Memcached cache exposed (amplification DDoS / data leak risk)", "severity": "HIGH"},
    27017: {"name": "MongoDB", "desc": "NoSQL Database exposed to external network", "severity": "CRITICAL"},
    9200: {"name": "Elasticsearch", "desc": "Search engine API exposed without authentication", "severity": "HIGH"},
    2375: {"name": "Docker Daemon", "desc": "Unencrypted Docker REST API allowing root host takeover", "severity": "CRITICAL"},
    2379: {"name": "etcd", "desc": "Distributed key-value store cluster API exposed", "severity": "HIGH"},
    9092: {"name": "Apache Kafka", "desc": "Message broker broker port exposed", "severity": "MEDIUM"},
}


@dataclass
class ListeningSocket:
    """Represents an active listening network socket."""
    protocol: str              # 'tcp' or 'udp'
    local_address: str         # '0.0.0.0', '127.0.0.1', '::', '192.168.1.5'
    local_port: int            # e.g., 22, 80, 3306
    process_name: str          # e.g., 'sshd', 'mysqld', 'nginx'
    pid: Optional[int] = None  # e.g., 842
    raw_info: str = ""

    @property
    def is_wildcard(self) -> bool:
        """Returns True if socket is bound to all network interfaces (0.0.0.0, ::, *)."""
        addr = self.local_address.strip()
        return addr in {"0.0.0.0", "::", "*", "[::]", "0:0:0:0:0:0:0:0"}

    @property
    def is_loopback(self) -> bool:
        """Returns True if socket is strictly bound to localhost (127.x.x.x, ::1)."""
        addr = self.local_address.strip()
        if addr in {"127.0.0.1", "::1", "[::1]"}:
            return True
        if addr.startswith("127."):
            return True
        return False

    @property
    def is_exposed(self) -> bool:
        """Returns True if socket is accessible externally (wildcard or non-loopback IP)."""
        return not self.is_loopback


@dataclass
class NetworkInterface:
    """Represents a network interface on the host."""
    name: str
    ip_addresses: List[str] = field(default_factory=list)
    is_up: bool = True
    is_loopback: bool = False


class NetworkAuditor:
    """
    Core auditing engine for socket utilities, interface bindings,
    and listening services across Linux distributions.
    """

    def __init__(self, mock_mode: bool = False, mock_sockets: Optional[List[ListeningSocket]] = None):
        self.mock_mode = mock_mode
        self._mock_sockets = mock_sockets or []

    def run_cmd(self, cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
        """Executes a system shell command safely with timeout handling."""
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return res.returncode, res.stdout, res.stderr
        except FileNotFoundError:
            logger.debug(f"Command not found: {cmd[0]}")
            return 127, "", f"Command '{cmd[0]}' not found"
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {' '.join(cmd)}")
            return 124, "", "Command timed out"
        except Exception as e:
            logger.error(f"Error executing {' '.join(cmd)}: {e}")
            return 1, "", str(e)

    def get_network_interfaces(self) -> List[NetworkInterface]:
        """Discovers network interfaces and assigned IP addresses via 'ip addr'."""
        interfaces: List[NetworkInterface] = []
        if self.mock_mode:
            return [
                NetworkInterface(name="lo", ip_addresses=["127.0.0.1", "::1"], is_up=True, is_loopback=True),
                NetworkInterface(name="eth0", ip_addresses=["192.168.122.50"], is_up=True, is_loopback=False),
            ]

        # Attempt JSON output first with 'ip -j addr'
        code, stdout, _ = self.run_cmd(["ip", "-j", "addr"])
        if code == 0 and stdout.strip():
            try:
                data = json.loads(stdout)
                for item in data:
                    ifname = item.get("ifname", "")
                    flags = item.get("flags", [])
                    is_up = "UP" in flags
                    is_lo = "LOOPBACK" in flags or ifname == "lo"
                    ips = []
                    for addr_info in item.get("addr_info", []):
                        local_ip = addr_info.get("local")
                        if local_ip:
                            ips.append(local_ip)
                    interfaces.append(NetworkInterface(name=ifname, ip_addresses=ips, is_up=is_up, is_loopback=is_lo))
                return interfaces
            except json.JSONDecodeError:
                pass

        # Fallback to standard 'ip addr' text parsing
        code, stdout, _ = self.run_cmd(["ip", "addr"])
        if code == 0 and stdout.strip():
            current_iface: Optional[NetworkInterface] = None
            for line in stdout.splitlines():
                match_iface = re.match(r"^\d+:\s+([^:]+):.*<([^>]+)>", line)
                if match_iface:
                    if current_iface:
                        interfaces.append(current_iface)
                    ifname = match_iface.group(1).split("@")[0].strip()
                    flags = match_iface.group(2).split(",")
                    is_up = "UP" in flags
                    is_lo = "LOOPBACK" in flags or ifname == "lo"
                    current_iface = NetworkInterface(name=ifname, is_up=is_up, is_loopback=is_lo)
                    continue

                if current_iface:
                    match_inet = re.search(r"inet6?\s+([0-9a-fA-F:.]+)(?:/\d+)?", line)
                    if match_inet:
                        ip_val = match_inet.group(1).split("/")[0]
                        current_iface.ip_addresses.append(ip_val)

            if current_iface:
                interfaces.append(current_iface)

        return interfaces

    def parse_ss_line(self, line: str, proto: str) -> Optional[ListeningSocket]:
        """
        Parses a single line of 'ss -tlpn' or 'ss -ulpn' output.
        Example:
        LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=842,fd=3))
        LISTEN 0 128 [::]:22    [::]:*    users:(("sshd",pid=842,fd=4))
        """
        line = line.strip()
        if not line or line.startswith("State") or line.startswith("Netid"):
            return None

        parts = line.split()
        if len(parts) < 4:
            return None

        # Look for local address:port column (typically index 3 or 4 depending on State column)
        local_col = ""
        process_col = ""

        # In ss output with LISTEN state:
        # State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port, Process
        for idx, part in enumerate(parts):
            if ":" in part and not part.startswith("users:"):
                local_col = part
                # The process information usually comes in later columns
                process_col = " ".join(parts[idx + 2:]) if len(parts) > idx + 2 else ""
                break

        if not local_col:
            return None

        # Parse address and port
        # Formats: 0.0.0.0:22, [::]:22, :::22, *:80, 127.0.0.1:3306, [::1]:8080
        local_address = "0.0.0.0"
        local_port = 0

        try:
            if local_col.startswith("["):
                # IPv6 bracket notation: [::]:22 or [fe80::...]:80
                bracket_end = local_col.rfind("]")
                if bracket_end != -1:
                    local_address = local_col[1:bracket_end]
                    port_str = local_col[bracket_end + 2:]
                    local_port = int(port_str)
            elif local_col.count(":") > 1:
                # Raw IPv6 notation: :::22 or fe80::1:80
                last_colon = local_col.rfind(":")
                local_address = local_col[:last_colon]
                local_port = int(local_col[last_colon + 1:])
            else:
                # IPv4 or wildcard: 0.0.0.0:22 or *:80
                addr_part, port_part = local_col.rsplit(":", 1)
                local_address = addr_part if addr_part != "*" else "0.0.0.0"
                local_port = int(port_part)
        except (ValueError, IndexError):
            return None

        # Parse process name and PID from users:(("sshd",pid=842,fd=3))
        process_name = "unknown"
        pid = None

        if process_col:
            name_match = re.search(r'"([^"]+)"', process_col)
            if name_match:
                process_name = name_match.group(1)

            pid_match = re.search(r'pid=(\d+)', process_col)
            if pid_match:
                pid = int(pid_match.group(1))

        return ListeningSocket(
            protocol=proto,
            local_address=local_address,
            local_port=local_port,
            process_name=process_name,
            pid=pid,
            raw_info=line,
        )

    def get_listening_sockets(self) -> List[ListeningSocket]:
        """
        Executes cross-distro socket utilities ('ss -tlpn', 'ss -ulpn')
        to discover all active listening sockets.
        """
        if self.mock_mode:
            return list(self._mock_sockets)

        sockets: List[ListeningSocket] = []

        # 1. TCP Listening sockets
        code, stdout, _ = self.run_cmd(["ss", "-tlpn"])
        if code == 0:
            for line in stdout.splitlines():
                sock = self.parse_ss_line(line, "tcp")
                if sock:
                    sockets.append(sock)
        else:
            # Fallback without -p if permission denied or non-root
            code_np, stdout_np, _ = self.run_cmd(["ss", "-tln"])
            if code_np == 0:
                for line in stdout_np.splitlines():
                    sock = self.parse_ss_line(line, "tcp")
                    if sock:
                        sockets.append(sock)

        # 2. UDP Listening sockets
        code, stdout, _ = self.run_cmd(["ss", "-ulpn"])
        if code == 0:
            for line in stdout.splitlines():
                sock = self.parse_ss_line(line, "udp")
                if sock:
                    sockets.append(sock)
        else:
            code_np, stdout_np, _ = self.run_cmd(["ss", "-uln"])
            if code_np == 0:
                for line in stdout_np.splitlines():
                    sock = self.parse_ss_line(line, "udp")
                    if sock:
                        sockets.append(sock)

        return sockets

    def audit_socket_exposures(self, sockets: List[ListeningSocket]) -> List[Dict[str, Any]]:
        """
        Audits listening sockets for dangerous bindings and cleartext/database exposures.
        Generates findings adhering to the DefenSys schema contract.
        """
        findings: List[Dict[str, Any]] = []

        for sock in sockets:
            if not sock.is_exposed:
                continue

            port = sock.local_port
            proto = sock.protocol
            proc = sock.process_name
            addr = sock.local_address

            # Check 1: Insecure / Plaintext Protocol
            if port in INSECURE_PROTOCOLS:
                meta = INSECURE_PROTOCOLS[port]
                findings.append({
                    "rule_id": "NET_FW_003",
                    "module": "module_2",
                    "category": "Insecure Protocols",
                    "check_name": f"Cleartext Protocol Exposed ({meta['name']})",
                    "status": "FAILED",
                    "severity": meta["severity"],
                    "current_value": f"{meta['name']} (Port {port}/{proto}, PID {sock.pid or 'N/A'}) bound to {addr} ({proc})",
                    "expected_value": f"{meta['name']} disabled or migrated to secure encrypted alternative (SSH/TLS)",
                    "target_file": "active_firewall",
                    "remediation_script": "remediate_firewall.sh",
                })

            # Check 2: Sensitive Database or Cache Exposed to Wildcard
            if port in SENSITIVE_SERVICES and sock.is_wildcard:
                meta = SENSITIVE_SERVICES[port]
                findings.append({
                    "rule_id": "NET_FW_002",
                    "module": "module_2",
                    "category": "Network Exposure",
                    "check_name": f"Exposed Database / Cache Service ({meta['name']})",
                    "status": "FAILED",
                    "severity": meta["severity"],
                    "current_value": f"{meta['name']} (Port {port}/{proto}) listening on wildcard {addr} ({proc})",
                    "expected_value": f"Service bound exclusively to 127.0.0.1 or restricted via firewall policy",
                    "target_file": "active_firewall",
                    "remediation_script": "remediate_firewall.sh",
                })

            # Check 3: Wildcard Service Exposure
            if sock.is_wildcard and port not in INSECURE_PROTOCOLS and port not in SENSITIVE_SERVICES:
                # Flag unhardened wildcard services
                severity = "HIGH" if port < 1024 and port != 22 else "MEDIUM"
                findings.append({
                    "rule_id": "NET_FW_005",
                    "module": "module_2",
                    "category": "Network Exposure",
                    "check_name": "Wildcard Network Socket Binding",
                    "status": "FAILED",
                    "severity": severity,
                    "current_value": f"Service '{proc}' listening on {addr}:{port} ({proto.upper()})",
                    "expected_value": "Service bound to specific interface or localhost (127.0.0.1)",
                    "target_file": "active_firewall",
                    "remediation_script": "remediate_firewall.sh",
                })

        return findings


if __name__ == "__main__":
    auditor = NetworkAuditor()
    print("[*] DefenSys Module 2: Network & Socket Auditor (Initialized)")
    sockets = auditor.get_listening_sockets()
    print(f"[*] Discovered {len(sockets)} listening sockets.")
    for s in sockets:
        print(f"    - {s.protocol.upper()} {s.local_address}:{s.local_port} ({s.process_name}) Wildcard={s.is_wildcard}")
