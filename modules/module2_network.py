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
- Dynamic firewall manager detection (firewalld, ufw, nftables, iptables).
- Firewall status & inbound policy auditing (default drop/deny vs permissive accept).
- Correlation between open sockets and firewall rules to identify exposed attack surfaces.
- Generation of structured findings adhering strictly to the DefenSys JSON Data Contract.
- Built-in verification test suite and multi-distro simulation engine.
"""

import argparse
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import unittest
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
    9092: {"name": "Apache Kafka", "desc": "Message broker port exposed", "severity": "MEDIUM"},
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


@dataclass
class FirewallInfo:
    """Represents discovered host firewall manager state and policies."""
    manager: str                       # 'firewalld', 'ufw', 'nftables', 'iptables', 'none'
    is_installed: bool = False
    is_active: bool = False
    is_enabled: bool = False
    default_inbound_policy: str = "UNKNOWN"  # 'DROP', 'REJECT', 'DENY', 'ACCEPT', 'UNKNOWN'
    open_ports: List[str] = field(default_factory=list)        # e.g. ['22/tcp', '80/tcp']
    open_services: List[str] = field(default_factory=list)     # e.g. ['ssh', 'cockpit']
    active_zones: List[str] = field(default_factory=list)      # for firewalld e.g. ['public']
    raw_output: str = ""


class NetworkAuditor:
    """
    Core auditing engine for socket utilities, interface bindings,
    and adaptive firewall auditing across Linux distributions.
    """

    def __init__(
        self,
        mock_mode: bool = False,
        mock_sockets: Optional[List[ListeningSocket]] = None,
        mock_firewall: Optional[FirewallInfo] = None,
    ):
        self.mock_mode = mock_mode
        self._mock_sockets = mock_sockets or []
        self._mock_firewall = mock_firewall

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

    def is_tool_available(self, tool_name: str) -> bool:
        """Checks if a binary executable exists in PATH."""
        return shutil.which(tool_name) is not None

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

        # Look for local address:port column
        local_col = ""
        process_col = ""

        for idx, part in enumerate(parts):
            if ":" in part and not part.startswith("users:"):
                local_col = part
                process_col = " ".join(parts[idx + 2:]) if len(parts) > idx + 2 else ""
                break

        if not local_col:
            return None

        # Parse address and port
        local_address = "0.0.0.0"
        local_port = 0

        try:
            if local_col.startswith("["):
                bracket_end = local_col.rfind("]")
                if bracket_end != -1:
                    local_address = local_col[1:bracket_end]
                    port_str = local_col[bracket_end + 2:]
                    local_port = int(port_str)
            elif local_col.count(":") > 1:
                last_colon = local_col.rfind(":")
                local_address = local_col[:last_colon]
                local_port = int(local_col[last_colon + 1:])
            else:
                addr_part, port_part = local_col.rsplit(":", 1)
                local_address = addr_part if addr_part != "*" else "0.0.0.0"
                local_port = int(port_part)
        except (ValueError, IndexError):
            return None

        # Parse process name and PID
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
            # Fallback without -p if non-root
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

    def detect_firewall_manager(self) -> FirewallInfo:
        """
        Dynamically detects the active firewall manager (firewalld, ufw, nftables, iptables)
        and extracts status, default policies, and open rules.
        """
        if self.mock_mode and self._mock_firewall:
            return self._mock_firewall

        # 1. Test Firewalld (RHEL / CentOS / Fedora / Rocky / Alma)
        if self.is_tool_available("firewall-cmd"):
            info = FirewallInfo(manager="firewalld", is_installed=True)
            code, stdout, _ = self.run_cmd(["firewall-cmd", "--state"])
            info.raw_output = stdout.strip()
            if code == 0 and "running" in stdout:
                info.is_active = True
                _, zone_out, _ = self.run_cmd(["firewall-cmd", "--get-default-zone"])
                def_zone = zone_out.strip() or "public"
                info.active_zones = [def_zone]

                _, srv_out, _ = self.run_cmd(["firewall-cmd", f"--zone={def_zone}", "--list-services"])
                if srv_out.strip():
                    info.open_services = srv_out.strip().split()

                _, prt_out, _ = self.run_cmd(["firewall-cmd", f"--zone={def_zone}", "--list-ports"])
                if prt_out.strip():
                    info.open_ports = prt_out.strip().split()

                info.default_inbound_policy = "REJECT"

                _, en_out, _ = self.run_cmd(["systemctl", "is-enabled", "firewalld"])
                info.is_enabled = (en_out.strip() == "enabled")
                return info
            else:
                info.is_active = False
                info.default_inbound_policy = "ACCEPT"
                return info

        # 2. Test UFW (Kali Linux / Ubuntu / Debian)
        if self.is_tool_available("ufw"):
            info = FirewallInfo(manager="ufw", is_installed=True)
            code, stdout, _ = self.run_cmd(["ufw", "status", "verbose"])
            info.raw_output = stdout.strip()
            if code == 0:
                if "Status: active" in stdout:
                    info.is_active = True
                    if "deny (incoming)" in stdout:
                        info.default_inbound_policy = "DENY"
                    elif "reject (incoming)" in stdout:
                        info.default_inbound_policy = "REJECT"
                    elif "allow (incoming)" in stdout:
                        info.default_inbound_policy = "ACCEPT"
                    else:
                        info.default_inbound_policy = "DENY"

                    for line in stdout.splitlines():
                        if "ALLOW IN" in line:
                            rule_part = line.split("ALLOW IN")[0].strip()
                            if rule_part:
                                info.open_ports.append(rule_part)
                    return info
                else:
                    info.is_active = False
                    info.default_inbound_policy = "ACCEPT"
                    return info

        # 3. Test nftables
        if self.is_tool_available("nft"):
            info = FirewallInfo(manager="nftables", is_installed=True)
            code, stdout, _ = self.run_cmd(["systemctl", "is-active", "nftables"])
            if code == 0 and "active" in stdout:
                info.is_active = True
                _, rset, _ = self.run_cmd(["nft", "list", "ruleset"])
                info.raw_output = rset
                if "hook input" in rset and ("policy drop" in rset or "drop;" in rset):
                    info.default_inbound_policy = "DROP"
                else:
                    info.default_inbound_policy = "ACCEPT"
                return info

        # 4. Test raw iptables
        if self.is_tool_available("iptables"):
            info = FirewallInfo(manager="iptables", is_installed=True)
            code, stdout, _ = self.run_cmd(["iptables", "-S", "INPUT"])
            info.raw_output = stdout.strip()
            if code == 0:
                info.is_active = True
                if "-P INPUT DROP" in stdout:
                    info.default_inbound_policy = "DROP"
                elif "-P INPUT REJECT" in stdout:
                    info.default_inbound_policy = "REJECT"
                elif "-P INPUT ACCEPT" in stdout:
                    info.default_inbound_policy = "ACCEPT"
                return info

        # 5. No firewall detected
        return FirewallInfo(
            manager="none",
            is_installed=False,
            is_active=False,
            is_enabled=False,
            default_inbound_policy="ACCEPT",
            raw_output="No active firewall daemon found.",
        )

    def audit_network(self, os_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Performs a full audit of network sockets, interface bindings, and firewall status.
        Generates findings strictly formatted to the DefenSys JSON Data Contract.
        """
        findings: List[Dict[str, Any]] = []

        # 1. Discover sockets and firewall manager
        sockets = self.get_listening_sockets()
        fw_info = self.detect_firewall_manager()

        logger.info(f"Discovered {len(sockets)} listening sockets. Firewall: {fw_info.manager} (Active={fw_info.is_active})")

        # Check 1: Inactive / Disabled Firewall (NET_FW_001)
        if not fw_info.is_active:
            exposed_count = sum(1 for s in sockets if s.is_exposed)
            exposed_desc = f"{exposed_count} listening service(s) exposed" if exposed_count > 0 else "no listening services exposed"

            ssh_sock = next((s for s in sockets if s.local_port == 22 and s.is_exposed), None)
            if ssh_sock:
                current_val = f"Port 22 listening on {ssh_sock.local_address} (Firewall Inactive - {fw_info.manager})"
            else:
                current_val = f"Host firewall is INACTIVE/DISABLED ({fw_info.manager}) with {exposed_desc}"

            findings.append({
                "rule_id": "NET_FW_001",
                "module": "module_2",
                "category": "Network Exposure",
                "check_name": "Unrestricted Exposed Service",
                "status": "FAILED",
                "severity": "CRITICAL",
                "current_value": current_val,
                "expected_value": "Firewall Active with restricted inbound ports",
                "target_file": "active_firewall",
                "remediation_script": "remediate_firewall.sh",
            })
        else:
            findings.append({
                "rule_id": "NET_FW_001",
                "module": "module_2",
                "category": "Network Exposure",
                "check_name": "Active Firewall Enforcement",
                "status": "PASSED",
                "severity": "INFO",
                "current_value": f"Firewall '{fw_info.manager}' is active and operational",
                "expected_value": "Firewall Active with restricted inbound ports",
                "target_file": "active_firewall",
                "remediation_script": "remediate_firewall.sh",
            })

            # Check 2: Permissive Default Inbound Policy (NET_FW_004)
            if fw_info.default_inbound_policy == "ACCEPT":
                findings.append({
                    "rule_id": "NET_FW_004",
                    "module": "module_2",
                    "category": "Firewall Security",
                    "check_name": "Permissive Default Inbound Policy",
                    "status": "FAILED",
                    "severity": "HIGH",
                    "current_value": f"Default incoming policy in {fw_info.manager} is ACCEPT (traffic allowed by default)",
                    "expected_value": "Default incoming policy set to DROP or DENY",
                    "target_file": "active_firewall",
                    "remediation_script": "remediate_firewall.sh",
                })
            else:
                findings.append({
                    "rule_id": "NET_FW_004",
                    "module": "module_2",
                    "category": "Firewall Security",
                    "check_name": "Default Inbound Policy Hardened",
                    "status": "PASSED",
                    "severity": "INFO",
                    "current_value": f"Default incoming policy in {fw_info.manager} is {fw_info.default_inbound_policy}",
                    "expected_value": "Default incoming policy set to DROP or DENY",
                    "target_file": "active_firewall",
                    "remediation_script": "remediate_firewall.sh",
                })

        # Check 3: Socket-level Audits
        for sock in sockets:
            if not sock.is_exposed:
                continue

            port = sock.local_port
            proto = sock.protocol
            proc = sock.process_name
            addr = sock.local_address

            # Check 3A: Insecure / Cleartext Protocols (NET_FW_003)
            if port in INSECURE_PROTOCOLS:
                meta = INSECURE_PROTOCOLS[port]
                findings.append({
                    "rule_id": "NET_FW_003",
                    "module": "module_2",
                    "category": "Insecure Protocols",
                    "check_name": f"Cleartext Protocol Exposed ({meta['name']})",
                    "status": "FAILED",
                    "severity": meta["severity"],
                    "current_value": f"{meta['name']} (Port {port}/{proto}, PID {sock.pid or 'N/A'}) listening on {addr} ({proc})",
                    "expected_value": f"{meta['name']} disabled or replaced with secure encrypted alternative (SSH/TLS)",
                    "target_file": "active_firewall",
                    "remediation_script": "remediate_firewall.sh",
                })

            # Check 3B: Database / Caching Service Exposed (NET_FW_002)
            if port in SENSITIVE_SERVICES and (sock.is_wildcard or not fw_info.is_active):
                meta = SENSITIVE_SERVICES[port]
                findings.append({
                    "rule_id": "NET_FW_002",
                    "module": "module_2",
                    "category": "Network Exposure",
                    "check_name": f"Exposed Database / Cache Service ({meta['name']})",
                    "status": "FAILED",
                    "severity": meta["severity"],
                    "current_value": f"{meta['name']} (Port {port}/{proto}) listening on wildcard {addr} ({proc})",
                    "expected_value": f"{meta['name']} bound strictly to 127.0.0.1 or restricted via firewall policy",
                    "target_file": "active_firewall",
                    "remediation_script": "remediate_firewall.sh",
                })

            # Check 3C: Unrestricted Wildcard Binding (NET_FW_005)
            if sock.is_wildcard and port not in INSECURE_PROTOCOLS and port not in SENSITIVE_SERVICES and port != 22:
                findings.append({
                    "rule_id": "NET_FW_005",
                    "module": "module_2",
                    "category": "Network Exposure",
                    "check_name": "Wildcard Network Socket Binding",
                    "status": "FAILED",
                    "severity": "HIGH" if port < 1024 else "MEDIUM",
                    "current_value": f"Service '{proc}' listening on wildcard {addr}:{port} ({proto.upper()})",
                    "expected_value": "Service bound to specific interface or localhost (127.0.0.1)",
                    "target_file": "active_firewall",
                    "remediation_script": "remediate_firewall.sh",
                })

            # Check 3D: SSH Exposed Unrestrictedly (NET_FW_006)
            if port == 22 and (not fw_info.is_active or fw_info.default_inbound_policy == "ACCEPT"):
                findings.append({
                    "rule_id": "NET_FW_006",
                    "module": "module_2",
                    "category": "Network Exposure",
                    "check_name": "Unrestricted SSH Exposure",
                    "status": "FAILED",
                    "severity": "HIGH",
                    "current_value": f"SSH daemon (Port 22/{proto}) listening on {addr} without active firewall perimeter",
                    "expected_value": "SSH traffic restricted by active firewall, rate-limiting, or VPN subnet",
                    "target_file": "active_firewall",
                    "remediation_script": "remediate_firewall.sh",
                })

        return findings


def build_scan_metadata(os_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Builds scan metadata adhering to data/findings.json contract."""
    hostname = socket.gethostname()
    os_name = "Linux"
    os_family = "generic"
    kernel_version = platform.release()

    if os_info:
        hostname = os_info.get("hostname", hostname)
        os_name = os_info.get("os_name", os_name)
        os_family = os_info.get("os_family", os_family)
        kernel_version = os_info.get("kernel_version", kernel_version)
    elif os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("ID_LIKE="):
                        os_family = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("ID=") and os_family == "generic":
                        os_family = line.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": hostname,
        "os_name": os_name,
        "os_family": os_family,
        "kernel_version": kernel_version,
    }


# Public API wrapper for defensys main controller and teammates
def audit_network(os_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Entry point for DefenSys CLI to run Module 2 network auditing."""
    auditor = NetworkAuditor()
    return auditor.audit_network(os_info=os_info)


def run_audit(os_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Alias for audit_network adhering to common module convention."""
    return audit_network(os_info=os_info)


# ------------------------------------------------------------------------------
# Built-in Verification Test Suite
# ------------------------------------------------------------------------------
class TestModule2NetworkAuditor(unittest.TestCase):
    """Automated unit & regression tests for Module 2 Network Auditor."""

    def test_ss_line_parsing_ipv4(self):
        auditor = NetworkAuditor()
        line = 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=842,fd=3))'
        sock = auditor.parse_ss_line(line, "tcp")
        self.assertIsNotNone(sock)
        self.assertEqual(sock.local_address, "0.0.0.0")
        self.assertEqual(sock.local_port, 22)
        self.assertEqual(sock.process_name, "sshd")
        self.assertEqual(sock.pid, 842)
        self.assertTrue(sock.is_wildcard)
        self.assertTrue(sock.is_exposed)

    def test_ss_line_parsing_ipv6_brackets(self):
        auditor = NetworkAuditor()
        line = 'LISTEN 0 128 [::]:3306 [::]:* users:(("mysqld",pid=1120,fd=21))'
        sock = auditor.parse_ss_line(line, "tcp")
        self.assertIsNotNone(sock)
        self.assertEqual(sock.local_address, "::")
        self.assertEqual(sock.local_port, 3306)
        self.assertEqual(sock.process_name, "mysqld")
        self.assertTrue(sock.is_wildcard)

    def test_loopback_isolation(self):
        auditor = NetworkAuditor()
        line = 'LISTEN 0 128 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=1024,fd=6))'
        sock = auditor.parse_ss_line(line, "tcp")
        self.assertIsNotNone(sock)
        self.assertTrue(sock.is_loopback)
        self.assertFalse(sock.is_exposed)

    def test_rhel_firewalld_hardened_scenario(self):
        mock_fw = FirewallInfo(
            manager="firewalld",
            is_installed=True,
            is_active=True,
            default_inbound_policy="REJECT",
            open_ports=["22/tcp"],
            open_services=["ssh"],
        )
        mock_socks = [
            ListeningSocket(protocol="tcp", local_address="0.0.0.0", local_port=22, process_name="sshd", pid=842),
            ListeningSocket(protocol="tcp", local_address="127.0.0.1", local_port=5432, process_name="postgres", pid=900),
        ]
        auditor = NetworkAuditor(mock_mode=True, mock_sockets=mock_socks, mock_firewall=mock_fw)
        findings = auditor.audit_network()

        # Should verify PASSED firewall enforcement
        rule_001 = next(f for f in findings if f["rule_id"] == "NET_FW_001")
        self.assertEqual(rule_001["status"], "PASSED")

        rule_004 = next(f for f in findings if f["rule_id"] == "NET_FW_004")
        self.assertEqual(rule_004["status"], "PASSED")

    def test_kali_inactive_firewall_unrestricted_ssh(self):
        mock_fw = FirewallInfo(
            manager="ufw",
            is_installed=True,
            is_active=False,
            default_inbound_policy="ACCEPT",
        )
        mock_socks = [
            ListeningSocket(protocol="tcp", local_address="0.0.0.0", local_port=22, process_name="sshd", pid=842),
            ListeningSocket(protocol="tcp", local_address="0.0.0.0", local_port=23, process_name="telnetd", pid=910),
            ListeningSocket(protocol="tcp", local_address="0.0.0.0", local_port=3306, process_name="mysqld", pid=1120),
        ]
        auditor = NetworkAuditor(mock_mode=True, mock_sockets=mock_socks, mock_firewall=mock_fw)
        findings = auditor.audit_network()

        rule_ids = {f["rule_id"] for f in findings}
        self.assertIn("NET_FW_001", rule_ids)
        self.assertIn("NET_FW_002", rule_ids)
        self.assertIn("NET_FW_003", rule_ids)

        # Check exact contract fields
        for f in findings:
            self.assertEqual(f["module"], "module_2")
            self.assertEqual(f["remediation_script"], "remediate_firewall.sh")
            self.assertIn(f["status"], ["FAILED", "PASSED"])
            self.assertIn(f["severity"], ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])


def run_tests() -> bool:
    """Executes the test suite and returns True if all tests pass."""
    suite = unittest.TestLoader().loadTestsFromTestCase(TestModule2NetworkAuditor)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


def main():
    parser = argparse.ArgumentParser(description="DefenSys Module 2 — Network & Firewall Security Auditor")
    parser.add_argument("--audit", action="store_true", help="Run network & firewall security audit")
    parser.add_argument("--json", action="store_true", help="Output audit results in DefenSys JSON contract format")
    parser.add_argument("--output", type=str, help="Write JSON findings to target file (e.g. data/findings.json)")
    parser.add_argument("--test", action="store_true", help="Run built-in automated test suite")
    parser.add_argument("--mock-rhel", action="store_true", help="Simulate audit on a hardened RHEL 9 node")
    parser.add_argument("--mock-kali", action="store_true", help="Simulate audit on an exposed Kali Linux node")

    args = parser.parse_args()

    if args.test:
        print("[*] Running Module 2 Unit & Regression Test Suite...")
        success = run_tests()
        sys.exit(0 if success else 1)

    auditor = NetworkAuditor()

    if args.mock_rhel:
        mock_fw = FirewallInfo(
            manager="firewalld",
            is_installed=True,
            is_active=True,
            default_inbound_policy="REJECT",
            open_ports=["22/tcp"],
            open_services=["ssh"],
        )
        mock_socks = [
            ListeningSocket(protocol="tcp", local_address="0.0.0.0", local_port=22, process_name="sshd", pid=842),
            ListeningSocket(protocol="tcp", local_address="127.0.0.1", local_port=3306, process_name="mysqld", pid=1024),
        ]
        auditor = NetworkAuditor(mock_mode=True, mock_sockets=mock_socks, mock_firewall=mock_fw)
        os_meta = {"hostname": "rhel-node-01", "os_name": "Red Hat Enterprise Linux 9.4", "os_family": "rhel"}
    elif args.mock_kali:
        mock_fw = FirewallInfo(manager="ufw", is_installed=True, is_active=False, default_inbound_policy="ACCEPT")
        mock_socks = [
            ListeningSocket(protocol="tcp", local_address="0.0.0.0", local_port=22, process_name="sshd", pid=842),
            ListeningSocket(protocol="tcp", local_address="0.0.0.0", local_port=3306, process_name="mysqld", pid=1120),
            ListeningSocket(protocol="tcp", local_address="0.0.0.0", local_port=23, process_name="in.telnetd", pid=1140),
        ]
        auditor = NetworkAuditor(mock_mode=True, mock_sockets=mock_socks, mock_firewall=mock_fw)
        os_meta = {"hostname": "kali-sec-node", "os_name": "Kali Linux", "os_family": "debian"}
    else:
        os_meta = None

    findings = auditor.audit_network(os_info=os_meta)
    metadata = build_scan_metadata(os_info=os_meta)

    full_payload = {
        "scan_metadata": metadata,
        "findings": findings,
    }

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(full_payload, f, indent=2)
        print(f"[+] Successfully wrote {len(findings)} findings to {args.output}")

    if args.json or (not args.audit and not args.mock_rhel and not args.mock_kali and not args.output):
        print(json.dumps(full_payload, indent=2))
    else:
        print("\n=======================================================")
        print("   DefenSys — Module 2 Network Audit Summary Report    ")
        print("=======================================================")
        print(f"Target Host : {metadata['hostname']} ({metadata['os_name']})")
        print(f"Timestamp   : {metadata['timestamp']}")
        print(f"Total Checks: {len(findings)}")
        print("-------------------------------------------------------")
        for f in findings:
            status_icon = "[PASS]" if f["status"] == "PASSED" else "[FAIL]"
            print(f"{status_icon} [{f['severity']}] {f['rule_id']}: {f['check_name']}")
            print(f"       Current : {f['current_value']}")
            print(f"       Expected: {f['expected_value']}")
            if f["status"] == "FAILED":
                print(f"       Fix     : scripts/{f['remediation_script']}")
            print("-------------------------------------------------------")


if __name__ == "__main__":
    main()
