#!/usr/bin/env python3
"""
DefenSys — Module 1: System, SSH & Authentication Auditor
Lead Maintainer: Member 1 (System & Configuration Security Lead)
Target Architecture: Linux / RHEL / Debian / Kali (Python 3 + Bash)

Scope & Capabilities:
- Parse /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf
  for PermitRootLogin, PasswordAuthentication, and PubkeyAuthentication.
- Audit ownership/permissions on /etc/shadow, /etc/passwd, /etc/sudoers.
- Detect dangerous SUID/SGID binaries across generic Linux filesystems.
- Emit findings that adhere strictly to the DefenSys JSON Data Contract.
- Provide a public API (audit_system / run_audit) for defensys.py.
"""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import platform
import re
import socket
import stat
import sys
import unittest
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Configure logging
logger = logging.getLogger("defensys.module1")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [Module-1:System] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ------------------------------------------------------------------------------
# Expected hardened values & sensitive path baselines
# ------------------------------------------------------------------------------
SSH_EXPECTATIONS: Dict[str, Dict[str, str]] = {
    "PermitRootLogin": {
        "expected": "no",
        "rule_id": "SYS_SSH_001",
        "check_name": "SSH Root Login Enabled",
        "severity": "HIGH",
        "category": "Authentication",
        # Values that are considered secure enough to PASS
        "secure_values": {"no", "prohibit-password", "without-password", "forced-commands-only"},
    },
    "PasswordAuthentication": {
        "expected": "no",
        "rule_id": "SYS_SSH_002",
        "check_name": "SSH Password Authentication Enabled",
        "severity": "HIGH",
        "category": "Authentication",
        "secure_values": {"no"},
    },
    "PubkeyAuthentication": {
        "expected": "yes",
        "rule_id": "SYS_SSH_003",
        "check_name": "SSH Public Key Authentication Disabled",
        "severity": "MEDIUM",
        "category": "Authentication",
        "secure_values": {"yes"},
    },
}

# (path, expected_mode_octal_max, expected_owner_uid, expected_group_gid_or_None, rule_id, check_name, severity)
SENSITIVE_FILES: List[Tuple[str, int, int, Optional[int], str, str, str]] = [
    ("/etc/shadow", 0o640, 0, None, "SYS_PERM_001", "Insecure /etc/shadow Permissions", "CRITICAL"),
    ("/etc/passwd", 0o644, 0, None, "SYS_PERM_002", "Insecure /etc/passwd Permissions", "HIGH"),
    ("/etc/sudoers", 0o440, 0, None, "SYS_PERM_003", "Insecure /etc/sudoers Permissions", "CRITICAL"),
]

# Commonly abused or unexpected SUID/SGID binaries (relative basenames)
SUSPICIOUS_SUID_BASENAMES = {
    "nmap",
    "vim",
    "vi",
    "nano",
    "python",
    "python3",
    "perl",
    "ruby",
    "find",
    "bash",
    "sh",
    "dash",
    "cp",
    "mv",
    "less",
    "more",
    "awk",
    "env",
    "wget",
    "curl",
    "nc",
    "ncat",
    "netcat",
    "tcpdump",
}

DEFAULT_SUID_SCAN_PATHS = [
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
]


@dataclass
class SSHDirective:
    """Represents an effective sshd_config directive after Include merge."""

    key: str
    value: str
    source_file: str
    line_number: int = 0


@dataclass
class FilePermissionInfo:
    """Represents ownership and mode metadata for a sensitive file."""

    path: str
    exists: bool
    mode: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    error: Optional[str] = None


@dataclass
class SystemAuditor:
    """
    Distro-agnostic system / SSH / authentication auditor.

    mock_mode allows Windows hosts and CI environments to exercise the
    finding contract without requiring a live Linux filesystem.
    """

    mock_mode: bool = False
    mock_ssh_config: Optional[str] = None
    mock_ssh_dropins: Optional[Dict[str, str]] = None
    mock_file_stats: Optional[Dict[str, FilePermissionInfo]] = None
    mock_suid_binaries: Optional[List[str]] = None
    ssh_main_config: str = "/etc/ssh/sshd_config"
    ssh_dropin_glob: str = "/etc/ssh/sshd_config.d/*.conf"
    suid_scan_paths: List[str] = field(default_factory=lambda: list(DEFAULT_SUID_SCAN_PATHS))

    # ------------------------------------------------------------------
    # SSH configuration parsing
    # ------------------------------------------------------------------
    def _read_text(self, path: str) -> str:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()

    def _parse_ssh_content(self, content: str, source_file: str) -> List[SSHDirective]:
        """Parse sshd_config-style content into directive objects (last wins later)."""
        directives: List[SSHDirective] = []
        for idx, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip inline comments carefully (keep values that may contain # rarely)
            if "#" in line:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
            parts = re.split(r"\s+", line, maxsplit=1)
            if len(parts) < 2:
                continue
            key, value = parts[0], parts[1].strip()
            # Skip Include lines here; handled by collector
            if key.lower() == "include":
                continue
            directives.append(
                SSHDirective(key=key, value=value, source_file=source_file, line_number=idx)
            )
        return directives

    def collect_ssh_directives(self) -> Dict[str, SSHDirective]:
        """
        Collect effective SSH directives from main config + drop-in directory.
        Later definitions override earlier ones (sshd last-match semantics for
        most boolean toggles used here).
        """
        effective: Dict[str, SSHDirective] = {}

        if self.mock_mode:
            main_content = self.mock_ssh_config or ""
            for directive in self._parse_ssh_content(main_content, self.ssh_main_config):
                effective[directive.key.lower()] = directive
            for drop_path, drop_content in (self.mock_ssh_dropins or {}).items():
                for directive in self._parse_ssh_content(drop_content, drop_path):
                    effective[directive.key.lower()] = directive
            return effective

        sources: List[Tuple[str, str]] = []
        if os.path.isfile(self.ssh_main_config):
            try:
                sources.append((self.ssh_main_config, self._read_text(self.ssh_main_config)))
            except OSError as exc:
                logger.warning("Unable to read %s: %s", self.ssh_main_config, exc)
        else:
            logger.warning("SSH main config not found: %s", self.ssh_main_config)

        for drop_path in sorted(glob.glob(self.ssh_dropin_glob)):
            try:
                sources.append((drop_path, self._read_text(drop_path)))
            except OSError as exc:
                logger.warning("Unable to read drop-in %s: %s", drop_path, exc)

        for source_file, content in sources:
            for directive in self._parse_ssh_content(content, source_file):
                effective[directive.key.lower()] = directive

        return effective

    def _make_finding(
        self,
        *,
        rule_id: str,
        category: str,
        check_name: str,
        status: str,
        severity: str,
        current_value: str,
        expected_value: str,
        target_file: str,
        remediation_script: str = "remediate_ssh.sh",
    ) -> Dict[str, Any]:
        """Build a single finding object matching docs/API_CONTRACT.md."""
        return {
            "rule_id": rule_id,
            "module": "module_1",
            "category": category,
            "check_name": check_name,
            "status": status,
            "severity": severity,
            "current_value": current_value,
            "expected_value": expected_value,
            "target_file": target_file,
            "remediation_script": remediation_script,
        }

    def audit_ssh(self) -> List[Dict[str, Any]]:
        """Audit PermitRootLogin, PasswordAuthentication, PubkeyAuthentication."""
        findings: List[Dict[str, Any]] = []
        directives = self.collect_ssh_directives()

        for key, meta in SSH_EXPECTATIONS.items():
            directive = directives.get(key.lower())
            if directive is None:
                # OpenSSH defaults: PermitRootLogin prohibit-password (modern),
                # PasswordAuthentication yes, PubkeyAuthentication yes.
                defaults = {
                    "PermitRootLogin": "prohibit-password (OpenSSH default)",
                    "PasswordAuthentication": "yes (OpenSSH default)",
                    "PubkeyAuthentication": "yes (OpenSSH default)",
                }
                current_raw = defaults.get(key, "unset")
                current_norm = current_raw.split()[0].lower()
                source = self.ssh_main_config
            else:
                current_raw = f"{directive.key} {directive.value}"
                current_norm = directive.value.strip().lower()
                source = directive.source_file

            secure_values = {v.lower() for v in meta["secure_values"]}
            is_secure = current_norm in secure_values

            if is_secure:
                passed_names = {
                    "PermitRootLogin": "SSH Root Login Hardened",
                    "PasswordAuthentication": "SSH Password Authentication Hardened",
                    "PubkeyAuthentication": "SSH Public Key Authentication Enabled",
                }
                findings.append(
                    self._make_finding(
                        rule_id=meta["rule_id"],
                        category=meta["category"],
                        check_name=passed_names.get(key, meta["check_name"]),
                        status="PASSED",
                        severity="INFO",
                        current_value=current_raw if directive else f"{key} {current_raw}",
                        expected_value=f"{key} {meta['expected']}",
                        target_file=source,
                    )
                )
            else:
                findings.append(
                    self._make_finding(
                        rule_id=meta["rule_id"],
                        category=meta["category"],
                        check_name=meta["check_name"],
                        status="FAILED",
                        severity=meta["severity"],
                        current_value=current_raw if directive else f"{key} {current_raw}",
                        expected_value=f"{key} {meta['expected']}",
                        target_file=source,
                    )
                )

        logger.info("SSH audit produced %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # File permission & ownership audits
    # ------------------------------------------------------------------
    def _stat_file(self, path: str) -> FilePermissionInfo:
        if self.mock_mode and self.mock_file_stats is not None:
            return self.mock_file_stats.get(
                path, FilePermissionInfo(path=path, exists=False, error="not present in mock")
            )

        if not os.path.exists(path):
            return FilePermissionInfo(path=path, exists=False, error="file not found")

        try:
            st = os.stat(path)
            return FilePermissionInfo(
                path=path,
                exists=True,
                mode=stat.S_IMODE(st.st_mode),
                uid=st.st_uid,
                gid=st.st_gid,
            )
        except OSError as exc:
            return FilePermissionInfo(path=path, exists=False, error=str(exc))

    def audit_file_permissions(self) -> List[Dict[str, Any]]:
        """Audit /etc/shadow, /etc/passwd, and /etc/sudoers permissions/ownership."""
        findings: List[Dict[str, Any]] = []

        for path, max_mode, expected_uid, expected_gid, rule_id, check_name, severity in SENSITIVE_FILES:
            info = self._stat_file(path)

            if not info.exists:
                findings.append(
                    self._make_finding(
                        rule_id=rule_id,
                        category="File Permissions",
                        check_name=check_name,
                        status="FAILED",
                        severity=severity,
                        current_value=f"{path} missing or unreadable ({info.error or 'unknown'})",
                        expected_value=f"{path} mode <= {oct(max_mode)}, owner uid={expected_uid}",
                        target_file=path,
                        remediation_script="",
                    )
                )
                continue

            mode = info.mode or 0
            uid = info.uid if info.uid is not None else -1
            gid = info.gid if info.gid is not None else -1
            problems: List[str] = []

            if mode & ~max_mode:
                # Mode has bits beyond the allowed maximum mask
                problems.append(f"mode={oct(mode)} (expected <= {oct(max_mode)})")
            # Also fail if world-writable or (for shadow/sudoers) world-readable
            if path.endswith("shadow") or path.endswith("sudoers"):
                if mode & stat.S_IROTH:
                    problems.append("world-readable")
                if mode & stat.S_IWOTH:
                    problems.append("world-writable")
            if mode & stat.S_IWOTH:
                if "world-writable" not in problems:
                    problems.append("world-writable")

            if uid != expected_uid:
                problems.append(f"owner uid={uid} (expected {expected_uid})")
            if expected_gid is not None and gid != expected_gid:
                problems.append(f"group gid={gid} (expected {expected_gid})")

            if problems:
                findings.append(
                    self._make_finding(
                        rule_id=rule_id,
                        category="File Permissions",
                        check_name=check_name,
                        status="FAILED",
                        severity=severity,
                        current_value=f"{path} " + ", ".join(problems),
                        expected_value=f"{path} mode <= {oct(max_mode)}, owner uid={expected_uid}",
                        target_file=path,
                        remediation_script="",
                    )
                )
            else:
                findings.append(
                    self._make_finding(
                        rule_id=rule_id,
                        category="File Permissions",
                        check_name=check_name.replace("Insecure", "Secure"),
                        status="PASSED",
                        severity="INFO",
                        current_value=f"{path} mode={oct(mode)} uid={uid} gid={gid}",
                        expected_value=f"{path} mode <= {oct(max_mode)}, owner uid={expected_uid}",
                        target_file=path,
                        remediation_script="",
                    )
                )

        logger.info("File permission audit produced %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # SUID / SGID binary scan
    # ------------------------------------------------------------------
    def _scan_suid_sgid(self) -> List[str]:
        if self.mock_mode:
            return list(self.mock_suid_binaries or [])

        discovered: List[str] = []
        for root in self.suid_scan_paths:
            if not os.path.isdir(root):
                continue
            try:
                for entry in os.listdir(root):
                    full = os.path.join(root, entry)
                    try:
                        st = os.lstat(full)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        discovered.append(full)
            except OSError as exc:
                logger.warning("Unable to scan %s: %s", root, exc)
        return discovered

    def audit_suid_sgid(self) -> List[Dict[str, Any]]:
        """Flag suspicious SUID/SGID binaries that expand local privilege attack paths."""
        findings: List[Dict[str, Any]] = []
        binaries = self._scan_suid_sgid()
        suspicious = [
            path
            for path in binaries
            if os.path.basename(path).lower() in SUSPICIOUS_SUID_BASENAMES
        ]

        if suspicious:
            preview = ", ".join(suspicious[:8])
            extra = f" (+{len(suspicious) - 8} more)" if len(suspicious) > 8 else ""
            findings.append(
                self._make_finding(
                    rule_id="SYS_SUID_001",
                    category="Privilege Escalation",
                    check_name="Suspicious SUID/SGID Binaries Present",
                    status="FAILED",
                    severity="HIGH",
                    current_value=f"{len(suspicious)} suspicious SUID/SGID binary(ies): {preview}{extra}",
                    expected_value="No unexpected interpreter/shell/network tools with SUID/SGID bits",
                    target_file="suid_sgid_scan",
                    remediation_script="",
                )
            )
        else:
            findings.append(
                self._make_finding(
                    rule_id="SYS_SUID_001",
                    category="Privilege Escalation",
                    check_name="SUID/SGID Binary Inventory Clean",
                    status="PASSED",
                    severity="INFO",
                    current_value=f"Scanned {len(binaries)} SUID/SGID binaries; none matched suspicious baseline",
                    expected_value="No unexpected interpreter/shell/network tools with SUID/SGID bits",
                    target_file="suid_sgid_scan",
                    remediation_script="",
                )
            )

        logger.info("SUID/SGID audit produced %d findings (scanned=%d)", len(findings), len(binaries))
        return findings

    # ------------------------------------------------------------------
    # Full audit orchestration
    # ------------------------------------------------------------------
    def audit_system(self, os_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Run the full Module 1 audit and return findings in contract format.
        os_info is accepted for CLI compatibility with Module 2 / defensys.py.
        """
        _ = os_info  # reserved for future metadata correlation
        findings: List[Dict[str, Any]] = []
        findings.extend(self.audit_ssh())
        findings.extend(self.audit_file_permissions())
        findings.extend(self.audit_suid_sgid())
        return findings


def build_scan_metadata(os_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Builds scan metadata adhering to data/findings.json contract (compatible with Module 2)."""
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
            with open("/etc/os-release", "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("ID_LIKE="):
                        os_family = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("ID=") and os_family == "generic":
                        os_family = line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": hostname,
        "os_name": os_name,
        "os_family": os_family,
        "kernel_version": kernel_version,
    }


# Public API wrappers for DefenSys CLI controller and teammates
def audit_system(os_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Entry point for DefenSys CLI to run Module 1 system auditing."""
    auditor = SystemAuditor()
    return auditor.audit_system(os_info=os_info)


def run_audit(os_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Alias for audit_system adhering to common module convention (matches Module 2)."""
    return audit_system(os_info=os_info)


def merge_findings_payload(
    module_findings: List[Dict[str, Any]],
    output_path: str,
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Merge Module 1 findings into data/findings.json without wiping Module 2+ results.
    Overlap-safe: replaces only findings where module == 'module_1'.
    """
    existing_findings: List[Dict[str, Any]] = []
    if os.path.isfile(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as handle:
                existing = json.load(handle)
            if isinstance(existing, dict) and isinstance(existing.get("findings"), list):
                existing_findings = [
                    item
                    for item in existing["findings"]
                    if isinstance(item, dict) and item.get("module") != "module_1"
                ]
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not merge existing findings from %s: %s", output_path, exc)

    payload = {
        "scan_metadata": metadata,
        "findings": existing_findings + module_findings,
    }
    return payload


# ------------------------------------------------------------------------------
# Unit / regression tests (mock-mode; safe on Windows & CI)
# ------------------------------------------------------------------------------
class TestModule1SystemAuditor(unittest.TestCase):
    def test_ssh_root_login_failed(self):
        auditor = SystemAuditor(
            mock_mode=True,
            mock_ssh_config="PermitRootLogin yes\nPasswordAuthentication no\nPubkeyAuthentication yes\n",
            mock_file_stats={
                "/etc/shadow": FilePermissionInfo("/etc/shadow", True, 0o640, 0, 0),
                "/etc/passwd": FilePermissionInfo("/etc/passwd", True, 0o644, 0, 0),
                "/etc/sudoers": FilePermissionInfo("/etc/sudoers", True, 0o440, 0, 0),
            },
            mock_suid_binaries=[],
        )
        findings = auditor.audit_system()
        by_id = {f["rule_id"]: f for f in findings}
        self.assertEqual(by_id["SYS_SSH_001"]["status"], "FAILED")
        self.assertEqual(by_id["SYS_SSH_001"]["remediation_script"], "remediate_ssh.sh")
        self.assertEqual(by_id["SYS_SSH_001"]["module"], "module_1")
        self.assertEqual(by_id["SYS_SSH_002"]["status"], "PASSED")
        self.assertEqual(by_id["SYS_SSH_003"]["status"], "PASSED")

    def test_ssh_dropin_override(self):
        auditor = SystemAuditor(
            mock_mode=True,
            mock_ssh_config="PermitRootLogin yes\n",
            mock_ssh_dropins={
                "/etc/ssh/sshd_config.d/50-cloud.conf": "PermitRootLogin no\nPasswordAuthentication no\n"
            },
            mock_file_stats={
                "/etc/shadow": FilePermissionInfo("/etc/shadow", True, 0o000, 0, 0),
                "/etc/passwd": FilePermissionInfo("/etc/passwd", True, 0o644, 0, 0),
                "/etc/sudoers": FilePermissionInfo("/etc/sudoers", True, 0o440, 0, 0),
            },
            mock_suid_binaries=[],
        )
        findings = {f["rule_id"]: f for f in auditor.audit_ssh()}
        self.assertEqual(findings["SYS_SSH_001"]["status"], "PASSED")
        self.assertIn("sshd_config.d", findings["SYS_SSH_001"]["target_file"])

    def test_insecure_shadow_permissions(self):
        auditor = SystemAuditor(
            mock_mode=True,
            mock_ssh_config="PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\n",
            mock_file_stats={
                "/etc/shadow": FilePermissionInfo("/etc/shadow", True, 0o666, 0, 0),
                "/etc/passwd": FilePermissionInfo("/etc/passwd", True, 0o644, 0, 0),
                "/etc/sudoers": FilePermissionInfo("/etc/sudoers", True, 0o440, 0, 0),
            },
            mock_suid_binaries=[],
        )
        findings = {f["rule_id"]: f for f in auditor.audit_file_permissions()}
        self.assertEqual(findings["SYS_PERM_001"]["status"], "FAILED")
        self.assertEqual(findings["SYS_PERM_001"]["severity"], "CRITICAL")

    def test_suspicious_suid_binary(self):
        auditor = SystemAuditor(
            mock_mode=True,
            mock_ssh_config="PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\n",
            mock_file_stats={
                "/etc/shadow": FilePermissionInfo("/etc/shadow", True, 0o640, 0, 0),
                "/etc/passwd": FilePermissionInfo("/etc/passwd", True, 0o644, 0, 0),
                "/etc/sudoers": FilePermissionInfo("/etc/sudoers", True, 0o440, 0, 0),
            },
            mock_suid_binaries=["/usr/bin/python3", "/usr/bin/nmap"],
        )
        findings = {f["rule_id"]: f for f in auditor.audit_suid_sgid()}
        self.assertEqual(findings["SYS_SUID_001"]["status"], "FAILED")

    def test_finding_contract_keys(self):
        auditor = SystemAuditor(
            mock_mode=True,
            mock_ssh_config="PermitRootLogin yes\n",
            mock_file_stats={
                "/etc/shadow": FilePermissionInfo("/etc/shadow", True, 0o640, 0, 0),
                "/etc/passwd": FilePermissionInfo("/etc/passwd", True, 0o644, 0, 0),
                "/etc/sudoers": FilePermissionInfo("/etc/sudoers", True, 0o440, 0, 0),
            },
            mock_suid_binaries=[],
        )
        required = {
            "rule_id",
            "module",
            "category",
            "check_name",
            "status",
            "severity",
            "current_value",
            "expected_value",
            "target_file",
            "remediation_script",
        }
        for finding in auditor.audit_system():
            self.assertTrue(required.issubset(finding.keys()))
            self.assertEqual(finding["module"], "module_1")

    def test_merge_preserves_module2_findings(self):
        """Overlap-safe writer must keep Module 2 findings when updating findings.json."""
        import tempfile

        existing = {
            "scan_metadata": {"hostname": "old"},
            "findings": [
                {
                    "rule_id": "NET_FW_001",
                    "module": "module_2",
                    "category": "Network Exposure",
                    "check_name": "Unrestricted Exposed Service",
                    "status": "FAILED",
                    "severity": "CRITICAL",
                    "current_value": "Firewall Inactive",
                    "expected_value": "Firewall Active",
                    "target_file": "active_firewall",
                    "remediation_script": "remediate_firewall.sh",
                },
                {
                    "rule_id": "SYS_SSH_001",
                    "module": "module_1",
                    "category": "Authentication",
                    "check_name": "SSH Root Login Enabled",
                    "status": "FAILED",
                    "severity": "HIGH",
                    "current_value": "PermitRootLogin yes",
                    "expected_value": "PermitRootLogin no",
                    "target_file": "/etc/ssh/sshd_config",
                    "remediation_script": "remediate_ssh.sh",
                },
            ],
        }
        new_mod1 = [
            {
                "rule_id": "SYS_SSH_001",
                "module": "module_1",
                "category": "Authentication",
                "check_name": "SSH Root Login Hardened",
                "status": "PASSED",
                "severity": "INFO",
                "current_value": "PermitRootLogin no",
                "expected_value": "PermitRootLogin no",
                "target_file": "/etc/ssh/sshd_config.d/99-defensys.conf",
                "remediation_script": "remediate_ssh.sh",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "findings.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(existing, handle)
            payload = merge_findings_payload(
                new_mod1,
                path,
                {"hostname": "kali-sec-node", "os_name": "Kali Linux"},
            )
            modules = {item["module"] for item in payload["findings"]}
            self.assertIn("module_2", modules)
            self.assertIn("module_1", modules)
            self.assertEqual(
                sum(1 for item in payload["findings"] if item["module"] == "module_1"),
                1,
            )
            self.assertEqual(
                next(item for item in payload["findings"] if item["rule_id"] == "SYS_SSH_001")[
                    "status"
                ],
                "PASSED",
            )


def run_tests() -> bool:
    """Executes the test suite and returns True if all tests pass."""
    suite = unittest.TestLoader().loadTestsFromTestCase(TestModule1SystemAuditor)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DefenSys Module 1 — System, SSH & Authentication Auditor"
    )
    parser.add_argument("--audit", action="store_true", help="Run system & SSH security audit")
    parser.add_argument(
        "--json", action="store_true", help="Output audit results in DefenSys JSON contract format"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Write JSON findings to target file (e.g. data/findings.json). Merges with non-module_1 findings.",
    )
    parser.add_argument("--test", action="store_true", help="Run built-in automated test suite")
    parser.add_argument(
        "--mock-insecure",
        action="store_true",
        help="Simulate audit on an insecure Linux node (root login + weak perms)",
    )
    parser.add_argument(
        "--mock-hardened",
        action="store_true",
        help="Simulate audit on a hardened RHEL/Debian node",
    )

    args = parser.parse_args()

    if args.test:
        print("[*] Running Module 1 Unit & Regression Test Suite...")
        success = run_tests()
        sys.exit(0 if success else 1)

    os_meta: Optional[Dict[str, Any]] = None

    if args.mock_insecure:
        auditor = SystemAuditor(
            mock_mode=True,
            mock_ssh_config=(
                "PermitRootLogin yes\n"
                "PasswordAuthentication yes\n"
                "PubkeyAuthentication no\n"
            ),
            mock_file_stats={
                "/etc/shadow": FilePermissionInfo("/etc/shadow", True, 0o666, 0, 0),
                "/etc/passwd": FilePermissionInfo("/etc/passwd", True, 0o777, 0, 0),
                "/etc/sudoers": FilePermissionInfo("/etc/sudoers", True, 0o644, 0, 0),
            },
            mock_suid_binaries=["/usr/bin/python3", "/usr/bin/nmap", "/bin/bash"],
        )
        os_meta = {
            "hostname": "kali-sec-node",
            "os_name": "Kali Linux",
            "os_family": "debian",
            "kernel_version": "6.8.0-kali",
        }
    elif args.mock_hardened:
        auditor = SystemAuditor(
            mock_mode=True,
            mock_ssh_config=(
                "PermitRootLogin no\n"
                "PasswordAuthentication no\n"
                "PubkeyAuthentication yes\n"
            ),
            mock_file_stats={
                "/etc/shadow": FilePermissionInfo("/etc/shadow", True, 0o000, 0, 0),
                "/etc/passwd": FilePermissionInfo("/etc/passwd", True, 0o644, 0, 0),
                "/etc/sudoers": FilePermissionInfo("/etc/sudoers", True, 0o440, 0, 0),
            },
            mock_suid_binaries=["/usr/bin/passwd", "/usr/bin/sudo"],
        )
        os_meta = {
            "hostname": "rhel-node-01",
            "os_name": "Red Hat Enterprise Linux 9.4",
            "os_family": "rhel",
            "kernel_version": "5.14.0-427.el9",
        }
    else:
        auditor = SystemAuditor()

    findings = auditor.audit_system(os_info=os_meta)
    metadata = build_scan_metadata(os_info=os_meta)
    full_payload = {
        "scan_metadata": metadata,
        "findings": findings,
    }

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
        full_payload = merge_findings_payload(findings, args.output, metadata)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(full_payload, handle, indent=2)
        print(f"[+] Successfully wrote {len(findings)} Module-1 findings to {args.output}")

    if args.json or (
        not args.audit
        and not args.mock_insecure
        and not args.mock_hardened
        and not args.output
    ):
        print(json.dumps(full_payload, indent=2))
    else:
        print("\n=======================================================")
        print("   DefenSys — Module 1 System Audit Summary Report     ")
        print("=======================================================")
        print(f"Target Host : {metadata['hostname']} ({metadata['os_name']})")
        print(f"Timestamp   : {metadata['timestamp']}")
        print(f"Total Checks: {len(findings)}")
        print("-------------------------------------------------------")
        for item in findings:
            status_icon = "[PASS]" if item["status"] == "PASSED" else "[FAIL]"
            print(f"{status_icon} [{item['severity']}] {item['rule_id']}: {item['check_name']}")
            print(f"       Current : {item['current_value']}")
            print(f"       Expected: {item['expected_value']}")
            if item["status"] == "FAILED" and item.get("remediation_script"):
                print(f"       Fix     : scripts/{item['remediation_script']}")
            print("-------------------------------------------------------")


if __name__ == "__main__":
    main()
