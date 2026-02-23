"""Bootstrap training data for per-source classifiers.

Generates labelled TrainingRecord instances by running real sample
values through extract_features(). No synthetic vectors -- feature
extraction is always live so bootstrap data stays consistent with
whatever extract_features() produces at runtime.

Wazuh ground truth derived from discovery runs 9-15 (session_005).
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

# Type alias for a source bootstrap function
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
# Wazuh bootstrap -- ground truth from runs 9-15
# ---------------------------------------------------------------------------

def _wazuh_bootstrap() -> list[TrainingRecord]:
    """Labelled training records derived from Wazuh-ES telemetry.

    Field patterns and correct labels from session_005 ground truth table.
    Sample values are representative -- sufficient variety for feature
    vectors to capture the statistical fingerprint of each field type.
    """
    src = "wazuh"
    records: list[TrainingRecord] = []

    # -- ENTITY: IPv4 addresses --
    ipv4_samples = [
        "192.168.1.10", "10.0.0.5", "172.16.0.20", "192.168.100.1",
        "10.10.10.10", "192.168.2.50", "172.31.255.1", "10.0.1.100",
        "192.168.0.254", "8.8.8.8",
    ]
    for path in ("agent.ip", "data.srcip", "data.dstip"):
        records.append(_make_record(src, path, "entity", ipv4_samples))

    # -- ENTITY: MD5 hashes --
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

    # -- ENTITY: SHA1 hashes --
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

    # -- ENTITY: SHA256 hashes --
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

    # -- ENTITY: MITRE technique IDs --
    technique_samples = [
        "T1059", "T1078", "T1055", "T1003", "T1021",
        "T1566", "T1190", "T1133", "T1505", "T1053",
    ]
    records.append(_make_record(
        src, "rule.mitre_techniques", "entity", technique_samples,
    ))

    # -- ENTITY: FQDNs / hostnames --
    fqdn_samples = [
        "server01.corp.local", "web02.internal.example.com",
        "db01.prod.corp", "proxy03.dmz.local",
        "mail01.example.com", "app04.staging.corp",
        "cache02.internal.local", "lb01.prod.example.com",
        "wazuh-manager.corp.local", "agent01.endpoint.corp",
    ]
    for path in ("agent.name", "predecoder.hostname"):
        records.append(_make_record(src, path, "entity", fqdn_samples))

    # -- TEMPORAL: ISO timestamps --
    timestamp_samples = [
        "2026-01-15T10:30:00Z", "2026-01-15T11:45:22Z",
        "2026-01-16T08:00:15Z", "2026-01-16T09:12:33Z",
        "2026-01-17T14:55:01Z", "2026-01-17T16:20:45Z",
        "2026-01-18T07:30:00Z", "2026-01-18T22:15:10Z",
        "2026-02-01T00:00:00Z", "2026-02-10T13:45:59Z",
    ]
    for path in ("@timestamp", "data.win.system.systemTime"):
        records.append(_make_record(src, path, "temporal", timestamp_samples))

    # -- METRIC: Rule levels (small integers) --
    rule_level_samples = [
        "3", "5", "7", "3", "12", "5", "3", "7", "10", "2",
    ]
    records.append(_make_record(
        src, "rule.level", "metric", rule_level_samples,
    ))

    # -- METRIC: Windows event IDs --
    event_id_samples = [
        "4624", "4625", "4648", "4672", "4688",
        "4698", "4702", "4720", "4728", "4776",
    ]
    records.append(_make_record(
        src, "data.win.system.eventID", "metric", event_id_samples,
    ))

    # -- ENUM: Rule groups (low-cardinality categories) --
    rule_group_samples = [
        "authentication_success", "authentication_failed",
        "syscheck", "rootcheck", "web",
        "windows", "linux", "ossec",
        "ids", "firewall",
    ]
    records.append(_make_record(
        src, "rule.groups", "enum", rule_group_samples,
    ))

    # -- ENUM: Decoder names --
    decoder_samples = [
        "windows", "syslog", "ossec", "web-accesslog",
        "iptables", "sshd", "sudo", "auditd",
        "windows-eventchannel", "json",
    ]
    records.append(_make_record(
        src, "decoder.name", "enum", decoder_samples,
    ))

    # -- TEXT: Long descriptive messages --
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

    logger.info(
        "Wazuh bootstrap: %d training records generated", len(records),
    )
    return records


# ---------------------------------------------------------------------------
# Registry -- maps source_id to bootstrap function
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