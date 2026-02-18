"""Tests for JSON flattener and field feature extraction."""

import math
import pytest
from grasp.discovery.features import (
    FEATURE_DIM,
    FEATURE_NAMES,
    collect_field_values,
    extract_features,
    flatten_event,
)


# -----------------------------------------------------------------------
# Flattener tests
# -----------------------------------------------------------------------


class TestFlattenEvent:
    """Verify JSON flattening produces correct dot-notation paths."""

    def test_flat_dict(self):
        event = {"a": 1, "b": "hello"}
        flat = flatten_event(event)
        assert flat == {"a": 1, "b": "hello"}

    def test_nested_dict(self):
        event = {"data": {"srcip": "1.2.3.4", "dstip": "5.6.7.8"}}
        flat = flatten_event(event)
        assert flat == {"data.srcip": "1.2.3.4", "data.dstip": "5.6.7.8"}

    def test_deeply_nested(self):
        event = {"a": {"b": {"c": {"d": "deep"}}}}
        flat = flatten_event(event)
        assert flat == {"a.b.c.d": "deep"}

    def test_array_values(self):
        event = {"tags": ["alert", "critical"]}
        flat = flatten_event(event)
        assert flat == {"tags.0": "alert", "tags.1": "critical"}

    def test_null_values(self):
        event = {"a": None, "b": "present"}
        flat = flatten_event(event)
        assert flat == {"a": None, "b": "present"}

    def test_empty_dict(self):
        assert flatten_event({}) == {}

    def test_mixed_nesting(self):
        event = {
            "rule": {"level": 5, "mitre": {"id": ["T1059"]}},
            "agent": {"name": "server01"},
        }
        flat = flatten_event(event)
        assert flat["rule.level"] == 5
        assert flat["rule.mitre.id.0"] == "T1059"
        assert flat["agent.name"] == "server01"


class TestCollectFieldValues:
    """Verify field value collection across multiple events."""

    def test_basic_collection(self):
        payloads = [
            {"ip": "1.1.1.1", "port": 80},
            {"ip": "2.2.2.2", "port": 443},
        ]
        fields = collect_field_values(payloads)
        assert fields["ip"] == ["1.1.1.1", "2.2.2.2"]
        assert fields["port"] == [80, 443]

    def test_missing_fields_get_none(self):
        payloads = [
            {"ip": "1.1.1.1", "host": "server01"},
            {"ip": "2.2.2.2"},
        ]
        fields = collect_field_values(payloads)
        assert fields["ip"] == ["1.1.1.1", "2.2.2.2"]
        # host missing in second event
        assert None in fields["host"]

    def test_nested_collection(self):
        payloads = [
            {"data": {"srcip": "1.1.1.1"}},
            {"data": {"srcip": "2.2.2.2"}},
        ]
        fields = collect_field_values(payloads)
        assert "data.srcip" in fields
        assert fields["data.srcip"] == ["1.1.1.1", "2.2.2.2"]


# -----------------------------------------------------------------------
# Feature extraction tests
# -----------------------------------------------------------------------


class TestExtractFeatures:
    """Verify feature vectors capture correct statistical properties."""

    def test_feature_vector_length(self):
        feat = extract_features("test", ["a", "b", "c"])
        assert len(feat.vector) == FEATURE_DIM
        assert len(FEATURE_NAMES) == FEATURE_DIM

    def test_ip_addresses_features(self):
        ips = [
            "192.168.1.1", "192.168.1.2", "10.0.0.1",
            "172.16.0.5", "8.8.8.8", "1.1.1.1",
        ]
        feat = extract_features("src_ip", ips)
        vec = dict(zip(FEATURE_NAMES, feat.vector))

        # IPs have dots
        assert vec["dot_separator_ratio"] > 0.9
        # IPs are mostly numeric
        assert vec["numeric_ratio"] > 0.5
        # IPs have consistent format
        assert vec["format_consistency"] > 0.1
        # Not fully parseable as numbers
        assert vec["is_numeric_ratio"] == 0.0

    def test_timestamps_features(self):
        ts = [
            "2026-01-15T10:30:00Z",
            "2026-01-15T11:45:22Z",
            "2026-01-16T08:00:15Z",
        ]
        feat = extract_features("timestamp", ts)
        vec = dict(zip(FEATURE_NAMES, feat.vector))

        # Timestamps have dashes and colons
        assert vec["dash_separator_ratio"] > 0.9
        assert vec["colon_separator_ratio"] > 0.9
        # High format consistency
        assert vec["format_consistency"] > 0.3

    def test_md5_hash_features(self):
        hashes = [
            "d41d8cd98f00b204e9800998ecf8427e",
            "5d41402abc4b2a76b9719d911017c592",
            "e99a18c428cb38d5f260853678922e03",
        ]
        feat = extract_features("hash", hashes)
        vec = dict(zip(FEATURE_NAMES, feat.vector))

        # Hashes have fixed length
        assert vec["has_fixed_length"] == 1.0
        # High hex ratio
        assert vec["hex_ratio"] > 0.9
        # High entropy
        assert vec["entropy"] > 0.3
        # Low cardinality (unique per event)
        assert vec["cardinality_ratio"] == 1.0

    def test_port_numbers_features(self):
        ports = ["80", "443", "8080", "22", "3389", "53"]
        feat = extract_features("port", ports)
        vec = dict(zip(FEATURE_NAMES, feat.vector))

        # All numeric
        assert vec["is_numeric_ratio"] == 1.0
        assert vec["is_integer_ratio"] == 1.0
        # Short strings
        assert vec["mean_length"] < 0.01  # Normalized, very short

    def test_category_features(self):
        cats = ["high", "high", "medium", "low", "high", "medium",
                "low", "high", "medium", "high"]
        feat = extract_features("severity", cats)
        vec = dict(zip(FEATURE_NAMES, feat.vector))

        # Low cardinality
        assert vec["cardinality_ratio"] < 0.5
        # Alpha dominant
        assert vec["alpha_ratio"] > 0.9

    def test_empty_values(self):
        feat = extract_features("empty", [])
        assert feat.vector == [0.0] * FEATURE_DIM
        assert feat.unique_count == 0

    def test_all_nulls(self):
        feat = extract_features("nulls", [None, None, None])
        assert feat.null_count == 3
        assert feat.unique_count == 0

    def test_mixed_with_nulls(self):
        feat = extract_features("mixed", ["a", None, "b", None])
        assert feat.sample_count == 4
        assert feat.null_count == 2
        assert feat.unique_count == 2

    def test_hostname_features(self):
        hosts = [
            "server01.example.com",
            "web02.example.com",
            "db01.internal.corp",
        ]
        feat = extract_features("hostname", hosts)
        vec = dict(zip(FEATURE_NAMES, feat.vector))

        # Dots present
        assert vec["dot_separator_ratio"] > 0.9
        # Alpha dominant (more letters than digits)
        assert vec["alpha_ratio"] > 0.5

    def test_sample_values_capped(self):
        vals = [str(i) for i in range(100)]
        feat = extract_features("big", vals)
        assert len(feat.sample_values) <= 10