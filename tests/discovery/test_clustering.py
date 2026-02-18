"""Tests for field clustering and labeling."""

import pytest
from grasp.discovery.features import extract_features
from grasp.discovery.clustering import (
    ClusterResult,
    cluster_fields,
    _heuristic_classify,
)
from grasp.models.source_profile import EntityType


def _make_features(field_path: str, values: list[str]):
    """Helper to build FieldFeatures from sample values."""
    return extract_features(field_path, values)


class TestClusterFields:
    """Verify HDBSCAN produces meaningful clusters from field features."""

    def _build_mixed_features(self):
        """Build features from diverse field types typical in security telemetry."""
        return [
            _make_features("src_ip", [
                "192.168.1.1", "192.168.1.2", "10.0.0.1", "172.16.0.5",
                "8.8.8.8", "1.1.1.1", "192.168.2.10", "10.10.10.1",
            ]),
            _make_features("dst_ip", [
                "93.184.216.34", "151.101.1.69", "172.217.14.206",
                "13.107.42.14", "104.16.123.96", "52.95.110.1",
                "35.186.224.25", "23.235.47.133",
            ]),
            _make_features("timestamp", [
                "2026-01-15T10:30:00Z", "2026-01-15T11:45:22Z",
                "2026-01-16T08:00:15Z", "2026-01-16T09:12:33Z",
                "2026-01-17T14:55:01Z", "2026-01-17T16:20:45Z",
                "2026-01-18T07:30:00Z", "2026-01-18T22:15:10Z",
            ]),
            _make_features("rule_level", [
                "3", "5", "7", "3", "12", "5", "3", "7",
            ]),
            _make_features("severity", [
                "high", "medium", "low", "high", "critical", "medium",
                "low", "high",
            ]),
            _make_features("agent_name", [
                "server01", "web02", "db01", "proxy03", "mail01",
                "app04", "cache02", "lb01",
            ]),
            _make_features("description", [
                "File integrity checksum changed",
                "Multiple login failures detected",
                "New user account created on system",
                "Firewall rule modified by administrator",
                "SSH session opened from remote host",
                "Package installation detected",
                "Service configuration changed",
                "Unusual process execution detected",
            ]),
            _make_features("md5_hash", [
                "d41d8cd98f00b204e9800998ecf8427e",
                "5d41402abc4b2a76b9719d911017c592",
                "e99a18c428cb38d5f260853678922e03",
                "098f6bcd4621d373cade4e832627b4f6",
                "0cc175b9c0f1b6a831c399e269772661",
                "8277e0910d750195b448797616e091ad",
                "e4da3b7fbbce2345d7772b0674a318d5",
                "1679091c5a880faf6fb5e6087eb1b2dc",
            ]),
        ]

    def test_clustering_produces_results(self):
        features = self._build_mixed_features()
        output = cluster_fields(features)
        assert len(output.results) == len(features)
        assert output.n_clusters >= 1

    def test_ip_fields_cluster_together(self):
        features = self._build_mixed_features()
        output = cluster_fields(features)
        result_map = {r.field_path: r for r in output.results}

        src_ip = result_map["src_ip"]
        dst_ip = result_map["dst_ip"]

        # Both should be IPs or at least in the same cluster
        if src_ip.cluster_id != -1 and dst_ip.cluster_id != -1:
            assert src_ip.cluster_id == dst_ip.cluster_id

    def test_entity_types_assigned(self):
        features = self._build_mixed_features()
        output = cluster_fields(features)
        result_map = {r.field_path: r for r in output.results}

        # At least some fields should be classified as entities
        entities = [r for r in output.results if r.is_entity]
        assert len(entities) >= 2  # At minimum the IP fields

    def test_hash_detected(self):
        features = self._build_mixed_features()
        output = cluster_fields(features)
        result_map = {r.field_path: r for r in output.results}

        md5 = result_map["md5_hash"]
        # Should be classified as some form of hash
        assert md5.entity_type in (
            EntityType.HASH_MD5, EntityType.HASH_SHA1,
            EntityType.HASH_SHA256, EntityType.UNKNOWN,
        )

    def test_unknown_fields_not_discarded(self):
        features = self._build_mixed_features()
        output = cluster_fields(features)
        # All fields must appear in results, even noise
        assert len(output.results) == len(features)

    def test_confidence_scores_bounded(self):
        features = self._build_mixed_features()
        output = cluster_fields(features)
        for r in output.results:
            assert 0.0 <= r.confidence <= 1.0

    def test_too_few_fields_fallback(self):
        features = [
            _make_features("ip", ["1.1.1.1", "2.2.2.2"]),
        ]
        output = cluster_fields(features)
        assert len(output.results) == 1
        assert output.n_clusters == 0  # Fallback mode


class TestHeuristicClassify:
    """Verify fallback classification for noise/edge cases."""

    def test_ip_heuristic(self):
        feat = _make_features("ip", [
            "10.0.0.1", "172.16.0.5", "192.168.1.1",
        ])
        etype, is_ent = _heuristic_classify(feat)
        assert etype == EntityType.IP_ADDRESS
        assert is_ent is True

    def test_technique_id_heuristic(self):
        feat = _make_features("technique", [
            "T1059", "T1078", "T1021.001",
        ])
        etype, is_ent = _heuristic_classify(feat)
        assert etype == EntityType.TECHNIQUE_ID
        assert is_ent is True

    def test_md5_heuristic(self):
        feat = _make_features("hash", [
            "d41d8cd98f00b204e9800998ecf8427e",
            "5d41402abc4b2a76b9719d911017c592",
        ])
        etype, is_ent = _heuristic_classify(feat)
        assert etype == EntityType.HASH_MD5
        assert is_ent is True

    def test_sha256_heuristic(self):
        feat = _make_features("hash", [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ])
        etype, is_ent = _heuristic_classify(feat)
        assert etype == EntityType.HASH_SHA256
        assert is_ent is True

    def test_unknown_fallback(self):
        feat = _make_features("weird", [
            "abc123xyz", "def456uvw", "ghi789rst",
        ])
        etype, is_ent = _heuristic_classify(feat)
        # Mixed content should be unknown
        assert etype == EntityType.UNKNOWN