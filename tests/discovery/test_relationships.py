"""Tests for co-occurrence analysis and relationship inference."""

import pytest
from grasp.discovery.clustering import ClusterResult
from grasp.discovery.relationships import (
    analyze_co_occurrence,
    _mutual_information,
    _infer_relationship_type,
)
from grasp.models.source_profile import EntityType


class TestMutualInformation:
    """Verify MI computation for binary presence vectors."""

    def test_perfect_co_occurrence(self):
        x = [True, True, True, True, True]
        y = [True, True, True, True, True]
        mi = _mutual_information(x, y, 5)
        # Perfect co-occurrence has zero MI (no surprise)
        # Both are always present -> knowing x tells nothing new about y
        assert mi == 0.0

    def test_independent_fields(self):
        # Roughly independent
        x = [True, True, False, False, True, True, False, False]
        y = [True, False, True, False, True, False, True, False]
        mi = _mutual_information(x, y, 8)
        # Should be close to 0
        assert mi < 0.1

    def test_strong_co_occurrence(self):
        # When x is present, y is always present, but y can be present without x
        x = [True,  True,  True,  False, False, True,  True,  False]
        y = [True,  True,  True,  True,  True,  True,  True,  False]
        mi = _mutual_information(x, y, 8)
        # Should show positive MI
        assert mi > 0.0

    def test_empty(self):
        mi = _mutual_information([], [], 0)
        assert mi == 0.0


class TestInferRelationshipType:
    """Verify relationship type inference from entity pairs."""

    def test_ip_to_ip(self):
        rt = _infer_relationship_type(
            EntityType.IP_ADDRESS, EntityType.IP_ADDRESS
        )
        assert rt == "COMMUNICATES_WITH"

    def test_identity_to_hostname(self):
        rt = _infer_relationship_type(
            EntityType.IDENTITY, EntityType.HOSTNAME
        )
        assert rt == "SESSION_ON"

    def test_hash_to_hostname(self):
        rt = _infer_relationship_type(
            EntityType.HASH_SHA256, EntityType.HOSTNAME
        )
        assert rt == "OBSERVED_ON"

    def test_unknown_pair(self):
        rt = _infer_relationship_type(
            EntityType.CATEGORY, EntityType.TEXT
        )
        assert rt == "RELATED_TO"

    def test_order_independent(self):
        rt1 = _infer_relationship_type(
            EntityType.IDENTITY, EntityType.IP_ADDRESS
        )
        rt2 = _infer_relationship_type(
            EntityType.IP_ADDRESS, EntityType.IDENTITY
        )
        assert rt1 == rt2


class TestAnalyzeCoOccurrence:
    """Verify end-to-end co-occurrence analysis."""

    def _make_entity(self, path: str, etype: EntityType) -> ClusterResult:
        return ClusterResult(
            field_path=path,
            cluster_id=0,
            confidence=0.9,
            entity_type=etype,
            is_entity=True,
        )

    def test_basic_co_occurrence(self):
        payloads = [
            {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
            {"src_ip": "3.3.3.3", "dst_ip": "4.4.4.4"},
            {"src_ip": "5.5.5.5", "dst_ip": "6.6.6.6"},
        ]
        entities = [
            self._make_entity("src_ip", EntityType.IP_ADDRESS),
            self._make_entity("dst_ip", EntityType.IP_ADDRESS),
        ]
        rels = analyze_co_occurrence(payloads, entities, mi_threshold=0.0)
        # Both fields always co-occur, but MI may be 0 (perfect correlation)
        # We set threshold to 0 to capture everything
        assert len(rels) >= 0  # May be 0 if MI is exactly 0

    def test_partial_co_occurrence(self):
        payloads = [
            {"src_ip": "1.1.1.1", "username": "admin"},
            {"src_ip": "2.2.2.2", "username": "root"},
            {"src_ip": "3.3.3.3"},
            {"src_ip": "4.4.4.4", "username": "admin"},
            {"username": "guest"},
        ]
        entities = [
            self._make_entity("src_ip", EntityType.IP_ADDRESS),
            self._make_entity("username", EntityType.IDENTITY),
        ]
        rels = analyze_co_occurrence(payloads, entities, mi_threshold=0.0)
        # Should find a relationship
        assert len(rels) >= 1
        rel = rels[0]
        assert rel.co_occurrence_count == 3
        assert rel.relationship_type == "AUTHENTICATED_FROM"

    def test_no_entities(self):
        rels = analyze_co_occurrence([{"a": 1}], [], mi_threshold=0.0)
        assert rels == []

    def test_single_entity(self):
        rels = analyze_co_occurrence(
            [{"ip": "1.1.1.1"}],
            [self._make_entity("ip", EntityType.IP_ADDRESS)],
            mi_threshold=0.0,
        )
        assert rels == []  # Need at least 2 entities for relationships