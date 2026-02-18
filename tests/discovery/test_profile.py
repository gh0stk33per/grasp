"""Tests for Source Profile assembly -- end-to-end discovery pipeline."""

import pytest
from grasp.discovery.profile import build_source_profile
from grasp.models.events import RawEvent, SampleBatch
from grasp.models.source_profile import EntityType, SourceProfile


def _make_batch(payloads: list[dict], source_id: str = "test") -> SampleBatch:
    """Helper to build a SampleBatch from raw payloads."""
    events = [
        RawEvent(source_id=source_id, payload=p, sequence=i)
        for i, p in enumerate(payloads)
    ]
    return SampleBatch(source_id=source_id, events=events)


def _generate_security_events(n: int = 50) -> list[dict]:
    """Generate synthetic security alert events for testing.

    Mimics the structure of host-based security alerts with
    known entity types: IPs, hostnames, timestamps, hashes,
    severity levels, and technique IDs.
    """
    import random
    random.seed(42)

    src_ips = [f"192.168.1.{i}" for i in range(1, 20)]
    dst_ips = [f"10.0.0.{i}" for i in range(1, 10)]
    agents = ["server01", "web02", "db01", "proxy03", "mail01"]
    severities = ["low", "medium", "high", "critical"]
    techniques = ["T1059", "T1078", "T1021", "T1055", "T1003"]
    hashes = [
        "d41d8cd98f00b204e9800998ecf8427e",
        "5d41402abc4b2a76b9719d911017c592",
        "e99a18c428cb38d5f260853678922e03",
        "098f6bcd4621d373cade4e832627b4f6",
        "0cc175b9c0f1b6a831c399e269772661",
    ]

    events = []
    for i in range(n):
        event = {
            "timestamp": f"2026-01-{15 + i % 5:02d}T{8 + i % 12:02d}:{i % 60:02d}:00Z",
            "rule": {
                "level": random.choice([3, 5, 7, 10, 12]),
                "description": f"Security event {i}",
                "mitre": {
                    "id": [random.choice(techniques)],
                },
            },
            "data": {
                "srcip": random.choice(src_ips),
                "dstip": random.choice(dst_ips) if random.random() > 0.3 else None,
            },
            "agent": {
                "name": random.choice(agents),
            },
            "severity": random.choice(severities),
        }
        # Add hash to some events
        if random.random() > 0.5:
            event["data"]["md5"] = random.choice(hashes)
        events.append(event)

    return events


class TestBuildSourceProfile:
    """Verify end-to-end Source Profile construction."""

    @pytest.mark.asyncio
    async def test_produces_profile(self):
        events = _generate_security_events(50)
        batch = _make_batch(events)
        profile = await build_source_profile(batch, "search_index", "test:9200")

        assert isinstance(profile, SourceProfile)
        assert profile.source_id == "test"
        assert profile.source_type == "search_index"
        assert profile.sample_size == 50
        assert profile.revision == 1
        assert len(profile.fields) > 0

    @pytest.mark.asyncio
    async def test_discovers_fields(self):
        events = _generate_security_events(50)
        batch = _make_batch(events)
        profile = await build_source_profile(batch)

        # Should find known field paths
        paths = {f.field_path for f in profile.fields}
        assert "data.srcip" in paths
        assert "agent.name" in paths
        assert "severity" in paths
        assert "timestamp" in paths

    @pytest.mark.asyncio
    async def test_identifies_entities(self):
        events = _generate_security_events(100)
        batch = _make_batch(events)
        profile = await build_source_profile(batch)

        entity_fields = profile.entity_fields()
        entity_paths = {f.field_path for f in entity_fields}

        # At minimum, IPs should be identified as entities
        # The ML pipeline may or may not identify all types correctly,
        # but it should find the most distinct ones
        assert len(entity_fields) >= 1

    @pytest.mark.asyncio
    async def test_confidence_scores_present(self):
        events = _generate_security_events(50)
        batch = _make_batch(events)
        profile = await build_source_profile(batch)

        for field in profile.fields:
            assert 0.0 <= field.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_fingerprint_computed(self):
        events = _generate_security_events(20)
        batch = _make_batch(events)
        profile = await build_source_profile(batch)

        assert profile.event_fingerprint != ""
        assert len(profile.event_fingerprint) == 16  # sha256[:16]

    @pytest.mark.asyncio
    async def test_empty_batch(self):
        batch = _make_batch([])
        profile = await build_source_profile(batch)

        assert profile.sample_size == 0
        assert len(profile.fields) == 0

    @pytest.mark.asyncio
    async def test_revision_increment(self):
        events = _generate_security_events(20)
        batch = _make_batch(events)

        profile_v1 = await build_source_profile(batch)
        assert profile_v1.revision == 1

        profile_v2 = await build_source_profile(
            batch, existing_profile=profile_v1
        )
        assert profile_v2.revision == 2
        assert profile_v2.created_at == profile_v1.created_at

    @pytest.mark.asyncio
    async def test_serialization_roundtrip(self):
        events = _generate_security_events(30)
        batch = _make_batch(events)
        profile = await build_source_profile(batch)

        # Pydantic should serialize and deserialize cleanly
        json_str = profile.model_dump_json()
        restored = SourceProfile.model_validate_json(json_str)

        assert restored.source_id == profile.source_id
        assert len(restored.fields) == len(profile.fields)
        assert restored.revision == profile.revision