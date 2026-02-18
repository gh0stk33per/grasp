"""Source Profile assembly and discovery orchestration.

This module is the conductor of the discovery pipeline. It takes a
SampleBatch from an adapter and drives it through the full discovery
sequence: flatten -> extract features -> cluster -> label -> analyze
co-occurrence -> assemble Source Profile.

The assembled Source Profile is the output of the discovery engine
and the input to the graph engine. It represents everything GRASP
has learned about a data source from unsupervised analysis.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from grasp.discovery.clustering import ClusterResult, cluster_fields
from grasp.discovery.features import (
    FieldFeatures,
    collect_field_values,
    extract_features,
)
from grasp.discovery.relationships import analyze_co_occurrence
from grasp.models.events import SampleBatch
from grasp.models.source_profile import (
    EntityType,
    FieldProfile,
    SourceProfile,
)

logger = logging.getLogger("grasp.discovery.profile")


async def build_source_profile(
    batch: SampleBatch,
    source_type: str = "unknown",
    endpoint: str = "",
    existing_profile: SourceProfile | None = None,
) -> SourceProfile:
    """Run the full discovery pipeline and assemble a Source Profile.

    This is the main entry point for the discovery engine. It
    orchestrates the entire analysis sequence:

    1. Flatten events and collect values per field path
    2. Extract feature vectors for each field
    3. Cluster fields by feature similarity
    4. Analyze co-occurrence between entity-typed fields
    5. Assemble and return the complete Source Profile

    If an existing profile is provided, this produces a new revision
    rather than a fresh profile (for drift detection and refresh).

    Args:
        batch: SampleBatch from an adapter.
        source_type: Transport type identifier.
        endpoint: Sanitized connection endpoint.
        existing_profile: Previous profile for revision tracking.

    Returns:
        Complete SourceProfile with all discovery results.
    """
    payloads = batch.payloads()
    n_events = len(payloads)

    if n_events == 0:
        logger.warning("Empty sample batch for source %s", batch.source_id)
        return _empty_profile(batch.source_id, source_type, endpoint)

    logger.info(
        "Starting discovery for source [%s]: %d events", batch.source_id, n_events
    )

    # Stage 1: Flatten and collect field values
    logger.info("Stage 1: Flattening events and collecting field values")
    field_values = collect_field_values(payloads)
    logger.info("Discovered %d unique field paths", len(field_values))

    # Stage 2: Extract feature vectors
    logger.info("Stage 2: Extracting feature vectors")
    features: list[FieldFeatures] = []
    for path, values in field_values.items():
        feat = extract_features(path, values)
        features.append(feat)

    logger.info("Extracted features for %d fields", len(features))

    # Stage 3: Cluster fields
    logger.info("Stage 3: Clustering fields by feature similarity")
    clustering = cluster_fields(features)
    logger.info(
        "Clustering complete: %d clusters, %d noise",
        clustering.n_clusters, clustering.noise_count,
    )

    # Build lookup from clustering results
    cluster_map: dict[str, ClusterResult] = {
        cr.field_path: cr for cr in clustering.results
    }

    # Stage 4: Analyze co-occurrence
    logger.info("Stage 4: Analyzing entity co-occurrence")
    entity_clusters = [cr for cr in clustering.results if cr.is_entity]
    relationships = analyze_co_occurrence(payloads, entity_clusters)
    logger.info("Discovered %d relationships", len(relationships))

    # Stage 5: Assemble Source Profile
    logger.info("Stage 5: Assembling Source Profile")

    field_profiles: list[FieldProfile] = []
    for feat in features:
        cr = cluster_map.get(feat.field_path)
        fp = FieldProfile(
            field_path=feat.field_path,
            sample_count=feat.sample_count,
            null_count=feat.null_count,
            unique_count=feat.unique_count,
            entity_type=cr.entity_type if cr else EntityType.UNKNOWN,
            confidence=cr.confidence if cr else 0.0,
            cluster_id=cr.cluster_id if cr else -1,
            feature_vector=feat.vector,
            cardinality_ratio=(
                feat.unique_count / feat.sample_count
                if feat.sample_count > 0 else 0.0
            ),
            is_entity=cr.is_entity if cr else False,
            sample_values=feat.sample_values,
        )
        field_profiles.append(fp)

    # Compute event structure fingerprint for drift detection
    fingerprint = _compute_fingerprint(payloads[:10])

    # Determine revision
    revision = 1
    created_at = datetime.now(timezone.utc)
    if existing_profile:
        revision = existing_profile.revision + 1
        created_at = existing_profile.created_at

    profile = SourceProfile(
        source_id=batch.source_id,
        source_type=source_type,
        endpoint=endpoint,
        fields=field_profiles,
        relationships=relationships,
        sample_size=n_events,
        revision=revision,
        created_at=created_at,
        updated_at=datetime.now(timezone.utc),
        event_fingerprint=fingerprint,
    )

    # Log summary
    entity_count = len(profile.entity_fields())
    logger.info(
        "Source Profile assembled for [%s] rev %d: "
        "%d fields (%d entities), %d relationships",
        batch.source_id,
        profile.revision,
        len(profile.fields),
        entity_count,
        len(profile.relationships),
    )

    return profile


def _compute_fingerprint(sample_events: list[dict]) -> str:
    """Compute a structural fingerprint of the event format.

    Uses the sorted set of field paths from a small sample to
    create a hash. If the fingerprint changes between profile
    revisions, it indicates schema drift.
    """
    if not sample_events:
        return ""

    from grasp.discovery.features import flatten_event

    all_paths: set[str] = set()
    for event in sample_events:
        flat = flatten_event(event)
        all_paths.update(flat.keys())

    path_str = json.dumps(sorted(all_paths), sort_keys=True)
    return hashlib.sha256(path_str.encode()).hexdigest()[:16]


def _empty_profile(
    source_id: str, source_type: str, endpoint: str
) -> SourceProfile:
    """Create an empty profile when no events are available."""
    return SourceProfile(
        source_id=source_id,
        source_type=source_type,
        endpoint=endpoint,
        sample_size=0,
    )