"""Co-occurrence and relationship inference.

Analyzes which entity-typed fields appear together in events and
quantifies the strength of co-occurrence using mutual information.
Strong co-occurrence between entity fields implies a relationship
in the graph.

For example: if a source IP field and destination IP field both have
non-null values in 95% of events, that is a strong co-occurrence
indicating a network communication relationship.

Relationship types are inferred from the entity type pairs involved,
not from field names. IP + IP = COMMUNICATES_WITH, regardless of
whether the fields are named "srcip"/"dstip" or "agent.ip"/"target.ip".
"""

from __future__ import annotations

import logging
import math
from itertools import combinations
from typing import Any

from grasp.discovery.clustering import ClusterResult
from grasp.discovery.features import flatten_event
from grasp.models.source_profile import EntityType, RelationshipPattern

logger = logging.getLogger("grasp.discovery.relationships")

# Relationship type inference from entity type pairs.
# Order-independent: sorted tuple of entity types -> relationship type.
RELATIONSHIP_TYPE_MAP: dict[tuple[EntityType, ...], str] = {
    (EntityType.IP_ADDRESS, EntityType.IP_ADDRESS): "COMMUNICATES_WITH",
    (EntityType.IDENTITY, EntityType.IP_ADDRESS): "AUTHENTICATED_FROM",
    (EntityType.IDENTITY, EntityType.HOSTNAME): "SESSION_ON",
    (EntityType.IDENTITY, EntityType.FQDN): "SESSION_ON",
    (EntityType.HASH_MD5, EntityType.HOSTNAME): "OBSERVED_ON",
    (EntityType.HASH_SHA1, EntityType.HOSTNAME): "OBSERVED_ON",
    (EntityType.HASH_SHA256, EntityType.HOSTNAME): "OBSERVED_ON",
    (EntityType.HASH_MD5, EntityType.IP_ADDRESS): "OBSERVED_ON",
    (EntityType.HASH_SHA1, EntityType.IP_ADDRESS): "OBSERVED_ON",
    (EntityType.HASH_SHA256, EntityType.IP_ADDRESS): "OBSERVED_ON",
    (EntityType.IP_ADDRESS, EntityType.TECHNIQUE_ID): "TECHNIQUE_APPLIED",
    (EntityType.HOSTNAME, EntityType.TECHNIQUE_ID): "TECHNIQUE_APPLIED",
    (EntityType.FQDN, EntityType.TECHNIQUE_ID): "TECHNIQUE_APPLIED",
    (EntityType.IDENTITY, EntityType.TECHNIQUE_ID): "TECHNIQUE_USED_BY",
    (EntityType.IP_ADDRESS, EntityType.PORT): "CONNECTS_ON",
    (EntityType.IP_ADDRESS, EntityType.HOSTNAME): "RESOLVES_TO",
    (EntityType.IP_ADDRESS, EntityType.FQDN): "RESOLVES_TO",
    (EntityType.IP_ADDRESS, EntityType.URL): "HOSTS",
    (EntityType.HOSTNAME, EntityType.PORT): "LISTENS_ON",
}


def analyze_co_occurrence(
    payloads: list[dict[str, Any]],
    entity_fields: list[ClusterResult],
    mi_threshold: float = 0.1,
) -> list[RelationshipPattern]:
    """Compute co-occurrence relationships between entity fields.

    For every pair of entity-typed fields, compute:
    1. Co-occurrence count: how many events have both fields non-null
    2. Mutual information: how much knowing one field tells you about
       the other's presence

    Only pairs exceeding the mutual information threshold are returned
    as candidate relationships.

    Args:
        payloads: Raw event payloads from the sample.
        entity_fields: Fields classified as entities by the clusterer.
        mi_threshold: Minimum mutual information to report a relationship.

    Returns:
        List of discovered RelationshipPattern objects.
    """
    if len(entity_fields) < 2 or not payloads:
        return []

    entity_paths = [ef.field_path for ef in entity_fields]
    entity_type_map = {ef.field_path: ef.entity_type for ef in entity_fields}

    # Build presence matrix: for each event, which entity fields are present
    n_events = len(payloads)
    presence: dict[str, list[bool]] = {p: [] for p in entity_paths}

    for payload in payloads:
        flat = flatten_event(payload)
        for path in entity_paths:
            val = flat.get(path)
            present = val is not None and str(val).strip() != ""
            presence[path].append(present)

    # Compute pairwise mutual information
    relationships: list[RelationshipPattern] = []

    for path_a, path_b in combinations(entity_paths, 2):
        pres_a = presence[path_a]
        pres_b = presence[path_b]

        mi = _mutual_information(pres_a, pres_b, n_events)
        co_count = sum(
            1 for a, b in zip(pres_a, pres_b) if a and b
        )

        if mi < mi_threshold or co_count == 0:
            continue

        # Infer relationship type from entity types
        type_a = entity_type_map[path_a]
        type_b = entity_type_map[path_b]
        rel_type = _infer_relationship_type(type_a, type_b)

        # Confidence based on MI and co-occurrence rate
        co_rate = co_count / n_events if n_events > 0 else 0.0
        confidence = min(mi * co_rate * 2, 1.0)

        relationships.append(RelationshipPattern(
            source_field=path_a,
            target_field=path_b,
            source_entity_type=type_a,
            target_entity_type=type_b,
            mutual_information=round(mi, 4),
            co_occurrence_count=co_count,
            relationship_type=rel_type,
            confidence=round(confidence, 4),
        ))

    # Sort by MI descending
    relationships.sort(key=lambda r: r.mutual_information, reverse=True)

    logger.info(
        "Found %d relationships from %d entity field pairs",
        len(relationships),
        len(list(combinations(entity_paths, 2))),
    )

    return relationships


def _mutual_information(
    x: list[bool], y: list[bool], n: int
) -> float:
    """Compute mutual information between two binary presence vectors.

    MI(X;Y) = sum over x,y of P(x,y) * log2(P(x,y) / (P(x)*P(y)))

    Higher MI means stronger co-occurrence -- knowing whether field X
    is present tells you more about whether field Y is present.
    """
    if n == 0:
        return 0.0

    # Joint distribution counts
    both_present = sum(1 for a, b in zip(x, y) if a and b)
    a_only = sum(1 for a, b in zip(x, y) if a and not b)
    b_only = sum(1 for a, b in zip(x, y) if not a and b)
    neither = sum(1 for a, b in zip(x, y) if not a and not b)

    # Marginals
    p_a1 = sum(x) / n
    p_a0 = 1 - p_a1
    p_b1 = sum(y) / n
    p_b0 = 1 - p_b1

    mi = 0.0
    for joint, pa, pb in [
        (both_present / n, p_a1, p_b1),
        (a_only / n, p_a1, p_b0),
        (b_only / n, p_a0, p_b1),
        (neither / n, p_a0, p_b0),
    ]:
        if joint > 0 and pa > 0 and pb > 0:
            mi += joint * math.log2(joint / (pa * pb))

    return max(mi, 0.0)


def _infer_relationship_type(
    type_a: EntityType, type_b: EntityType
) -> str:
    """Infer a relationship label from two entity types.

    Uses the RELATIONSHIP_TYPE_MAP for known pairs. Falls back to
    RELATED_TO for unknown combinations -- the relationship still
    exists, we just cannot label it specifically.
    """
    key = tuple(sorted([type_a, type_b]))
    return RELATIONSHIP_TYPE_MAP.get(key, "RELATED_TO")