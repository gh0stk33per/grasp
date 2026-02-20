"""Co-occurrence and relationship inference - Simplified Model.

Analyzes which entity-typed fields appear together in events and
quantifies the strength of co-occurrence using mutual information.
Strong co-occurrence between entity fields implies a relationship
in the graph.

SIMPLIFIED APPROACH:
- All entity pairs default to CO_OCCURS_WITH relationship
- Type hints can refine relationship labels but don't gate detection
- Relationship semantics determined by graph engine, not discovery
"""

from __future__ import annotations

import logging
import math
from itertools import combinations
from typing import Any, Optional

from grasp.discovery.clustering import ClusterResult
from grasp.discovery.features import flatten_event
from grasp.models.source_profile import (
    FieldClass,
    TypeHint,
    RelationshipPattern,
)

logger = logging.getLogger("grasp.discovery.relationships")


# Relationship type inference from type hint pairs.
# Optional refinement - most relationships will be CO_OCCURS_WITH
HINT_RELATIONSHIP_MAP: dict[tuple[Optional[TypeHint], Optional[TypeHint]], str] = {
    (TypeHint.IPV4, TypeHint.IPV4): "COMMUNICATES_WITH",
    (TypeHint.IPV6, TypeHint.IPV6): "COMMUNICATES_WITH",
    (TypeHint.IPV4, TypeHint.IPV6): "COMMUNICATES_WITH",
    (TypeHint.IPV4, TypeHint.FQDN): "RESOLVES_TO",
    (TypeHint.IPV6, TypeHint.FQDN): "RESOLVES_TO",
    (TypeHint.HASH_MD5, TypeHint.FQDN): "OBSERVED_ON",
    (TypeHint.HASH_SHA1, TypeHint.FQDN): "OBSERVED_ON",
    (TypeHint.HASH_SHA256, TypeHint.FQDN): "OBSERVED_ON",
    (TypeHint.HASH, TypeHint.FQDN): "OBSERVED_ON",
    (TypeHint.IPV4, TypeHint.URL): "HOSTS",
    (TypeHint.IPV6, TypeHint.URL): "HOSTS",
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
    # Map field_path to (field_class, type_hint)
    field_info_map = {
        ef.field_path: (ef.field_class, ef.type_hint)
        for ef in entity_fields
    }

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

        # Get field info
        class_a, hint_a = field_info_map[path_a]
        class_b, hint_b = field_info_map[path_b]

        # Infer relationship type from type hints (optional refinement)
        rel_type = _infer_relationship_type(hint_a, hint_b)

        # Confidence based on MI and co-occurrence rate
        co_rate = co_count / n_events if n_events > 0 else 0.0
        confidence = min(mi * co_rate * 2, 1.0)

        relationships.append(RelationshipPattern(
            source_field=path_a,
            target_field=path_b,
            source_class=class_a,
            target_class=class_b,
            source_hint=hint_a,
            target_hint=hint_b,
            mutual_information=round(mi, 4),
            co_occurrence_count=co_count,
            relationship_type=rel_type,
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
    hint_a: Optional[TypeHint],
    hint_b: Optional[TypeHint],
) -> str:
    """Infer a relationship label from two type hints.

    Uses the HINT_RELATIONSHIP_MAP for known hint pairs. Falls back to
    CO_OCCURS_WITH for unknown combinations -- the relationship still
    exists, we just cannot label it specifically.

    The graph engine or downstream analysis can refine these labels
    based on additional context.
    """
    if hint_a is None or hint_b is None:
        return "CO_OCCURS_WITH"

    # Try both orderings
    key = tuple(sorted([hint_a, hint_b], key=lambda h: h.value if h else ""))
    if key in HINT_RELATIONSHIP_MAP:
        return HINT_RELATIONSHIP_MAP[key]

    # Try explicit ordering
    if (hint_a, hint_b) in HINT_RELATIONSHIP_MAP:
        return HINT_RELATIONSHIP_MAP[(hint_a, hint_b)]
    if (hint_b, hint_a) in HINT_RELATIONSHIP_MAP:
        return HINT_RELATIONSHIP_MAP[(hint_b, hint_a)]

    return "CO_OCCURS_WITH"