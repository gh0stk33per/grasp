"""Unsupervised field clustering and labeling.

Takes feature vectors from all fields in a sample and clusters them
using HDBSCAN. Fields that share statistical properties (similar
lengths, character distributions, entropy, separators) land in the
same cluster. Clusters are then labeled with semantic entity types.

The labeling stage uses lightweight heuristics on cluster centroids --
not regex matching on individual values. This is the critical
distinction from regex-ladder approaches: we classify field populations,
not individual strings.

Fields that do not cluster cleanly are tagged as UNKNOWN with a low
confidence score. They are NOT discarded -- unknown fields still
participate in co-occurrence analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import hdbscan
import numpy as np
from sklearn.preprocessing import StandardScaler

from grasp.discovery.features import FEATURE_NAMES, FieldFeatures
from grasp.models.source_profile import EntityType

logger = logging.getLogger("grasp.discovery.clustering")


@dataclass
class ClusterResult:
    """Result of clustering a single field."""
    field_path: str
    cluster_id: int
    confidence: float
    entity_type: EntityType
    is_entity: bool


@dataclass
class ClusteringOutput:
    """Complete clustering results for all fields in a sample."""
    results: list[ClusterResult]
    n_clusters: int
    noise_count: int


def cluster_fields(features: list[FieldFeatures]) -> ClusteringOutput:
    """Cluster fields by their feature vectors using HDBSCAN.

    Steps:
    1. Build feature matrix from all field feature vectors
    2. Standardize features (zero mean, unit variance)
    3. Run HDBSCAN to discover density-based clusters
    4. Label each cluster with a semantic entity type
    5. Determine which fields represent graph-worthy entities

    Args:
        features: Feature vectors for all fields from the sample.

    Returns:
        ClusteringOutput with per-field cluster assignments and labels.
    """
    if not features:
        return ClusteringOutput(results=[], n_clusters=0, noise_count=0)

    n_fields = len(features)

    # Need minimum fields for meaningful clustering
    if n_fields < 3:
        return _fallback_classification(features)

    # Build feature matrix
    matrix = np.array([f.vector for f in features], dtype=np.float64)

    # Standardize features
    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)

    # HDBSCAN clustering
    # min_cluster_size=2: even two similar fields form a valid cluster
    # min_samples=1: permissive -- we'd rather over-cluster than miss patterns
    # The security telemetry domain typically has clear field-type separations
    min_cs = max(2, n_fields // 10)
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min(min_cs, 5),
        min_samples=1,
        metric="euclidean",
        cluster_selection_method="eom",
    )
    clusterer.fit(scaled)

    labels = clusterer.labels_
    probabilities = clusterer.probabilities_
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    noise_count = int(np.sum(labels == -1))

    logger.info(
        "HDBSCAN found %d clusters, %d noise fields from %d total fields",
        n_clusters, noise_count, n_fields,
    )

    # Label each cluster
    cluster_labels = _label_clusters(features, labels, scaled)

    # Build results
    results = []
    for i, feat in enumerate(features):
        cid = int(labels[i])
        prob = float(probabilities[i])
        etype, is_ent = cluster_labels.get(cid, (EntityType.UNKNOWN, False))

        # Noise points get UNKNOWN with zero confidence
        if cid == -1:
            etype, is_ent = _heuristic_classify(feat)
            prob = 0.3 if etype != EntityType.UNKNOWN else 0.0

        results.append(ClusterResult(
            field_path=feat.field_path,
            cluster_id=cid,
            confidence=prob,
            entity_type=etype,
            is_entity=is_ent,
        ))

    return ClusteringOutput(
        results=results,
        n_clusters=n_clusters,
        noise_count=noise_count,
    )


def _label_clusters(
    features: list[FieldFeatures],
    labels: np.ndarray,
    scaled: np.ndarray,
) -> dict[int, tuple[EntityType, bool]]:
    """Assign semantic labels to each cluster based on centroid features.

    Examines the mean feature vector (centroid) of each cluster and
    applies lightweight heuristics to determine what type of field
    the cluster represents. This is classification of populations,
    not individual values.
    """
    unique_labels = set(labels)
    unique_labels.discard(-1)

    cluster_labels: dict[int, tuple[EntityType, bool]] = {}

    for cid in unique_labels:
        mask = labels == cid
        members = [features[i] for i in range(len(features)) if mask[i]]
        centroid = scaled[mask].mean(axis=0)

        # Get feature values by name for readability
        f = dict(zip(FEATURE_NAMES, centroid))

        etype, is_ent = _classify_centroid(f, members)
        cluster_labels[cid] = (etype, is_ent)

        member_paths = [m.field_path for m in members]
        logger.info(
            "Cluster %d -> %s (entity=%s) fields=%s",
            cid, etype.value, is_ent, member_paths,
        )

    return cluster_labels


def _classify_centroid(
    f: dict[str, float],
    members: list[FieldFeatures],
) -> tuple[EntityType, bool]:
    """Classify a cluster from its centroid features.

    These heuristics operate on standardized features (z-scores),
    so thresholds are relative to the feature distribution, not
    absolute values. A positive z-score means above average.

    The heuristics are intentionally ordered from most specific
    to most general -- early matches take priority.
    """
    # Check member raw values for additional signal
    all_samples = []
    for m in members:
        all_samples.extend(m.sample_values)

    # --- Timestamp: high format consistency, presence of colons and dashes ---
    if (f.get("colon_separator_ratio", 0) > 0.5
            and f.get("dash_separator_ratio", 0) > 0.5
            and f.get("format_consistency", 0) > 0):
        return EntityType.TIMESTAMP, False

    # --- IP address: dot separators, numeric content, fixed-ish length ---
    if (f.get("dot_separator_ratio", 0) > 0.5
            and f.get("numeric_ratio", 0) > 0
            and f.get("alpha_ratio", 0) < 0):
        return EntityType.IP_ADDRESS, True

    # --- Port: fully numeric, integer, limited range ---
    if (f.get("is_numeric_ratio", 0) > 1.0
            and f.get("is_integer_ratio", 0) > 1.0
            and f.get("mean_length", 0) < 0):
        # Check actual values
        if all_samples:
            try:
                vals = [int(s) for s in all_samples[:10] if s.isdigit()]
                if vals and all(0 <= v <= 65535 for v in vals):
                    return EntityType.PORT, True
            except ValueError:
                pass
        return EntityType.NUMERIC, False

    # --- Hash: fixed length, high hex ratio, high entropy ---
    if (f.get("has_fixed_length", 0) > 0.5
            and f.get("hex_ratio", 0) > 0.5
            and f.get("entropy", 0) > 0.5):
        # Distinguish by typical lengths
        if members:
            sample_lens = set()
            for m in members:
                for s in m.sample_values:
                    sample_lens.add(len(s))
            if sample_lens:
                typical_len = max(sample_lens, key=lambda x: 1)
                if typical_len == 32:
                    return EntityType.HASH_MD5, True
                elif typical_len == 40:
                    return EntityType.HASH_SHA1, True
                elif typical_len == 64:
                    return EntityType.HASH_SHA256, True
        return EntityType.UNKNOWN, True

    # --- FQDN/Hostname: dots, alpha-dominant, moderate length ---
    if (f.get("dot_separator_ratio", 0) > 0
            and f.get("alpha_ratio", 0) > 0
            and f.get("numeric_ratio", 0) < 0.5):
        return EntityType.FQDN, True

    # --- MAC address: colon separators, hex content, fixed format ---
    if (f.get("colon_separator_ratio", 0) > 0.5
            and f.get("hex_ratio", 0) > 0.5
            and f.get("has_fixed_length", 0) > 0):
        return EntityType.MAC_ADDRESS, True

    # --- URL: slash separators, colon (for ://), moderate-high length ---
    if (f.get("slash_separator_ratio", 0) > 0.5
            and f.get("colon_separator_ratio", 0) > 0):
        return EntityType.URL, True

    # --- Category: very low cardinality ---
    if f.get("cardinality_ratio", 0) < -1.0:
        return EntityType.CATEGORY, False

    # --- Technique ID: check sample values for Txxxx pattern ---
    if all_samples:
        import re
        tech_matches = sum(
            1 for s in all_samples if re.match(r"^T\d{4}(\.\d{3})?$", s)
        )
        if tech_matches > len(all_samples) * 0.5:
            return EntityType.TECHNIQUE_ID, True

    # --- Identity: moderate cardinality, alpha-dominant, short ---
    if (f.get("alpha_ratio", 0) > 0.5
            and f.get("cardinality_ratio", 0) > 0
            and f.get("mean_length", 0) < 0):
        return EntityType.IDENTITY, True

    # --- Numeric: parseable as number ---
    if f.get("is_numeric_ratio", 0) > 0.5:
        return EntityType.NUMERIC, False

    # --- Text: long, high alpha, high entropy ---
    if (f.get("mean_length", 0) > 0.5
            and f.get("alpha_ratio", 0) > 0):
        return EntityType.TEXT, False

    return EntityType.UNKNOWN, False


def _heuristic_classify(feat: FieldFeatures) -> tuple[EntityType, bool]:
    """Fallback classification for noise points not assigned to a cluster.

    Uses direct value inspection rather than centroid features. This is
    the safety net -- if HDBSCAN cannot cluster a field, we still try
    to classify it individually.
    """
    import re

    samples = feat.sample_values
    if not samples:
        return EntityType.UNKNOWN, False

    # IP address check
    ip_re = re.compile(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    )
    ip_matches = sum(1 for s in samples if ip_re.match(s))
    if ip_matches > len(samples) * 0.7:
        return EntityType.IP_ADDRESS, True

    # Technique ID check
    tech_re = re.compile(r"^T\d{4}(\.\d{3})?$")
    tech_matches = sum(1 for s in samples if tech_re.match(s))
    if tech_matches > len(samples) * 0.7:
        return EntityType.TECHNIQUE_ID, True

    # Hash checks (by length + hex)
    hex_re = re.compile(r"^[0-9a-fA-F]+$")
    for hash_len, htype in [(32, EntityType.HASH_MD5),
                             (40, EntityType.HASH_SHA1),
                             (64, EntityType.HASH_SHA256)]:
        matches = sum(
            1 for s in samples
            if len(s) == hash_len and hex_re.match(s)
        )
        if matches > len(samples) * 0.7:
            return htype, True

    return EntityType.UNKNOWN, False


def _fallback_classification(
    features: list[FieldFeatures],
) -> ClusteringOutput:
    """Classify fields individually when too few for HDBSCAN.

    Used when the sample has fewer than 3 fields -- not enough
    for meaningful density-based clustering. Falls back to
    per-field heuristic classification.
    """
    results = []
    for feat in features:
        etype, is_ent = _heuristic_classify(feat)
        results.append(ClusterResult(
            field_path=feat.field_path,
            cluster_id=-1,
            confidence=0.3 if etype != EntityType.UNKNOWN else 0.0,
            entity_type=etype,
            is_entity=is_ent,
        ))
    return ClusteringOutput(
        results=results,
        n_clusters=0,
        noise_count=len(features),
    )