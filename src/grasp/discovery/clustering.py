"""Unsupervised field clustering - Source-Agnostic Edition.

Simplified approach that classifies fields into graph roles rather than
source-specific semantic types. The goal is to identify:

  - ENTITY: High-cardinality structured values that become graph nodes
  - TEMPORAL: Timestamp fields for event ordering
  - METRIC: Numeric measurements (node properties, not nodes)
  - ENUM: Low-cardinality categorical values (node properties)
  - TEXT: Long descriptive content (context, not structure)
  - UNKNOWN: Doesn't fit patterns (preserved for co-occurrence)

Type hints (ip, hash, hostname, etc.) are derived from format patterns
but do NOT gate entity classification. A field is an ENTITY based on
its statistical fingerprint, not because we recognize its format.

This approach works across ES indices, CSV files, Kafka streams,
Redis stores, Pixhawk binaries - any source that produces field/value
pairs after adapter decoding.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import hdbscan
import numpy as np
from sklearn.preprocessing import StandardScaler

from grasp.discovery.features import FEATURE_NAMES, FieldFeatures
from grasp.models.source_profile import FieldClass, TypeHint

logger = logging.getLogger("grasp.discovery.clustering")


# ---------------------------------------------------------------------------
# Pattern matchers for type hints (not classification)
# ---------------------------------------------------------------------------

RE_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
RE_IPV6 = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
RE_MAC = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")
RE_HEX_FIXED = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
RE_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
RE_URL = re.compile(r"^https?://")
RE_FQDN = re.compile(r"^[a-zA-Z][a-zA-Z0-9\-]*(\.[a-zA-Z][a-zA-Z0-9\-]*)+$")
RE_TIMESTAMP_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def _detect_type_hint(samples: list[str]) -> Optional[TypeHint]:
    """Detect format pattern from sample values. Returns hint or None."""
    if not samples:
        return None
    
    # Count matches for each pattern
    def match_ratio(pattern) -> float:
        matches = sum(1 for s in samples if pattern.match(s))
        return matches / len(samples)
    
    # Check patterns in order of specificity
    if match_ratio(RE_IPV4) > 0.8:
        # Validate octets are 0-255
        valid = 0
        for s in samples:
            m = RE_IPV4.match(s)
            if m and all(0 <= int(g) <= 255 for g in m.groups()):
                valid += 1
        if valid / len(samples) > 0.8:
            return TypeHint.IPV4
    
    if match_ratio(RE_IPV6) > 0.6:
        return TypeHint.IPV6
    
    if match_ratio(RE_MAC) > 0.6:
        return TypeHint.MAC
    
    if match_ratio(RE_HEX_FIXED) > 0.7:
        # Distinguish hash types by length
        lengths = [len(s) for s in samples if RE_HEX_FIXED.match(s)]
        if lengths:
            dominant = max(set(lengths), key=lengths.count)
            if dominant == 32:
                return TypeHint.HASH_MD5
            elif dominant == 40:
                return TypeHint.HASH_SHA1
            elif dominant == 64:
                return TypeHint.HASH_SHA256
        return TypeHint.HASH
    
    if match_ratio(RE_UUID) > 0.6:
        return TypeHint.UUID
    
    if match_ratio(RE_URL) > 0.5:
        return TypeHint.URL
    
    if match_ratio(RE_FQDN) > 0.5:
        return TypeHint.FQDN
    
    return None


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ClusterResult:
    """Result of clustering a single field."""
    field_path: str
    cluster_id: int
    confidence: float
    field_class: FieldClass
    is_entity: bool
    type_hint: Optional[TypeHint] = None


@dataclass
class ClusteringOutput:
    """Complete clustering results for all fields in a sample."""
    results: list[ClusterResult]
    n_clusters: int
    noise_count: int


# ---------------------------------------------------------------------------
# Core classification logic - FEATURE-BASED, not pattern-based
# ---------------------------------------------------------------------------

def _classify_from_features(
    feat: FieldFeatures,
    centroid: Optional[dict[str, float]] = None,
) -> tuple[str, bool]:
    """Classify a field based on its statistical features.
    
    This is the heart of source-agnostic classification. We look at:
    - Cardinality: How many unique values relative to sample size?
    - Length distribution: Short fixed? Variable? Long?
    - Character composition: Numeric? Alpha? Mixed? Structured?
    - Format consistency: Do values follow a pattern?
    
    Args:
        feat: Extracted features for the field
        centroid: Optional cluster centroid features (z-scores)
    
    Returns:
        (field_class, is_entity) tuple
    """
    # Use per-field features, fall back to raw computation
    f = dict(zip(FEATURE_NAMES, feat.vector))
    samples = feat.sample_values
    n_unique = feat.unique_count
    n_samples = feat.sample_count - feat.null_count
    
    if n_samples == 0:
        return FieldClass.UNKNOWN, False
    
    cardinality = n_unique / max(n_samples, 1)
    
    # --- TEMPORAL: Timestamp patterns ---
    # Colons + dashes + moderate length + format consistency
    if (f.get("colon_separator_ratio", 0) > 0.8
            and f.get("dash_separator_ratio", 0) > 0.5
            and 15 < feat.vector[0] * 1000 < 35):  # mean_length ~19-30
        # Validate with regex
        ts_matches = sum(1 for s in samples if RE_TIMESTAMP_ISO.search(s))
        if ts_matches / max(len(samples), 1) > 0.7:
            return FieldClass.TEMPORAL, False
    
    # --- METRIC: Pure numeric ---
    if f.get("is_numeric_ratio", 0) > 0.9:
        return FieldClass.METRIC, False
    
    # --- ENUM: Low cardinality ---
    # Very few unique values relative to samples = categorical
    if n_unique <= 3 and n_samples >= 5:
        return FieldClass.ENUM, False
    if cardinality < 0.1 and n_samples >= 10:
        return FieldClass.ENUM, False
    
    # --- TEXT: Long, mostly alpha, variable ---
    mean_len = f.get("mean_length", 0) * 1000  # denormalize
    if (mean_len > 50 
            and f.get("alpha_ratio", 0) > 0.7
            and f.get("whitespace_ratio", 0) > 0.05):
        return FieldClass.TEXT, False
    
    # --- ENTITY: Structured, moderate cardinality, not too long ---
    # This is the key decision: is this field graph-worthy?
    
    # Entity signals:
    entity_score = 0.0
    
    # Moderate-to-high cardinality (not enum, not unique per event)
    if 0.1 < cardinality < 0.95:
        entity_score += 0.3
    elif cardinality >= 0.95 and n_unique > 5:
        # High cardinality with variety = likely identifiers
        entity_score += 0.2
    
    # Structured format (has separators consistently)
    separator_presence = (
        f.get("dot_separator_ratio", 0) +
        f.get("dash_separator_ratio", 0) +
        f.get("colon_separator_ratio", 0) +
        f.get("underscore_separator_ratio", 0) +
        f.get("at_separator_ratio", 0)
    )
    if separator_presence > 0.3:
        entity_score += 0.2
    
    # Consistent format (low length variance)
    if f.get("length_variance_ratio", 1) < 0.3:
        entity_score += 0.15
    
    # Fixed length = very structured (hashes, IDs)
    if f.get("has_fixed_length", 0) > 0.5:
        entity_score += 0.2
    
    # Moderate length (not tiny enums, not long text)
    if 5 < mean_len < 100:
        entity_score += 0.15
    
    # Mixed alphanumeric (identifiers often are)
    if (f.get("alpha_ratio", 0) > 0.2 
            and f.get("numeric_ratio", 0) > 0.1):
        entity_score += 0.1
    
    # High entropy relative to length = information-dense
    if f.get("entropy", 0) > 0.4:
        entity_score += 0.1
    
    # Decision threshold
    if entity_score >= 0.5:
        return FieldClass.ENTITY, True
    
    # --- UNKNOWN: Doesn't fit patterns ---
    return FieldClass.UNKNOWN, False


# ---------------------------------------------------------------------------
# Main clustering pipeline
# ---------------------------------------------------------------------------

def cluster_fields(features: list[FieldFeatures]) -> ClusteringOutput:
    """Cluster fields by their feature vectors using HDBSCAN.
    
    Simplified pipeline:
    1. Build feature matrix from all field feature vectors
    2. Standardize features (zero mean, unit variance)
    3. Run HDBSCAN to discover density-based clusters
    4. Classify each field based on features (not cluster label)
    5. Add type hints from format patterns
    
    Args:
        features: Feature vectors for all fields from the sample.
    
    Returns:
        ClusteringOutput with per-field classifications.
    """
    if not features:
        return ClusteringOutput(results=[], n_clusters=0, noise_count=0)
    
    n_fields = len(features)
    
    # For very small field sets, skip clustering
    if n_fields < 5:
        results = []
        for feat in features:
            fc, is_ent = _classify_from_features(feat)
            hint = _detect_type_hint(feat.sample_values) if is_ent else None
            results.append(ClusterResult(
                field_path=feat.field_path,
                cluster_id=-1,
                confidence=0.5,
                field_class=fc,
                is_entity=is_ent,
                type_hint=hint,
            ))
        return ClusteringOutput(results=results, n_clusters=0, noise_count=n_fields)
    
    # Build feature matrix
    matrix = np.array([f.vector for f in features], dtype=np.float64)
    
    # Standardize features
    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)
    
    # HDBSCAN clustering
    min_cs = max(2, min(n_fields // 10, 5))
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cs,
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
        "HDBSCAN: %d clusters, %d noise from %d fields",
        n_clusters, noise_count, n_fields,
    )
    
    # Classify each field individually based on features
    # Clustering is for grouping similar fields, not for classification
    results = []
    for i, feat in enumerate(features):
        cid = int(labels[i])
        prob = float(probabilities[i])
        
        # Classify based on features
        fc, is_ent = _classify_from_features(feat)
        
        # Detect type hint for entities
        hint = None
        if is_ent:
            hint = _detect_type_hint(feat.sample_values)
        
        results.append(ClusterResult(
            field_path=feat.field_path,
            cluster_id=cid,
            confidence=prob if cid != -1 else 0.5,
            field_class=fc,
            is_entity=is_ent,
            type_hint=hint,
        ))
        
        logger.debug(
            "Field %s -> %s (entity=%s, hint=%s, cid=%d)",
            feat.field_path, fc, is_ent, hint, cid,
        )
    
    # Log entity summary
    entities = [r for r in results if r.is_entity]
    logger.info(
        "Classification complete: %d entities, %d temporal, %d metric, %d enum, %d text, %d unknown",
        len(entities),
        sum(1 for r in results if r.field_class == FieldClass.TEMPORAL),
        sum(1 for r in results if r.field_class == FieldClass.METRIC),
        sum(1 for r in results if r.field_class == FieldClass.ENUM),
        sum(1 for r in results if r.field_class == FieldClass.TEXT),
        sum(1 for r in results if r.field_class == FieldClass.UNKNOWN),
    )
    
    return ClusteringOutput(
        results=results,
        n_clusters=n_clusters,
        noise_count=noise_count,
    )