"""Unsupervised field clustering and labeling.

Takes feature vectors from all fields in a sample and clusters them
using HDBSCAN. Fields that share statistical properties (similar
lengths, character distributions, entropy, separators) land in the
same cluster. Clusters are then labeled with semantic entity types.

Two-phase classification:
  Phase 1 - Centroid-based labeling from cluster feature statistics
  Phase 2 - Value-based validation that spot-checks sample values
            against the assigned label, correcting misclassifications

Fields that do not cluster cleanly are tagged as UNKNOWN with a low
confidence score. They are NOT discarded -- unknown fields still
participate in co-occurrence analysis.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import hdbscan
import numpy as np
from sklearn.preprocessing import StandardScaler

from grasp.discovery.features import FEATURE_NAMES, FieldFeatures
from grasp.models.source_profile import EntityType

logger = logging.getLogger("grasp.discovery.clustering")

# -------------------------------------------------------------------
# Value validation patterns (compiled once)
# -------------------------------------------------------------------

RE_IPV4 = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)
RE_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
RE_HEX = re.compile(r"^[0-9a-fA-F]+$")
RE_MAC = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")
RE_FQDN = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9\-]*(\.[a-zA-Z][a-zA-Z0-9\-]*)*\.[a-zA-Z]{2,}$"
)
RE_URL = re.compile(r"^https?://")


def _is_valid_ipv4(s: str) -> bool:
    """Check if string is a valid IPv4 address with octets 0-255."""
    m = RE_IPV4.match(s)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def _validate_samples(samples: list[str], validator, min_ratio: float = 0.6) -> bool:
    """Check if at least min_ratio of sample values pass validation."""
    if not samples:
        return False
    passing = sum(1 for s in samples if validator(s))
    return (passing / len(samples)) >= min_ratio


# -------------------------------------------------------------------
# Data classes
# -------------------------------------------------------------------

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


# -------------------------------------------------------------------
# Main clustering pipeline
# -------------------------------------------------------------------

def cluster_fields(features: list[FieldFeatures]) -> ClusteringOutput:
    """Cluster fields by their feature vectors using HDBSCAN.

    Steps:
    1. Build feature matrix from all field feature vectors
    2. Standardize features (zero mean, unit variance)
    3. Run HDBSCAN to discover density-based clusters
    4. Label each cluster with a semantic entity type (Phase 1)
    5. Validate labels against sample values (Phase 2)
    6. Determine which fields represent graph-worthy entities

    Args:
        features: Feature vectors for all fields from the sample.

    Returns:
        ClusteringOutput with per-field cluster assignments and labels.
    """
    if not features:
        return ClusteringOutput(results=[], n_clusters=0, noise_count=0)

    n_fields = len(features)

    if n_fields < 3:
        results = [_validate_and_classify(feat) for feat in features]
        return ClusteringOutput(results=results, n_clusters=0, noise_count=len(features))

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
        "HDBSCAN found %d clusters, %d noise fields from %d total fields",
        n_clusters, noise_count, n_fields,
    )

    # Phase 1: Label each cluster from centroid features
    cluster_labels = _label_clusters(features, labels, scaled)

    # Build initial results
    results = []
    for i, feat in enumerate(features):
        cid = int(labels[i])
        prob = float(probabilities[i])

        if cid == -1:
            # Noise: classify individually
            result = _validate_and_classify(feat)
            result.cluster_id = -1
        else:
            etype, is_ent = cluster_labels.get(cid, (EntityType.UNKNOWN, False))
            result = ClusterResult(
                field_path=feat.field_path,
                cluster_id=cid,
                confidence=prob,
                entity_type=etype,
                is_entity=is_ent,
            )

        results.append(result)

    # Phase 2: Validate all labels against sample values
    results = _post_validation(results, features)

    return ClusteringOutput(
        results=results,
        n_clusters=n_clusters,
        noise_count=noise_count,
    )


# -------------------------------------------------------------------
# Phase 1: Centroid-based cluster labeling
# -------------------------------------------------------------------

def _label_clusters(
    features: list[FieldFeatures],
    labels: np.ndarray,
    scaled: np.ndarray,
) -> dict[int, tuple[EntityType, bool]]:
    """Assign semantic labels to each cluster based on centroid features."""
    unique_labels = set(labels)
    unique_labels.discard(-1)

    cluster_labels: dict[int, tuple[EntityType, bool]] = {}

    for cid in unique_labels:
        mask = labels == cid
        members = [features[i] for i in range(len(features)) if mask[i]]
        centroid = scaled[mask].mean(axis=0)

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

    Heuristics ordered from most specific to most general.
    Uses centroid z-scores for initial classification.
    """
    # Collect all sample values across members for validation
    all_samples = []
    for m in members:
        all_samples.extend(m.sample_values)

    # --- Timestamp: colons + dashes + moderate length ---
    if (f.get("colon_separator_ratio", 0) > 0.5
            and f.get("dash_separator_ratio", 0) > 0.5
            and f.get("format_consistency", 0) > 0):
        return EntityType.TIMESTAMP, False

    # --- Hash: fixed length + high hex + high entropy ---
    if (f.get("has_fixed_length", 0) > 0.5
            and f.get("hex_ratio", 0) > 0.5
            and f.get("entropy", 0) > 0.5):
        return _classify_hash_cluster(members)

    # --- IP address: dots + numeric, validated against actual octets ---
    if (f.get("dot_separator_ratio", 0) > 0.5
            and f.get("numeric_ratio", 0) > 0):
        # Must validate sample values -- compliance codes also have dots + digits
        # High threshold (0.95) because real IP fields are consistently IPs
        if _validate_samples(all_samples, _is_valid_ipv4, 0.95):
            return EntityType.IP_ADDRESS, True

    # --- MAC address: colons + hex + fixed format ---
    if (f.get("colon_separator_ratio", 0) > 0.5
            and f.get("hex_ratio", 0) > 0.5):
        if _validate_samples(all_samples, lambda s: bool(RE_MAC.match(s)), 0.6):
            return EntityType.MAC_ADDRESS, True

    # --- URL: slashes + colons ---
    if (f.get("slash_separator_ratio", 0) > 0.5
            and f.get("colon_separator_ratio", 0) > 0):
        if _validate_samples(all_samples, lambda s: bool(RE_URL.match(s)), 0.5):
            return EntityType.URL, True

    # --- FQDN/Hostname: dots + alpha-dominant ---
    if (f.get("dot_separator_ratio", 0) > 0
            and f.get("alpha_ratio", 0) > 0):
        if _validate_samples(all_samples, lambda s: bool(RE_FQDN.match(s)), 0.5):
            return EntityType.FQDN, True

    # --- Technique ID: check values ---
    if _validate_samples(all_samples, lambda s: bool(RE_TECHNIQUE.match(s)), 0.5):
        return EntityType.TECHNIQUE_ID, True

    # --- Port: removed from centroid classification ---
    # Numeric clusters default to NUMERIC. Port identification happens
    # only in Phase 2 per-field validation (_classify_from_values) where
    # actual values like 22, 80, 443 can be checked individually.
    # This prevents system IDs, levels, and counters from being
    # misclassified as ports at the cluster level.

    # --- Category: very low cardinality ---
    if f.get("cardinality_ratio", 0) < -1.0:
        return EntityType.CATEGORY, False

    # --- Numeric: parseable as number ---
    if f.get("is_numeric_ratio", 0) > 0.5:
        return EntityType.NUMERIC, False

    # --- Identity: moderate cardinality, alpha-dominant, short ---
    if (f.get("alpha_ratio", 0) > 0.5
            and f.get("cardinality_ratio", 0) > 0
            and f.get("mean_length", 0) < 0):
        return EntityType.IDENTITY, True

    # --- Text: long, high alpha ---
    if (f.get("mean_length", 0) > 0.5
            and f.get("alpha_ratio", 0) > 0):
        return EntityType.TEXT, False

    return EntityType.UNKNOWN, False


def _classify_hash_cluster(
    members: list[FieldFeatures],
) -> tuple[EntityType, bool]:
    """Distinguish hash types within a hash cluster by value lengths."""
    length_counts: dict[int, int] = {}
    for m in members:
        for s in m.sample_values:
            if RE_HEX.match(s):
                length_counts[len(s)] = length_counts.get(len(s), 0) + 1

    if not length_counts:
        return EntityType.UNKNOWN, True

    # If mixed lengths, report the most common but still mark as entity
    dominant_len = max(length_counts, key=length_counts.get)

    # Check if all members share the same length (homogeneous cluster)
    # or if this is a mixed-hash cluster
    unique_lengths = set()
    for m in members:
        for s in m.sample_values:
            if RE_HEX.match(s):
                unique_lengths.add(len(s))

    if len(unique_lengths) == 1:
        if dominant_len == 32:
            return EntityType.HASH_MD5, True
        elif dominant_len == 40:
            return EntityType.HASH_SHA1, True
        elif dominant_len == 64:
            return EntityType.HASH_SHA256, True

    # Mixed lengths in cluster -- label by dominant but note it's mixed
    # Individual fields will be corrected in Phase 2 validation
    if dominant_len == 32:
        return EntityType.HASH_MD5, True
    elif dominant_len == 40:
        return EntityType.HASH_SHA1, True
    elif dominant_len == 64:
        return EntityType.HASH_SHA256, True

    return EntityType.UNKNOWN, True


# -------------------------------------------------------------------
# Phase 2: Post-clustering value validation
# -------------------------------------------------------------------

def _post_validation(
    results: list[ClusterResult],
    features: list[FieldFeatures],
) -> list[ClusterResult]:
    """Validate and correct every classification against sample values.

    Phase 2 checks EVERY field individually against its own sample values,
    regardless of cluster assignment. This catches cases where:
    - A cluster label is wrong for some members (mixed clusters)
    - A field's values don't match its assigned type
    - Unknown fields can be positively identified from values alone
    """
    feat_map = {f.field_path: f for f in features}
    corrected = 0

    for result in results:
        feat = feat_map.get(result.field_path)
        if not feat or not feat.sample_values:
            continue

        samples = feat.sample_values
        original_type = result.entity_type

        # For UNKNOWN fields: try to positively classify from values
        if original_type == EntityType.UNKNOWN:
            new_type, new_entity = _classify_from_values(samples)
            if new_type != EntityType.UNKNOWN:
                logger.info(
                    "Phase 2 discovery: %s unknown -> %s",
                    result.field_path, new_type.value,
                )
                result.entity_type = new_type
                result.is_entity = new_entity
                result.confidence = max(result.confidence * 0.5, 0.4)
                corrected += 1
                continue

        # For assigned types: validate the assignment is correct
        if original_type != EntityType.UNKNOWN:
            validated_type, validated_entity = _validate_field_type(
                samples, original_type
            )
            if validated_type != original_type:
                logger.info(
                    "Phase 2 correction: %s %s -> %s",
                    result.field_path, original_type.value, validated_type.value,
                )
                result.entity_type = validated_type
                result.is_entity = validated_entity
                result.confidence = min(result.confidence, 0.6)
                corrected += 1

    logger.info("Phase 2 validation corrected %d fields", corrected)
    return results


def _validate_field_type(
    samples: list[str],
    assigned_type: EntityType,
) -> tuple[EntityType, bool]:
    """Validate a single field's assigned type against its sample values.

    Returns the corrected (or confirmed) type and entity flag.
    """
    # --- Validate IP assignments ---
    if assigned_type == EntityType.IP_ADDRESS:
        if not _validate_samples(samples, _is_valid_ipv4, 0.95):
            # Not actually IPs -- try to reclassify
            return _classify_from_values(samples)

    # --- Validate port assignments ---
    if assigned_type == EntityType.PORT:
        def is_port(s):
            try:
                v = int(s)
                return 0 <= v <= 65535
            except (ValueError, OverflowError):
                return False

        if not _validate_samples(samples, is_port, 0.8):
            return _classify_from_values(samples)

        # Must have at least some well-known port indicators
        try:
            vals = [int(s) for s in samples if s.lstrip("-").isdigit()]
            if vals:
                has_low_port = any(v <= 1024 for v in vals)
                common_high = {3306, 3389, 5432, 5900, 8080, 8443, 8888, 9200, 9300}
                has_common = any(v in common_high for v in vals)
                if not has_low_port and not has_common:
                    return EntityType.NUMERIC, False
        except (ValueError, OverflowError):
            pass

    # --- Validate hash assignments ---
    if assigned_type in (EntityType.HASH_MD5, EntityType.HASH_SHA1, EntityType.HASH_SHA256):
        if not _validate_samples(samples, lambda s: bool(RE_HEX.match(s)), 0.8):
            return _classify_from_values(samples)
        # Correct hash subtype based on actual lengths
        lengths = [len(s) for s in samples if RE_HEX.match(s)]
        if lengths:
            dominant = max(set(lengths), key=lengths.count)
            if dominant == 32:
                return EntityType.HASH_MD5, True
            elif dominant == 40:
                return EntityType.HASH_SHA1, True
            elif dominant == 64:
                return EntityType.HASH_SHA256, True

    # --- Validate technique ID assignments ---
    if assigned_type == EntityType.TECHNIQUE_ID:
        if not _validate_samples(samples, lambda s: bool(RE_TECHNIQUE.match(s)), 0.5):
            return _classify_from_values(samples)

    # --- Validate FQDN assignments ---
    if assigned_type == EntityType.FQDN:
        if not _validate_samples(samples, lambda s: bool(RE_FQDN.match(s)), 0.5):
            return _classify_from_values(samples)

    return assigned_type, assigned_type in (
        EntityType.IP_ADDRESS, EntityType.HOSTNAME, EntityType.FQDN,
        EntityType.HASH_MD5, EntityType.HASH_SHA1, EntityType.HASH_SHA256,
        EntityType.IDENTITY, EntityType.TECHNIQUE_ID, EntityType.PORT,
        EntityType.MAC_ADDRESS, EntityType.URL,
    )


def _classify_from_values(samples: list[str]) -> tuple[EntityType, bool]:
    """Classify a field purely from its sample values.

    Used when Phase 1 cluster labeling is incorrect and the field
    needs reclassification. Checks types from most specific to
    most general.
    """
    if not samples:
        return EntityType.UNKNOWN, False

    # IP address -- high threshold, real IP fields are consistently valid
    if _validate_samples(samples, _is_valid_ipv4, 0.95):
        return EntityType.IP_ADDRESS, True

    # Technique ID
    if _validate_samples(samples, lambda s: bool(RE_TECHNIQUE.match(s)), 0.5):
        return EntityType.TECHNIQUE_ID, True

    # MAC address
    if _validate_samples(samples, lambda s: bool(RE_MAC.match(s)), 0.6):
        return EntityType.MAC_ADDRESS, True

    # Hashes by length
    hex_samples = [s for s in samples if RE_HEX.match(s)]
    if len(hex_samples) > len(samples) * 0.7:
        lengths = [len(s) for s in hex_samples]
        if lengths:
            dominant = max(set(lengths), key=lengths.count)
            if dominant == 32:
                return EntityType.HASH_MD5, True
            elif dominant == 40:
                return EntityType.HASH_SHA1, True
            elif dominant == 64:
                return EntityType.HASH_SHA256, True

    # URL
    if _validate_samples(samples, lambda s: bool(RE_URL.match(s)), 0.5):
        return EntityType.URL, True

    # FQDN
    if _validate_samples(samples, lambda s: bool(RE_FQDN.match(s)), 0.5):
        return EntityType.FQDN, True

    # Numeric
    def is_numeric(s):
        try:
            float(s)
            return True
        except (ValueError, OverflowError):
            return False

    if _validate_samples(samples, is_numeric, 0.8):
        # Check if port range with well-known port indicators
        try:
            vals = [int(s) for s in samples if s.lstrip("-").isdigit()]
            if vals:
                all_in_range = all(0 <= v <= 65535 for v in vals)
                has_low_port = any(v <= 1024 for v in vals)
                common_high = {3306, 3389, 5432, 5900, 8080, 8443, 8888, 9200, 9300}
                has_common = any(v in common_high for v in vals)
                if all_in_range and (has_low_port or has_common):
                    return EntityType.PORT, True
        except (ValueError, OverflowError):
            pass
        return EntityType.NUMERIC, False

    # Category: low cardinality short strings -- catches labels, modes, statuses, booleans
    unique_ratio = len(set(samples)) / max(len(samples), 1)
    n_unique = len(set(samples))
    avg_len = sum(len(s) for s in samples) / max(len(samples), 1)
    has_alpha = sum(1 for s in samples if any(c.isalpha() for c in s)) / max(len(samples), 1)

    if n_unique <= 3 and len(samples) >= 3:
        return EntityType.CATEGORY, False

    # Compliance codes: contain dots/dashes with mixed alpha-numeric segments
    # Values like CC6.8, AU.14, 164.312.b, A.10.1.1, SI.7
    compliance_pattern = re.compile(r"^[A-Z]{1,4}[\.\-]\d|^\d+\.\d+")
    compliance_matches = sum(1 for s in samples if compliance_pattern.match(s))
    if compliance_matches > len(samples) * 0.5:
        return EntityType.CATEGORY, False

    # Identity: short alpha-dominant strings that look like usernames
    # Values like 'root', 'admin', 'SYSTEM', 'wazuh', 'zettawise1'
    # NOT: long strings, paths, descriptions, process names
    if avg_len < 30 and has_alpha > 0.5 and n_unique > 1:
        # Reject if values look like paths (contain / or \)
        path_like = sum(1 for s in samples if "/" in s or "\\" in s)
        if path_like > len(samples) * 0.3:
            return EntityType.UNKNOWN, False

        # Reject if values contain parentheses (enriched fields like 'root(uid=0)')
        # or are very long descriptive text
        complex_vals = sum(1 for s in samples if "(" in s or len(s) > 40)
        if complex_vals > len(samples) * 0.3:
            return EntityType.UNKNOWN, False

        # Hostname indicators: contains at least one dash or dot, alpha content
        # Machine names like 'wazuh-aio', 'server01', 'dvwasrv'
        hostname_like = sum(
            1 for s in samples
            if ("-" in s) and any(c.isalpha() for c in s)
            and not any(c == "." for c in s)  # FQDNs handled separately
            and 3 < len(s) < 40
        )
        if hostname_like > len(samples) * 0.3:
            return EntityType.HOSTNAME, True

        # Identity: short, alpha-dominant, no special patterns
        # Must have reasonable cardinality (not 1 unique = constant, not too many)
        if 1 < n_unique <= 50 and avg_len < 20 and has_alpha > 0.7:
            # Final sanity: values should not contain dots (compliance codes)
            dot_vals = sum(1 for s in samples if "." in s)
            if dot_vals < len(samples) * 0.3:
                return EntityType.IDENTITY, True

    return EntityType.UNKNOWN, False


def _validate_and_classify(feat: FieldFeatures) -> ClusterResult:
    """Classify a single field using value-based validation.

    Used for noise points and fallback when too few fields for HDBSCAN.
    Combines Phase 1 and Phase 2 into a single pass.
    """
    etype, is_ent = _classify_from_values(feat.sample_values)
    conf = 0.5 if etype != EntityType.UNKNOWN else 0.0

    return ClusterResult(
        field_path=feat.field_path,
        cluster_id=-1,
        confidence=conf,
        entity_type=etype,
        is_entity=is_ent,
    )