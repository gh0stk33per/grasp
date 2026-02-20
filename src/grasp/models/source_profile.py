"""Source Profile data model - Simplified Classification.

The Source Profile is the central data contract in GRASP. The discovery
engine produces it, the graph engine consumes it, and the API exposes it.

SIMPLIFIED MODEL:
- FieldClass replaces EntityType for graph role classification
- TypeHint provides optional format pattern detection
- Classification is feature-based, not format-based
- Works across any source: ES, CSV, Kafka, Redis, binary logs
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class FieldClass(str, Enum):
    """Graph role classification - source-agnostic.
    
    Fields are classified by their statistical fingerprint,
    not by recognizing specific formats. This works across
    any data source that produces field/value pairs.
    """
    ENTITY = "entity"      # Graph node candidate (high cardinality, structured)
    TEMPORAL = "temporal"  # Timestamp for event ordering
    METRIC = "metric"      # Numeric measurement (node property)
    ENUM = "enum"          # Low-cardinality category (node property)
    TEXT = "text"          # Long descriptive content (context)
    UNKNOWN = "unknown"    # Doesn't fit patterns (preserved for co-occurrence)


class TypeHint(str, Enum):
    """Optional format hints derived from value patterns.
    
    These are HINTS, not classification gates. A field is an ENTITY
    because of its statistical properties, not because we recognize
    it as an IP address. The hint helps with display and filtering.
    """
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MAC = "mac"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH = "hash"          # Generic hash (unknown algorithm)
    UUID = "uuid"
    URL = "url"
    FQDN = "fqdn"
    EMAIL = "email"
    PATH = "path"          # File/registry path
    SID = "sid"            # Windows Security Identifier
    ARN = "arn"            # AWS ARN
    # Extensible - add hints as patterns are discovered
    # These do NOT require code changes to classification logic


# Legacy alias for backward compatibility during transition
EntityType = FieldClass


class FieldProfile(BaseModel):
    """Everything GRASP knows about a single field in a data source.
    
    Built from unsupervised feature extraction and clustering.
    Classification is based on statistical fingerprint, not format matching.
    """
    field_path: str = Field(
        description="Dot-notation path from document root (e.g. 'data.srcip')"
    )
    sample_count: int = Field(
        description="Number of values observed during sampling"
    )
    null_count: int = Field(
        default=0,
        description="Number of null/missing values in sample"
    )
    unique_count: int = Field(
        description="Distinct values observed"
    )
    
    # Simplified classification
    field_class: FieldClass = Field(
        default=FieldClass.UNKNOWN,
        description="Graph role classification (entity, temporal, metric, enum, text, unknown)"
    )
    type_hint: Optional[TypeHint] = Field(
        default=None,
        description="Optional format hint (ipv4, hash, uuid, etc.) - does not affect classification"
    )
    is_entity: bool = Field(
        default=False,
        description="Whether this field represents a graph-worthy entity"
    )
    
    # Clustering metadata
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Classification confidence from clustering (0.0-1.0)"
    )
    cluster_id: int = Field(
        default=-1,
        description="Cluster assignment from HDBSCAN (-1 = noise/unassigned)"
    )
    
    # Feature data
    feature_vector: list[float] = Field(
        default_factory=list,
        description="Numeric feature vector used for clustering"
    )
    cardinality_ratio: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="unique_count / sample_count -- low = categorical, high = identifier"
    )
    sample_values: list[str] = Field(
        default_factory=list,
        description="Small sample of values for debugging and profile inspection (max 10)"
    )
    
    # Legacy field for backward compatibility
    @property
    def entity_type(self) -> FieldClass:
        """Legacy alias for field_class."""
        return self.field_class


class RelationshipPattern(BaseModel):
    """A discovered co-occurrence pattern between two entity fields.
    
    When two entity-typed fields consistently appear together in events,
    they form a candidate relationship. Mutual information quantifies
    the strength of co-occurrence.
    
    NOTE: Relationship type inference is now simpler - we don't try to
    guess COMMUNICATES_WITH vs AUTHENTICATED_TO from field types. The
    graph engine or downstream analysis determines relationship semantics.
    """
    source_field: str = Field(
        description="Dot-notation path of the first entity field"
    )
    target_field: str = Field(
        description="Dot-notation path of the second entity field"
    )
    source_class: FieldClass = Field(
        description="Field class of the source field"
    )
    target_class: FieldClass = Field(
        description="Field class of the target field"
    )
    source_hint: Optional[TypeHint] = Field(
        default=None,
        description="Type hint of source field (if detected)"
    )
    target_hint: Optional[TypeHint] = Field(
        default=None,
        description="Type hint of target field (if detected)"
    )
    mutual_information: float = Field(
        ge=0.0,
        description="Mutual information score quantifying co-occurrence strength"
    )
    co_occurrence_count: int = Field(
        description="Number of events where both fields have non-null values"
    )
    relationship_type: str = Field(
        default="CO_OCCURS_WITH",
        description="Relationship label - defaults to generic, refined by graph engine"
    )
    
    # Legacy aliases
    @property
    def source_entity_type(self) -> FieldClass:
        return self.source_class
    
    @property
    def target_entity_type(self) -> FieldClass:
        return self.target_class


class SourceProfile(BaseModel):
    """The complete profile of a discovered data source.
    
    Assembled by the discovery engine from unsupervised analysis of
    sampled events. Source-agnostic - works for ES, CSV, Kafka, Redis,
    Pixhawk binaries, or any source the adapter layer can decode.
    """
    source_id: str = Field(
        description="Unique identifier for this source (from env config)"
    )
    source_type: str = Field(
        description="Transport type: search_index, file, syslog, binary"
    )
    endpoint: str = Field(
        default="",
        description="Connection endpoint (sanitized -- no credentials)"
    )
    
    # Discovery results
    fields: list[FieldProfile] = Field(
        default_factory=list,
        description="All discovered fields with classifications"
    )
    relationships: list[RelationshipPattern] = Field(
        default_factory=list,
        description="Discovered co-occurrence relationships between entity fields"
    )
    
    # Sampling metadata
    sample_size: int = Field(
        default=0,
        description="Number of events in the discovery sample"
    )
    sample_time_start: Optional[datetime] = Field(
        default=None,
        description="Earliest event timestamp in sample (if discoverable)"
    )
    sample_time_end: Optional[datetime] = Field(
        default=None,
        description="Latest event timestamp in sample (if discoverable)"
    )
    
    # Profile lifecycle
    revision: int = Field(
        default=1,
        description="Profile revision counter (increments on refresh)"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this profile was first created"
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this profile revision was produced"
    )
    
    # Operational metadata
    event_fingerprint: str = Field(
        default="",
        description="Hash of sample event structure for drift detection"
    )
    throughput_estimate: Optional[float] = Field(
        default=None,
        description="Estimated events per second from source"
    )
    
    # Classification summary
    @property
    def entity_count(self) -> int:
        """Count of fields classified as entities."""
        return sum(1 for f in self.fields if f.is_entity)
    
    @property
    def classification_summary(self) -> dict[str, int]:
        """Count of fields by classification."""
        from collections import Counter
        return dict(Counter(f.field_class.value for f in self.fields))
    
    def entity_fields(self) -> list[FieldProfile]:
        """Return only fields classified as entities."""
        return [f for f in self.fields if f.is_entity]
    
    def get_field(self, path: str) -> Optional[FieldProfile]:
        """Look up a field profile by dot-notation path."""
        for f in self.fields:
            if f.field_path == path:
                return f
        return None
    
    def fields_by_class(self, fc: FieldClass) -> list[FieldProfile]:
        """Return fields with a specific classification."""
        return [f for f in self.fields if f.field_class == fc]
    
    def fields_with_hint(self, hint: TypeHint) -> list[FieldProfile]:
        """Return entity fields with a specific type hint."""
        return [f for f in self.fields if f.type_hint == hint]
    
    def relationship_map(self) -> dict[tuple[str, str], RelationshipPattern]:
        """Return relationships indexed by (source_field, target_field) pair."""
        return {
            (r.source_field, r.target_field): r
            for r in self.relationships
        }