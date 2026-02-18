"""Source Profile data model.

The Source Profile is the central data contract in GRASP. The discovery
engine produces it, the graph engine consumes it, and the API exposes it.
It represents everything GRASP has learned about a data source through
unsupervised analysis -- field types, entity classifications, relationship
patterns, and confidence scores.

A Source Profile is living metadata. It refines continuously as GRASP
processes more events, adjusting confidence scores and discovering new
patterns. It is versioned and immutable per revision -- updates produce
new revisions, never in-place mutations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    """Entity classifications discovered from value analysis.

    Known types are labeled semantically. Unknown types use the
    DISCOVERED_N convention -- the system never discards what it
    does not understand.
    """
    IP_ADDRESS = "ip_address"
    HOSTNAME = "hostname"
    FQDN = "fqdn"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    IDENTITY = "identity"
    TIMESTAMP = "timestamp"
    PORT = "port"
    MAC_ADDRESS = "mac_address"
    URL = "url"
    TECHNIQUE_ID = "technique_id"
    CATEGORY = "category"
    NUMERIC = "numeric"
    TEXT = "text"
    UNKNOWN = "unknown"


class FieldProfile(BaseModel):
    """Everything GRASP knows about a single field in a data source.

    Built from unsupervised feature extraction and clustering.
    The feature_vector is the raw numeric representation used for
    clustering. The entity_type and cluster_id are the results.
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
    entity_type: EntityType = Field(
        default=EntityType.UNKNOWN,
        description="Classified entity type from cluster labeling"
    )
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
    is_entity: bool = Field(
        default=False,
        description="Whether this field represents a graph-worthy entity"
    )
    sample_values: list[str] = Field(
        default_factory=list,
        description="Small sample of values for debugging and profile inspection (max 10)"
    )


class RelationshipPattern(BaseModel):
    """A discovered co-occurrence pattern between two entity fields.

    When two entity-typed fields consistently appear together in events,
    they form a candidate relationship. Mutual information quantifies
    the strength of co-occurrence. The relationship_type is inferred
    from the entity types involved.
    """
    source_field: str = Field(
        description="Dot-notation path of the first entity field"
    )
    target_field: str = Field(
        description="Dot-notation path of the second entity field"
    )
    source_entity_type: EntityType = Field(
        description="Entity type of the source field"
    )
    target_entity_type: EntityType = Field(
        description="Entity type of the target field"
    )
    mutual_information: float = Field(
        ge=0.0,
        description="Mutual information score quantifying co-occurrence strength"
    )
    co_occurrence_count: int = Field(
        description="Number of events where both fields have non-null values"
    )
    relationship_type: str = Field(
        default="RELATED_TO",
        description="Inferred relationship label (e.g. COMMUNICATES_WITH, AUTHENTICATED_TO)"
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence in the inferred relationship type"
    )


class SourceProfile(BaseModel):
    """The complete profile of a discovered data source.

    Assembled by the discovery engine from unsupervised analysis of
    sampled events. Versioned and immutable per revision -- the graph
    engine references a specific profile revision when processing events.
    """
    source_id: str = Field(
        description="Unique identifier for this source (from env config)"
    )
    source_type: str = Field(
        description="Transport type: search_index, file, syslog"
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

    def entity_fields(self) -> list[FieldProfile]:
        """Return only fields classified as entities."""
        return [f for f in self.fields if f.is_entity]

    def get_field(self, path: str) -> Optional[FieldProfile]:
        """Look up a field profile by dot-notation path."""
        for f in self.fields:
            if f.field_path == path:
                return f
        return None

    def relationship_map(self) -> dict[tuple[str, str], RelationshipPattern]:
        """Return relationships indexed by (source_field, target_field) pair."""
        return {
            (r.source_field, r.target_field): r
            for r in self.relationships
        }