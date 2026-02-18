"""Raw event wrapper.

Events flow through GRASP inside this envelope. The payload is never
modified -- native signal preservation is a core principle. The envelope
carries routing metadata so the graph engine knows which Source Profile
to apply.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class RawEvent(BaseModel):
    """Immutable envelope around a raw event payload.

    The payload is the original event exactly as received from the source.
    No fields are added, removed, renamed, or transformed. The envelope
    metadata exists only for GRASP's internal routing.
    """
    source_id: str = Field(
        description="Which source produced this event (matches SourceProfile.source_id)"
    )
    payload: dict[str, Any] = Field(
        description="The raw event exactly as received -- never modified"
    )
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When GRASP received this event (not the event's own timestamp)"
    )
    sequence: Optional[int] = Field(
        default=None,
        description="Adapter-assigned sequence number for ordering"
    )

    class Config:
        frozen = True


class SampleBatch(BaseModel):
    """A batch of raw events collected during discovery sampling.

    Used by the discovery engine to analyze field structure and
    compute feature vectors. The batch preserves insertion order.
    """
    source_id: str = Field(
        description="Source that produced these events"
    )
    events: list[RawEvent] = Field(
        default_factory=list,
        description="Ordered list of sampled events"
    )
    sampled_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this sample was collected"
    )

    @property
    def size(self) -> int:
        return len(self.events)

    def payloads(self) -> list[dict[str, Any]]:
        """Extract just the raw payloads for discovery processing."""
        return [e.payload for e in self.events]