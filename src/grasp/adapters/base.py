"""Abstract adapter interface.

All transport adapters implement this contract. The interface defines
exactly two responsibilities: transport (how to get events) and
health (is the connection alive). Adapters do NOT transform, normalize,
enrich, or filter data.

Uses Python Protocol for structural typing -- adapters implement the
contract without inheritance. This allows adapters to be developed
and tested independently.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator

from grasp.models.events import RawEvent, SampleBatch

logger = logging.getLogger("grasp.adapters")


class ConnectionState(str, Enum):
    """Adapter connection states."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass
class AdapterHealth:
    """Health snapshot for an adapter connection."""
    state: ConnectionState = ConnectionState.DISCONNECTED
    source_id: str = ""
    adapter_type: str = ""
    endpoint: str = ""
    last_event_at: datetime | None = None
    events_delivered: int = 0
    errors: int = 0
    message: str = ""
    checked_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class BaseAdapter(ABC):
    """Abstract base for all GRASP transport adapters.

    Subclasses must implement all abstract methods. The contract:
    - connect(): establish connection, validate accessibility
    - sample(n): retrieve exactly n events for discovery analysis
    - stream(): yield events continuously as an async iterator
    - health(): report current connection state
    - disconnect(): clean up resources

    Configuration is passed as a plain dict sourced from environment
    variables. Each adapter type defines its own required keys.
    """

    def __init__(self, source_id: str, config: dict[str, Any]):
        self.source_id = source_id
        self.config = config
        self._state = ConnectionState.DISCONNECTED
        self._events_delivered = 0
        self._errors = 0
        self._last_event_at: datetime | None = None

    @property
    @abstractmethod
    def adapter_type(self) -> str:
        """Return the adapter type identifier (e.g. 'search_index', 'file')."""
        ...

    @abstractmethod
    async def connect(self) -> ConnectionState:
        """Establish connection to the data source.

        Returns the resulting connection state. Implementations should
        validate that the source is accessible and the credentials work.
        Must not raise -- connection failures return FAILED state.
        """
        ...

    @abstractmethod
    async def sample(self, n: int = 1000) -> SampleBatch:
        """Retrieve n events for discovery analysis.

        Returns a SampleBatch containing up to n raw events. If the
        source has fewer than n events, returns what is available.
        Events are returned in source order with no transformation.
        """
        ...

    @abstractmethod
    async def stream(self) -> AsyncIterator[RawEvent]:
        """Yield events continuously from the source.

        Async iterator that delivers events as they become available.
        Implementations handle reconnection, backpressure, and
        incremental tracking internally.
        """
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Release all resources and close connections."""
        ...

    def health(self) -> AdapterHealth:
        """Report current adapter health. Override for source-specific checks."""
        return AdapterHealth(
            state=self._state,
            source_id=self.source_id,
            adapter_type=self.adapter_type,
            endpoint=self.config.get("endpoint", ""),
            last_event_at=self._last_event_at,
            events_delivered=self._events_delivered,
            errors=self._errors,
        )

    def _record_event(self) -> None:
        """Track event delivery metrics. Call from subclass on each event."""
        self._events_delivered += 1
        self._last_event_at = datetime.now(timezone.utc)

    def _record_error(self, msg: str) -> None:
        """Track errors. Call from subclass on failures."""
        self._errors += 1
        logger.warning(
            "Adapter %s error [%s]: %s",
            self.adapter_type, self.source_id, msg,
        )